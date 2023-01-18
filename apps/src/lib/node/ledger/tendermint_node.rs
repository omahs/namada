use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;

use borsh::BorshSerialize;
use namada::types::chain::ChainId;
use namada::types::key::*;
use namada::types::time::DateTimeUtc;
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::config;
use crate::facade::tendermint::node::Id as TendermintNodeId;
use crate::facade::tendermint::Genesis;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_config::{
    Error as TendermintError, TendermintConfig,
};

/// Env. var to output Tendermint log to stdout
pub const ENV_VAR_TM_STDOUT: &str = "NAMADA_TM_STDOUT";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialize Tendermint: {0}")]
    Init(std::io::Error),
    #[error("Failed to load Tendermint config file: {0}")]
    LoadConfig(TendermintError),
    #[error("Failed to open Tendermint config for writing: {0}")]
    OpenWriteConfig(std::io::Error),
    #[error("Failed to serialize Tendermint config TOML to string: {0}")]
    ConfigSerializeToml(toml::ser::Error),
    #[error("Failed to write Tendermint config: {0}")]
    WriteConfig(std::io::Error),
    #[error("Failed to start up Tendermint node: {0}")]
    StartUp(std::io::Error),
    #[error("{0}")]
    Runtime(String),
    #[error("Failed to convert to String: {0:?}")]
    TendermintPath(std::ffi::OsString),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Check if the TENDERMINT env var has been set and use that as the
/// location of the tendermint binary. Otherwise, assume it is on path
///
/// Returns an error if the env var is defined but not a valid Unicode.
fn from_env_or_default() -> Result<String> {
    match std::env::var("TENDERMINT") {
        Ok(path) => {
            tracing::info!("Using tendermint path from env variable: {}", path);
            Ok(path)
        }
        Err(std::env::VarError::NotPresent) => Ok(String::from("tendermint")),
        Err(std::env::VarError::NotUnicode(msg)) => {
            Err(Error::TendermintPath(msg))
        }
    }
}

/// Run the tendermint node.
pub async fn run(
    home_dir: PathBuf,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    ledger_address: String,
    config: config::Tendermint,
    abort_recv: tokio::sync::oneshot::Receiver<
        tokio::sync::oneshot::Sender<()>,
    >,
) -> Result<()> {
    let home_dir_string = home_dir.to_string_lossy().to_string();
    let tendermint_path = from_env_or_default()?;
    let mode = config.tendermint_mode.to_str().to_owned();

    // init and run a tendermint node child process
    let output = Command::new(&tendermint_path)
        .args(["init", &mode, "--home", &home_dir_string])
        .output()
        .await
        .map_err(Error::Init)?;
    if !output.status.success() {
        panic!("Tendermint failed to initialize with {:#?}", output);
    }

    #[cfg(feature = "abcipp")]
    write_tm_genesis(&home_dir, chain_id, genesis_time, &config).await;
    #[cfg(not(feature = "abcipp"))]
    write_tm_genesis(&home_dir, chain_id, genesis_time).await;

    update_tendermint_config(&home_dir, config).await?;

    let mut tendermint_node = Command::new(&tendermint_path);
    tendermint_node.args([
        "start",
        "--proxy_app",
        &ledger_address,
        "--home",
        &home_dir_string,
    ]);

    let log_stdout = match env::var(ENV_VAR_TM_STDOUT) {
        Ok(val) => val.to_ascii_lowercase().trim() == "true",
        _ => false,
    };
    if !log_stdout {
        tendermint_node.stdout(Stdio::null());
    }

    let mut tendermint_node = tendermint_node
        .kill_on_drop(true)
        .spawn()
        .map_err(Error::StartUp)?;
    tracing::info!("Tendermint node started");

    tokio::select! {
        status = tendermint_node.wait() => {
            match status {
                Ok(status) => {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(Error::Runtime(status.to_string()))
                    }
                },
                Err(err) => {
                    Err(Error::Runtime(err.to_string()))
                }
            }
        },
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Tendermint node...");
                    tendermint_node.kill().await.unwrap();
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Tendermint abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Tendermint node...");
                    tendermint_node.kill().await.unwrap();
                }
            }
            Ok(())
        }
    }
}

pub fn reset(tendermint_dir: impl AsRef<Path>) -> Result<()> {
    let tendermint_path = from_env_or_default()?;
    let tendermint_dir = tendermint_dir.as_ref().to_string_lossy();
    // reset all the Tendermint state, if any
    std::process::Command::new(tendermint_path)
        .args([
            "reset-state",
            "unsafe-all",
            // NOTE: log config: https://docs.tendermint.com/master/nodes/logging.html#configuring-log-levels
            // "--log-level=\"*debug\"",
            "--home",
            &tendermint_dir,
        ])
        .output()
        .expect("Failed to reset tendermint node's data");
    std::fs::remove_dir_all(format!("{}/config", tendermint_dir,))
        .expect("Failed to reset tendermint node's config");
    Ok(())
}

/// Convert a common signing scheme validator key into JSON for
/// Tendermint
fn validator_key_to_json(
    sk: &common::SecretKey,
) -> std::result::Result<serde_json::Value, ParseSecretKeyError> {
    let raw_hash = tm_consensus_key_raw_hash(&sk.ref_to());
    let (id_str, pk_arr, kp_arr) = match sk {
        common::SecretKey::Ed25519(_) => {
            let sk_ed: ed25519::SecretKey = sk.try_to_sk().unwrap();
            let keypair = [
                sk_ed.try_to_vec().unwrap(),
                sk_ed.ref_to().try_to_vec().unwrap(),
            ]
            .concat();
            ("Ed25519", sk_ed.ref_to().try_to_vec().unwrap(), keypair)
        }
        common::SecretKey::Secp256k1(_) => {
            let sk_sec: secp256k1::SecretKey = sk.try_to_sk().unwrap();
            (
                "Secp256k1",
                sk_sec.ref_to().try_to_vec().unwrap(),
                sk_sec.try_to_vec().unwrap(),
            )
        }
    };

    Ok(json!({
        "address": raw_hash,
        "pub_key": {
            "type": format!("tendermint/PubKey{}",id_str),
            "value": base64::encode(pk_arr),
        },
        "priv_key": {
            "type": format!("tendermint/PrivKey{}",id_str),
            "value": base64::encode(kp_arr),
        }
    }))
}

/// Initialize validator private key for Tendermint
pub async fn write_validator_key_async(
    home_dir: impl AsRef<Path>,
    consensus_key: &common::SecretKey,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("priv_validator_key.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    fs::create_dir_all(wallet_dir)
        .await
        .expect("Couldn't create private validator key directory");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .expect("Couldn't create private validator key file");
    let key = validator_key_to_json(consensus_key).unwrap();
    let data = serde_json::to_vec_pretty(&key)
        .expect("Couldn't encode private validator key file");
    file.write_all(&data[..])
        .await
        .expect("Couldn't write private validator key file");
}

/// Initialize validator private key for Tendermint
pub fn write_validator_key(
    home_dir: impl AsRef<Path>,
    consensus_key: &common::SecretKey,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("priv_validator_key.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    std::fs::create_dir_all(wallet_dir)
        .expect("Couldn't create private validator key directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("Couldn't create private validator key file");
    let key = validator_key_to_json(consensus_key).unwrap();
    serde_json::to_writer_pretty(file, &key)
        .expect("Couldn't write private validator key file");
}

/// Initialize validator private state for Tendermint
pub fn write_validator_state(home_dir: impl AsRef<Path>) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("data").join("priv_validator_state.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    std::fs::create_dir_all(wallet_dir)
        .expect("Couldn't create private validator state directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("Couldn't create private validator state file");
    let state = json!({
       "height": "0",
       "round": 0,
       "step": 0
    });
    serde_json::to_writer_pretty(file, &state)
        .expect("Couldn't write private validator state file");
}

/// Length of a Tendermint Node ID in bytes
const TENDERMINT_NODE_ID_LENGTH: usize = 20;

/// Derive Tendermint node ID from public key
pub fn id_from_pk(pk: &common::PublicKey) -> TendermintNodeId {
    let mut bytes = [0u8; TENDERMINT_NODE_ID_LENGTH];

    match pk {
        common::PublicKey::Ed25519(_) => {
            let _pk: ed25519::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.try_to_vec().unwrap().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
        common::PublicKey::Secp256k1(_) => {
            let _pk: secp256k1::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.try_to_vec().unwrap().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
    }
    TendermintNodeId::new(bytes)
}

async fn update_tendermint_config(
    home_dir: impl AsRef<Path>,
    tendermint_config: config::Tendermint,
) -> Result<()> {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("config.toml");
    let mut config =
        TendermintConfig::load_toml_file(&path).map_err(Error::LoadConfig)?;

    config.p2p.laddr =
        TendermintAddress::from_str(&tendermint_config.p2p_address.to_string())
            .unwrap();
    config.p2p.persistent_peers = tendermint_config.p2p_persistent_peers;
    config.p2p.pex = tendermint_config.p2p_pex;
    config.p2p.allow_duplicate_ip = tendermint_config.p2p_allow_duplicate_ip;

    config.consensus.create_empty_blocks = true;

    // We set this to true as we don't want any invalid tx be re-applied. This
    // also implies that it's not possible for an invalid tx to become valid
    // again in the future.
    config.mempool.keep_invalid_txs_in_cache = false;

    config.rpc.laddr =
        TendermintAddress::from_str(&tendermint_config.rpc_address.to_string())
            .unwrap();
    // Bumped from the default `1_000_000`, because some WASMs can be
    // quite large
    config.rpc.max_body_bytes = 2_000_000;

    config.instrumentation.prometheus =
        tendermint_config.instrumentation_prometheus;
    config.instrumentation.prometheus_listen_addr = tendermint_config
        .instrumentation_prometheus_listen_addr
        .to_string();
    config.instrumentation.namespace =
        tendermint_config.instrumentation_namespace;

    #[cfg(feature = "abciplus")]
    {
        config.consensus.timeout_commit =
            tendermint_config.consensus_timeout_commit;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(Error::OpenWriteConfig)?;
    let config_str =
        toml::to_string(&config).map_err(Error::ConfigSerializeToml)?;
    file.write_all(config_str.as_bytes())
        .await
        .map_err(Error::WriteConfig)
}

async fn write_tm_genesis(
    home_dir: impl AsRef<Path>,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    #[cfg(feature = "abcipp")] config: &config::Tendermint,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("genesis.json");
    let mut file = File::open(&path).await.unwrap_or_else(|err| {
        panic!(
            "Couldn't open the genesis file at {:?}, error: {}",
            path, err
        )
    });
    let mut file_contents = vec![];
    file.read_to_end(&mut file_contents)
        .await
        .expect("Couldn't read Tendermint genesis file");
    let mut genesis: Genesis = serde_json::from_slice(&file_contents[..])
        .expect("Couldn't deserialize the genesis file");
    genesis.chain_id =
        FromStr::from_str(chain_id.as_str()).expect("Invalid chain ID");
    genesis.genesis_time = genesis_time
        .try_into()
        .expect("Couldn't convert DateTimeUtc to Tendermint Time");
    #[cfg(feature = "abcipp")]
    {
        genesis.consensus_params.timeout.commit =
            config.consensus_timeout_commit.into();
    }

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "Couldn't open the genesis file at {:?} for writing, error: {}",
                path, err
            )
        });
    let data = serde_json::to_vec_pretty(&genesis)
        .expect("Couldn't encode the Tendermint genesis file");
    file.write_all(&data[..])
        .await
        .expect("Couldn't write the Tendermint genesis file");
}

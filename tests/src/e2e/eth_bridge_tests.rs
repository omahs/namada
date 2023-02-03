mod helpers;

use std::num::NonZeroU64;

use color_eyre::eyre::Result;
use namada::ledger::eth_bridge::{
    ContractVersion, Contracts, EthereumBridgeConfig, MinimumConfirmations,
    UpgradeableContract,
};
use namada::types::address::wnam;
use namada::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
use namada::types::ethereum_events::EthAddress;
use namada::types::{address, token};
use namada_apps::config::ethereum_bridge;
use namada_core::types::ethereum_events::{EthereumEvent, TransferToNamada};

use super::setup::set_ethereum_bridge_mode;
use crate::e2e::eth_bridge_tests::helpers::{
    attempt_wrapped_erc20_transfer, find_wrapped_erc20_balance, send_transfer,
    setup_single_validator_test, EventsEndpointClient,
};
use crate::e2e::helpers::{
    find_address, get_actor_rpc, init_established_account,
};
use crate::e2e::setup;
use crate::e2e::setup::constants::{
    wasm_abs_path, ALBERT, ALBERT_KEY, BERTHA, NAM, TX_WRITE_STORAGE_KEY_WASM,
};
use crate::e2e::setup::{Bin, Who};
use crate::{run, run_as};

const ETH_BRIDGE_ADDRESS: &str = "atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew";

/// # Examples
///
/// ```
/// let storage_key = storage_key("queue");
/// assert_eq!(storage_key, "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/queue");
/// ```
fn storage_key(path: &str) -> String {
    format!("#{ETH_BRIDGE_ADDRESS}/{}", path)
}

#[test]
#[ignore]
// this test is outdated, so it is ignored
fn everything() {
    const LEDGER_STARTUP_TIMEOUT_SECONDS: u64 = 30;
    const CLIENT_COMMAND_TIMEOUT_SECONDS: u64 = 30;
    const SOLE_VALIDATOR: Who = Who::Validator(0);

    let test = setup::single_node_net().unwrap();

    let mut namadan_ledger = run_as!(
        test,
        SOLE_VALIDATOR,
        Bin::Node,
        &["ledger"],
        Some(LEDGER_STARTUP_TIMEOUT_SECONDS)
    )
    .unwrap();
    namadan_ledger
        .exp_string("Namada ledger node started")
        .unwrap();
    namadan_ledger
        .exp_string("Tendermint node started")
        .unwrap();
    namadan_ledger.exp_string("Committed block hash").unwrap();
    let _bg_ledger = namadan_ledger.background();

    let tx_data_path = test.test_dir.path().join("queue_storage_key.txt");
    std::fs::write(&tx_data_path, &storage_key("queue")[..]).unwrap();

    let tx_code_path = wasm_abs_path(TX_WRITE_STORAGE_KEY_WASM);

    let tx_data_path = tx_data_path.to_string_lossy().to_string();
    let tx_code_path = tx_code_path.to_string_lossy().to_string();
    let ledger_addr = get_actor_rpc(&test, &SOLE_VALIDATOR);
    let tx_args = vec![
        "tx",
        "--signer",
        ALBERT,
        "--code-path",
        &tx_code_path,
        "--data-path",
        &tx_data_path,
        "--ledger-address",
        &ledger_addr,
    ];

    for &dry_run in &[true, false] {
        let tx_args = if dry_run {
            vec![tx_args.clone(), vec!["--dry-run"]].concat()
        } else {
            tx_args.clone()
        };
        let mut namadac_tx = run!(
            test,
            Bin::Client,
            tx_args,
            Some(CLIENT_COMMAND_TIMEOUT_SECONDS)
        )
        .unwrap();

        if !dry_run {
            namadac_tx.exp_string("Transaction accepted").unwrap();
            namadac_tx.exp_string("Transaction applied").unwrap();
        }
        // TODO: we should check here explicitly with the ledger via a
        //  Tendermint RPC call that the path `value/#EthBridge/queue`
        //  is unchanged rather than relying solely  on looking at namadac
        //  stdout.
        namadac_tx.exp_string("Transaction is invalid").unwrap();
        namadac_tx
            .exp_string(&format!("Rejected: {}", ETH_BRIDGE_ADDRESS))
            .unwrap();
        namadac_tx.assert_success();
    }
}

/// Tests that we can start the ledger with an endpoint for submitting Ethereum
/// events. This mode can be used in further end-to-end tests.
#[test]
fn run_ledger_with_ethereum_events_endpoint() -> Result<()> {
    let test = setup::single_node_net()?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::EventsEndpoint,
    );

    // Start the ledger as a validator
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;
    ledger.exp_string(
        "Starting to listen for Borsh-serialized Ethereum events",
    )?;
    ledger.exp_string("Namada ledger node started")?;

    ledger.send_control('c')?;
    ledger.exp_string(
        "Stopping listening for Borsh-serialized Ethereum events",
    )?;

    Ok(())
}

/// In this test, we check the following:
/// 1. We can successfully add tranfers to the bridge pool.
/// 2. We can query the bridge pool and it is non-empty.
/// 3. We request a proof of inclusion of the transfer into the
///    bridge pool.
#[test]
fn test_add_to_bridge_pool() {
    const LEDGER_STARTUP_TIMEOUT_SECONDS: u64 = 40;
    const CLIENT_COMMAND_TIMEOUT_SECONDS: u64 = 60;
    const QUERY_TIMEOUT_SECONDS: u64 = 40;
    const SOLE_VALIDATOR: Who = Who::Validator(0);
    const RECEIVER: &str = "0x6B175474E89094C55Da98b954EedeAC495271d0F";
    let wnam_address = wnam().to_canonical();
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params = Some(EthereumBridgeConfig {
                min_confirmations: Default::default(),
                contracts: Contracts {
                    native_erc20: wnam(),
                    bridge: UpgradeableContract {
                        address: EthAddress([0; 20]),
                        version: Default::default(),
                    },
                    governance: UpgradeableContract {
                        address: EthAddress([1; 20]),
                        version: Default::default(),
                    },
                },
            });
            genesis
        },
        None,
    )
    .unwrap();
    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::EventsEndpoint,
    );

    let mut namadan_ledger = run_as!(
        test,
        SOLE_VALIDATOR,
        Bin::Node,
        &["ledger"],
        Some(LEDGER_STARTUP_TIMEOUT_SECONDS)
    )
    .unwrap();
    namadan_ledger
        .exp_string("Namada ledger node started")
        .unwrap();
    namadan_ledger
        .exp_string("Tendermint node started")
        .unwrap();
    namadan_ledger.exp_string("Committed block hash").unwrap();
    let _bg_ledger = namadan_ledger.background();

    let ledger_addr = get_actor_rpc(&test, &SOLE_VALIDATOR);
    let tx_args = vec![
        "add-erc20-transfer",
        "--address",
        BERTHA,
        "--signer",
        BERTHA,
        "--amount",
        "100",
        "--erc20",
        &wnam_address,
        "--ethereum-address",
        RECEIVER,
        "--fee-amount",
        "10",
        "--fee-payer",
        BERTHA,
        "--gas-amount",
        "0",
        "--gas-limit",
        "0",
        "--gas-token",
        NAM,
        "--ledger-address",
        &ledger_addr,
    ];

    let mut namadac_tx = run!(
        test,
        Bin::Client,
        tx_args,
        Some(CLIENT_COMMAND_TIMEOUT_SECONDS)
    )
    .unwrap();
    namadac_tx.exp_string("Transaction accepted").unwrap();
    namadac_tx.exp_string("Transaction applied").unwrap();
    namadac_tx.exp_string("Transaction is valid").unwrap();
    drop(namadac_tx);

    let mut namadar = run!(
        test,
        Bin::Relayer,
        [
            "ethereum-bridge-pool",
            "query",
            "--ledger-address",
            &ledger_addr,
        ],
        Some(QUERY_TIMEOUT_SECONDS),
    )
    .unwrap();
    // get the returned hash of the transfer.
    let regex =
        expectrl::Regex(r#""bridge_pool_contents":(?s).*(?-s)"[0-9A-F]+":"#);
    let mut hash = String::from_utf8(
        namadar
            .session
            .expect(regex)
            .unwrap()
            .get(0)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
    .split_ascii_whitespace()
    .last()
    .unwrap()
    .to_string();
    hash.remove(0);
    hash.truncate(hash.len() - 2);

    let proof_args = vec![
        "ethereum-bridge-pool",
        "construct-proof",
        "--hash-list",
        &hash,
        "--ledger-address",
        &ledger_addr,
    ];
    let mut namadar =
        run!(test, Bin::Relayer, proof_args, Some(QUERY_TIMEOUT_SECONDS),)
            .unwrap();
    namadar.exp_string("Ethereum ABI-encoded proof:").unwrap();
}

/// Tests transfers of wNAM ERC20s from Ethereum are treated differently to
/// other ERC20 transfers.
#[tokio::test]
async fn test_wnam_transfer() -> Result<()> {
    let ethereum_bridge_params = EthereumBridgeConfig {
        min_confirmations: MinimumConfirmations::from(unsafe {
            // SAFETY: The only way the API contract of `NonZeroU64` can
            // be violated is if we construct values
            // of this type using 0 as argument.
            NonZeroU64::new_unchecked(10)
        }),
        contracts: Contracts {
            native_erc20: wnam(),
            bridge: UpgradeableContract {
                address: EthAddress([2; 20]),
                version: ContractVersion::default(),
            },
            governance: UpgradeableContract {
                address: EthAddress([3; 20]),
                version: ContractVersion::default(),
            },
        },
    };

    // use a network-config.toml with eth bridge parameters in it
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params = Some(ethereum_bridge_params);
            genesis
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::EventsEndpoint,
    );
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;

    ledger.exp_string("Namada ledger node started")?;
    ledger.exp_string("This node is a validator")?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    let bg_ledger = ledger.background();

    let wnam_transfer = TransferToNamada {
        amount: token::Amount::from(100),
        asset: ethereum_bridge_params.contracts.native_erc20,
        receiver: address::testing::established_address_1(),
    };
    let transfers = EthereumEvent::TransfersToNamada {
        nonce: 100.into(),
        transfers: vec![wnam_transfer.clone()],
    };

    // TODO(namada#1055): right now, we use a hardcoded Ethereum events endpoint
    // address that would only work for e2e tests involving a single
    // validator node - this should become an attribute of the validator under
    // test once the linked issue is implemented
    const ETHEREUM_EVENTS_ENDPOINT: &str = "http://0.0.0.0:3030/eth_events";
    let mut client =
        EventsEndpointClient::new(ETHEREUM_EVENTS_ENDPOINT.to_string());
    client.send(&transfers).await?;

    let mut ledger = bg_ledger.foreground();
    let TransferToNamada {
        receiver, amount, ..
    } = wnam_transfer;
    // TODO(namada#989): once implemented, check NAM balance of receiver
    ledger.exp_string(&format!(
        "Redemption of the wrapped native token is not yet supported - \
         (receiver - {receiver}, amount - {amount})"
    ))?;

    Ok(())
}

/// Test we can transfer some DAI to an implicit address on Namada.
#[tokio::test]
async fn test_dai_transfer_implicit() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let transfer_amount = token::Amount::from(10_000_000);
    // [`ALBERT`] is a pre-existing implicit address in our wallet
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger = send_transfer(bg_ledger, dai_transfer).await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, transfer_amount);

    Ok(())
}

/// Test we can transfer some DAI to an established address on Namada.
#[tokio::test]
async fn test_dai_transfer_established() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    // create an established account that Albert controls
    let established_alias = "albert-established";
    init_established_account(
        &test,
        &Who::Validator(0),
        ALBERT,
        ALBERT_KEY,
        established_alias,
    )?;
    let established_addr = find_address(&test, established_alias)?;

    let transfer_amount = token::Amount::from(10_000_000);

    let dai_transfer = TransferToNamada {
        amount: transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: established_addr.to_owned(),
    };
    let _bg_ledger = send_transfer(bg_ledger, dai_transfer).await?;

    let established_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &established_addr,
    )?;
    assert_eq!(established_wdai_balance, transfer_amount);

    Ok(())
}

/// Test transferring some wDAI from an implicit address on Namada to another
/// implicit address of Namada.
#[tokio::test]
async fn test_wdai_transfer_implicit_to_implicit() -> Result<()> {
    let (test, bg_ledger) = setup_single_validator_test()?;

    let initial_transfer_amount = token::Amount::from(10_000_000);
    let albert_addr = find_address(&test, ALBERT)?;

    let dai_transfer = TransferToNamada {
        amount: initial_transfer_amount.to_owned(),
        asset: DAI_ERC20_ETH_ADDRESS,
        receiver: albert_addr.to_owned(),
    };
    let _bg_ledger = send_transfer(bg_ledger, dai_transfer).await?;

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(albert_wdai_balance, initial_transfer_amount);

    // attempt a transfer from Albert to Bertha that should succeed, as it's
    // signed with Albert's key
    let bertha_addr = find_address(&test, BERTHA)?;
    let second_transfer_amount = token::Amount::from(10_000);
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr.to_string(),
        &bertha_addr.to_string(),
        &albert_addr.to_string(),
        &second_transfer_amount,
    )?;
    cmd.exp_string("Transaction is valid.")?;
    cmd.exp_string("Transaction is valid.")?;
    cmd.assert_success();

    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(
        albert_wdai_balance,
        initial_transfer_amount - second_transfer_amount
    );

    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_addr,
    )?;
    assert_eq!(bertha_wdai_balance, second_transfer_amount);

    // attempt a transfer from Albert to Bertha that should fail, as it's not
    // signed with Albert's key
    let mut cmd = attempt_wrapped_erc20_transfer(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr.to_string(),
        &bertha_addr.to_string(),
        &bertha_addr.to_string(),
        &second_transfer_amount,
    )?;
    cmd.exp_string("Transaction is valid.")?;
    cmd.exp_string("Transaction is invalid.")?;
    cmd.assert_success();

    // check balances are unchanged after an unsuccessful transfer
    let albert_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &albert_addr,
    )?;
    assert_eq!(
        albert_wdai_balance,
        initial_transfer_amount - second_transfer_amount
    );

    let bertha_wdai_balance = find_wrapped_erc20_balance(
        &test,
        &Who::Validator(0),
        &DAI_ERC20_ETH_ADDRESS,
        &bertha_addr,
    )?;
    assert_eq!(bertha_wdai_balance, second_transfer_amount);

    Ok(())
}

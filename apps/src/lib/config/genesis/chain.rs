use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::ledger::parameters::EpochDuration;
use namada::types::address::{Address, EstablishedAddressGen};
use namada::types::chain::{ChainId, ChainIdPrefix};
use namada::types::time::{
    DateTimeUtc, DurationNanos, DurationSecs, Rfc3339String,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::toml_utils::{read_toml, write_toml};
use super::{templates, transactions};
use crate::config::{Config, TendermintMode};
use crate::facade::tendermint::node::Id as TendermintNodeId;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::node::ledger::tendermint_node::id_from_pk;
use crate::wallet::{pre_genesis, Alias, Wallet};
use crate::wasm_loader;

pub const METADATA_FILE_NAME: &str = "chain.toml";

// Rng source used for generating genesis addresses. Because the process has to
// be deterministic, change of this value is a breaking change for genesis.
const ADDRESS_RNG_SOURCE: &[u8] = &[];

impl Finalized {
    /// Write all genesis and the chain metadata TOML files to the given
    /// directory.
    pub fn write_toml_files(&self, output_dir: &Path) -> eyre::Result<()> {
        let vps_file = output_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = output_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = output_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = output_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            output_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = output_dir.join(METADATA_FILE_NAME);

        write_toml(&self.vps, &vps_file, "Validity predicates")?;
        write_toml(&self.tokens, &tokens_file, "Tokens")?;
        write_toml(&self.balances, &balances_file, "Balances")?;
        write_toml(&self.parameters, &parameters_file, "Parameters")?;
        write_toml(&self.transactions, &transactions_file, "Transactions")?;
        write_toml(&self.metadata, &metadata_file, "Chain metadata")?;
        Ok(())
    }

    /// Try to read all genesis and the chain metadata TOML files from the given
    /// directory.
    pub fn read_toml_files(input_dir: &Path) -> eyre::Result<Self> {
        let vps_file = input_dir.join(templates::VPS_FILE_NAME);
        let tokens_file = input_dir.join(templates::TOKENS_FILE_NAME);
        let balances_file = input_dir.join(templates::BALANCES_FILE_NAME);
        let parameters_file = input_dir.join(templates::PARAMETERS_FILE_NAME);
        let transactions_file =
            input_dir.join(templates::TRANSACTIONS_FILE_NAME);
        let metadata_file = input_dir.join(METADATA_FILE_NAME);

        let vps = read_toml(&vps_file, "Validity predicates")?;
        let tokens = read_toml(&tokens_file, "Tokens")?;
        let balances = read_toml(&balances_file, "Balances")?;
        let parameters = read_toml(&parameters_file, "Parameters")?;
        let transactions = read_toml(&transactions_file, "Transactions")?;
        let metadata = read_toml(&metadata_file, "Chain metadata")?;
        Ok(Self {
            vps,
            tokens,
            balances,
            parameters,
            transactions,
            metadata,
        })
    }

    /// Find the address of the configured native token
    pub fn get_native_token(&self) -> &Address {
        let alias = &self.parameters.parameters.native_token;
        &self
            .tokens
            .token
            .get(alias)
            .expect("The native token must exist")
            .address
    }

    /// Derive Namada wallet from genesis
    pub fn derive_wallet(
        &self,
        base_dir: &Path,
        pre_genesis_wallet: Option<Wallet>,
        validator: Option<(Alias, pre_genesis::ValidatorWallet)>,
    ) -> Wallet {
        let mut wallet = Wallet::load_or_new(base_dir);
        dbg!(&wallet);
        for (alias, config) in &self.tokens.token {
            dbg!("add token", alias);
            wallet.add_address(alias.normalize(), config.address.clone());
        }
        if let Some(txs) = &self.transactions.validator_account {
            for tx in txs {
                wallet.add_address(tx.tx.alias.normalize(), tx.address.clone());
            }
        }
        if let Some(txs) = &self.transactions.established_account {
            for tx in txs {
                wallet.add_address(tx.tx.alias.normalize(), tx.address.clone());
            }
        }
        if let Some(pre_genesis_wallet) = pre_genesis_wallet {
            wallet.extend(pre_genesis_wallet);
        }
        if let Some((alias, validator_wallet)) = validator {
            let address = self
                .transactions
                .find_validator(&alias)
                .map(|tx| tx.address.clone())
                .expect("Validator alias not found in genesis transactions.");
            wallet.extend_from_pre_genesis_validator(
                address,
                alias,
                validator_wallet,
            )
        }
        wallet
    }

    /// Derive Namada configuration from genesis
    pub fn derive_config(
        &self,
        base_dir: &Path,
        node_mode: TendermintMode,
        validator_alias: Option<Alias>,
        allow_duplicate_ip: bool,
    ) -> Config {
        if node_mode != TendermintMode::Validator && validator_alias.is_some() {
            println!(
                "Warning: Validator alias used to derive config, but node \
                 mode is not validator, it is {node_mode:?}!"
            );
        }
        let mut config =
            Config::new(base_dir, self.metadata.chain_id.clone(), node_mode);

        // Derive persistent peers from genesis
        let persistent_peers = self.derive_persistent_peers();
        // If `validator_wallet` is given, find its net_address
        let validator_net_and_tm_address =
            if let Some(alias) = validator_alias.as_ref() {
                self.transactions.find_validator(alias).map(|validator_tx| {
                    (
                        validator_tx.tx.net_address,
                        validator_tx.derive_tendermint_address(),
                    )
                })
            } else {
                None
            };
        // Check if the validators are localhost to automatically turn off
        // Tendermint P2P address book strict mode to allow it
        let is_localhost = persistent_peers.iter().all(|peer| match peer {
            TendermintAddress::Tcp {
                peer_id: _,
                host,
                port: _,
            } => match host.as_str() {
                "127.0.0.1" => true,
                "localhost" => true,
                _ => false,
            },
            TendermintAddress::Unix { path: _ } => false,
        });

        // Configure the ledger
        config.ledger.genesis_time = self.metadata.genesis_time.clone();

        // Add a ledger P2P persistent peers
        config.ledger.tendermint.p2p_persistent_peers = persistent_peers;
        config.ledger.tendermint.consensus_timeout_commit =
            self.metadata.consensus_timeout_commit.into();
        config.ledger.tendermint.p2p_allow_duplicate_ip = allow_duplicate_ip;
        config.ledger.tendermint.p2p_addr_book_strict = !is_localhost;

        if let Some((net_address, tm_address)) = validator_net_and_tm_address {
            // Take out address of self from the P2P persistent peers
            config.ledger.tendermint.p2p_persistent_peers = config.ledger.tendermint.p2p_persistent_peers.iter()
                        .filter_map(|peer|
                            // we do not add the validator in its own persistent peer list
                            if peer != &tm_address  {
                                Some(peer.to_owned())
                            } else {
                                None
                            })
                        .collect();

            let first_port = net_address.port();
            if !is_localhost {
                config
                    .ledger
                    .tendermint
                    .p2p_address
                    .set_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
            }
            config.ledger.tendermint.p2p_address.set_port(first_port);
            if !is_localhost {
                config
                    .ledger
                    .tendermint
                    .rpc_address
                    .set_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
            }
            config
                .ledger
                .tendermint
                .rpc_address
                .set_port(first_port + 1);
            config.ledger.shell.ledger_address.set_port(first_port + 2);

            // Validator node should turned off peer exchange reactor
            config.ledger.tendermint.p2p_pex = false;
        }

        config
    }

    /// Derive persistent peers from genesis validators
    fn derive_persistent_peers(&self) -> Vec<TendermintAddress> {
        self.transactions
            .validator_account
            .as_ref()
            .map(|txs| {
                txs.iter()
                    .map(FinalizedValidatorAccountTx::derive_tendermint_address)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the chain parameters set in genesis
    pub fn get_chain_parameters(
        &self,
        wasm_dir: impl AsRef<Path>,
    ) -> namada::ledger::parameters::Parameters {
        let templates::ChainParams {
            native_token,
            min_num_of_blocks,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
        } = self.parameters.parameters.clone();

        let implicit_vp_filename = self
            .vps
            .wasm
            .get(&implicit_vp)
            .expect("Implicit VP must be present")
            .filename;
        let implicit_vp =
            wasm_loader::read_wasm(&wasm_dir, &implicit_vp_filename)
                .expect("Implicit VP WASM code couldn't get read");

        let min_duration: i64 = 60 * 60 * 24 * 365 / (epochs_per_year as i64);
        let epoch_duration = EpochDuration {
            min_num_of_blocks: min_num_of_blocks,
            min_duration: namada::types::time::Duration::seconds(min_duration)
                .into(),
        };
        let max_expected_time_per_block =
            namada::types::time::Duration::seconds(max_expected_time_per_block)
                .into();
        let vp_whitelist = vp_whitelist.unwrap_or_default();
        let tx_whitelist = tx_whitelist.unwrap_or_default();
        let staked_ratio = Decimal::ZERO;
        let pos_inflation_amount = 0;

        namada::ledger::parameters::Parameters {
            epoch_duration,
            max_expected_time_per_block,
            vp_whitelist,
            tx_whitelist,
            implicit_vp,
            epochs_per_year,
            pos_gain_p,
            pos_gain_d,
            staked_ratio,
            pos_inflation_amount,
        }
    }

    pub fn get_pos_params(&self) -> namada::proof_of_stake::PosParams {
        let templates::PosParams {
            max_validator_slots,
            pipeline_len,
            unbonding_len,
            tm_votes_per_token,
            block_proposer_reward,
            block_vote_reward,
            max_inflation_rate,
            target_staked_ratio,
            duplicate_vote_min_slash_rate,
            light_client_attack_min_slash_rate,
        } = self.parameters.pos_params.clone();

        namada::proof_of_stake::PosParams {
            max_validator_slots,
            pipeline_len,
            unbonding_len,
            tm_votes_per_token,
            block_proposer_reward,
            block_vote_reward,
            max_inflation_rate,
            target_staked_ratio,
            duplicate_vote_min_slash_rate,
            light_client_attack_min_slash_rate,
        }
    }

    pub fn get_gov_params(
        &self,
    ) -> namada::ledger::governance::parameters::GovParams {
        let templates::GovernanceParams {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_period,
            max_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
        } = self.parameters.gov_params.clone();
        namada::ledger::governance::parameters::GovParams {
            min_proposal_fund,
            max_proposal_code_size,
            min_proposal_period,
            max_proposal_period,
            max_proposal_content_size,
            min_proposal_grace_epochs,
        }
    }
}

/// Create the [`Finalized`] chain configuration. Derives the chain ID from the
/// genesis bytes and assigns addresses to tokens and transactions that
/// initialize established accounts.
///
/// Invariant: The output must deterministic. For the same input this function
/// must return the same output.
pub fn finalize(
    templates: templates::All,
    chain_id_prefix: ChainIdPrefix,
    genesis_time: DateTimeUtc,
    consensus_timeout_commit: crate::facade::tendermint::Timeout,
) -> Finalized {
    let genesis_time: Rfc3339String = genesis_time.into();
    let consensus_timeout_commit: DurationNanos =
        consensus_timeout_commit.into();

    // Derive seed for address generator
    let genesis_to_gen_address = GenesisToGenAddresses {
        templates,
        metadata: Metadata {
            chain_id: chain_id_prefix.clone(),
            genesis_time,
            consensus_timeout_commit,
            address_gen: None,
        },
    };
    let genesis_bytes = genesis_to_gen_address.try_to_vec().unwrap();
    let mut addr_gen = established_address_gen(&genesis_bytes);

    // Generate addresses
    let templates::All {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    } = genesis_to_gen_address.templates;
    let tokens = FinalizedTokens::finalize_from(tokens, &mut addr_gen);
    let transactions =
        FinalizedTransactions::finalize_from(transactions, &mut addr_gen);

    // Store the last state of the address generator in the metadata
    let mut metadata = genesis_to_gen_address.metadata;
    metadata.address_gen = Some(addr_gen);

    // Derive chain ID
    let to_finalize = ToFinalize {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    };
    let to_finalize_bytes = to_finalize.try_to_vec().unwrap();
    let chain_id = ChainId::from_genesis(chain_id_prefix, to_finalize_bytes);

    // Construct the `Finalized` chain
    let ToFinalize {
        vps,
        tokens,
        balances,
        parameters,
        transactions,
        metadata,
    } = to_finalize;
    let Metadata {
        chain_id: _,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    } = metadata;
    let metadata = Metadata {
        chain_id,
        genesis_time,
        consensus_timeout_commit,
        address_gen,
    };
    Finalized {
        metadata,
        vps,
        tokens,
        balances,
        parameters,
        transactions,
    }
}

/// Use bytes as a deterministic seed for address generator.
fn established_address_gen(bytes: &[u8]) -> EstablishedAddressGen {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // hex of the first 40 chars of the hash
    let hash = format!("{:.width$X}", hasher.finalize(), width = 40);
    EstablishedAddressGen::new(&hash)
}

/// Deterministically generate an [`Address`].
fn gen_address(gen: &mut EstablishedAddressGen) -> Address {
    gen.generate_address(ADDRESS_RNG_SOURCE)
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
#[derive(
    Clone, Debug, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct GenesisToGenAddresses {
    /// Filled-in templates
    pub templates: templates::All,
    /// Chain metadata
    pub metadata: Metadata<ChainIdPrefix>,
}

/// Chain genesis config to be finalized. This struct is used to derive the
/// chain ID to construct a [`Finalized`] chain genesis config.
pub type ToFinalize = Chain<ChainIdPrefix>;

/// Chain genesis config.
pub type Finalized = Chain<ChainId>;

/// Chain genesis config with generic chain ID.
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Chain<ID> {
    pub vps: templates::ValidityPredicates,
    pub tokens: FinalizedTokens,
    pub balances: templates::Balances,
    pub parameters: templates::Parameters,
    pub transactions: FinalizedTransactions,
    /// Chain metadata
    pub metadata: Metadata<ID>,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTokens {
    pub token: BTreeMap<Alias, FinalizedTokenConfig>,
}
impl FinalizedTokens {
    fn finalize_from(
        tokens: templates::Tokens,
        addr_gen: &mut EstablishedAddressGen,
    ) -> FinalizedTokens {
        let templates::Tokens { token } = tokens;
        let token = token
            .into_iter()
            .map(|(key, config)| {
                let address = gen_address(addr_gen);
                (key, FinalizedTokenConfig { address, config })
            })
            .collect();
        FinalizedTokens { token }
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTokenConfig {
    pub address: Address,
    #[serde(flatten)]
    pub config: templates::TokenConfig,
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedTransactions {
    pub established_account: Option<Vec<FinalizedEstablishedAccountTx>>,
    pub validator_account: Option<Vec<FinalizedValidatorAccountTx>>,
    pub transfer: Option<Vec<transactions::SignedTransferTx>>,
    pub bond: Option<Vec<transactions::SignedBondTx>>,
}
impl FinalizedTransactions {
    fn finalize_from(
        transactions: transactions::Transactions,
        addr_gen: &mut EstablishedAddressGen,
    ) -> FinalizedTransactions {
        let transactions::Transactions {
            established_account,
            validator_account,
            transfer,
            bond,
        } = transactions;
        let established_account = established_account.map(|txs| {
            txs.into_iter()
                .map(|tx| {
                    let address = gen_address(addr_gen);
                    FinalizedEstablishedAccountTx { address, tx }
                })
                .collect()
        });
        let validator_account = validator_account.map(|txs| {
            txs.into_iter()
                .map(|tx| {
                    let address = gen_address(addr_gen);
                    FinalizedValidatorAccountTx { address, tx }
                })
                .collect()
        });
        FinalizedTransactions {
            established_account,
            validator_account,
            transfer,
            bond,
        }
    }

    fn find_validator(
        &self,
        alias: &Alias,
    ) -> Option<&FinalizedValidatorAccountTx> {
        self.validator_account
            .as_ref()
            .and_then(|txs| txs.iter().find(|tx| &tx.tx.alias == alias))
    }
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedEstablishedAccountTx {
    pub address: Address,
    #[serde(flatten)]
    pub tx: transactions::SignedEstablishedAccountTx,
}

#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
)]
pub struct FinalizedValidatorAccountTx {
    pub address: Address,
    #[serde(flatten)]
    pub tx: transactions::SignedValidatorAccountTx,
}
impl FinalizedValidatorAccountTx {
    pub fn derive_tendermint_address(&self) -> TendermintAddress {
        // Derive the node ID from the node key
        let node_id: TendermintNodeId =
            id_from_pk(&self.tx.tendermint_node_key.pk.raw);

        // Build the list of persistent peers from the validators' node IDs
        TendermintAddress::from_str(&format!(
            "{}@{}",
            node_id, self.tx.net_address,
        ))
        .expect("Validator address must be valid")
    }
}

/// Chain metadata
#[derive(
    Clone,
    Debug,
    Deserialize,
    Serialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
)]
pub struct Metadata<ID> {
    /// Chain ID in [`Finalized`] or chain ID prefix in
    /// [`GenesisToGenAddresses`] and [`ToFinalize`].
    pub chain_id: ID,
    // Genesis timestamp
    pub genesis_time: Rfc3339String,
    /// The Tendermint consensus timeout_commit configuration
    pub consensus_timeout_commit: DurationNanos,
    /// This generator should be used to initialize the ledger for the
    /// next address that will be generated on chain.
    ///
    /// The value is expected to always be `None` in [`GenesisToGenAddresses`]
    /// and `Some` in [`ToFinalize`] and [`Finalized`].
    pub address_gen: Option<EstablishedAddressGen>,
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;

    /// Test that the [`finalize`] returns deterministic output with the same
    /// chain ID for the same input.
    #[test]
    fn test_finalize_is_deterministic() {
        // Load the localnet templates
        let templates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("genesis/localnet");
        let templates = templates::load_and_validate(&templates_dir).unwrap();

        let chain_id_prefix: ChainIdPrefix =
            FromStr::from_str("test-prefix").unwrap();

        let genesis_time =
            DateTimeUtc::from_str("2021-12-31T00:00:00Z").unwrap();

        let consensus_timeout_commit =
            crate::facade::tendermint::Timeout::from_str("1s").unwrap();

        let finalized_0 = finalize(
            templates.clone(),
            chain_id_prefix.clone(),
            genesis_time.clone(),
            consensus_timeout_commit.clone(),
        );

        let finalized_1 = finalize(
            templates,
            chain_id_prefix,
            genesis_time,
            consensus_timeout_commit,
        );

        pretty_assertions::assert_eq!(finalized_0, finalized_1);
    }
}

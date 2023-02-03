//! Validity predicate for the Ethereum bridge pool
//!
//! This pool holds user initiated transfers of value from
//! Namada to Ethereum. It is to act like a mempool: users
//! add in their desired transfers and their chosen amount
//! of NAM to cover Ethereum side gas fees. These transfers
//! can be relayed in batches along with Merkle proofs.
//!
//! This VP checks that additions to the pool are handled
//! correctly. This means that the appropriate data is
//! added to the pool and gas fees are submitted appropriately
//! and that tokens to be transferred are escrowed.
use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use eyre::eyre;
use namada_core::ledger::eth_bridge::storage::bridge_pool::{
    get_pending_key, is_bridge_pool_key, BRIDGE_POOL_ADDRESS,
};
use namada_ethereum_bridge::parameters::read_native_erc20_address;
use namada_ethereum_bridge::storage::wrapped_erc20s;

use crate::ledger::native_vp::ethereum_bridge::vp::check_balance_changes;
use crate::ledger::native_vp::{Ctx, NativeVp, StorageReader};
use crate::ledger::storage::traits::StorageHasher;
use crate::ledger::storage::{DBIter, DB};
use crate::proto::SignedTxData;
use crate::types::address::{nam, Address, InternalAddress};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::storage::Key;
use crate::types::token::{balance_key, Amount};
use crate::vm::WasmCacheAccess;

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

/// A positive or negative amount
enum SignedAmount {
    Positive(Amount),
    Negative(Amount),
}

/// Validity predicate for the Ethereum bridge
pub struct BridgePoolVp<'ctx, D, H, CA>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, D, H, CA>,
}

impl<'a, D, H, CA> BridgePoolVp<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Get the change in the balance of an account
    /// associated with an address
    fn account_balance_delta(&self, address: &Address) -> Option<SignedAmount> {
        let account_key = balance_key(&nam(), address);
        let before: Amount = (&self.ctx)
            .read_pre_value(&account_key)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, %account_key, "reading pre value");
                None
            })?;
        let after: Amount = (&self.ctx)
            .read_post_value(&account_key)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, %account_key, "reading post value");
                None
            })?;
        if before > after {
            Some(SignedAmount::Negative(before - after))
        } else {
            Some(SignedAmount::Positive(after - before))
        }
    }

    /// Check that the correct amount of Nam was sent
    /// from the correct account into escrow
    fn check_nam_escrowed(&self, delta: EscrowDelta) -> Result<bool, Error> {
        let EscrowDelta {
            payer_account,
            escrow_account,
            expected_debit,
            expected_credit,
        } = delta;
        let debited = self.account_balance_delta(payer_account);
        let credited = self.account_balance_delta(escrow_account);

        match (debited, credited) {
            (
                Some(SignedAmount::Negative(debit)),
                Some(SignedAmount::Positive(credit)),
            ) => Ok(debit == expected_debit && credit == expected_credit),
            (Some(SignedAmount::Positive(_)), _) => {
                tracing::debug!(
                    "The account {} was not debited.",
                    payer_account
                );
                Ok(false)
            }
            (_, Some(SignedAmount::Negative(_))) => {
                tracing::debug!(
                    "The Ethereum bridge pool's escrow was not credited from \
                     account {}.",
                    payer_account
                );
                Ok(false)
            }
            (None, _) | (_, None) => Err(Error(eyre!(
                "Could not calculate the balance delta for {}",
                payer_account
            ))),
        }
    }

    /// Deteremine the debit and credit amounts that should be checked.
    fn escrow_check<'trans>(
        &self,
        transfer: &'trans PendingTransfer,
    ) -> Result<EscrowCheck<'trans>, Error> {
        // there is a corner case where the gas fees and escrowed Nam
        // are debited from the same address when mint wNam.
        Ok(
            if transfer.gas_fee.payer == transfer.transfer.sender
                && transfer.transfer.asset
                    == read_native_erc20_address(self.ctx.storage)?
            {
                let debit = transfer
                    .gas_fee
                    .amount
                    .checked_add(&transfer.transfer.amount)
                    .ok_or_else(|| {
                        Error(eyre!(
                            "Addition oveflowed adding gas fee + transfer \
                             amount."
                        ))
                    })?;
                EscrowCheck {
                    gas_check: EscrowDelta {
                        payer_account: &transfer.gas_fee.payer,
                        escrow_account: &BRIDGE_POOL_ADDRESS,
                        expected_debit: debit,
                        expected_credit: transfer.gas_fee.amount,
                    },
                    token_check: EscrowDelta {
                        payer_account: &transfer.transfer.sender,
                        escrow_account: &Address::Internal(
                            InternalAddress::EthBridge,
                        ),
                        expected_debit: debit,
                        expected_credit: transfer.transfer.amount,
                    },
                }
            } else {
                EscrowCheck {
                    gas_check: EscrowDelta {
                        payer_account: &transfer.gas_fee.payer,
                        escrow_account: &BRIDGE_POOL_ADDRESS,
                        expected_debit: transfer.gas_fee.amount,
                        expected_credit: transfer.gas_fee.amount,
                    },
                    token_check: EscrowDelta {
                        payer_account: &transfer.transfer.sender,
                        escrow_account: &Address::Internal(
                            InternalAddress::EthBridge,
                        ),
                        expected_debit: transfer.transfer.amount,
                        expected_credit: transfer.transfer.amount,
                    },
                }
            },
        )
    }
}

/// Check if a delta matches the delta given by a transfer
fn check_delta(delta: &(Address, Amount), transfer: &PendingTransfer) -> bool {
    delta.0 == transfer.transfer.sender && delta.1 == transfer.transfer.amount
}

/// Helper struct for handling the different escrow
/// checking scenarios.
struct EscrowDelta<'a> {
    payer_account: &'a Address,
    escrow_account: &'a Address,
    expected_debit: Amount,
    expected_credit: Amount,
}

/// There are two checks we must do when minting wNam.
/// 1. Check that gas fees were escrowed.
/// 2. Check that the Nam to back wNam was escrowed.
struct EscrowCheck<'a> {
    gas_check: EscrowDelta<'a>,
    token_check: EscrowDelta<'a>,
}

impl<'a, D, H, CA> NativeVp for BridgePoolVp<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::EthBridgePool;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Error> {
        tracing::debug!(
            tx_data_len = tx_data.len(),
            keys_changed_len = keys_changed.len(),
            verifiers_len = _verifiers.len(),
            "Ethereum Bridge Pool VP triggered",
        );
        let signed: SignedTxData = BorshDeserialize::try_from_slice(tx_data)
            .map_err(|e| Error(e.into()))?;

        let transfer: PendingTransfer = match signed.data {
            Some(data) => BorshDeserialize::try_from_slice(data.as_slice())
                .map_err(|e| Error(e.into()))?,
            None => {
                tracing::debug!(
                    "Rejecting transaction as there was no signed data"
                );
                return Ok(false);
            }
        };

        let pending_key = get_pending_key(&transfer);
        // check that transfer is not already in the pool
        match (&self.ctx).read_pre_value::<PendingTransfer>(&pending_key) {
            Ok(Some(_)) => {
                tracing::debug!(
                    "Rejecting transaction as the transfer is already in the \
                     Ethereum bridge pool."
                );
                return Ok(false);
            }
            Err(e) => {
                return Err(eyre!(
                    "Could not read the storage key associated with the \
                     transfer: {:?}",
                    e
                )
                .into());
            }
            _ => {}
        }
        for key in keys_changed.iter().filter(|k| is_bridge_pool_key(k)) {
            if *key != pending_key {
                tracing::debug!(
                    "Rejecting transaction as it is attempting to change an \
                     incorrect key in the Ethereum bridge pool: {}.\n \
                     Expected key: {}",
                    key,
                    pending_key
                );
                return Ok(false);
            }
        }
        let pending: PendingTransfer =
            (&self.ctx).read_post_value(&pending_key)?.ok_or(eyre!(
                "Rejecting transaction as the transfer wasn't added to the \
                 pool of pending transfers"
            ))?;
        if pending != transfer {
            tracing::debug!(
                "An incorrect transfer was added to the Ethereum bridge pool: \
                 {:?}.\n Expected: {:?}",
                transfer,
                pending
            );
            return Ok(false);
        }
        // The deltas in the escrowed amounts we must check.
        let escrow_checks = self.escrow_check(&transfer)?;
        // check that gas we correctly escrowed.
        if !self.check_nam_escrowed(escrow_checks.gas_check)? {
            return Ok(false);
        }
        // if we are going to mint wNam on Ethereum, the appropriate
        // amount of Nam must be escrowed in the Ethereum bridge VP's storage.
        let wnam_address = read_native_erc20_address(self.ctx.storage)?;
        if transfer.transfer.asset == wnam_address {
            // check that correct amount of Nam was put into escrow.
            return if self.check_nam_escrowed(escrow_checks.token_check)? {
                tracing::info!(
                    "The Ethereum bridge pool VP accepted the transfer {:?}.",
                    transfer
                );
                Ok(true)
            } else {
                Ok(false)
            };
        }

        // check that the assets to be transferred were escrowed
        let asset_key = wrapped_erc20s::Keys::from(&transfer.transfer.asset);
        let owner_key = asset_key.balance(&transfer.transfer.sender);
        let escrow_key = asset_key.balance(&BRIDGE_POOL_ADDRESS);
        if keys_changed.contains(&owner_key)
            && keys_changed.contains(&escrow_key)
        {
            match check_balance_changes(
                &self.ctx,
                (&escrow_key).try_into().expect("This should not fail"),
                (&owner_key).try_into().expect("This should not fail"),
            ) {
                Ok(Some(delta)) if check_delta(&delta, &transfer) => {}
                other => {
                    tracing::debug!(
                        "The assets of the transfer were not properly \
                         escrowed into the Ethereum bridge pool: {:?}",
                        other
                    );
                    return Ok(false);
                }
            }
        } else {
            tracing::debug!(
                "The assets of the transfer were not properly escrowed into \
                 the Ethereum bridge pool."
            );
            return Ok(false);
        }

        tracing::info!(
            "The Ethereum bridge pool VP accepted the transfer {:?}.",
            transfer
        );
        Ok(true)
    }
}

#[cfg(test)]
mod test_bridge_pool_vp {
    use std::env::temp_dir;

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada_core::ledger::eth_bridge::storage::bridge_pool::get_signed_root_key;
    use namada_core::types::address;
    use namada_ethereum_bridge::parameters::{
        Contracts, EthereumBridgeConfig, UpgradeableContract,
    };

    use super::*;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::mockdb::MockDB;
    use crate::ledger::storage::traits::Sha256Hasher;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::ledger::storage::Storage;
    use crate::proto::Tx;
    use crate::types::address::wnam;
    use crate::types::chain::ChainId;
    use crate::types::eth_bridge_pool::{GasFee, TransferToEthereum};
    use crate::types::ethereum_events::EthAddress;
    use crate::types::hash::Hash;
    use crate::types::key::{common, ed25519, SecretKey, SigScheme};
    use crate::types::storage::TxIndex;
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    /// The amount of NAM Bertha has
    const ASSET: EthAddress = EthAddress([0; 20]);
    const BERTHA_WEALTH: u64 = 1_000_000;
    const BERTHA_TOKENS: u64 = 10_000;
    const ESCROWED_AMOUNT: u64 = 1_000;
    const ESCROWED_TOKENS: u64 = 1_000;
    const GAS_FEE: u64 = 100;
    const TOKENS: u64 = 100;

    /// A set of balances for an address
    struct Balance {
        owner: Address,
        balance: Amount,
        token: Amount,
    }

    impl Balance {
        fn new(address: Address) -> Self {
            Self {
                owner: address,
                balance: 0.into(),
                token: 0.into(),
            }
        }
    }

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_1() -> Address {
        Address::decode("atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp")
            .expect("The token address decoding shouldn't fail")
    }

    fn bertha_keypair() -> common::SecretKey {
        // generated from
        // [`namada::types::key::ed25519::gen_keypair`]
        let bytes = [
            240, 3, 224, 69, 201, 148, 60, 53, 112, 79, 80, 107, 101, 127, 186,
            6, 176, 162, 113, 224, 62, 8, 183, 187, 124, 234, 244, 251, 92, 36,
            119, 243,
        ];
        let ed_sk = ed25519::SecretKey::try_from_slice(&bytes).unwrap();
        ed_sk.try_to_sk().unwrap()
    }

    /// The bridge pool at the beginning of all tests
    fn initial_pool() -> PendingTransfer {
        PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([0; 20]),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        }
    }

    /// Create a writelog representing storage before a transfer is added to the
    /// pool.
    fn new_writelog() -> WriteLog {
        let mut writelog = WriteLog::default();
        // setup the initial bridge pool storage
        writelog
            .write(&get_signed_root_key(), Hash([0; 32]).try_to_vec().unwrap())
            .expect("Test failed");
        let transfer = initial_pool();
        writelog
            .write(&get_pending_key(&transfer), transfer.try_to_vec().unwrap())
            .expect("Test failed");
        // set up a user with a balance
        update_balances(
            &mut writelog,
            Balance::new(bertha_address()),
            SignedAmount::Positive(BERTHA_WEALTH.into()),
            SignedAmount::Positive(BERTHA_TOKENS.into()),
        );
        // set up the initial balances of the bridge pool
        update_balances(
            &mut writelog,
            Balance::new(BRIDGE_POOL_ADDRESS),
            SignedAmount::Positive(ESCROWED_AMOUNT.into()),
            SignedAmount::Positive(ESCROWED_TOKENS.into()),
        );
        writelog.commit_tx();
        writelog
    }

    /// Update gas and token balances of an address and
    /// return the keys changed
    fn update_balances(
        write_log: &mut WriteLog,
        balance: Balance,
        gas_delta: SignedAmount,
        token_delta: SignedAmount,
    ) -> BTreeSet<Key> {
        // get the balance keys
        let token_key =
            wrapped_erc20s::Keys::from(&ASSET).balance(&balance.owner);
        let account_key = balance_key(&nam(), &balance.owner);

        // update the balance of nam
        let new_balance = match gas_delta {
            SignedAmount::Positive(amount) => balance.balance + amount,
            SignedAmount::Negative(amount) => balance.balance - amount,
        }
        .try_to_vec()
        .expect("Test failed");

        // update the balance of tokens
        let new_token_balance = match token_delta {
            SignedAmount::Positive(amount) => balance.token + amount,
            SignedAmount::Negative(amount) => balance.token - amount,
        }
        .try_to_vec()
        .expect("Test failed");

        // write the changes to the log
        write_log
            .write(&account_key, new_balance)
            .expect("Test failed");
        write_log
            .write(&token_key, new_token_balance)
            .expect("Test failed");

        // return the keys changed
        [account_key, token_key].into()
    }

    /// Initialize some dummy storage for testing
    fn setup_storage() -> Storage<MockDB, Sha256Hasher> {
        let mut storage = Storage::<MockDB, Sha256Hasher>::open(
            std::path::Path::new(""),
            ChainId::default(),
            address::nam(),
            None,
        );
        // a dummy config for testing
        let config = EthereumBridgeConfig {
            min_confirmations: Default::default(),
            contracts: Contracts {
                native_erc20: wnam(),
                bridge: UpgradeableContract {
                    address: EthAddress([42; 20]),
                    version: Default::default(),
                },
                governance: UpgradeableContract {
                    address: EthAddress([18; 20]),
                    version: Default::default(),
                },
            },
        };
        config.init_storage(&mut storage);
        storage
    }

    /// Setup a ctx for running native vps
    fn setup_ctx<'a>(
        tx: &'a Tx,
        storage: &'a Storage<MockDB, Sha256Hasher>,
        write_log: &'a WriteLog,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
    ) -> Ctx<'a, MockDB, Sha256Hasher, WasmCacheRwAccess> {
        Ctx::new(
            &BRIDGE_POOL_ADDRESS,
            storage,
            write_log,
            tx,
            &TxIndex(0),
            VpGasMeter::new(0u64),
            keys_changed,
            verifiers,
            VpCache::new(temp_dir(), 100usize),
        )
    }

    enum Expect {
        True,
        False,
        Error,
    }

    /// Helper function that tests various ways gas can be escrowed,
    /// either correctly or incorrectly, is handled appropriately
    fn assert_bridge_pool<F>(
        payer_gas_delta: SignedAmount,
        gas_escrow_delta: SignedAmount,
        payer_delta: SignedAmount,
        escrow_delta: SignedAmount,
        insert_transfer: F,
        expect: Expect,
    ) where
        F: FnOnce(PendingTransfer, &mut WriteLog) -> BTreeSet<Key>,
    {
        // setup
        let mut write_log = new_writelog();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: TOKENS.into(),
            },
            gas_fee: GasFee {
                amount: GAS_FEE.into(),
                payer: bertha_address(),
            },
        };
        // add transfer to pool
        let mut keys_changed =
            insert_transfer(transfer.clone(), &mut write_log);

        // change Bertha's balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: bertha_address(),
                balance: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            payer_gas_delta,
            payer_delta,
        );
        keys_changed.append(&mut new_keys_changed);

        // change the bridge pool balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: BRIDGE_POOL_ADDRESS,
                balance: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            gas_escrow_delta,
            escrow_delta,
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp.validate_tx(&signed, &keys_changed, &verifiers);
        match expect {
            Expect::True => assert!(res.expect("Test failed")),
            Expect::False => assert!(!res.expect("Test failed")),
            Expect::Error => assert!(res.is_err()),
        }
    }

    /// Test adding a transfer to the pool and escrowing gas passes vp
    #[test]
    fn test_happy_flow() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::True,
        );
    }

    /// Test that if the balance for the gas payer
    /// was not correctly adjusted, reject
    #[test]
    fn test_incorrect_gas_withdrawn() {
        assert_bridge_pool(
            SignedAmount::Negative(10.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the gas payer's balance
    /// does not decrease, we reject the tx
    #[test]
    fn test_payer_balance_must_decrease() {
        assert_bridge_pool(
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the gas amount escrowed is incorrect,
    /// the tx is rejected
    #[test]
    fn test_incorrect_gas_deposited() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(10.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the number of tokens debited
    /// from one account does not equal the amount
    /// credited the other, the tx is rejected
    #[test]
    fn test_incorrect_token_deltas() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(10.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the number of tokens transferred
    /// is incorrect, the tx is rejected
    #[test]
    fn test_incorrect_tokens_escrowed() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(10.into()),
            SignedAmount::Positive(10.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that the amount of gas escrowed increases,
    /// otherwise the tx is rejected.
    #[test]
    fn test_escrowed_gas_must_increase() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that the amount of tokens escrowed in the
    /// bridge pool is positive.
    #[test]
    fn test_escrowed_tokens_must_increase() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(TOKENS.into()),
            SignedAmount::Negative(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the transfer was not added to the
    /// pool, the vp rejects
    #[test]
    fn test_not_adding_transfer_rejected() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, _| BTreeSet::from([get_pending_key(&transfer)]),
            Expect::Error,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_transfer() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([11; 20]),
                        amount: 100.into(),
                    },
                    gas_fee: GasFee {
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                log.write(&get_pending_key(&transfer), t.try_to_vec().unwrap())
                    .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::False,
        );
    }

    /// Test that if the wrong transaction was added
    /// to the pool, it is rejected.
    #[test]
    fn test_add_wrong_key() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                let t = PendingTransfer {
                    transfer: TransferToEthereum {
                        asset: EthAddress([0; 20]),
                        sender: bertha_address(),
                        recipient: EthAddress([11; 20]),
                        amount: 100.into(),
                    },
                    gas_fee: GasFee {
                        amount: GAS_FEE.into(),
                        payer: bertha_address(),
                    },
                };
                log.write(&get_pending_key(&t), transfer.try_to_vec().unwrap())
                    .unwrap();
                BTreeSet::from([get_pending_key(&transfer)])
            },
            Expect::Error,
        );
    }

    /// Test that no tx may alter the storage containing
    /// the signed merkle root.
    #[test]
    fn test_signed_merkle_root_changes_rejected() {
        assert_bridge_pool(
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
            SignedAmount::Positive(TOKENS.into()),
            |transfer, log| {
                log.write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
                BTreeSet::from([
                    get_pending_key(&transfer),
                    get_signed_root_key(),
                ])
            },
            Expect::False,
        );
    }

    /// Test that adding a transfer to the pool
    /// that is already in the pool fails.
    #[test]
    fn test_adding_transfer_twice_fails() {
        // setup
        let mut write_log = new_writelog();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = initial_pool();

        // add transfer to pool
        let mut keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };

        // update Bertha's balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: bertha_address(),
                balance: BERTHA_WEALTH.into(),
                token: BERTHA_TOKENS.into(),
            },
            SignedAmount::Negative(GAS_FEE.into()),
            SignedAmount::Negative(TOKENS.into()),
        );
        keys_changed.append(&mut new_keys_changed);

        // update the bridge pool balances
        let mut new_keys_changed = update_balances(
            &mut write_log,
            Balance {
                owner: BRIDGE_POOL_ADDRESS,
                balance: ESCROWED_AMOUNT.into(),
                token: ESCROWED_TOKENS.into(),
            },
            SignedAmount::Positive(GAS_FEE.into()),
            SignedAmount::Positive(TOKENS.into()),
        );
        keys_changed.append(&mut new_keys_changed);
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp.validate_tx(&signed, &keys_changed, &verifiers);
        assert!(!res.expect("Test failed"));
    }

    /// Test that a transfer added to the pool with zero gas fees
    /// is rejected.
    #[test]
    fn test_zero_gas_fees_rejected() {
        // setup
        let mut write_log = new_writelog();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: ASSET,
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let mut keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 0 tokens
        keys_changed.insert(
            wrapped_erc20s::Keys::from(&ASSET).balance(&bertha_address()),
        );
        keys_changed.insert(
            wrapped_erc20s::Keys::from(&ASSET).balance(&BRIDGE_POOL_ADDRESS),
        );

        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp
            .validate_tx(&signed, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(!res);
    }

    /// Test that we can escrow Nam if we
    /// want to mint wNam on Ethereum.
    #[test]
    fn test_mint_wnam() {
        // setup
        let mut write_log = new_writelog();
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));
        write_log.commit_tx();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                amount: 100.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        write_log
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 200)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        write_log
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        write_log
            .write(
                &eb_account_key,
                Amount::from(100).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");

        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp
            .validate_tx(&signed, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(res);
    }

    /// Test that we can reject a transfer that
    /// mints wNam if we don't escrow the correct
    /// amount of Nam.
    #[test]
    fn test_reject_mint_wnam() {
        // setup
        let mut write_log = new_writelog();
        write_log.commit_tx();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                amount: 100.into(),
                payer: bertha_address(),
            },
        };

        // add transfer to pool
        let keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        write_log
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 200)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        write_log
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        write_log
            .write(
                &eb_account_key,
                Amount::from(10).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        let verifiers = BTreeSet::default();

        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp
            .validate_tx(&signed, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(!res);
    }

    /// Test that we check escrowing Nam correctly when minting wNam
    /// and the gas payer account is different from the transferring
    /// account.
    #[test]
    fn test_mint_wnam_separate_gas_payer() {
        // setup
        let mut write_log = new_writelog();
        // initialize the eth bridge balance to 0
        let eb_account_key =
            balance_key(&nam(), &Address::Internal(InternalAddress::EthBridge));
        write_log
            .write(
                &eb_account_key,
                Amount::default().try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        // initialize the gas payers account
        let gas_payer_balance_key =
            balance_key(&nam(), &established_address_1());
        write_log
            .write(
                &gas_payer_balance_key,
                Amount::from(BERTHA_WEALTH)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        write_log.commit_tx();
        let storage = setup_storage();
        let tx = Tx::new(vec![], None);

        // the transfer to be added to the pool
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: wnam(),
                sender: bertha_address(),
                recipient: EthAddress([1; 20]),
                amount: 100.into(),
            },
            gas_fee: GasFee {
                amount: 100.into(),
                payer: established_address_1(),
            },
        };

        // add transfer to pool
        let keys_changed = {
            write_log
                .write(
                    &get_pending_key(&transfer),
                    transfer.try_to_vec().unwrap(),
                )
                .unwrap();
            BTreeSet::from([get_pending_key(&transfer)])
        };
        // We escrow 100 Nam into the bridge pool VP
        // and 100 Nam in the Eth bridge VP
        let account_key = balance_key(&nam(), &bertha_address());
        write_log
            .write(
                &account_key,
                Amount::from(BERTHA_WEALTH - 100)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        write_log
            .write(
                &gas_payer_balance_key,
                Amount::from(BERTHA_WEALTH - 100)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        let bp_account_key = balance_key(&nam(), &BRIDGE_POOL_ADDRESS);
        write_log
            .write(
                &bp_account_key,
                Amount::from(ESCROWED_AMOUNT + 100)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");
        write_log
            .write(
                &eb_account_key,
                Amount::from(10).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        let verifiers = BTreeSet::default();
        // create the data to be given to the vp
        let vp = BridgePoolVp {
            ctx: setup_ctx(
                &tx,
                &storage,
                &write_log,
                &keys_changed,
                &verifiers,
            ),
        };

        let to_sign = transfer.try_to_vec().expect("Test failed");
        let sig = common::SigScheme::sign(&bertha_keypair(), &to_sign);
        let signed = SignedTxData {
            data: Some(to_sign),
            sig,
        }
        .try_to_vec()
        .expect("Test failed");

        let res = vp
            .validate_tx(&signed, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(!res);
    }
}

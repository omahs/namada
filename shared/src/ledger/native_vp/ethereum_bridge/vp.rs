//! Validity predicate for the Ethereum bridge
use std::collections::{BTreeSet, HashSet};

use borsh::BorshDeserialize;
use eyre::{eyre, Result};
use itertools::Itertools;
use namada_core::ledger::eth_bridge::storage::{
    self, escrow_key, wrapped_erc20s,
};
use namada_core::ledger::storage::traits::StorageHasher;
use namada_core::ledger::{eth_bridge, storage as ledger_storage};
use namada_core::types::address::{nam, Address, InternalAddress};
use namada_core::types::storage::Key;
use namada_core::types::token::{balance_key, Amount};

use crate::ledger::native_vp::ethereum_bridge::authorize;
use crate::ledger::native_vp::{Ctx, NativeVp, StorageReader, VpEnv};
use crate::vm::WasmCacheAccess;

/// Validity predicate for the Ethereum bridge
pub struct EthBridge<'ctx, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, DB, H, CA>,
}

impl<'ctx, DB, H, CA> EthBridge<'ctx, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// If the bridge's escrow key was changed, we check
    /// that the balance increased and that the bridge pool
    /// VP has been triggered. The bridge pool VP will carry
    /// out the rest of the checks.
    fn check_escrow(
        &self,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Error> {
        let escrow_key = balance_key(&nam(), &eth_bridge::ADDRESS);
        let escrow_pre: Amount = if let Ok(Some(bytes)) =
            self.ctx.read_bytes_pre(&escrow_key)
        {
            BorshDeserialize::try_from_slice(bytes.as_slice()).map_err(
                |_| Error(eyre!("Couldn't deserialize a balance from storage")),
            )?
        } else {
            tracing::debug!(
                "Could not retrieve the Ethereum bridge VP's balance from \
                 storage"
            );
            return Ok(false);
        };
        let escrow_post: Amount =
            if let Ok(Some(bytes)) = self.ctx.read_bytes_post(&escrow_key) {
                BorshDeserialize::try_from_slice(bytes.as_slice()).map_err(
                    |_| {
                        Error(eyre!(
                            "Couldn't deserialize the balance of the Ethereum \
                             bridge VP from storage."
                        ))
                    },
                )?
            } else {
                tracing::debug!(
                    "Could not retrieve the modified Ethereum bridge VP's \
                     balance after applying tx"
                );
                return Ok(false);
            };

        // The amount escrowed should increase.
        if escrow_pre < escrow_post {
            Ok(verifiers.contains(&storage::bridge_pool::BRIDGE_POOL_ADDRESS))
        } else {
            tracing::info!(
                "A normal tx cannot decrease the amount of Nam escrowed in \
                 the Ethereum bridge"
            );
            Ok(false)
        }
    }
}

/// One of the the two types of checks
/// this VP must perform.
#[derive(Debug)]
enum CheckType {
    Escrow,
    Erc20Transfer(wrapped_erc20s::Key, wrapped_erc20s::Key),
}

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
/// Generic error that may be returned by the validity predicate
pub struct Error(#[from] eyre::Error);

impl<'a, DB, H, CA> NativeVp for EthBridge<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = eth_bridge::INTERNAL_ADDRESS;

    /// Validate that a wasm transaction is permitted to change keys under this
    /// account.
    ///
    /// We permit only the following changes via wasm for the time being:
    /// - a wrapped ERC20's supply key to decrease iff one of its balance keys
    ///   decreased by the same amount
    /// - a wrapped ERC20's balance key to decrease iff another one of its
    ///   balance keys increased by the same amount
    /// - Escrowing Nam in order to mint wrapped Nam on Ethereum
    ///
    /// Some other changes to the storage subspace of this account are expected
    /// to happen natively i.e. bypassing this validity predicate. For example,
    /// changes to the `eth_msgs/...` keys. For those cases, we reject here as
    /// no wasm transactions should be able to modify those keys.
    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool, Self::Error> {
        tracing::debug!(
            tx_data_len = tx_data.len(),
            keys_changed_len = keys_changed.len(),
            verifiers_len = verifiers.len(),
            "Ethereum Bridge VP triggered",
        );

        let (key_a, key_b) = match determine_check_type(keys_changed)? {
            Some(CheckType::Erc20Transfer(key_a, key_b)) => (key_a, key_b),
            Some(CheckType::Escrow) => return self.check_escrow(verifiers),
            None => return Ok(false),
        };
        let (sender, _) = match check_balance_changes(&self.ctx, key_a, key_b)?
        {
            Some(sender) => sender,
            None => return Ok(false),
        };
        let authed = authorize::is_authorized(verifiers, &sender);
        Ok(authed)
    }
}

/// Checks if `keys_changed` represents a valid set of changed keys.
/// Depending on which keys get changed, chooses which type of
/// check to perform in the `validate_tx` function.
///  1. If the Ethereum bridge escrow key was changed, we need to check
///     that escrow was performed correctly.
///  2. If two erc20 keys where changed, this is a transfer that needs
///     to be checked.
fn determine_check_type(
    keys_changed: &BTreeSet<Key>,
) -> Result<Option<CheckType>, Error> {
    // we aren't concerned with keys that changed outside of our account
    let keys_changed: HashSet<_> = keys_changed
        .iter()
        .filter(|key| storage::is_eth_bridge_key(key))
        .collect();
    if keys_changed.is_empty() {
        return Err(Error(eyre!(
            "No keys changed under our account so this validity predicate \
             shouldn't have been triggered"
        )));
    }
    tracing::debug!(
        relevant_keys.len = keys_changed.len(),
        "Found keys changed under our account"
    );
    if keys_changed.len() == 1 && keys_changed.contains(&escrow_key()) {
        return Ok(Some(CheckType::Escrow));
    } else if keys_changed.len() != 2 {
        tracing::debug!(
            relevant_keys.len = keys_changed.len(),
            "Rejecting transaction as only two keys should have changed"
        );
        return Ok(None);
    }

    let mut keys = HashSet::<_>::default();
    for key in keys_changed.into_iter() {
        let key = match wrapped_erc20s::Key::try_from(key) {
            Ok(key) => {
                // Until burning is implemented, we disallow changes to any
                // supply keys via wasm transactions
                if matches!(key.suffix, wrapped_erc20s::KeyType::Supply) {
                    tracing::debug!(
                        ?key,
                        "Rejecting transaction as key is a supply key"
                    );
                    return Ok(None);
                }
                key
            }
            Err(error) => {
                tracing::debug!(
                    %key,
                    ?error,
                    "Rejecting transaction as key is not a wrapped ERC20 key"
                );
                return Ok(None);
            }
        };
        keys.insert(key);
    }

    // We can .unwrap() here as we know for sure that this set has len=2
    let (key_a, key_b) = keys.into_iter().collect_tuple().unwrap();
    if key_a.asset != key_b.asset {
        tracing::debug!(
            ?key_a,
            ?key_b,
            "Rejecting transaction as keys are for different assets"
        );
        return Ok(None);
    }
    Ok(Some(CheckType::Erc20Transfer(key_a, key_b)))
}

/// Checks that the balances at both `key_a` and `key_b` have changed by some
/// amount, and that the changes balance each other out. If the balance changes
/// are invalid, the reason is logged and a `None` is returned. Otherwise,
/// return the `Address` of the owner of the balance which is decreasing,
/// and by how much it decreased, which should be authorizing the balance
/// change.
pub(super) fn check_balance_changes(
    reader: impl StorageReader,
    key_a: wrapped_erc20s::Key,
    key_b: wrapped_erc20s::Key,
) -> Result<Option<(Address, Amount)>> {
    let (balance_a, balance_b) =
        match (key_a.suffix.clone(), key_b.suffix.clone()) {
            (
                wrapped_erc20s::KeyType::Balance { .. },
                wrapped_erc20s::KeyType::Balance { .. },
            ) => (Key::from(&key_a), Key::from(&key_b)),
            (
                wrapped_erc20s::KeyType::Balance { .. },
                wrapped_erc20s::KeyType::Supply,
            )
            | (
                wrapped_erc20s::KeyType::Supply,
                wrapped_erc20s::KeyType::Balance { .. },
            ) => {
                tracing::debug!(
                    ?key_a,
                    ?key_b,
                    "Rejecting transaction that is attempting to change a \
                     supply key"
                );
                return Ok(None);
            }
            (
                wrapped_erc20s::KeyType::Supply,
                wrapped_erc20s::KeyType::Supply,
            ) => {
                // in theory, this should be unreachable!() as we would have
                // already rejected if both supply keys were for
                // the same asset
                tracing::debug!(
                    ?key_a,
                    ?key_b,
                    "Rejecting transaction that is attempting to change two \
                     supply keys"
                );
                return Ok(None);
            }
        };
    let balance_a_pre = reader
        .read_pre_value::<Amount>(&balance_a)?
        .unwrap_or_default()
        .change();
    let balance_a_post = match reader.read_post_value::<Amount>(&balance_a)? {
        Some(value) => value,
        None => {
            tracing::debug!(
                ?balance_a,
                "Rejecting transaction as could not read_post balance key"
            );
            return Ok(None);
        }
    }
    .change();
    let balance_b_pre = reader
        .read_pre_value::<Amount>(&balance_b)?
        .unwrap_or_default()
        .change();
    let balance_b_post = match reader.read_post_value::<Amount>(&balance_b)? {
        Some(value) => value,
        None => {
            tracing::debug!(
                ?balance_b,
                "Rejecting transaction as could not read_post balance key"
            );
            return Ok(None);
        }
    }
    .change();

    let balance_a_delta = calculate_delta(balance_a_pre, balance_a_post)?;
    let balance_b_delta = calculate_delta(balance_b_pre, balance_b_post)?;
    if balance_a_delta != -balance_b_delta {
        tracing::debug!(
            ?balance_a_pre,
            ?balance_b_pre,
            ?balance_a_post,
            ?balance_b_post,
            ?balance_a_delta,
            ?balance_b_delta,
            "Rejecting transaction as balance changes do not match"
        );
        return Ok(None);
    }
    if balance_a_delta == 0 {
        assert_eq!(balance_b_delta, 0);
        tracing::debug!("Rejecting transaction as no balance change");
        return Ok(None);
    }
    if balance_a_post < 0 {
        tracing::debug!(
            ?balance_a_post,
            "Rejecting transaction as balance is negative"
        );
        return Ok(None);
    }
    if balance_b_post < 0 {
        tracing::debug!(
            ?balance_b_post,
            "Rejecting transaction as balance is negative"
        );
        return Ok(None);
    }

    if balance_a_delta < 0 {
        if let wrapped_erc20s::KeyType::Balance { owner } = key_a.suffix {
            Ok(Some((
                owner,
                Amount::from(
                    u64::try_from(balance_b_delta)
                        .expect("This should not fail"),
                ),
            )))
        } else {
            unreachable!()
        }
    } else {
        assert!(balance_b_delta < 0);
        if let wrapped_erc20s::KeyType::Balance { owner } = key_b.suffix {
            Ok(Some((
                owner,
                Amount::from(
                    u64::try_from(balance_a_delta)
                        .expect("This should not fail"),
                ),
            )))
        } else {
            unreachable!()
        }
    }
}

/// Return the delta between `balance_pre` and `balance_post`, erroring if there
/// is an underflow
fn calculate_delta(balance_pre: i128, balance_post: i128) -> Result<i128> {
    match balance_post.checked_sub(balance_pre) {
        Some(result) => Ok(result),
        None => Err(eyre!(
            "Underflow while calculating delta: {} - {}",
            balance_post,
            balance_pre
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::env::temp_dir;

    use borsh::BorshSerialize;
    use namada_core::ledger::eth_bridge;
    use namada_core::ledger::eth_bridge::storage::bridge_pool::BRIDGE_POOL_ADDRESS;
    use namada_core::types::address;
    use namada_ethereum_bridge::parameters::{
        Contracts, EthereumBridgeConfig, UpgradeableContract,
    };
    use rand::Rng;

    use super::*;
    use crate::ledger::gas::VpGasMeter;
    use crate::ledger::storage::mockdb::MockDB;
    use crate::ledger::storage::traits::Sha256Hasher;
    use crate::ledger::storage::write_log::WriteLog;
    use crate::ledger::storage::Storage;
    use crate::proto::Tx;
    use crate::types::address::wnam;
    use crate::types::chain::ChainId;
    use crate::types::ethereum_events;
    use crate::types::ethereum_events::EthAddress;
    use crate::types::storage::TxIndex;
    use crate::vm::wasm::VpCache;
    use crate::vm::WasmCacheRwAccess;

    const ARBITRARY_OWNER_A_ADDRESS: &str =
        "atest1d9khqw36x9zyxwfhgfpygv2pgc65gse4gy6rjs34gfzr2v69gy6y23zpggurjv2yx5m52sesu6r4y4";
    const ARBITRARY_OWNER_B_ADDRESS: &str =
        "atest1v4ehgw36xuunwd6989prwdfkxqmnvsfjxs6nvv6xxucrs3f3xcmns3fcxdzrvvz9xverzvzr56le8f";
    const ARBITRARY_OWNER_A_INITIAL_BALANCE: u64 = 100;
    const ESCROW_AMOUNT: u64 = 100;
    const BRIDGE_POOL_ESCROW_INITIAL_BALANCE: u64 = 0;

    /// Return some arbitrary random key belonging to this account
    fn arbitrary_key() -> Key {
        let mut rng = rand::thread_rng();
        let rn = rng.gen::<u64>();
        storage::prefix()
            .push(&format!("arbitrary key segment {}", rn))
            .expect("should always be able to construct this key")
    }

    /// Initialize some dummy storage for testing
    fn setup_storage() -> Storage<MockDB, Sha256Hasher> {
        let mut storage = Storage::<MockDB, Sha256Hasher>::open(
            std::path::Path::new(""),
            ChainId::default(),
            address::nam(),
            None,
        );

        // setup a user with a balance
        let balance_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        storage
            .write(
                &balance_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");

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
            &eth_bridge::ADDRESS,
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

    #[test]
    fn test_error_if_triggered_without_keys_changed() {
        let keys_changed = BTreeSet::new();

        let result = determine_check_type(&keys_changed);

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_if_not_two_keys_changed() {
        {
            let keys_changed = BTreeSet::from_iter(vec![arbitrary_key(); 3]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }
        {
            let keys_changed = BTreeSet::from_iter(vec![
                escrow_key(),
                arbitrary_key(),
                arbitrary_key(),
            ]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }
    }

    #[test]
    fn test_rejects_if_not_two_multitoken_keys_changed() {
        {
            let keys_changed =
                BTreeSet::from_iter(vec![arbitrary_key(), arbitrary_key()]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .supply(),
            ]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }

        {
            let keys_changed = BTreeSet::from_iter(vec![
                arbitrary_key(),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_A_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }
    }

    #[test]
    fn test_rejects_if_multitoken_keys_for_different_assets() {
        {
            let keys_changed = BTreeSet::from_iter(vec![
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_A_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
                wrapped_erc20s::Keys::from(
                    &ethereum_events::testing::USDC_ERC20_ETH_ADDRESS,
                )
                .balance(
                    &Address::decode(ARBITRARY_OWNER_B_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }
    }

    #[test]
    fn test_rejects_if_supply_key_changed() {
        let asset = &ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
        {
            let keys_changed = BTreeSet::from_iter(vec![
                wrapped_erc20s::Keys::from(asset).supply(),
                wrapped_erc20s::Keys::from(asset).balance(
                    &Address::decode(ARBITRARY_OWNER_B_ADDRESS)
                        .expect("Couldn't set up test"),
                ),
            ]);

            let result = determine_check_type(&keys_changed);

            assert_matches!(result, Ok(None));
        }
    }

    /// Test that escrowing Nam is accepted.
    #[test]
    fn test_escrow_nam_accepted() {
        let mut writelog = WriteLog::default();
        let storage = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        writelog
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");

        // credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &eth_bridge::ADDRESS);
        writelog
            .write(
                &escrow_key,
                Amount::from(
                    BRIDGE_POOL_ESCROW_INITIAL_BALANCE + ESCROW_AMOUNT,
                )
                .try_to_vec()
                .expect("Test failed"),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([BRIDGE_POOL_ADDRESS]);

        // set up the VP
        let tx = Tx::new(vec![], None);
        let vp = EthBridge {
            ctx: setup_ctx(&tx, &storage, &writelog, &keys_changed, &verifiers),
        };

        let res = vp.validate_tx(
            &tx.try_to_vec().expect("Test failed"),
            &keys_changed,
            &verifiers,
        );
        assert!(res.expect("Test failed"));
    }

    /// Test that escrowing must increase the balance
    #[test]
    fn test_escrowed_nam_must_increase() {
        let mut writelog = WriteLog::default();
        let storage = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        writelog
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");

        // do not credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &eth_bridge::ADDRESS);
        writelog
            .write(
                &escrow_key,
                Amount::from(BRIDGE_POOL_ESCROW_INITIAL_BALANCE)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([BRIDGE_POOL_ADDRESS]);

        // set up the VP
        let tx = Tx::new(vec![], None);
        let vp = EthBridge {
            ctx: setup_ctx(&tx, &storage, &writelog, &keys_changed, &verifiers),
        };

        let res = vp.validate_tx(
            &tx.try_to_vec().expect("Test failed"),
            &keys_changed,
            &verifiers,
        );
        assert!(!res.expect("Test failed"));
    }

    /// Test that the VP checks that the bridge pool vp will
    /// be triggered if escrowing occurs.
    #[test]
    fn test_escrowing_must_trigger_bridge_pool_vp() {
        let mut writelog = WriteLog::default();
        let storage = setup_storage();
        // debit the user's balance
        let account_key = balance_key(
            &nam(),
            &Address::decode(ARBITRARY_OWNER_A_ADDRESS).expect("Test failed"),
        );
        writelog
            .write(
                &account_key,
                Amount::from(ARBITRARY_OWNER_A_INITIAL_BALANCE - ESCROW_AMOUNT)
                    .try_to_vec()
                    .expect("Test failed"),
            )
            .expect("Test failed");

        // credit the balance to the escrow
        let escrow_key = balance_key(&nam(), &eth_bridge::ADDRESS);
        writelog
            .write(
                &escrow_key,
                Amount::from(
                    BRIDGE_POOL_ESCROW_INITIAL_BALANCE + ESCROW_AMOUNT,
                )
                .try_to_vec()
                .expect("Test failed"),
            )
            .expect("Test failed");

        let keys_changed = BTreeSet::from([account_key, escrow_key]);
        let verifiers = BTreeSet::from([]);

        // set up the VP
        let tx = Tx::new(vec![], None);
        let vp = EthBridge {
            ctx: setup_ctx(&tx, &storage, &writelog, &keys_changed, &verifiers),
        };

        let res = vp.validate_tx(
            &tx.try_to_vec().expect("Test failed"),
            &keys_changed,
            &verifiers,
        );
        assert!(!res.expect("Test failed"));
    }
}

//! A "faucet" account for testnet.
//!
//! This VP allows anyone to withdraw up to
//! [`testnet_pow::read_withdrawal_limit`] tokens without the faucet's
//! signature, but with a valid PoW challenge solution that cannot be replayed.
//!
//! Any other storage key changes are allowed only with a valid signature.

use namada_vp_prelude::*;
use once_cell::unsync::Lazy;

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Vec<u8>,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_testnet_faucet called with user addr: {}, key_changed: {:?}, \
         verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    let signed_tx_data =
        Lazy::new(|| SignedTxData::try_from_slice(&tx_data[..]));

    let valid_sig = Lazy::new(|| match &*signed_tx_data {
        Ok(signed_tx_data) => {
            let threshold = key::threshold(ctx, &addr).unwrap().unwrap_or(1);
            if signed_tx_data.total_signatures() < threshold {
                return false;
            }
            let mut valid_signatures = 0;
            for sig_data in &signed_tx_data.sigs {
                let pk = key::get(&ctx, &addr, sig_data.index);
                if let Ok(Some(public_key)) = pk {
                    let signature_result = ctx
                        .verify_tx_signature(&public_key, &sig_data.sig)
                        .unwrap_or(false);
                    if signature_result {
                        valid_signatures += 1;
                    }
                    if valid_signatures >= threshold {
                        return true;
                    }
                }
            }
            return valid_signatures >= threshold;
        }
        _ => false,
    });

    if !is_valid_tx(ctx, &tx_data)? {
        return reject();
    }

    for key in keys_changed.iter() {
        let is_valid = if let Some(owner) = token::is_any_token_balance_key(key)
        {
            if owner == &addr {
                let pre: token::Amount = ctx.read_pre(key)?.unwrap_or_default();
                let post: token::Amount =
                    ctx.read_post(key)?.unwrap_or_default();
                let change = post.change() - pre.change();

                if change < 0 {
                    // Allow to withdraw without a sig if there's a valid PoW
                    if ctx.has_valid_pow() {
                        let max_free_debit =
                            testnet_pow::read_withdrawal_limit(
                                &ctx.pre(),
                                &addr,
                            )?;
                        change >= -max_free_debit.change()
                    } else {
                        debug_log!("No PoW solution, a signature is required");
                        // Debit without a solution has to signed
                        *valid_sig
                    }
                } else {
                    // credit is permissive
                    true
                }
            } else {
                // balance changes of other accounts
                true
            }
        } else if let Some(owner) = key.is_validity_predicate() {
            let has_post: bool = ctx.has_key_post(key)?;
            if owner == &addr {
                if has_post {
                    let vp: Vec<u8> = ctx.read_bytes_post(key)?.unwrap();
                    return Ok(*valid_sig && is_vp_whitelisted(ctx, &vp)?);
                } else {
                    return reject();
                }
            } else {
                let vp: Vec<u8> = ctx.read_bytes_post(key)?.unwrap();
                return is_vp_whitelisted(ctx, &vp);
            }
        } else {
            // Allow any other key change if authorized by a signature
            *valid_sig
        };

        if !is_valid {
            debug_log!("key {} modification failed vp", key);
            return reject();
        }
    }

    accept()
}

#[cfg(test)]
mod tests {
    use address::testing::arb_non_internal_address;
    // Use this as `#[test]` annotation to enable logging
    use namada_tests::log::test;
    use namada_tests::tx::{self, tx_host_env, TestTxEnv};
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::key::{RefTo, SigScheme};
    use proptest::prelude::*;
    use storage::testing::arb_account_storage_key_no_vp;

    use super::*;

    const VP_ALWAYS_TRUE_WASM: &str =
        "../../wasm_for_tests/vp_always_true.wasm";

    /// Allows anyone to withdraw up to 1_000 tokens in a single tx
    pub const MAX_FREE_DEBIT: i128 = 1_000_000_000; // in micro units

    /// Test that no-op transaction (i.e. no storage modifications) accepted.
    #[test]
    fn test_no_op_transaction() {
        let tx_data: Vec<u8> = vec![];
        let addr: Address = address::testing::established_address_1();
        let keys_changed: BTreeSet<storage::Key> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = BTreeSet::default();

        // The VP env must be initialized before calling `validate_tx`
        vp_host_env::init();

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).unwrap()
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from(10_098_123);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, None, amount);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx_host_env::ctx(),
                &source,
                address,
                &token,
                None,
                amount,
                &None,
                &None,
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, &vp_code)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            !validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    /// Test that a validity predicate update with a valid signature is
    /// accepted.
    #[test]
    fn test_signed_vp_update_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = &keypair.ref_to();
        let vp_code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        tx_env.write_public_key(&vp_owner, public_key);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, &vp_code)
                .unwrap();
        });

        let mut vp_env = vp_host_env::take();
        let tx = vp_env.tx.clone();
        let signed_tx = tx.sign(&keypair);
        let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
        vp_env.tx = signed_tx;
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .unwrap()
        );
    }

    prop_compose! {
        /// Generates an account address and a storage key inside its storage.
        fn arb_account_storage_subspace_key()
            // Generate an address
            (address in arb_non_internal_address())
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            (storage_key in arb_account_storage_key_no_vp(address.clone()),
            // Use the generated address too
            address in Just(address))
        -> (Address, Key) {
            (address, storage_key)
        }
    }

    proptest! {
    /// Test that a debit of more than [`MAX_FREE_DEBIT`] tokens without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_over_limit_rejected(amount in (MAX_FREE_DEBIT as u64 + 1..)) {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        // Init the VP
        let vp_owner = address::testing::established_address_1();
        let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
        let withdrawal_limit = token::Amount::from(MAX_FREE_DEBIT as u64);
        testnet_pow::init_faucet_storage(&mut tx_env.storage, &vp_owner, difficulty, withdrawal_limit).unwrap();

        let target = address::testing::established_address_2();
        let token = address::nam();
        let amount = token::Amount::from(amount);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, None, amount);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
        // Apply transfer in a transaction
        tx_host_env::token::transfer(tx::ctx(), address, &target, &token, None, amount, &None, &None).unwrap();
        });

        let vp_env = vp_host_env::take();
        let tx_data: Vec<u8> = vec![];
        let keys_changed: BTreeSet<storage::Key> =
        vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(!validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
    }

    /// Test that a debit of less than or equal to [`MAX_FREE_DEBIT`] tokens
    /// without a valid signature but with a valid PoW solution is accepted.
    #[test]
    fn test_unsigned_debit_under_limit_accepted(amount in (..MAX_FREE_DEBIT as u64 + 1)) {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        // Init the VP
        let vp_owner = address::testing::established_address_1();
        let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
        let withdrawal_limit = token::Amount::from(MAX_FREE_DEBIT as u64);
        testnet_pow::init_faucet_storage(&mut tx_env.storage, &vp_owner, difficulty, withdrawal_limit).unwrap();

        let target = address::testing::established_address_2();
        let target_key = key::testing::keypair_1();
        let token = address::nam();
        let amount = token::Amount::from(amount);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, None, amount);

        // Construct a PoW solution like a client would
        let challenge = testnet_pow::Challenge::new(&mut tx_env.storage, &vp_owner, target.clone()).unwrap();
        let solution = challenge.solve();
        let solution_bytes = solution.try_to_vec().unwrap();
        // The signature itself doesn't matter and is not being checked in this
        // test, it's just used to construct `SignedTxData`
        let sig = key::common::SigScheme::sign(&target_key, &solution_bytes);
        let signed_solution = SignedTxData {
            data: Some(solution_bytes),
            sig,
        };

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Don't call `Solution::invalidate_if_valid` - this is done by the
            // shell's finalize_block.
            let valid = solution.validate(tx::ctx(), address, target.clone()).unwrap();
            assert!(valid);
            // Apply transfer in a transaction
            tx_host_env::token::transfer(tx::ctx(), address, &target, &token, None, amount, &None, &None).unwrap();
        });

        let mut vp_env = vp_host_env::take();
        // This is set by the protocol when the wrapper tx has a valid PoW
        vp_env.has_valid_pow = true;
        let tx_data: Vec<u8> = signed_solution.try_to_vec().unwrap();
        let keys_changed: BTreeSet<storage::Key> =
        vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
    }

        /// Test that a signed tx that performs arbitrary storage writes or
        /// deletes to the account is accepted.
        #[test]
        fn test_signed_arb_storage_write(
            (vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Init the VP
            let difficulty = testnet_pow::Difficulty::try_new(0).unwrap();
            let withdrawal_limit = token::Amount::from(MAX_FREE_DEBIT as u64);
            testnet_pow::init_faucet_storage(&mut tx_env.storage, &vp_owner, difficulty, withdrawal_limit).unwrap();

            let keypair = key::testing::keypair_1();
            let public_key = &keypair.ref_to();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            tx_env.write_public_key(&vp_owner, public_key);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let mut vp_env = vp_host_env::take();
            let tx = vp_env.tx.clone();
            let signed_tx = tx.sign(&keypair);
            let tx_data: Vec<u8> = signed_tx.data.as_ref().cloned().unwrap();
            vp_env.tx = signed_tx;
            let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers).unwrap());
        }
    }
}

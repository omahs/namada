use std::borrow::Borrow;
use std::collections::BTreeSet;

use namada::ledger::gas::BlockGasMeter;
use namada::ledger::parameters::{self, EpochDuration};
use namada::ledger::storage::mockdb::MockDB;
use namada::ledger::storage::testing::TestStorage;
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{Sha256Hasher, WlStorage};
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::storage::{Key, TxIndex};
use namada::types::time::DurationSecs;
use namada::types::{key, token};
use namada::vm::prefix_iter::PrefixIterators;
use namada::vm::wasm::run::Error;
use namada::vm::wasm::{self, TxCache, VpCache};
use namada::vm::{self, WasmCacheRwAccess};
use namada_tx_prelude::{BorshSerialize, Ctx};
use tempfile::TempDir;

use crate::vp::TestVpEnv;

/// Tx execution context provides access to host env functions
static mut CTX: Ctx = unsafe { Ctx::new() };

/// Tx execution context provides access to host env functions
pub fn ctx() -> &'static mut Ctx {
    unsafe { &mut CTX }
}

/// This module combines the native host function implementations from
/// `native_tx_host_env` with the functions exposed to the tx wasm
/// that will call to the native functions, instead of interfacing via a
/// wasm runtime. It can be used for host environment integration tests.
pub mod tx_host_env {
    pub use namada_tx_prelude::*;

    pub use super::ctx;
    pub use super::native_tx_host_env::*;
}

/// Host environment structures required for transactions.
#[derive(Debug)]
pub struct TestTxEnv {
    pub wl_storage: WlStorage<MockDB, Sha256Hasher>,
    pub iterators: PrefixIterators<'static, MockDB>,
    pub verifiers: BTreeSet<Address>,
    pub gas_meter: BlockGasMeter,
    pub tx_index: TxIndex,
    pub result_buffer: Option<Vec<u8>>,
    pub vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    pub vp_cache_dir: TempDir,
    pub tx_wasm_cache: TxCache<WasmCacheRwAccess>,
    pub tx_cache_dir: TempDir,
    pub tx: Tx,
}
impl Default for TestTxEnv {
    fn default() -> Self {
        let (vp_wasm_cache, vp_cache_dir) =
            wasm::compilation_cache::common::testing::cache();
        let (tx_wasm_cache, tx_cache_dir) =
            wasm::compilation_cache::common::testing::cache();

        let wl_storage = WlStorage {
            storage: TestStorage::default(),
            write_log: WriteLog::default(),
        };
        let chain_id = wl_storage.storage.chain_id.clone();
        Self {
            wl_storage,
            iterators: PrefixIterators::default(),
            gas_meter: BlockGasMeter::default(),
            tx_index: TxIndex::default(),
            verifiers: BTreeSet::default(),
            result_buffer: None,
            vp_wasm_cache,
            vp_cache_dir,
            tx_wasm_cache,
            tx_cache_dir,
            tx: Tx::new(vec![], None, chain_id, None),
        }
    }
}

impl TestTxEnv {
    pub fn all_touched_storage_keys(&self) -> BTreeSet<Key> {
        self.wl_storage.write_log.get_keys()
    }

    pub fn get_verifiers(&self) -> BTreeSet<Address> {
        self.wl_storage
            .write_log
            .verifiers_and_changed_keys(&self.verifiers)
            .0
    }

    pub fn init_parameters(
        &mut self,
        epoch_duration: Option<EpochDuration>,
        vp_whitelist: Option<Vec<String>>,
        tx_whitelist: Option<Vec<String>>,
    ) {
        let _ = parameters::update_epoch_parameter(
            &mut self.wl_storage.storage,
            &epoch_duration.unwrap_or(EpochDuration {
                min_num_of_blocks: 1,
                min_duration: DurationSecs(5),
            }),
        );
        let _ = parameters::update_tx_whitelist_parameter(
            &mut self.wl_storage.storage,
            tx_whitelist.unwrap_or_default(),
        );
        let _ = parameters::update_vp_whitelist_parameter(
            &mut self.wl_storage.storage,
            vp_whitelist.unwrap_or_default(),
        );
    }

    /// Fake accounts' existence by initializing their VP storage.
    /// This is needed for accounts that are being modified by a tx test to
    /// pass account existence check in `tx_write` function. Only established
    /// addresses ([`Address::Established`]) have their VP storage initialized,
    /// as other types of accounts should not have wasm VPs in storage in any
    /// case.
    pub fn spawn_accounts(
        &mut self,
        addresses: impl IntoIterator<Item = impl Borrow<Address>>,
    ) {
        for address in addresses {
            if matches!(
                address.borrow(),
                Address::Internal(_) | Address::Implicit(_)
            ) {
                continue;
            }
            let key = Key::validity_predicate(address.borrow());
            let vp_code = vec![];
            self.wl_storage
                .storage
                .write(&key, vp_code)
                .expect("Unable to write VP");
        }
    }

    /// Commit the genesis state. Typically, you'll want to call this after
    /// setting up the initial state, before running a transaction.
    pub fn commit_genesis(&mut self) {
        self.wl_storage.commit_genesis().unwrap();
    }

    pub fn commit_tx_and_block(&mut self) {
        self.wl_storage.commit_tx();
        self.wl_storage
            .commit_block()
            .map_err(|err| println!("{:?}", err))
            .ok();
        self.iterators = PrefixIterators::default();
        self.verifiers = BTreeSet::default();
        self.gas_meter = BlockGasMeter::default();
    }

    /// Credit tokens to the target account.
    pub fn credit_tokens(
        &mut self,
        target: &Address,
        token: &Address,
        sub_prefix: Option<Key>,
        amount: token::Amount,
    ) {
        let storage_key = match &sub_prefix {
            Some(sub_prefix) => {
                let prefix =
                    token::multitoken_balance_prefix(token, sub_prefix);
                token::multitoken_balance_key(&prefix, target)
            }
            None => token::balance_key(token, target),
        };
        self.wl_storage
            .storage
            .write(&storage_key, amount.try_to_vec().unwrap())
            .unwrap();
    }

    /// Set public key for the address.
    pub fn write_public_key(
        &mut self,
        address: &Address,
        public_key: &key::common::PublicKey,
    ) {
        let storage_key = key::pk_key(address);
        self.wl_storage
            .storage
            .write(&storage_key, public_key.try_to_vec().unwrap())
            .unwrap();
    }

    /// Apply the tx changes to the write log.
    pub fn execute_tx(&mut self) -> Result<(), Error> {
        let empty_data = vec![];
        wasm::run::tx(
            &self.wl_storage.storage,
            &mut self.wl_storage.write_log,
            &mut self.gas_meter,
            &self.tx_index,
            &self.tx.code,
            self.tx.data.as_ref().unwrap_or(&empty_data),
            &mut self.vp_wasm_cache,
            &mut self.tx_wasm_cache,
        )
        .and(Ok(()))
    }
}

/// This module allows to test code with tx host environment functions.
/// It keeps a thread-local global `TxEnv`, which is passed to any of
/// invoked host environment functions and so it must be initialized
/// before the test.
mod native_tx_host_env {

    use std::cell::RefCell;
    use std::pin::Pin;

    // TODO replace with `std::concat_idents` once stabilized (https://github.com/rust-lang/rust/issues/29599)
    use concat_idents::concat_idents;
    use namada::vm::host_env::*;

    use super::*;

    thread_local! {
        /// A [`TestTxEnv`] that can be used for tx host env functions calls
        /// that implements the WASM host environment in native environment.
        pub static ENV: RefCell<Option<Pin<Box<TestTxEnv>>>> =
            RefCell::new(None);
    }

    /// Initialize the tx host environment in [`ENV`]. This will be used in the
    /// host env function calls via macro `native_host_fn!`.
    pub fn init() {
        ENV.with(|env| {
            let test_env = TestTxEnv::default();
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Set the tx host environment in [`ENV`] from the given [`TestTxEnv`].
    /// This will be used in the host env function calls via
    /// macro `native_host_fn!`.
    pub fn set(test_env: TestTxEnv) {
        ENV.with(|env| {
            *env.borrow_mut() = Some(Box::pin(test_env));
        });
    }

    /// Mutably borrow the [`TestTxEnv`] from [`ENV`]. The [`ENV`] must be
    /// initialized.
    pub fn with<T>(f: impl Fn(&mut TestTxEnv) -> T) -> T {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let mut env = env
                .as_mut()
                .expect(
                    "Did you forget to initialize the ENV? (e.g. call to \
                     `tx_host_env::init()`)",
                )
                .as_mut();
            f(&mut env)
        })
    }

    /// Take the [`TestTxEnv`] out of [`ENV`]. The [`ENV`] must be initialized.
    pub fn take() -> TestTxEnv {
        ENV.with(|env| {
            let mut env = env.borrow_mut();
            let env = env.take().expect(
                "Did you forget to initialize the ENV? (e.g. call to \
                 `tx_host_env::init()`)",
            );
            let env = Pin::into_inner(env);
            *env
        })
    }

    pub fn commit_tx_and_block() {
        with(|env| env.commit_tx_and_block())
    }

    /// Set the [`TestTxEnv`] back from a [`TestVpEnv`]. This is useful when
    /// testing validation with multiple transactions that accumulate some state
    /// changes.
    pub fn set_from_vp_env(vp_env: TestVpEnv) {
        let TestVpEnv {
            wl_storage,
            tx,
            vp_wasm_cache,
            vp_cache_dir,
            ..
        } = vp_env;
        let tx_env = TestTxEnv {
            wl_storage,
            vp_wasm_cache,
            vp_cache_dir,
            tx,
            ..Default::default()
        };
        set(tx_env);
    }

    /// A helper macro to create implementations of the host environment
    /// functions exported to wasm, which uses the environment from the
    /// `ENV` variable.
    macro_rules! native_host_fn {
            // unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) {
                        with(|TestTxEnv {
                                wl_storage,
                                iterators,
                                verifiers,
                                gas_meter,
                                result_buffer,
                                tx_index,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                                tx_wasm_cache,
                                tx_cache_dir: _,
                                tx: _,
                            }: &mut TestTxEnv| {

                            let tx_env = vm::host_env::testing::tx_env(
                                &wl_storage.storage,
                                &mut wl_storage.write_log,
                                iterators,
                                verifiers,
                                gas_meter,
                                tx_index,
                                result_buffer,
                                vp_wasm_cache,
                                tx_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &tx_env, $($arg),* ).unwrap()
                        })
                    }
                });
            };

            // non-unit return type
            ( $fn:ident ( $($arg:ident : $type:ty),* $(,)?) -> $ret:ty ) => {
                concat_idents!(extern_fn_name = namada, _, $fn {
                    #[no_mangle]
                    extern "C" fn extern_fn_name( $($arg: $type),* ) -> $ret {
                        with(|TestTxEnv {
                            tx_index,
                                wl_storage,
                                iterators,
                                verifiers,
                                gas_meter,
                                result_buffer,
                                vp_wasm_cache,
                                vp_cache_dir: _,
                                tx_wasm_cache,
                                tx_cache_dir: _,
                                tx: _,
                            }: &mut TestTxEnv| {

                            let tx_env = vm::host_env::testing::tx_env(
                                &wl_storage.storage,
                                &mut wl_storage.write_log,
                                iterators,
                                verifiers,
                                gas_meter,
                                tx_index,
                                result_buffer,
                                vp_wasm_cache,
                                tx_wasm_cache,
                            );

                            // Call the `host_env` function and unwrap any
                            // runtime errors
                            $fn( &tx_env, $($arg),* ).unwrap()
                        })
                    }
                });
            }
        }

    // Implement all the exported functions from
    // [`namada_vm_env::imports::tx`] `extern "C"` section.
    native_host_fn!(tx_read(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(tx_result_buffer(result_ptr: u64));
    native_host_fn!(tx_has_key(key_ptr: u64, key_len: u64) -> i64);
    native_host_fn!(tx_write(
        key_ptr: u64,
        key_len: u64,
        val_ptr: u64,
        val_len: u64
    ));
    native_host_fn!(tx_write_temp(
        key_ptr: u64,
        key_len: u64,
        val_ptr: u64,
        val_len: u64
    ));
    native_host_fn!(tx_delete(key_ptr: u64, key_len: u64));
    native_host_fn!(tx_iter_prefix(prefix_ptr: u64, prefix_len: u64) -> u64);
    native_host_fn!(tx_iter_next(iter_id: u64) -> i64);
    native_host_fn!(tx_insert_verifier(addr_ptr: u64, addr_len: u64));
    native_host_fn!(tx_update_validity_predicate(
        addr_ptr: u64,
        addr_len: u64,
        code_ptr: u64,
        code_len: u64,
    ));
    native_host_fn!(tx_init_account(
        code_ptr: u64,
        code_len: u64,
        result_ptr: u64
    ));
    native_host_fn!(tx_emit_ibc_event(event_ptr: u64, event_len: u64));
    native_host_fn!(tx_get_chain_id(result_ptr: u64));
    native_host_fn!(tx_get_block_height() -> u64);
    native_host_fn!(tx_get_tx_index() -> u32);
    native_host_fn!(tx_get_block_time() -> i64);
    native_host_fn!(tx_get_block_hash(result_ptr: u64));
    native_host_fn!(tx_get_block_epoch() -> u64);
    native_host_fn!(tx_get_native_token(result_ptr: u64));
    native_host_fn!(tx_log_string(str_ptr: u64, str_len: u64));
}

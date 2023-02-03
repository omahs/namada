//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use namada::ledger::pos::types::into_tm_voting_power;
use namada::ledger::storage_api::StorageRead;
use namada::ledger::{protocol, replay_protection};
use namada::types::hash;
use namada::types::storage::{BlockHash, BlockResults, Header};
use namada::types::token::Amount;

use super::governance::execute_governance_proposals;
use super::*;
use crate::facade::tendermint_proto::abci::Misbehavior as Evidence;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
use crate::node::ledger::shell::stats::InternalStats;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Updates the chain with new header, height, etc. Also keeps track
    /// of epoch changes and applies associated updates to validator sets,
    /// etc. as necessary.
    ///
    /// Validate and apply decrypted transactions unless
    /// [`Shell::process_proposal`] detected that they were not submitted in
    /// correct order or more decrypted txs arrived than expected. In that
    /// case, all decrypted transactions are not applied and must be
    /// included in the next `Shell::prepare_proposal` call.
    ///
    /// Incoming wrapper txs need no further validation. They
    /// are added to the block.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Invalid tx
    ///   2: Tx is invalidly signed
    ///   3: Wasm runtime error
    ///   4: Invalid order of decrypted txs
    ///   5. More decrypted txs than expected
    pub fn finalize_block(
        &mut self,
        req: shim::request::FinalizeBlock,
    ) -> Result<shim::response::FinalizeBlock> {
        // reset gas meter before we start
        self.gas_meter.reset();

        let mut response = shim::response::FinalizeBlock::default();
        // begin the next block and check if a new epoch began
        let (height, new_epoch) =
            self.update_state(req.header, req.hash, req.byzantine_validators);

        if new_epoch {
            let _proposals_result =
                execute_governance_proposals(self, &mut response)?;
        }

        let wrapper_fees = self.get_wrapper_tx_fees();
        let mut stats = InternalStats::default();

        // Tracks the accepted transactions
        self.wl_storage.storage.block.results = BlockResults::default();
        for (tx_index, processed_tx) in req.txs.iter().enumerate() {
            let tx = if let Ok(tx) = Tx::try_from(processed_tx.tx.as_ref()) {
                tx
            } else {
                tracing::error!(
                    "FinalizeBlock received a tx that could not be \
                     deserialized to a Tx type. This is likely a protocol \
                     transaction."
                );
                continue;
            };
            let tx_length = processed_tx.tx.len();

            let tx_type = if let Ok(tx_type) = process_tx(tx) {
                tx_type
            } else {
                tracing::error!(
                    "Internal logic error: FinalizeBlock received tx that \
                     could not be deserialized to a valid TxType"
                );
                continue;
            };
            // If [`process_proposal`] rejected a Tx, emit an event here and
            // move on to next tx
            if ErrorCodes::from_u32(processed_tx.result.code).unwrap()
                != ErrorCodes::Ok
            {
                let mut tx_event = Event::new_tx_event(&tx_type, height.0);
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                // if the rejected tx was decrypted, remove it
                // from the queue of txs to be processed and remove the hash
                // from storage
                if let TxType::Decrypted(_) = &tx_type {
                    let tx_hash = self
                        .wl_storage
                        .storage
                        .tx_queue
                        .pop()
                        .expect("Missing wrapper tx in queue")
                        .tx
                        .tx_hash;
                    let tx_hash_key =
                        replay_protection::get_tx_hash_key(&tx_hash);
                    self.wl_storage
                        .storage
                        .delete(&tx_hash_key)
                        .expect("Error while deleting tx hash from storage");
                }
                continue;
            }

            let (mut tx_event, tx_unsigned_hash) = match &tx_type {
                TxType::Wrapper(wrapper) => {
                    let mut tx_event = Event::new_tx_event(&tx_type, height.0);

                    // Writes both txs hash to storage
                    let tx = Tx::try_from(processed_tx.tx.as_ref()).unwrap();
                    let wrapper_tx_hash_key =
                        replay_protection::get_tx_hash_key(&hash::Hash(
                            tx.unsigned_hash(),
                        ));
                    self.wl_storage
                        .storage
                        .write(&wrapper_tx_hash_key, vec![])
                        .expect("Error while writing tx hash to storage");

                    let inner_tx_hash_key =
                        replay_protection::get_tx_hash_key(&wrapper.tx_hash);
                    self.wl_storage
                        .storage
                        .write(&inner_tx_hash_key, vec![])
                        .expect("Error while writing tx hash to storage");

                    #[cfg(not(feature = "mainnet"))]
                    let has_valid_pow =
                        self.invalidate_pow_solution_if_valid(wrapper);

                    // Charge fee
                    let fee_payer =
                        if wrapper.pk != address::masp_tx_key().ref_to() {
                            wrapper.fee_payer()
                        } else {
                            address::masp()
                        };

                    let balance_key =
                        token::balance_key(&wrapper.fee.token, &fee_payer);
                    let balance: token::Amount = self
                        .wl_storage
                        .read(&balance_key)
                        .expect("must be able to read")
                        .unwrap_or_default();

                    match balance.checked_sub(wrapper_fees) {
                        Some(amount) => {
                            self.wl_storage
                                .storage
                                .write(
                                    &balance_key,
                                    amount.try_to_vec().unwrap(),
                                )
                                .unwrap();
                        }
                        None => {
                            #[cfg(not(feature = "mainnet"))]
                            let reject = !has_valid_pow;
                            #[cfg(feature = "mainnet")]
                            let reject = true;
                            if reject {
                                // Burn remaining funds
                                self.wl_storage
                                    .storage
                                    .write(
                                        &balance_key,
                                        Amount::from(0).try_to_vec().unwrap(),
                                    )
                                    .unwrap();
                                tx_event["info"] =
                                    "Insufficient balance for fee".into();
                                tx_event["code"] = ErrorCodes::InvalidTx.into();
                                tx_event["gas_used"] = "0".to_string();

                                response.events.push(tx_event);
                                continue;
                            }
                        }
                    }

                    self.wl_storage.storage.tx_queue.push(WrapperTxInQueue {
                        tx: wrapper.clone(),
                        #[cfg(not(feature = "mainnet"))]
                        has_valid_pow,
                    });
                    (tx_event, None)
                }
                TxType::Decrypted(inner) => {
                    // We remove the corresponding wrapper tx from the queue
                    let wrapper_hash = self
                        .wl_storage
                        .storage
                        .tx_queue
                        .pop()
                        .expect("Missing wrapper tx in queue")
                        .tx
                        .tx_hash;
                    let mut event = Event::new_tx_event(&tx_type, height.0);

                    match inner {
                        DecryptedTx::Decrypted {
                            tx,
                            has_valid_pow: _,
                        } => {
                            stats.increment_tx_type(
                                namada::core::types::hash::Hash(tx.code_hash())
                                    .to_string(),
                            );
                        }
                        DecryptedTx::Undecryptable(_) => {
                            event["log"] =
                                "Transaction could not be decrypted.".into();
                            event["code"] = ErrorCodes::Undecryptable.into();
                        }
                    }
                    (event, Some(wrapper_hash))
                }
                TxType::Raw(_) => {
                    tracing::error!(
                        "Internal logic error: FinalizeBlock received a \
                         TxType::Raw transaction"
                    );
                    continue;
                }
                TxType::Protocol(_) => {
                    tracing::error!(
                        "Internal logic error: FinalizeBlock received a \
                         TxType::Protocol transaction"
                    );
                    continue;
                }
            };

            match protocol::apply_tx(
                tx_type,
                tx_length,
                TxIndex(
                    tx_index
                        .try_into()
                        .expect("transaction index out of bounds"),
                ),
                &mut self.gas_meter,
                &mut self.wl_storage.write_log,
                &self.wl_storage.storage,
                &mut self.vp_wasm_cache,
                &mut self.tx_wasm_cache,
            )
            .map_err(Error::TxApply)
            {
                Ok(result) => {
                    if result.is_accepted() {
                        tracing::trace!(
                            "all VPs accepted transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result
                        );
                        stats.increment_successful_txs();
                        self.wl_storage.commit_tx();
                        if !tx_event.contains_key("code") {
                            tx_event["code"] = ErrorCodes::Ok.into();
                            self.wl_storage
                                .storage
                                .block
                                .results
                                .accept(tx_index);
                        }
                        if let Some(ibc_event) = &result.ibc_event {
                            // Add the IBC event besides the tx_event
                            let event = Event::from(ibc_event.clone());
                            response.events.push(event);
                        }
                        match serde_json::to_string(
                            &result.initialized_accounts,
                        ) {
                            Ok(initialized_accounts) => {
                                tx_event["initialized_accounts"] =
                                    initialized_accounts;
                            }
                            Err(err) => {
                                tracing::error!(
                                    "Failed to serialize the initialized \
                                     accounts: {}",
                                    err
                                );
                            }
                        }
                    } else {
                        tracing::trace!(
                            "some VPs rejected transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result.vps_result.rejected_vps
                        );
                        stats.increment_rejected_txs();
                        self.wl_storage.drop_tx();
                        tx_event["code"] = ErrorCodes::InvalidTx.into();
                    }
                    tx_event["gas_used"] = result.gas_used.to_string();
                    tx_event["info"] = result.to_string();
                }
                Err(msg) => {
                    tracing::info!(
                        "Transaction {} failed with: {}",
                        tx_event["hash"],
                        msg
                    );
                    stats.increment_errored_txs();

                    // If transaction type is Decrypted and failed because of
                    // out of gas, remove its hash from storage to allow
                    // rewrapping it
                    if let Some(hash) = tx_unsigned_hash {
                        if let Error::TxApply(protocol::Error::GasError(namada::ledger::gas::Error::TransactionGasExceededError)) =
                            msg
                        {
                            let tx_hash_key =
                                replay_protection::get_tx_hash_key(&hash);
                            self.wl_storage
                                .storage
                                .delete(&tx_hash_key)
                                .expect(
                                "Error while deleting tx hash key from storage",
                            );
                        }
                    }

                    self.wl_storage.drop_tx();
                    tx_event["gas_used"] = self
                        .gas_meter
                        .get_current_transaction_gas()
                        .to_string();
                    tx_event["info"] = msg.to_string();
                    tx_event["code"] = ErrorCodes::WasmRuntimeError.into();
                }
            }
            response.events.push(tx_event);
        }

        stats.set_tx_cache_size(
            self.tx_wasm_cache.get_size(),
            self.tx_wasm_cache.get_cache_size(),
        );
        stats.set_vp_cache_size(
            self.vp_wasm_cache.get_size(),
            self.vp_wasm_cache.get_cache_size(),
        );

        tracing::info!("{}", stats);
        tracing::info!("{}", stats.format_tx_executed());

        if new_epoch {
            self.update_epoch(&mut response);
        }

        let _ = self
            .gas_meter
            .finalize_transaction()
            .map_err(|_| Error::GasOverflow)?;

        self.event_log_mut().log_events(response.events.clone());

        Ok(response)
    }

    /// Sets the metadata necessary for a new block, including
    /// the hash, height, validator changes, and evidence of
    /// byzantine behavior. Applies slashes if necessary.
    /// Returns a bool indicating if a new epoch began and
    /// the height of the new block.
    fn update_state(
        &mut self,
        header: Header,
        hash: BlockHash,
        byzantine_validators: Vec<Evidence>,
    ) -> (BlockHeight, bool) {
        let height = self.wl_storage.storage.last_height + 1;

        self.gas_meter.reset();

        self.wl_storage
            .storage
            .begin_block(hash, height)
            .expect("Beginning a block shouldn't fail");

        let header_time = header.time;
        self.wl_storage
            .storage
            .set_header(header)
            .expect("Setting a header shouldn't fail");

        self.byzantine_validators = byzantine_validators;

        let new_epoch = self
            .wl_storage
            .storage
            .update_epoch(height, header_time)
            .expect("Must be able to update epoch");

        self.slash();
        (height, new_epoch)
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let pos_params = self.wl_storage.read_pos_params();
        // TODO ABCI validator updates on block H affects the validator set
        // on block H+2, do we need to update a block earlier?
        self.wl_storage
            .validator_set_update(current_epoch, |update| {
                let (consensus_key, power) = match update {
                    ValidatorSetUpdate::Active(ActiveValidator {
                        consensus_key,
                        bonded_stake,
                    }) => {
                        let power: i64 = into_tm_voting_power(
                            pos_params.tm_votes_per_token,
                            bonded_stake,
                        );
                        (consensus_key, power)
                    }
                    ValidatorSetUpdate::Deactivated(consensus_key) => {
                        // Any validators that have become inactive must
                        // have voting power set to 0 to remove them from
                        // the active set
                        let power = 0_i64;
                        (consensus_key, power)
                    }
                };
                let pub_key = TendermintPublicKey {
                    sum: Some(key_to_tendermint(&consensus_key).unwrap()),
                };
                let pub_key = Some(pub_key);
                let update = ValidatorUpdate { pub_key, power };
                response.validator_updates.push(update);
            });
    }
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx, MIN_FEE};

    use super::*;
    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };

    /// Check that if a wrapper tx was rejected by [`process_proposal`],
    /// check that the correct event is returned. Check that it does
    /// not appear in the queue of txs to be decrypted
    #[test]
    fn test_process_proposal_rejected_wrapper_tx() {
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_wrappers = vec![];

        // Add unshielded balance for fee paymenty
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        // create some wrapper txs
        for i in 1u64..5 {
            let raw_tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
                shell.chain_id.clone(),
                None,
            );
            let wrapper = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            let tx = wrapper
                .sign(&keypair, shell.chain_id.clone(), None)
                .expect("Test failed");
            if i > 1 {
                processed_txs.push(ProcessedTx {
                    tx: tx.to_bytes(),
                    result: TxResult {
                        code: u32::try_from(i.rem_euclid(2))
                            .expect("Test failed"),
                        info: "".into(),
                    },
                });
            } else {
                shell.enqueue_tx(wrapper.clone());
            }

            if i != 3 {
                valid_wrappers.push(wrapper)
            }
        }

        // check that the correct events were created
        for (index, event) in shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs.clone(),
                ..Default::default()
            })
            .expect("Test failed")
            .iter()
            .enumerate()
        {
            assert_eq!(event.event_type.to_string(), String::from("accepted"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &index.rem_euclid(2).to_string());
        }
        // verify that the queue of wrapper txs to be processed is correct
        let mut valid_tx = valid_wrappers.iter();
        let mut counter = 0;
        for wrapper in shell.iter_tx_queue() {
            // we cannot easily implement the PartialEq trait for WrapperTx
            // so we check the hashes of the inner txs for equality
            assert_eq!(
                wrapper.tx.tx_hash,
                valid_tx.next().expect("Test failed").tx_hash
            );
            counter += 1;
        }
        assert_eq!(counter, 3);
    }

    /// Check that if a decrypted tx was rejected by [`process_proposal`],
    /// check that the correct event is returned. Check that it is still
    /// removed from the queue of txs to be included in the next block
    /// proposal
    #[test]
    fn test_process_proposal_rejected_decrypted_tx() {
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let raw_tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some(String::from("transaction data").as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            0.into(),
            raw_tx.clone(),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );

        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                tx: raw_tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }))
            .to_bytes(),
            result: TxResult {
                code: ErrorCodes::InvalidTx.into(),
                info: "".into(),
            },
        };
        shell.enqueue_tx(wrapper);

        // check that the decrypted tx was not applied
        for event in shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
        {
            assert_eq!(event.event_type.to_string(), String::from("applied"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &String::from(ErrorCodes::InvalidTx));
        }
        // check that the corresponding wrapper tx was removed from the queue
        assert!(shell.wl_storage.storage.tx_queue.is_empty());
    }

    /// Test that if a tx is undecryptable, it is applied
    /// but the tx result contains the appropriate error code.
    #[test]
    fn test_undecryptable_returns_error_code() {
        let (mut shell, _) = setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let pubkey = EncryptionKey::default();
        // not valid tx bytes
        let tx = "garbage data".as_bytes().to_owned();
        let inner_tx =
            namada::types::transaction::encrypted::EncryptedTx::encrypt(
                &tx, pubkey,
            );
        let wrapper = WrapperTx {
            fee: Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            pk: keypair.ref_to(),
            gas_limit: 0.into(),
            inner_tx,
            tx_hash: hash_tx(&tx),
            #[cfg(not(feature = "mainnet"))]
            pow_solution: None,
        };
        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
                wrapper.clone(),
            )))
            .to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };

        shell.enqueue_tx(wrapper);

        // check that correct error message is returned
        for event in shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
        {
            assert_eq!(event.event_type.to_string(), String::from("applied"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &String::from(ErrorCodes::Undecryptable));
            let log = event.attributes.get("log").expect("Test failed");
            assert!(log.contains("Transaction could not be decrypted."))
        }
        // check that the corresponding wrapper tx was removed from the queue
        assert!(shell.wl_storage.storage.tx_queue.is_empty());
    }

    /// Test that the wrapper txs are queued in the order they
    /// are received from the block. Tests that the previously
    /// decrypted txs are de-queued.
    #[test]
    fn test_mixed_txs_queued_in_correct_order() {
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_txs = vec![];

        // Add unshielded balance for fee payment
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        // create two decrypted txs
        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_no_op.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        for i in 0..2 {
            let raw_tx = Tx::new(
                tx_code.clone(),
                Some(
                    format!("Decrypted transaction data: {}", i)
                        .as_bytes()
                        .to_owned(),
                ),
                shell.chain_id.clone(),
                None,
            );
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            shell.enqueue_tx(wrapper_tx);
            processed_txs.push(ProcessedTx {
                tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                    tx: raw_tx,
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: false,
                }))
                .to_bytes(),
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "".into(),
                },
            });
        }
        // create two wrapper txs
        for i in 0..2 {
            let raw_tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(
                    format!("Encrypted transaction data: {}", i)
                        .as_bytes()
                        .to_owned(),
                ),
                shell.chain_id.clone(),
                None,
            );
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            let wrapper = wrapper_tx
                .sign(&keypair, shell.chain_id.clone(), None)
                .expect("Test failed");
            valid_txs.push(wrapper_tx);
            processed_txs.push(ProcessedTx {
                tx: wrapper.to_bytes(),
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "".into(),
                },
            });
        }
        // Put the wrapper txs in front of the decrypted txs
        processed_txs.rotate_left(2);
        // check that the correct events were created
        for (index, event) in shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed")
            .iter()
            .enumerate()
        {
            if index < 2 {
                // these should be accepted wrapper txs
                assert_eq!(
                    event.event_type.to_string(),
                    String::from("accepted")
                );
                let code =
                    event.attributes.get("code").expect("Test failed").as_str();
                assert_eq!(code, String::from(ErrorCodes::Ok).as_str());
            } else {
                // these should be accepted decrypted txs
                assert_eq!(
                    event.event_type.to_string(),
                    String::from("applied")
                );
                let code =
                    event.attributes.get("code").expect("Test failed").as_str();
                assert_eq!(code, String::from(ErrorCodes::Ok).as_str());
            }
        }

        // check that the applied decrypted txs were dequeued and the
        // accepted wrappers were enqueued in correct order
        let mut txs = valid_txs.iter();

        let mut counter = 0;
        for wrapper in shell.iter_tx_queue() {
            assert_eq!(
                wrapper.tx.tx_hash,
                txs.next().expect("Test failed").tx_hash
            );
            counter += 1;
        }
        assert_eq!(counter, 2);
    }

    /// Test that if a decrypted transaction fails because of out-of-gas, its
    /// hash is removed from storage to allow rewrapping it
    #[test]
    fn test_remove_tx_hash() {
        let (mut shell, _) = setup();
        let keypair = gen_keypair();

        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_no_op.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        let raw_tx = Tx::new(
            tx_code,
            Some("Encrypted transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper_tx = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            0.into(),
            raw_tx.clone(),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );

        // Write inner hash in storage
        let inner_hash_key =
            replay_protection::get_tx_hash_key(&wrapper_tx.tx_hash);
        shell
            .wl_storage
            .storage
            .write(&inner_hash_key, vec![])
            .expect("Test failed");

        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                tx: raw_tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }))
            .to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };
        shell.enqueue_tx(wrapper_tx);

        let _event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // FIXME: uncomment when proper gas metering is in place
        // // Check inner tx hash has been removed from storage
        // assert_eq!(event.event_type.to_string(), String::from("applied"));
        // let code = event.attributes.get("code").expect("Test
        // failed").as_str(); assert_eq!(code,
        // String::from(ErrorCodes::WasmRuntimeError).as_str());

        // assert!(
        //     !shell
        //         .storage
        //         .has_key(&inner_hash_key)
        //         .expect("Test failed")
        //         .0
        // )
    }
}

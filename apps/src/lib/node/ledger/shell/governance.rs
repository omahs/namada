use namada::core::ledger::slash_fund::ADDRESS as slash_fund_address;
use namada::ledger::events::EventType;
use namada::ledger::governance::{
    storage as gov_storage, ADDRESS as gov_address,
};
use namada::ledger::native_vp::governance::utils::{
    compute_tally, get_proposal_votes, ProposalEvent,
};
use namada::ledger::protocol;
use namada::ledger::storage::types::encode;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::types::address::Address;
use namada::types::governance::TallyResult;
use namada::types::storage::Epoch;
use namada::types::token;

use super::*;

#[derive(Default)]
pub struct ProposalsResult {
    passed: Vec<u64>,
    rejected: Vec<u64>,
}

pub fn execute_governance_proposals<D, H>(
    shell: &mut Shell<D, H>,
    response: &mut shim::response::FinalizeBlock,
) -> Result<ProposalsResult>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    let mut proposals_result = ProposalsResult::default();

    for id in std::mem::take(&mut shell.proposal_data) {
        let proposal_funds_key = gov_storage::get_funds_key(id);
        let proposal_end_epoch_key = gov_storage::get_voting_end_epoch_key(id);

        let funds = shell
            .read_storage_key::<token::Amount>(&proposal_funds_key)
            .ok_or_else(|| {
                Error::BadProposal(id, "Invalid proposal funds.".to_string())
            })?;
        let proposal_end_epoch = shell
            .read_storage_key::<Epoch>(&proposal_end_epoch_key)
            .ok_or_else(|| {
                Error::BadProposal(
                    id,
                    "Invalid proposal end_epoch.".to_string(),
                )
            })?;

        let votes =
            get_proposal_votes(&shell.wl_storage, proposal_end_epoch, id);
        let is_accepted = votes.and_then(|votes| {
            compute_tally(&shell.wl_storage, proposal_end_epoch, votes)
        });

        let transfer_address = match is_accepted {
            Ok(true) => {
                let proposal_author_key = gov_storage::get_author_key(id);
                let proposal_author = shell
                    .read_storage_key::<Address>(&proposal_author_key)
                    .ok_or_else(|| {
                        Error::BadProposal(
                            id,
                            "Invalid proposal author.".to_string(),
                        )
                    })?;

                let proposal_code_key = gov_storage::get_proposal_code_key(id);
                let proposal_code =
                    shell.read_storage_key_bytes(&proposal_code_key);
                match proposal_code {
                    Some(proposal_code) => {
                        let tx = Tx::new(
                            proposal_code,
                            Some(encode(&id)),
                            shell.chain_id.clone(),
                            None,
                        );
                        let tx_type =
                            TxType::Decrypted(DecryptedTx::Decrypted {
                                tx,
                                #[cfg(not(feature = "mainnet"))]
                                has_valid_pow: false,
                            });
                        let pending_execution_key =
                            gov_storage::get_proposal_execution_key(id);
                        shell
                            .wl_storage
                            .storage
                            .write(&pending_execution_key, "")
                            .expect("Should be able to write to storage.");
                        let tx_result = protocol::apply_tx(
                            tx_type,
                            0, /*  this is used to compute the fee
                                * based on the code size. We dont
                                * need it here. */
                            TxIndex::default(),
                            &mut BlockGasMeter::default(),
                            &mut shell.wl_storage.write_log,
                            &shell.wl_storage.storage,
                            &mut shell.vp_wasm_cache,
                            &mut shell.tx_wasm_cache,
                        );
                        shell
                            .wl_storage
                            .storage
                            .delete(&pending_execution_key)
                            .expect("Should be able to delete the storage.");
                        match tx_result {
                            Ok(tx_result) => {
                                if tx_result.is_accepted() {
                                    shell.wl_storage.write_log.commit_tx();
                                    let proposal_event: Event =
                                        ProposalEvent::new(
                                            EventType::Proposal.to_string(),
                                            TallyResult::Passed,
                                            id,
                                            true,
                                            true,
                                        )
                                        .into();
                                    response.events.push(proposal_event);
                                    proposals_result.passed.push(id);

                                    proposal_author
                                } else {
                                    shell.wl_storage.write_log.drop_tx();
                                    let proposal_event: Event =
                                        ProposalEvent::new(
                                            EventType::Proposal.to_string(),
                                            TallyResult::Passed,
                                            id,
                                            true,
                                            false,
                                        )
                                        .into();
                                    response.events.push(proposal_event);
                                    proposals_result.rejected.push(id);

                                    slash_fund_address
                                }
                            }
                            Err(_e) => {
                                shell.wl_storage.write_log.drop_tx();
                                let proposal_event: Event = ProposalEvent::new(
                                    EventType::Proposal.to_string(),
                                    TallyResult::Passed,
                                    id,
                                    true,
                                    false,
                                )
                                .into();
                                response.events.push(proposal_event);
                                proposals_result.rejected.push(id);

                                slash_fund_address
                            }
                        }
                    }
                    None => {
                        let proposal_event: Event = ProposalEvent::new(
                            EventType::Proposal.to_string(),
                            TallyResult::Passed,
                            id,
                            false,
                            false,
                        )
                        .into();
                        response.events.push(proposal_event);
                        proposals_result.passed.push(id);

                        proposal_author
                    }
                }
            }
            Ok(false) => {
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Rejected,
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);
                proposals_result.rejected.push(id);

                slash_fund_address
            }
            Err(err) => {
                tracing::error!(
                    "Unexpectedly failed to tally proposal ID {id} with error \
                     {err}"
                );
                let proposal_event: Event = ProposalEvent::new(
                    EventType::Proposal.to_string(),
                    TallyResult::Failed,
                    id,
                    false,
                    false,
                )
                .into();
                response.events.push(proposal_event);

                slash_fund_address
            }
        };

        let native_token = shell.wl_storage.storage.native_token.clone();
        // transfer proposal locked funds
        shell.wl_storage.transfer(
            &native_token,
            funds,
            &gov_address,
            &transfer_address,
        );
    }

    Ok(proposals_result)
}

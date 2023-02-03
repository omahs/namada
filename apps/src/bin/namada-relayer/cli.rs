//! Namada relayer CLI.

use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::cmds;
use namada_apps::client::eth_bridge::{bridge_pool, validator_set};

pub async fn main() -> Result<()> {
    let (cmd, ctx) = cli::namada_relayer_cli()?;
    match cmd {
        cmds::NamadaRelayer::EthBridgePool(sub) => match sub {
            cmds::EthBridgePool::ConstructProof(args) => {
                bridge_pool::construct_bridge_pool_proof(ctx, args).await;
            }
            cmds::EthBridgePool::QueryPool(query) => {
                bridge_pool::query_bridge_pool(query).await;
            }
            cmds::EthBridgePool::QuerySigned(query) => {
                bridge_pool::query_signed_bridge_pool(query).await;
            }
            cmds::EthBridgePool::QueryRelays(query) => {
                bridge_pool::query_relay_progress(query).await;
            }
        },
        cmds::NamadaRelayer::ValidatorSet(sub) => match sub {
            cmds::ValidatorSet::ActiveValidatorSet(args) => {
                validator_set::query_validator_set_args(args).await;
            }
            cmds::ValidatorSet::ValidatorSetProof(args) => {
                validator_set::query_validator_set_update_proof(args).await;
            }
        },
    }
    Ok(())
}

use std::collections::{HashMap, HashSet};

use namada_core::ledger::storage_api::collections::lazy_map;
use namada_core::ledger::storage_api::OptionExt;
use namada_proof_of_stake::types::{BondId, SlashNew, WeightedValidatorNew};
use namada_proof_of_stake::{
    self, active_validator_set_handle, bond_amount_new, bond_handle,
    find_delegation_validators, find_delegations,
    inactive_validator_set_handle, read_all_validator_addresses,
    read_pos_params, read_total_stake, read_validator_stake, unbond_handle,
    validator_slashes_handle,
};

use crate::ledger::queries::types::RequestCtx;
use crate::ledger::storage::{DBIter, StorageHasher, DB};
use crate::ledger::{pos, storage_api};
use crate::types::address::Address;
use crate::types::storage::Epoch;
use crate::types::token;

type AmountPair = (token::Amount, token::Amount);

// PoS validity predicate queries
router! {POS,
    ( "validator" ) = {
        ( "is_validator" / [addr: Address] ) -> bool = is_validator,

        ( "addresses" / [epoch: opt Epoch] )
            -> HashSet<Address> = validator_addresses,

        ( "stake" / [validator: Address] / [epoch: opt Epoch] )
            -> Option<token::Amount> = validator_stake,

        ( "slashes" / [validator: Address] )
            -> Vec<SlashNew> = validator_slashes,
    },

    ( "validator_set" ) = {
        // TODO: rename to "consensus"
        ( "active" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidatorNew> = active_validator_set,

        // TODO: rename to "below_capacity"
        ( "inactive" / [epoch: opt Epoch] )
            -> HashSet<WeightedValidatorNew> = inactive_validator_set,

        // TODO: add "below_threshold"
    },

    ( "total_stake" / [epoch: opt Epoch] )
        -> token::Amount = total_stake,

    ( "delegations" / [owner: Address] )
        -> HashSet<Address> = delegation_validators,

    ( "bond_deltas" / [source: Address] / [validator: Address] )
        -> HashMap<Epoch, token::Change> = bond_deltas,

    ( "bond" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = bond_new,

    ( "bond_with_slashing" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> AmountPair = bond_with_slashing,

    ( "unbond" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_new,

    ( "unbond_with_slashing" / [source: Address] / [validator: Address] )
        -> HashMap<(Epoch, Epoch), token::Amount> = unbond_with_slashing,

    ( "withdrawable_tokens" / [source: Address] / [validator: Address] / [epoch: opt Epoch] )
        -> token::Amount = withdrawable_tokens,

}

// Handlers that implement the functions via `trait StorageRead`:

/// Find if the given address belongs to a validator account.
fn is_validator<D, H>(
    ctx: RequestCtx<'_, D, H>,
    addr: Address,
) -> storage_api::Result<bool>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = namada_proof_of_stake::read_pos_params(ctx.wl_storage)?;
    namada_proof_of_stake::is_validator(
        ctx.wl_storage,
        &addr,
        &params,
        ctx.wl_storage.storage.block.epoch,
    )
}

/// Get all the validator known addresses. These validators may be in any state,
/// e.g. active, inactive or jailed.
fn validator_addresses<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    read_all_validator_addresses(ctx.wl_storage, epoch)
}

/// Get the total stake of a validator at the given epoch or current when
/// `None`. The total stake is a sum of validator's self-bonds and delegations
/// to their address.
/// Returns `None` when the given address is not a validator address. For a
/// validator with `0` stake, this returns `Ok(token::Amount::default())`.
fn validator_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<Option<token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    read_validator_stake(ctx.wl_storage, &params, &validator, epoch)
}

/// Get all the validator in the active set with their bonded stake.
fn active_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    active_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        bonded_stake,
                        address,
                    }
                },
            )
        })
        .collect()
}

/// Get all the validator in the inactive set with their bonded stake.
fn inactive_validator_set<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashSet<WeightedValidatorNew>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    inactive_validator_set_handle()
        .at(&epoch)
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: bonded_stake,
                        nested_sub_key: _position,
                    },
                    address,
                )| {
                    WeightedValidatorNew {
                        bonded_stake: bonded_stake.into(),
                        address,
                    }
                },
            )
        })
        .collect()
}

/// Get the total stake in PoS system at the given epoch or current when `None`.
fn total_stake<D, H>(
    ctx: RequestCtx<'_, D, H>,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    read_total_stake(ctx.wl_storage, &params, epoch)
}

fn bond_deltas<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<Epoch, token::Change>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    bond_handle(&source, &validator).to_hashmap(ctx.wl_storage)
}

fn bond_new<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;

    let handle = bond_handle(&source, &validator);
    handle
        .get_sum(ctx.wl_storage, epoch, &params)?
        .map(token::Amount::from_change)
        .ok_or_err_msg("Cannot find bond")
}

fn bond_with_slashing<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<AmountPair>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    let params = read_pos_params(ctx.wl_storage)?;
    let bond_id = BondId { source, validator };

    bond_amount_new(ctx.wl_storage, &params, &bond_id, epoch)
}

fn unbond_new<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = read_pos_params(ctx.wl_storage)?;

    let handle = unbond_handle(&source, &validator);
    let unbonds = handle
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: withdraw_epoch,
                        nested_sub_key: lazy_map::SubKey::Data(bond_epoch),
                    },
                    amount,
                )| ((bond_epoch, withdraw_epoch), amount),
            )
        })
        .collect();
    unbonds
}

fn unbond_with_slashing<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
) -> storage_api::Result<HashMap<(Epoch, Epoch), token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let params = read_pos_params(ctx.wl_storage)?;

    // TODO slashes
    let handle = unbond_handle(&source, &validator);
    let unbonds = handle
        .iter(ctx.wl_storage)?
        .map(|next_result| {
            next_result.map(
                |(
                    lazy_map::NestedSubKey::Data {
                        key: withdraw_epoch,
                        nested_sub_key: lazy_map::SubKey::Data(bond_epoch),
                    },
                    amount,
                )| ((bond_epoch, withdraw_epoch), amount),
            )
        })
        .collect();
    unbonds
}

fn withdrawable_tokens<D, H>(
    ctx: RequestCtx<'_, D, H>,
    source: Address,
    validator: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<token::Amount>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

    let handle = unbond_handle(&source, &validator);
    let mut total = token::Amount::default();
    for result in handle.iter(ctx.wl_storage)? {
        let (
            lazy_map::NestedSubKey::Data {
                key: end,
                nested_sub_key: lazy_map::SubKey::Data(_start),
            },
            amount,
        ) = result?;
        if end <= epoch {
            total += amount;
        }
    }
    Ok(total)
}

// /// Get the total bond amount for the given bond ID (this may be delegation
// or /// self-bond when `owner == validator`) at the given epoch, or the
// current /// epoch when `None`.
// fn bond_amount<D, H>(
//     ctx: RequestCtx<'_, D, H>,
//     owner: Address,
//     validator: Address,
//     epoch: Option<Epoch>,
// ) -> storage_api::Result<token::Amount>
// where
//     D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
//     H: 'static + StorageHasher + Sync,
// {
//     let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);

//     let bond_id = BondId {
//         source: owner,
//         validator,
//     };
//     // TODO update
//     ctx.wl_storage.bond_amount(&bond_id, epoch)
// }

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegation_validators<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
) -> storage_api::Result<HashSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    find_delegation_validators(ctx.wl_storage, &owner)
}

/// Find all the validator addresses to whom the given `owner` address has
/// some delegation in any epoch
fn delegations<D, H>(
    ctx: RequestCtx<'_, D, H>,
    owner: Address,
    epoch: Option<Epoch>,
) -> storage_api::Result<HashMap<Address, token::Amount>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let epoch = epoch.unwrap_or(ctx.wl_storage.storage.last_epoch);
    find_delegations(ctx.wl_storage, &owner, &epoch)
}

/// Validator slashes
fn validator_slashes<D, H>(
    ctx: RequestCtx<'_, D, H>,
    validator: Address,
) -> storage_api::Result<Vec<SlashNew>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let slash_handle = validator_slashes_handle(&validator);
    slash_handle.iter(ctx.wl_storage)?.collect()
}

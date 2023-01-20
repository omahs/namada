//! Token storage_api functions

use super::{StorageRead, StorageWrite};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::token;

/// Read the balance of a given token and owner.
pub fn read_balance<S>(
    storage: &mut S,
    token: &Address,
    owner: &Address,
) -> storage_api::Result<token::Amount>
where
    S: StorageRead + StorageWrite,
{
    let key = token::balance_key(token, owner);
    let balance = storage.read::<token::Amount>(&key)?.unwrap_or_default();
    Ok(balance)
}

/// Credit tokens to an account, to be used only during genesis
pub fn credit_tokens<S>(
    storage: &mut S,
    token: &Address,
    target: &Address,
    amount: token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let key = token::balance_key(token, target);
    let new_balance = read_balance(storage, token, target)? + amount;
    storage.write(&key, new_balance)
}

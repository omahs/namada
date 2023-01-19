//! Token storage_api functions

use super::{StorageRead, StorageWrite};
use crate::ledger::storage_api;
use crate::types::address::Address;
use crate::types::token;

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
    let new_balance = match storage.read::<token::Amount>(&key)? {
        Some(balance) => balance + amount,
        None => amount,
    };
    storage.write(&key, new_balance)
}

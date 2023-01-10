//! Storage with write log.

use std::iter::Peekable;

use crate::ledger::storage::write_log::{self, WriteLog};
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::ledger::storage_api::{ResultExt, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::storage;

/// Storage with write log that allows to implement prefix iterator that works
/// with changes not yet committed to the DB.
#[derive(Debug)]
pub struct WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Write log
    pub write_log: WriteLog,
    /// Storage provides access to DB
    pub storage: Storage<D, H>,
}

/// Storage with write log for transactions (`vm::host_env::TxCtx`), which can
/// only have mutable access to the `write_log` and read-only to the `storage`.
#[derive(Debug)]
pub struct TxWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a mut WriteLog,
    /// Read-only storage access to DB.
    pub storage: &'a Storage<D, H>,
}

/// Storage with write log for VPs (`vm::host_env::VpCtx`), which can
/// only have read-only access to the `write_log` and the `storage`.
#[derive(Debug)]
pub struct VpWlStorage<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a WriteLog,
    /// Read-only storage access to DB.
    pub storage: &'a Storage<D, H>,
}

impl<D, H> WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Combine storage with write-log
    pub fn new(write_log: WriteLog, storage: Storage<D, H>) -> Self {
        Self { write_log, storage }
    }
}

impl<D, H> WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher,
{
    /// Commit the genesis state to DB. This should only be used before any
    /// blocks are produced.
    pub fn commit_genesis(&mut self) -> storage_api::Result<()> {
        self.write_log
            .commit_genesis(&mut self.storage)
            .into_storage_result()
    }

    /// Commit the current transaction's write log to the block when it's
    /// accepted by all the triggered validity predicates. Starts a new
    /// transaction write log.
    pub fn commit_tx(&mut self) {
        self.write_log.commit_tx()
    }

    /// Commit the current block's write log to the storage and commit the block
    /// to DB. Starts a new block write log.
    pub fn commit_block(&mut self) -> storage_api::Result<()> {
        self.write_log
            .commit_block(&mut self.storage)
            .into_storage_result()?;
        self.storage.commit_block().into_storage_result()
    }
}

/// Prefix iterator for [`WlStorage`].
#[derive(Debug)]
pub struct PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    /// Peekable storage iterator
    storage_iter: Peekable<<D as DBIter<'iter>>::PrefixIter>,
    /// Peekable write log iterator
    write_log_iter: Peekable<write_log::PrefixIter>,
}

impl<'iter, D> Iterator for PrefixIter<'iter, D>
where
    D: DB + DBIter<'iter>,
{
    type Item = (String, Vec<u8>, u64);

    fn next(&mut self) -> Option<Self::Item> {
        enum Next {
            ReturnWl { advance_storage: bool },
            ReturnStorage,
        }
        loop {
            let what: Next;
            {
                let storage_peeked = self.storage_iter.peek();
                let wl_peeked = self.write_log_iter.peek();
                match (storage_peeked, wl_peeked) {
                    (None, None) => return None,
                    (None, Some(_)) => {
                        what = Next::ReturnWl {
                            advance_storage: false,
                        };
                    }
                    (Some(_), None) => {
                        what = Next::ReturnStorage;
                    }
                    (Some((storage_key, _, _)), Some((wl_key, _))) => {
                        let wl_key = wl_key.to_string();
                        if &wl_key <= storage_key {
                            what = Next::ReturnWl {
                                advance_storage: &wl_key == storage_key,
                            };
                        } else {
                            what = Next::ReturnStorage;
                        }
                    }
                }
            }
            match what {
                Next::ReturnWl { advance_storage } => {
                    if advance_storage {
                        let _ = self.storage_iter.next();
                    }

                    if let Some((key, modification)) =
                        self.write_log_iter.next()
                    {
                        match modification {
                            write_log::StorageModification::Write { value }
                            | write_log::StorageModification::Temp { value } => {
                                let gas = value.len() as u64;
                                return Some((key.to_string(), value, gas));
                            }
                            write_log::StorageModification::InitAccount {
                                vp,
                            } => {
                                let gas = vp.len() as u64;
                                return Some((key.to_string(), vp, gas));
                            }
                            write_log::StorageModification::Delete => {
                                continue;
                            }
                        }
                    }
                }
                Next::ReturnStorage => {
                    if let Some(next) = self.storage_iter.next() {
                        return Some(next);
                    }
                }
            }
        }
    }
}

impl<D, H> StorageRead for WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type PrefixIter<'iter> = PrefixIter<'iter, D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Vec<u8>>> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                Ok(Some(value.clone()))
            }
            Some(&write_log::StorageModification::Delete) => Ok(None),
            Some(&write_log::StorageModification::InitAccount {
                ref vp,
                ..
            }) => Ok(Some(vp.clone())),
            Some(&write_log::StorageModification::Temp { ref value }) => {
                Ok(Some(value.clone()))
            }
            None => {
                // when not found in write log, try to read from the storage
                self.storage.db.read_subspace_val(key).into_storage_result()
            }
        }
    }

    fn has_key(&self, key: &storage::Key) -> storage_api::Result<bool> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { .. })
            | Some(&write_log::StorageModification::InitAccount { .. })
            | Some(&write_log::StorageModification::Temp { .. }) => Ok(true),
            Some(&write_log::StorageModification::Delete) => {
                // the given key has been deleted
                Ok(false)
            }
            None => {
                // when not found in write log, try to check the storage
                self.storage.block.tree.has_key(key).into_storage_result()
            }
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> storage_api::Result<Self::PrefixIter<'iter>> {
        let storage_iter = self.storage.db.iter_prefix(prefix).peekable();
        let write_log_iter = self.write_log.iter_prefix(prefix).peekable();
        Ok(PrefixIter {
            storage_iter,
            write_log_iter,
        })
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> storage_api::Result<Option<(String, Vec<u8>)>> {
        Ok(iter.next().map(|(key, val, _gas)| (key, val)))
    }

    fn get_chain_id(&self) -> std::result::Result<String, storage_api::Error> {
        Ok(self.storage.chain_id.to_string())
    }

    fn get_block_height(
        &self,
    ) -> std::result::Result<storage::BlockHeight, storage_api::Error> {
        Ok(self.storage.block.height)
    }

    fn get_block_hash(
        &self,
    ) -> std::result::Result<storage::BlockHash, storage_api::Error> {
        Ok(self.storage.block.hash.clone())
    }

    fn get_block_epoch(
        &self,
    ) -> std::result::Result<storage::Epoch, storage_api::Error> {
        Ok(self.storage.block.epoch)
    }

    fn get_tx_index(
        &self,
    ) -> std::result::Result<storage::TxIndex, storage_api::Error> {
        Ok(self.storage.tx_index)
    }

    fn get_native_token(&self) -> storage_api::Result<Address> {
        Ok(self.storage.native_token.clone())
    }
}

// TODO re-use with WlStorage
impl<D, H> StorageRead for TxWlStorage<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type PrefixIter<'iter> = PrefixIter<'iter, D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Vec<u8>>> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                Ok(Some(value.clone()))
            }
            Some(&write_log::StorageModification::Delete) => Ok(None),
            Some(&write_log::StorageModification::InitAccount {
                ref vp,
                ..
            }) => Ok(Some(vp.clone())),
            Some(&write_log::StorageModification::Temp { ref value }) => {
                Ok(Some(value.clone()))
            }
            None => {
                // when not found in write log, try to read from the storage
                self.storage.db.read_subspace_val(key).into_storage_result()
            }
        }
    }

    fn has_key(&self, key: &storage::Key) -> storage_api::Result<bool> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { .. })
            | Some(&write_log::StorageModification::InitAccount { .. })
            | Some(&write_log::StorageModification::Temp { .. }) => Ok(true),
            Some(&write_log::StorageModification::Delete) => {
                // the given key has been deleted
                Ok(false)
            }
            None => {
                // when not found in write log, try to check the storage
                self.storage.block.tree.has_key(key).into_storage_result()
            }
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> storage_api::Result<Self::PrefixIter<'iter>> {
        let storage_iter = self.storage.db.iter_prefix(prefix).peekable();
        let write_log_iter = self.write_log.iter_prefix(prefix).peekable();
        Ok(PrefixIter {
            storage_iter,
            write_log_iter,
        })
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> storage_api::Result<Option<(String, Vec<u8>)>> {
        Ok(iter.next().map(|(key, val, _gas)| (key, val)))
    }

    fn get_chain_id(&self) -> std::result::Result<String, storage_api::Error> {
        Ok(self.storage.chain_id.to_string())
    }

    fn get_block_height(
        &self,
    ) -> std::result::Result<storage::BlockHeight, storage_api::Error> {
        Ok(self.storage.block.height)
    }

    fn get_block_hash(
        &self,
    ) -> std::result::Result<storage::BlockHash, storage_api::Error> {
        Ok(self.storage.block.hash.clone())
    }

    fn get_block_epoch(
        &self,
    ) -> std::result::Result<storage::Epoch, storage_api::Error> {
        Ok(self.storage.block.epoch)
    }

    fn get_tx_index(
        &self,
    ) -> std::result::Result<storage::TxIndex, storage_api::Error> {
        Ok(self.storage.tx_index)
    }

    fn get_native_token(&self) -> storage_api::Result<Address> {
        Ok(self.storage.native_token.clone())
    }
}

// TODO re-use with WlStorage
impl<D, H> StorageRead for VpWlStorage<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type PrefixIter<'iter> = PrefixIter<'iter, D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> storage_api::Result<Option<Vec<u8>>> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { ref value }) => {
                Ok(Some(value.clone()))
            }
            Some(&write_log::StorageModification::Delete) => Ok(None),
            Some(&write_log::StorageModification::InitAccount {
                ref vp,
                ..
            }) => Ok(Some(vp.clone())),
            Some(&write_log::StorageModification::Temp { ref value }) => {
                Ok(Some(value.clone()))
            }
            None => {
                // when not found in write log, try to read from the storage
                self.storage.db.read_subspace_val(key).into_storage_result()
            }
        }
    }

    fn has_key(&self, key: &storage::Key) -> storage_api::Result<bool> {
        // try to read from the write log first
        let (log_val, _gas) = self.write_log.read(key);
        match log_val {
            Some(&write_log::StorageModification::Write { .. })
            | Some(&write_log::StorageModification::InitAccount { .. })
            | Some(&write_log::StorageModification::Temp { .. }) => Ok(true),
            Some(&write_log::StorageModification::Delete) => {
                // the given key has been deleted
                Ok(false)
            }
            None => {
                // when not found in write log, try to check the storage
                self.storage.block.tree.has_key(key).into_storage_result()
            }
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> storage_api::Result<Self::PrefixIter<'iter>> {
        let storage_iter = self.storage.db.iter_prefix(prefix).peekable();
        let write_log_iter = self.write_log.iter_prefix(prefix).peekable();
        Ok(PrefixIter {
            storage_iter,
            write_log_iter,
        })
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> storage_api::Result<Option<(String, Vec<u8>)>> {
        Ok(iter.next().map(|(key, val, _gas)| (key, val)))
    }

    fn get_chain_id(&self) -> std::result::Result<String, storage_api::Error> {
        Ok(self.storage.chain_id.to_string())
    }

    fn get_block_height(
        &self,
    ) -> std::result::Result<storage::BlockHeight, storage_api::Error> {
        Ok(self.storage.block.height)
    }

    fn get_block_hash(
        &self,
    ) -> std::result::Result<storage::BlockHash, storage_api::Error> {
        Ok(self.storage.block.hash.clone())
    }

    fn get_block_epoch(
        &self,
    ) -> std::result::Result<storage::Epoch, storage_api::Error> {
        Ok(self.storage.block.epoch)
    }

    fn get_tx_index(
        &self,
    ) -> std::result::Result<storage::TxIndex, storage_api::Error> {
        Ok(self.storage.tx_index)
    }

    fn get_native_token(&self) -> storage_api::Result<Address> {
        Ok(self.storage.native_token.clone())
    }
}

impl<D, H> StorageWrite for WlStorage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> storage_api::Result<()> {
        let _ = self
            .write_log
            .write(key, val.as_ref().to_vec())
            .into_storage_result();
        Ok(())
    }

    fn delete(&mut self, key: &storage::Key) -> storage_api::Result<()> {
        let _ = self.write_log.delete(key).into_storage_result();
        Ok(())
    }
}

// TODO re-use with WlStorage
impl<D, H> StorageWrite for TxWlStorage<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn write_bytes(
        &mut self,
        key: &storage::Key,
        val: impl AsRef<[u8]>,
    ) -> storage_api::Result<()> {
        let _ = self
            .write_log
            .write(key, val.as_ref().to_vec())
            .into_storage_result();
        Ok(())
    }

    fn delete(&mut self, key: &storage::Key) -> storage_api::Result<()> {
        let _ = self.write_log.delete(key).into_storage_result();
        Ok(())
    }
}

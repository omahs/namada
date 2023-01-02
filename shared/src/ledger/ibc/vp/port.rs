//! IBC validity predicate for port module
use std::str::FromStr;

use thiserror::Error;

use super::super::storage::{
    capability, capability_index_key, capability_key, is_capability_index_key,
    port_id, port_key, Error as IbcStorageError,
};
use super::{Ibc, StateChange};
use crate::ibc::core::ics05_port::context::PortReader;
use crate::ibc::core::ics05_port::error::Error as Ics05Error;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::ModuleId;
use crate::ledger::native_vp::VpEnv;
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("State change error: {0}")]
    InvalidStateChange(String),
    #[error("Port error: {0}")]
    InvalidPort(String),
    #[error("Capability error: {0}")]
    Capability(String),
    #[error("IBC storage error: {0}")]
    IbcStorage(IbcStorageError),
}

/// IBC port functions result
pub type Result<T> = std::result::Result<T, Error>;
/// ConnectionReader result
type Ics05Result<T> = core::result::Result<T, Ics05Error>;

const MODULE_ID: &str = "ledger";

impl<'a, DB, H, CA> Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub(super) fn validate_port(&self, key: &Key) -> Result<()> {
        let port_id = port_id(key)?;
        match self.get_port_state_change(&port_id)? {
            StateChange::Created => {
                match self.authenticated_capability(&port_id) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(Error::InvalidPort(format!(
                        "The port is not authenticated: ID {}, {}",
                        port_id, e
                    ))),
                }
            }
            _ => Err(Error::InvalidPort(format!(
                "The state change of the port is invalid: Port {}",
                port_id
            ))),
        }
    }

    fn get_port_state_change(&self, port_id: &PortId) -> Result<StateChange> {
        let key = port_key(port_id);
        self.get_state_change(&key)
            .map_err(|e| Error::InvalidStateChange(e.to_string()))
    }

    pub(super) fn validate_capability(&self, key: &Key) -> Result<()> {
        if is_capability_index_key(key) {
            if self.capability_index_pre()? < self.capability_index()? {
                Ok(())
            } else {
                Err(Error::InvalidPort(
                    "The capability index is invalid".to_owned(),
                ))
            }
        } else {
            match self
                .get_state_change(key)
                .map_err(|e| Error::InvalidStateChange(e.to_string()))?
            {
                StateChange::Created => {
                    let expected_cap = capability(key)?;
                    let port_id = self.get_port_by_capability(expected_cap)?;
                    // check the capability has been mapped to the port
                    let cap = self.get_capability_by_port(&port_id)?;
                    if cap == expected_cap {
                        Ok(())
                    } else {
                        Err(Error::Capability(format!(
                            "The capability is not mapped: Port {}",
                            port_id
                        )))
                    }
                }
                _ => Err(Error::InvalidStateChange(format!(
                    "The state change of the capability is invalid: key {}",
                    key
                ))),
            }
        }
    }

    fn capability_index_pre(&self) -> Result<u64> {
        let key = capability_index_key();
        self.read_counter_pre(&key)
            .map_err(|e| Error::Capability(e.to_string()))
    }

    fn capability_index(&self) -> Result<u64> {
        let key = capability_index_key();
        self.read_counter(&key).map_err(|e| {
            Error::InvalidPort(format!(
                "The capability index doesn't exist: {}",
                e
            ))
        })
    }

    pub(super) fn get_port_by_capability(
        &self,
        cap_index: u64,
    ) -> Result<PortId> {
        let key = capability_key(cap_index);
        match self.ctx.read_bytes_post(&key) {
            Ok(Some(value)) => {
                let id = std::str::from_utf8(&value).map_err(|e| {
                    Error::InvalidPort(format!(
                        "Decoding the port ID failed: {}",
                        e
                    ))
                })?;
                PortId::from_str(id).map_err(|e| {
                    Error::InvalidPort(format!(
                        "Decoding the port ID failed: {}",
                        e
                    ))
                })
            }
            Ok(None) => Err(Error::InvalidPort(
                "The capability is not mapped to any port".to_owned(),
            )),
            Err(e) => Err(Error::InvalidPort(format!(
                "Reading the port failed: {}",
                e
            ))),
        }
    }

    pub(super) fn get_capability_by_port(
        &self,
        port_id: &PortId,
    ) -> Result<u64> {
        let key = port_key(port_id);
        match self.ctx.read_bytes_post(&key) {
            Ok(Some(value)) => {
                let index: [u8; 8] = value.try_into().map_err(|_| {
                    Error::Capability(format!(
                        "Decoding the capability index failed: Port {}",
                        port_id
                    ))
                })?;
                Ok(u64::from_be_bytes(index))
            }
            Ok(None) => Err(Error::Capability(format!(
                "No capability for the port: Port {}",
                port_id
            ))),
            Err(e) => Err(Error::Capability(format!(
                "Reading the capability failed: {}",
                e
            ))),
        }
    }
}

impl<'a, DB, H, CA> PortReader for Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    fn lookup_module_by_port(&self, port_id: &PortId) -> Ics05Result<ModuleId> {
        let key = port_key(port_id);
        match self.ctx.read_bytes_post(&key) {
            Ok(Some(value)) => {
                let index: [u8; 8] = value
                    .try_into()
                    .map_err(|_| Ics05Error::implementation_specific())?;
                let _index = u64::from_be_bytes(index);
                // TODO: Routing for other apps
                let module_id = ModuleId::new(MODULE_ID.into())
                    .expect("Creating the module ID shouldn't fail");
                Ok(module_id)
            }
            Ok(None) => Err(Ics05Error::unknown_port(port_id.clone())),
            Err(_) => Err(Ics05Error::implementation_specific()),
        }
    }
}

impl From<IbcStorageError> for Error {
    fn from(err: IbcStorageError) -> Self {
        Self::IbcStorage(err)
    }
}

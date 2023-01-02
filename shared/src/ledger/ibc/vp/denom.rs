//! IBC validity predicate for denom

use thiserror::Error;

use super::Ibc;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ledger::ibc::storage;
use crate::ledger::native_vp::VpEnv;
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::types::ibc::data::{Error as IbcDataError, IbcMessage};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding TX data error: {0}")]
    DecodingTxData(std::io::Error),
    #[error("IBC data error: {0}")]
    InvalidIbcData(IbcDataError),
    #[error("Invalid packet data: {0}")]
    PacketData(String),
    #[error("Denom error: {0}")]
    Denom(String),
}

/// IBC channel functions result
pub type Result<T> = std::result::Result<T, Error>;

impl<'a, DB, H, CA> Ibc<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub(super) fn validate_denom(&self, tx_data: &[u8]) -> Result<()> {
        let ibc_msg = IbcMessage::decode(tx_data)?;
        let msg = ibc_msg.msg_recv_packet()?;
        match serde_json::from_slice::<PacketData>(&msg.packet.data) {
            Ok(data) => {
                let coin = data.token;
                let token_hash = storage::calc_hash(&coin.denom.to_string());
                let denom_key = storage::ibc_denom_key(token_hash);
                match self.ctx.read_bytes_post(&denom_key) {
                    Ok(Some(v)) => match std::str::from_utf8(&v) {
                        Ok(d) if d == coin.denom.to_string() => Ok(()),
                        Ok(d) => Err(Error::Denom(format!(
                            "Mismatch the denom: original {}, denom {}",
                            coin.denom, d
                        ))),
                        Err(e) => Err(Error::Denom(format!(
                            "Decoding the denom failed: key {}, error {}",
                            denom_key, e
                        ))),
                    },
                    _ => Err(Error::Denom(format!(
                        "Looking up the denom failed: Key {}",
                        denom_key
                    ))),
                }
            }
            Err(e) => Err(Error::PacketData(format!(
                "unknown packet data: error {}",
                e
            ))),
        }
    }
}

impl From<IbcDataError> for Error {
    fn from(err: IbcDataError) -> Self {
        Self::InvalidIbcData(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::DecodingTxData(err)
    }
}

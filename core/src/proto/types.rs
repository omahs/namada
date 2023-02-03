use std::convert::{TryFrom, TryInto};
use std::hash::{Hash, Hasher};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::generated::types;
#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
use crate::tendermint_proto::abci::ResponseDeliverTx;
use crate::types::chain::ChainId;
use crate::types::key::*;
use crate::types::time::DateTimeUtc;
#[cfg(feature = "ferveo-tpke")]
use crate::types::token::Transfer;
use crate::types::transaction::hash_tx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::process_tx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::DecryptedTx;
#[cfg(feature = "ferveo-tpke")]
use crate::types::transaction::TxType;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Error decoding an DkgGossipMessage from bytes: {0}")]
    DkgDecodingError(prost::DecodeError),
    #[error("Dkg is empty")]
    NoDkgError,
    #[error("Timestamp is empty")]
    NoTimestampError,
    #[error("Timestamp is invalid: {0}")]
    InvalidTimestamp(prost_types::TimestampOutOfSystemRangeError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SignedTxData {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: common::Signature,
}

/// A generic signed data wrapper for Borsh encode-able data.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Signed<T: BorshSerialize + BorshDeserialize> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sig: common::Signature,
}

impl<T> PartialEq for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.sig == other.sig
    }
}

impl<T> Eq for Signed<T> where
    T: BorshSerialize + BorshDeserialize + Eq + PartialEq
{
}

impl<T> Hash for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.sig.hash(state);
    }
}

impl<T> PartialOrd for Signed<T>
where
    T: BorshSerialize + BorshDeserialize + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<T> Signed<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    /// Initialize a new signed data.
    pub fn new(keypair: &common::SecretKey, data: T) -> Self {
        let to_sign = data
            .try_to_vec()
            .expect("Encoding data for signing shouldn't fail");
        let sig = common::SigScheme::sign(keypair, to_sign);
        Self { data, sig }
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(
        &self,
        pk: &common::PublicKey,
    ) -> std::result::Result<(), VerifySigError> {
        let bytes = self
            .data
            .try_to_vec()
            .expect("Encoding data for verifying signature shouldn't fail");
        common::SigScheme::verify_signature_raw(pk, &bytes, &self.sig)
    }
}

/// A Tx with its code replaced by a hash salted with the Borsh
/// serialized timestamp of the transaction. This structure will almost
/// certainly be smaller than a Tx, yet in the usual cases it contains
/// enough information to confirm that the Tx is as intended and make a
/// non-malleable signature.
#[derive(
    Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema, Hash,
)]
pub struct SigningTx {
    pub code_hash: [u8; 32],
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
    pub chain_id: ChainId,
    pub expiration: Option<DateTimeUtc>,
}

impl SigningTx {
    pub fn hash(&self) -> [u8; 32] {
        let timestamp = Some(self.timestamp.into());
        let expiration = self.expiration.map(|e| e.into());
        let mut bytes = vec![];
        types::Tx {
            code: self.code_hash.to_vec(),
            data: self.data.clone(),
            timestamp,
            chain_id: self.chain_id.as_str().to_owned(),
            expiration,
        }
        .encode(&mut bytes)
        .expect("encoding a transaction failed");
        hash_tx(&bytes).0
    }

    /// Sign a transaction using [`SignedTxData`].
    pub fn sign(self, keypair: &common::SecretKey) -> Self {
        let to_sign = self.hash();
        let sig = common::SigScheme::sign(keypair, to_sign);
        let signed = SignedTxData {
            data: self.data,
            sig,
        }
        .try_to_vec()
        .expect("Encoding transaction data shouldn't fail");
        SigningTx {
            code_hash: self.code_hash,
            data: Some(signed),
            timestamp: self.timestamp,
            chain_id: self.chain_id,
            expiration: self.expiration,
        }
    }

    /// Verify that the transaction has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify_sig(
        &self,
        pk: &common::PublicKey,
        sig: &common::Signature,
    ) -> std::result::Result<(), VerifySigError> {
        // Try to get the transaction data from decoded `SignedTxData`
        let tx_data = self.data.clone().ok_or(VerifySigError::MissingData)?;
        let signed_tx_data = SignedTxData::try_from_slice(&tx_data[..])
            .expect("Decoding transaction data shouldn't fail");
        let data = signed_tx_data.data;
        let tx = SigningTx {
            code_hash: self.code_hash,
            data,
            timestamp: self.timestamp,
            chain_id: self.chain_id.clone(),
            expiration: self.expiration,
        };
        let signed_data = tx.hash();
        common::SigScheme::verify_signature_raw(pk, &signed_data, sig)
    }

    /// Expand this reduced Tx using the supplied code only if the the code
    /// hashes to the stored code hash
    pub fn expand(self, code: Vec<u8>) -> Option<Tx> {
        if hash_tx(&code).0 == self.code_hash {
            Some(Tx {
                code,
                data: self.data,
                timestamp: self.timestamp,
                chain_id: self.chain_id,
                expiration: self.expiration,
            })
        } else {
            None
        }
    }
}

impl From<Tx> for SigningTx {
    fn from(tx: Tx) -> SigningTx {
        SigningTx {
            code_hash: hash_tx(&tx.code).0,
            data: tx.data,
            timestamp: tx.timestamp,
            chain_id: tx.chain_id,
            expiration: tx.expiration,
        }
    }
}

/// A SigningTx but with the full code embedded. This structure will almost
/// certainly be bigger than SigningTxs and contains enough information to
/// execute the transaction.
#[derive(
    Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema, Hash,
)]
pub struct Tx {
    pub code: Vec<u8>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTimeUtc,
    pub chain_id: ChainId,
    pub expiration: Option<DateTimeUtc>,
}

impl TryFrom<&[u8]> for Tx {
    type Error = Error;

    fn try_from(tx_bytes: &[u8]) -> Result<Self> {
        let tx = types::Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        let timestamp = match tx.timestamp {
            Some(t) => t.try_into().map_err(Error::InvalidTimestamp)?,
            None => return Err(Error::NoTimestampError),
        };
        let chain_id = ChainId(tx.chain_id);
        let expiration = match tx.expiration {
            Some(e) => Some(e.try_into().map_err(Error::InvalidTimestamp)?),
            None => None,
        };

        Ok(Tx {
            code: tx.code,
            data: tx.data,
            timestamp,
            chain_id,
            expiration,
        })
    }
}

impl From<Tx> for types::Tx {
    fn from(tx: Tx) -> Self {
        let timestamp = Some(tx.timestamp.into());
        let expiration = tx.expiration.map(|e| e.into());

        types::Tx {
            code: tx.code,
            data: tx.data,
            timestamp,
            chain_id: tx.chain_id.as_str().to_owned(),
            expiration,
        }
    }
}

#[cfg(any(feature = "tendermint", feature = "tendermint-abcipp"))]
impl From<Tx> for ResponseDeliverTx {
    #[cfg(not(feature = "ferveo-tpke"))]
    fn from(_tx: Tx) -> ResponseDeliverTx {
        Default::default()
    }

    /// Annotate the Tx with meta-data based on its contents
    #[cfg(feature = "ferveo-tpke")]
    fn from(tx: Tx) -> ResponseDeliverTx {
        use crate::tendermint_proto::abci::{Event, EventAttribute};

        #[cfg(feature = "ABCI")]
        fn encode_str(x: &str) -> Vec<u8> {
            x.as_bytes().to_vec()
        }
        #[cfg(not(feature = "ABCI"))]
        fn encode_str(x: &str) -> String {
            x.to_string()
        }
        #[cfg(feature = "ABCI")]
        fn encode_string(x: String) -> Vec<u8> {
            x.into_bytes()
        }
        #[cfg(not(feature = "ABCI"))]
        fn encode_string(x: String) -> String {
            x
        }
        match process_tx(tx) {
            Ok(TxType::Decrypted(DecryptedTx::Decrypted {
                tx,
                #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: _,
            })) => {
                let empty_vec = vec![];
                let tx_data = tx.data.as_ref().unwrap_or(&empty_vec);
                let signed =
                    if let Ok(signed) = SignedTxData::try_from_slice(tx_data) {
                        signed
                    } else {
                        return Default::default();
                    };
                if let Ok(transfer) = Transfer::try_from_slice(
                    signed.data.as_ref().unwrap_or(&empty_vec),
                ) {
                    let events = vec![Event {
                        r#type: "transfer".to_string(),
                        attributes: vec![
                            EventAttribute {
                                key: encode_str("source"),
                                value: encode_string(transfer.source.encode()),
                                index: true,
                            },
                            EventAttribute {
                                key: encode_str("target"),
                                value: encode_string(transfer.target.encode()),
                                index: true,
                            },
                            EventAttribute {
                                key: encode_str("token"),
                                value: encode_string(transfer.token.encode()),
                                index: true,
                            },
                            EventAttribute {
                                key: encode_str("amount"),
                                value: encode_string(
                                    transfer.amount.to_string(),
                                ),
                                index: true,
                            },
                        ],
                    }];
                    ResponseDeliverTx {
                        events,
                        info: "Transfer tx".to_string(),
                        ..Default::default()
                    }
                } else {
                    Default::default()
                }
            }
            _ => Default::default(),
        }
    }
}

impl Tx {
    pub fn new(
        code: Vec<u8>,
        data: Option<Vec<u8>>,
        chain_id: ChainId,
        expiration: Option<DateTimeUtc>,
    ) -> Self {
        Tx {
            code,
            data,
            timestamp: DateTimeUtc::now(),
            chain_id,
            expiration,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let tx: types::Tx = self.clone().into();
        tx.encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        SigningTx::from(self.clone()).hash()
    }

    pub fn unsigned_hash(&self) -> [u8; 32] {
        match self.data {
            Some(ref data) => {
                match SignedTxData::try_from_slice(data) {
                    Ok(signed_data) => {
                        // Reconstruct unsigned tx
                        let unsigned_tx = Tx {
                            code: self.code.clone(),
                            data: signed_data.data,
                            timestamp: self.timestamp,
                            chain_id: self.chain_id.clone(),
                            expiration: self.expiration,
                        };
                        unsigned_tx.hash()
                    }
                    Err(_) => {
                        // Unsigned tx
                        self.hash()
                    }
                }
            }
            None => {
                // Unsigned tx
                self.hash()
            }
        }
    }

    pub fn code_hash(&self) -> [u8; 32] {
        SigningTx::from(self.clone()).code_hash
    }

    /// Sign a transaction using [`SignedTxData`].
    pub fn sign(self, keypair: &common::SecretKey) -> Self {
        let code = self.code.clone();
        SigningTx::from(self)
            .sign(keypair)
            .expand(code)
            .expect("code hashes to unexpected value")
    }

    /// Verify that the transaction has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify_sig(
        &self,
        pk: &common::PublicKey,
        sig: &common::Signature,
    ) -> std::result::Result<(), VerifySigError> {
        SigningTx::from(self.clone()).verify_sig(pk, sig)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub struct DkgGossipMessage {
    pub dkg: Dkg,
}

impl TryFrom<&[u8]> for DkgGossipMessage {
    type Error = Error;

    fn try_from(dkg_bytes: &[u8]) -> Result<Self> {
        let message = types::DkgGossipMessage::decode(dkg_bytes)
            .map_err(Error::DkgDecodingError)?;
        match &message.dkg_message {
            Some(types::dkg_gossip_message::DkgMessage::Dkg(dkg)) => {
                Ok(DkgGossipMessage {
                    dkg: dkg.clone().into(),
                })
            }
            None => Err(Error::NoDkgError),
        }
    }
}

impl From<DkgGossipMessage> for types::DkgGossipMessage {
    fn from(message: DkgGossipMessage) -> Self {
        types::DkgGossipMessage {
            dkg_message: Some(types::dkg_gossip_message::DkgMessage::Dkg(
                message.dkg.into(),
            )),
        }
    }
}

#[allow(dead_code)]
impl DkgGossipMessage {
    pub fn new(dkg: Dkg) -> Self {
        DkgGossipMessage { dkg }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let message: types::DkgGossipMessage = self.clone().into();
        message
            .encode(&mut bytes)
            .expect("encoding a DKG gossip message failed");
        bytes
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg {
    pub data: String,
}

impl From<types::Dkg> for Dkg {
    fn from(dkg: types::Dkg) -> Self {
        Dkg { data: dkg.data }
    }
}

impl From<Dkg> for types::Dkg {
    fn from(dkg: Dkg) -> Self {
        types::Dkg { data: dkg.data }
    }
}

#[allow(dead_code)]
impl Dkg {
    pub fn new(data: String) -> Self {
        Dkg { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx() {
        let code = "wasm code".as_bytes().to_owned();
        let data = "arbitrary data".as_bytes().to_owned();
        let chain_id = ChainId::default();
        let tx =
            Tx::new(code.clone(), Some(data.clone()), chain_id.clone(), None);

        let bytes = tx.to_bytes();
        let tx_from_bytes =
            Tx::try_from(bytes.as_ref()).expect("decoding failed");
        assert_eq!(tx_from_bytes, tx);

        let types_tx = types::Tx {
            code,
            data: Some(data),
            timestamp: None,
            chain_id: chain_id.0,
            expiration: None,
        };
        let mut bytes = vec![];
        types_tx.encode(&mut bytes).expect("encoding failed");
        match Tx::try_from(bytes.as_ref()) {
            Err(Error::NoTimestampError) => {}
            _ => panic!("unexpected result"),
        }
    }

    #[test]
    fn test_dkg_gossip_message() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);
        let message = DkgGossipMessage::new(dkg);

        let bytes = message.to_bytes();
        let message_from_bytes = DkgGossipMessage::try_from(bytes.as_ref())
            .expect("decoding failed");
        assert_eq!(message_from_bytes, message);
    }

    #[test]
    fn test_dkg() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);

        let types_dkg: types::Dkg = dkg.clone().into();
        let dkg_from_types = Dkg::from(types_dkg);
        assert_eq!(dkg_from_types, dkg);
    }
}

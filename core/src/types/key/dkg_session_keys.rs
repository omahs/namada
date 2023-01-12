//! Utilities around the DKG session keys

use std::cmp::Ordering;
use std::io::{Error, ErrorKind};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::impl_display_and_from_str_via_format;
use crate::types::address::Address;
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::string_encoding;
use crate::types::transaction::EllipticCurve;

/// A keypair used in the DKG protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DkgKeypair(ferveo_common::Keypair<EllipticCurve>);

impl DkgKeypair {
    /// Get the public key of the keypair
    pub fn public(&self) -> DkgPublicKey {
        self.0.public().into()
    }
}

impl From<ferveo_common::Keypair<EllipticCurve>> for DkgKeypair {
    fn from(kp: ferveo_common::Keypair<EllipticCurve>) -> Self {
        Self(kp)
    }
}

impl From<&DkgKeypair> for ferveo_common::Keypair<EllipticCurve> {
    fn from(kp: &DkgKeypair) -> Self {
        kp.0
    }
}

impl BorshSerialize for DkgKeypair {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let mut kp_buf = Vec::<u8>::new();
        CanonicalSerialize::serialize(&self.0, &mut kp_buf)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        BorshSerialize::serialize(&kp_buf, writer)
    }
}

impl BorshDeserialize for DkgKeypair {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let kp_bytes: Vec<u8> = BorshDeserialize::deserialize(buf)?;
        let kp: ferveo_common::Keypair<EllipticCurve> =
            CanonicalDeserialize::deserialize(kp_bytes.as_slice())
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
        Ok(kp.into())
    }
}

/// A public keypair used in the DKG protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DkgPublicKey(ferveo_common::PublicKey<EllipticCurve>);

impl From<ferveo_common::PublicKey<EllipticCurve>> for DkgPublicKey {
    fn from(pk: ferveo_common::PublicKey<EllipticCurve>) -> Self {
        Self(pk)
    }
}

impl From<&DkgPublicKey> for ferveo_common::PublicKey<EllipticCurve> {
    fn from(pk: &DkgPublicKey) -> Self {
        pk.0
    }
}

impl Eq for DkgPublicKey {}

impl PartialOrd for DkgPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.0
                .encryption_key
                .to_string()
                .cmp(&other.0.encryption_key.to_string()),
        )
    }
}

impl Ord for DkgPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .encryption_key
            .to_string()
            .cmp(&other.0.encryption_key.to_string())
    }
}

impl BorshSerialize for DkgPublicKey {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let mut pk_buf = Vec::<u8>::new();
        CanonicalSerialize::serialize(&self.0, &mut pk_buf)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        BorshSerialize::serialize(&pk_buf, writer)
    }
}

impl BorshDeserialize for DkgPublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let pk_bytes: Vec<u8> = BorshDeserialize::deserialize(buf)?;
        let pk: ferveo_common::PublicKey<EllipticCurve> =
            CanonicalDeserialize::deserialize(pk_bytes.as_slice())
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
        Ok(pk.into())
    }
}

impl BorshSchema for DkgPublicKey {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        // Encoded as `Vec<u8>`;
        let elements = "u8".into();
        let definition = borsh::schema::Definition::Sequence { elements };
        definitions.insert(Self::declaration(), definition);
    }

    fn declaration() -> borsh::schema::Declaration {
        "DkgPublicKey".into()
    }
}

impl string_encoding::Format for DkgPublicKey {
    const HRP: &'static str = string_encoding::DKG_PK_HRP;

    fn to_bytes(&self) -> Vec<u8> {
        self.try_to_vec()
            .expect("Encoding public key shouldn't fail")
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        BorshDeserialize::try_from_slice(bytes)
    }
}

impl_display_and_from_str_via_format!(DkgPublicKey);

/// Obtain a storage key for user's public dkg session key.
pub fn dkg_pk_key(owner: &Address) -> Key {
    Key::from(owner.to_db_key())
        .push(&DKG_PK_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a public dkg session key. If it is,
/// returns the owner.
pub fn is_dkg_pk_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key == DKG_PK_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

const DKG_PK_STORAGE_KEY: &str = "dkg_pk_key";

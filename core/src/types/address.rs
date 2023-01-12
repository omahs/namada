//! Implements transparent addresses as described in [Accounts
//! Addresses](docs/src/explore/design/ledger/accounts.md#addresses).

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::impl_display_and_from_str_via_format;
use crate::types::key::PublicKeyHash;
use crate::types::{key, string_encoding};

/// The length of an established [`Address`] encoded with Borsh.
pub const ESTABLISHED_ADDRESS_BYTES_LEN: usize = 45;

/// The length of [`Address`] encoded with Bech32m.
pub const ADDRESS_LEN: usize = 79 + string_encoding::hrp_len::<Address>();

pub(crate) const HASH_LEN: usize = 40;

/// An address string before bech32m encoding must be this size.
pub const FIXED_LEN_STRING_BYTES: usize = 45;

/// Internal IBC address
pub const IBC: Address = Address::Internal(InternalAddress::Ibc);
/// Internal IBC token burn address
pub const IBC_BURN: Address = Address::Internal(InternalAddress::IbcBurn);
/// Internal IBC token mint address
pub const IBC_MINT: Address = Address::Internal(InternalAddress::IbcMint);
/// Internal ledger parameters address
pub const PARAMETERS: Address = Address::Internal(InternalAddress::Parameters);
/// Internal PoS address
pub const POS: Address = Address::Internal(InternalAddress::PoS);
/// Internal PoS slash pool address
pub const POS_SLASH_POOL: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Raw strings used to produce internal addresses. All the strings must begin
/// with `PREFIX_INTERNAL` and be `FIXED_LEN_STRING_BYTES` characters long.
#[rustfmt::skip]
mod internal {
    pub const POS: &str = 
        "ano::Proof of Stake                          ";
    pub const POS_SLASH_POOL: &str =
        "ano::Proof of Stake Slash Pool               ";
    pub const PARAMETERS: &str =
        "ano::Protocol Parameters                     ";
    pub const GOVERNANCE: &str =
        "ano::Governance                              ";
    pub const SLASH_FUND: &str =
        "ano::Slash Fund                              ";
    pub const IBC: &str =
        "ibc::Inter-Blockchain Communication          ";
    pub const IBC_ESCROW: &str =
        "ibc::IBC Escrow Address                      ";
    pub const IBC_BURN: &str =
        "ibc::IBC Burn Address                        ";
    pub const IBC_MINT: &str =
        "ibc::IBC Mint Address                        ";
    pub const ETH_BRIDGE: &str =
        "ano::ETH Bridge Address                      ";
}

/// Error from decoding address from string
pub type DecodeError = string_encoding::DecodeError;

/// Result of decoding address from string
pub type Result<T> = std::result::Result<T, DecodeError>;

/// Fixed-length address strings prefix for established addresses.
const PREFIX_ESTABLISHED: &str = "est";
/// Fixed-length address strings prefix for implicit addresses.
const PREFIX_IMPLICIT: &str = "imp";
/// Fixed-length address strings prefix for internal addresses.
const PREFIX_INTERNAL: &str = "ano";
/// Fixed-length address strings prefix for IBC addresses.
const PREFIX_IBC: &str = "ibc";

/// An account's address
#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub enum Address {
    /// An established address is generated on-chain
    Established(EstablishedAddress),
    /// An implicit address is derived from a cryptographic key
    Implicit(ImplicitAddress),
    /// An internal address represents a module with a native VP
    Internal(InternalAddress),
}

impl Address {
    /// Encode an address with Bech32m encoding
    pub fn encode(&self) -> String {
        string_encoding::Format::encode(self)
    }

    /// Decode an address from Bech32m encoding
    pub fn decode(string: impl AsRef<str>) -> Result<Self> {
        string_encoding::Format::decode(string)
    }

    /// Try to get a raw hash of an address, only defined for established and
    /// implicit addresses.
    pub fn raw_hash(&self) -> Option<&str> {
        match self {
            Address::Established(established) => Some(&established.hash),
            Address::Implicit(ImplicitAddress(implicit)) => Some(&implicit.0),
            Address::Internal(_) => None,
        }
    }

    /// Convert an address to a fixed length 7-bit ascii string bytes
    pub fn to_fixed_len_string(&self) -> Vec<u8> {
        let mut string = match self {
            Address::Established(EstablishedAddress { hash }) => {
                format!("{}::{}", PREFIX_ESTABLISHED, hash)
            }
            Address::Implicit(ImplicitAddress(pkh)) => {
                format!("{}::{}", PREFIX_IMPLICIT, pkh)
            }
            Address::Internal(internal) => {
                let string = match internal {
                    InternalAddress::PoS => internal::POS.to_string(),
                    InternalAddress::PosSlashPool => {
                        internal::POS_SLASH_POOL.to_string()
                    }
                    InternalAddress::Parameters => {
                        internal::PARAMETERS.to_string()
                    }
                    InternalAddress::Governance => {
                        internal::GOVERNANCE.to_string()
                    }
                    InternalAddress::SlashFund => {
                        internal::SLASH_FUND.to_string()
                    }
                    InternalAddress::Ibc => internal::IBC.to_string(),
                    InternalAddress::IbcToken(hash) => {
                        format!("{}::{}", PREFIX_IBC, hash)
                    }
                    InternalAddress::IbcEscrow => {
                        internal::IBC_ESCROW.to_string()
                    }
                    InternalAddress::IbcBurn => internal::IBC_BURN.to_string(),
                    InternalAddress::IbcMint => internal::IBC_MINT.to_string(),
                    InternalAddress::EthBridge => {
                        internal::ETH_BRIDGE.to_string()
                    }
                };
                debug_assert_eq!(string.len(), FIXED_LEN_STRING_BYTES);
                string
            }
        }
        .into_bytes();
        string.resize(FIXED_LEN_STRING_BYTES, b' ');
        string
    }

    /// Try to parse an address from fixed-length utf-8 encoded address string.
    pub fn try_from_fixed_len_string(buf: &mut &[u8]) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        let string = std::str::from_utf8(buf)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
        if string.len() != FIXED_LEN_STRING_BYTES {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid length"));
        }
        match string.split_once("::") {
            Some((PREFIX_ESTABLISHED, hash)) => {
                if hash.len() == HASH_LEN {
                    Ok(Address::Established(EstablishedAddress {
                        hash: hash.to_string(),
                    }))
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Established address hash must be 40 characters long",
                    ))
                }
            }
            Some((PREFIX_IMPLICIT, pkh)) => {
                let pkh = PublicKeyHash::from_str(pkh)
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
                Ok(Address::Implicit(ImplicitAddress(pkh)))
            }
            Some((PREFIX_INTERNAL, _)) => match string {
                internal::POS => Ok(Address::Internal(InternalAddress::PoS)),
                internal::POS_SLASH_POOL => {
                    Ok(Address::Internal(InternalAddress::PosSlashPool))
                }
                internal::PARAMETERS => {
                    Ok(Address::Internal(InternalAddress::Parameters))
                }
                internal::GOVERNANCE => {
                    Ok(Address::Internal(InternalAddress::Governance))
                }
                internal::SLASH_FUND => {
                    Ok(Address::Internal(InternalAddress::SlashFund))
                }
                internal::ETH_BRIDGE => {
                    Ok(Address::Internal(InternalAddress::EthBridge))
                }
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid internal address",
                )),
            },
            Some((PREFIX_IBC, raw)) => match string {
                internal::IBC => Ok(Address::Internal(InternalAddress::Ibc)),
                internal::IBC_ESCROW => {
                    Ok(Address::Internal(InternalAddress::IbcEscrow))
                }
                internal::IBC_BURN => {
                    Ok(Address::Internal(InternalAddress::IbcBurn))
                }
                internal::IBC_MINT => {
                    Ok(Address::Internal(InternalAddress::IbcMint))
                }
                _ if raw.len() == HASH_LEN => Ok(Address::Internal(
                    InternalAddress::IbcToken(raw.to_string()),
                )),
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid IBC internal address",
                )),
            },
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid address prefix",
            )),
        }
    }

    fn pretty_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_string())
    }

    /// Print the type of the address and its bech32m encoded value
    pub fn to_pretty_string(&self) -> String {
        match self {
            Address::Established(_) => {
                format!("Established: {}", self.encode(),)
            }
            Address::Implicit(_) => {
                format!("Implicit: {}", self.encode(),)
            }
            Address::Internal(kind) => {
                format!("Internal {}: {}", kind, self.encode())
            }
        }
    }
}

impl string_encoding::Format for Address {
    const HRP: &'static str = string_encoding::ADDRESS_HRP;

    fn to_bytes(&self) -> Vec<u8> {
        Self::to_fixed_len_string(self)
    }

    fn decode_bytes(bytes: &[u8]) -> std::result::Result<Self, std::io::Error> {
        Self::try_from_fixed_len_string(&mut &bytes[..])
    }
}

impl_display_and_from_str_via_format!(Address);

impl serde::Serialize for Address {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encode();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pretty_fmt(f)
    }
}

/// An established address is generated on-chain
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct EstablishedAddress {
    hash: String,
}

/// A generator of established addresses
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct EstablishedAddressGen {
    last_hash: String,
}

impl EstablishedAddressGen {
    /// Initialize a new address generator with a given randomness seed.
    pub fn new(seed: impl AsRef<str>) -> Self {
        Self {
            last_hash: seed.as_ref().to_owned(),
        }
    }

    /// Generate a new established address. Requires a source of randomness as
    /// arbitrary bytes. In the ledger, this could be some unpredictable value,
    /// such as hash of the transaction that has initialized the new address.
    pub fn generate_address(
        &mut self,
        rng_source: impl AsRef<[u8]>,
    ) -> Address {
        let gen_bytes = self
            .try_to_vec()
            .expect("Encoding established addresses generator shouldn't fail");
        let mut hasher = Sha256::new();
        let bytes = [&gen_bytes, rng_source.as_ref()].concat();
        hasher.update(bytes);
        // hex of the first 40 chars of the hash
        let hash = format!("{:.width$X}", hasher.finalize(), width = HASH_LEN);
        self.last_hash = hash.clone();
        Address::Established(EstablishedAddress { hash })
    }
}

/// An implicit address is derived from a cryptographic key
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ImplicitAddress(pub key::PublicKeyHash);

impl From<&key::common::PublicKey> for ImplicitAddress {
    fn from(pk: &key::common::PublicKey) -> Self {
        ImplicitAddress(pk.into())
    }
}

impl From<&key::common::PublicKey> for Address {
    fn from(pk: &key::common::PublicKey) -> Self {
        Self::Implicit(pk.into())
    }
}

/// An internal address represents a module with a native VP
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum InternalAddress {
    /// Proof-of-stake
    PoS,
    /// Proof-of-stake slash pool contains slashed tokens
    PosSlashPool,
    /// Protocol parameters
    Parameters,
    /// Inter-blockchain communication
    Ibc,
    /// IBC-related token
    IbcToken(String),
    /// Escrow for IBC token transfer
    IbcEscrow,
    /// Burn tokens with IBC token transfer
    IbcBurn,
    /// Mint tokens from this address with IBC token transfer
    IbcMint,
    /// Governance address
    Governance,
    /// SlashFund address for governance
    SlashFund,
    /// Bridge to Ethereum
    EthBridge,
}

impl InternalAddress {
    /// Get an IBC token address from the port ID and channel ID
    pub fn ibc_token_address(
        port_id: String,
        channel_id: String,
        token: &Address,
    ) -> Self {
        let mut hasher = Sha256::new();
        let s = format!("{}/{}/{}", port_id, channel_id, token);
        hasher.update(&s);
        let hash = format!("{:.width$x}", hasher.finalize(), width = HASH_LEN);
        InternalAddress::IbcToken(hash)
    }
}

impl Display for InternalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PoS => "PoS".to_string(),
                Self::PosSlashPool => "PosSlashPool".to_string(),
                Self::Parameters => "Parameters".to_string(),
                Self::Governance => "Governance".to_string(),
                Self::SlashFund => "SlashFund".to_string(),
                Self::Ibc => "IBC".to_string(),
                Self::IbcToken(hash) => format!("IbcToken: {}", hash),
                Self::IbcEscrow => "IbcEscrow".to_string(),
                Self::IbcBurn => "IbcBurn".to_string(),
                Self::IbcMint => "IbcMint".to_string(),
                Self::EthBridge => "EthBridge".to_string(),
            }
        )
    }
}

/// Temporary helper for testing
pub fn nam() -> Address {
    Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn btc() -> Address {
    Address::decode("atest1v4ehgw36xdzryve5gsc52veeg5cnsv2yx5eygvp38qcrvd29xy6rys6p8yc5xvp4xfpy2v694wgwcp").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn eth() -> Address {
    Address::decode("atest1v4ehgw36xqmr2d3nx3ryvd2xxgmrq33j8qcns33sxezrgv6zxdzrydjrxveygd2yxumrsdpsf9jc2p").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn dot() -> Address {
    Address::decode("atest1v4ehgw36gg6nvs2zgfpyxsfjgc65yv6pxy6nwwfsxgungdzrggeyzv35gveyxsjyxymyz335hur2jn").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn schnitzel() -> Address {
    Address::decode("atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn apfel() -> Address {
    Address::decode("atest1v4ehgw36gfryydj9g3p5zv3kg9znyd358ycnzsfcggc5gvecgc6ygs2rxv6ry3zpg4zrwdfeumqcz9").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn kartoffel() -> Address {
    Address::decode("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn masp() -> Address {
    Address::decode("atest1v4ehgw36xaryysfsx5unvve4g5my2vjz89p52sjxxgenzd348yuyyv3hg3pnjs35g5unvde4ca36y5").expect("The token address decoding shouldn't fail")
}

/// Sentinel secret key to indicate a MASP source
pub fn masp_tx_key() -> crate::types::key::common::SecretKey {
    use crate::types::key::common;
    let bytes = [
        0, 27, 238, 157, 32, 131, 242, 184, 142, 146, 189, 24, 249, 68, 165,
        205, 71, 213, 158, 25, 253, 52, 217, 87, 52, 171, 225, 110, 131, 238,
        58, 94, 56,
    ];
    common::SecretKey::try_from_slice(bytes.as_ref()).unwrap()
}

/// Temporary helper for testing, a hash map of tokens addresses with their
/// informal currency codes.
pub fn tokens() -> HashMap<Address, &'static str> {
    vec![
        (nam(), "NAM"),
        (btc(), "BTC"),
        (eth(), "ETH"),
        (dot(), "DOT"),
        (schnitzel(), "Schnitzel"),
        (apfel(), "Apfel"),
        (kartoffel(), "Kartoffel"),
    ]
    .into_iter()
    .collect()
}

/// Temporary helper for testing, a hash map of tokens addresses with their
/// MASP XAN incentive schedules. If the reward is (a, b) then a rewarded tokens
/// are dispensed for every b possessed tokens.
pub fn masp_rewards() -> HashMap<Address, (u64, u64)> {
    vec![
        (nam(), (0, 100)),
        (btc(), (1, 100)),
        (eth(), (2, 100)),
        (dot(), (3, 100)),
        (schnitzel(), (4, 100)),
        (apfel(), (5, 100)),
        (kartoffel(), (6, 100)),
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Run `cargo test gen_established_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_established_address() {
        for _ in 0..10 {
            let address = testing::gen_established_address();
            println!("address {}", address);
        }
    }

    /// Run `cargo test gen_implicit_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_implicit_address() {
        for _ in 0..10 {
            let address = testing::gen_implicit_address();
            println!("address {}", address);
        }
    }

    #[test]
    fn test_address_serde_serialize() {
        let original_address = Address::decode("atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp").unwrap();
        let expect =
            "\"atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp\"";
        let decoded_address: Address =
            serde_json::from_str(expect).expect("could not read JSON");
        assert_eq!(original_address, decoded_address);

        let encoded_address = serde_json::to_string(&original_address).unwrap();
        assert_eq!(encoded_address, expect);
    }

    proptest! {
        #[test]
        /// Check that all the address types are of the same length
        /// `ADDRESS_LEN` when bech32m encoded, and that that decoding them
        /// yields back the same value.
        fn test_encoded_address_length(address in testing::arb_address()) {
            let encoded: String = address.encode();
            assert_eq!(encoded.len(), ADDRESS_LEN);
            // Also roundtrip check that we decode back the same value
            let decoded = Address::decode(&encoded).unwrap();
            assert_eq!(address, decoded);
        }

        #[test]
        fn test_established_address_bytes_length(address in testing::arb_established_address()) {
            let address = Address::Established(address);
            let bytes = address.try_to_vec().unwrap();
            assert_eq!(bytes.len(), ESTABLISHED_ADDRESS_BYTES_LEN);
        }
    }
}

/// Generate a new established address.
#[cfg(feature = "rand")]
pub fn gen_established_address(seed: impl AsRef<str>) -> Address {
    use rand::prelude::ThreadRng;
    use rand::{thread_rng, RngCore};

    let mut key_gen = EstablishedAddressGen::new(seed);

    let mut rng: ThreadRng = thread_rng();
    let mut rng_bytes = vec![0u8; 32];
    rng.fill_bytes(&mut rng_bytes[..]);
    let rng_source = rng_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("");
    key_gen.generate_address(rng_source)
}

/// Helpers for testing with addresses.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;
    use crate::types::key::*;

    /// Generate a new established address.
    pub fn gen_established_address() -> Address {
        let seed = "such randomness, much wow";
        super::gen_established_address(seed)
    }

    /// Generate a new implicit address.
    pub fn gen_implicit_address() -> Address {
        let keypair: common::SecretKey =
            key::testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let pkh = PublicKeyHash::from(&keypair.ref_to());
        Address::Implicit(ImplicitAddress(pkh))
    }

    /// A sampled established address for tests
    pub fn established_address_1() -> Address {
        Address::decode("atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_2() -> Address {
        Address::decode("atest1v4ehgw36xezyzv33x56rws6zxccnwwzzgycy23p3ggur2d3ex56yxdejxerrysejx3rrxdfs44s9wu").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_3() -> Address {
        Address::decode("atest1v4ehgw36xcerywfsgsu5vsfeg3zy2v3egcenx32pggcrswzxg4zns3p5xv6rsvf4gvenqwpkdnnqsy").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_4() -> Address {
        Address::decode("atest1v4ehgw36gscrw333g3z5zvjzg4rrq3psxu6rqd2xxqc5gs35gerrs3pjgfprvdejxqunxs29t6p5s9").expect("The token address decoding shouldn't fail")
    }

    /// Generate an arbitrary [`Address`] (established or implicit).
    pub fn arb_non_internal_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
        ]
    }

    /// Generate an arbitrary [`Address`] (established, implicit or internal).
    pub fn arb_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
            arb_internal_address().prop_map(Address::Internal),
        ]
    }

    /// Generate an arbitrary [`EstablishedAddress`].
    pub fn arb_established_address() -> impl Strategy<Value = EstablishedAddress>
    {
        any::<Vec<u8>>().prop_map(|rng_source| {
            let mut key_gen = EstablishedAddressGen::new("seed");
            match key_gen.generate_address(rng_source) {
                Address::Established(addr) => addr,
                _ => {
                    panic!(
                        "Assuming key gen to only generated established \
                         addresses"
                    )
                }
            }
        })
    }

    /// Generate an arbitrary [`ImplicitAddress`].
    pub fn arb_implicit_address() -> impl Strategy<Value = ImplicitAddress> {
        key::testing::arb_keypair::<ed25519::SigScheme>().prop_map(|keypair| {
            let keypair: common::SecretKey = keypair.try_to_sk().unwrap();
            let pkh = PublicKeyHash::from(&keypair.ref_to());
            ImplicitAddress(pkh)
        })
    }

    /// Generate an arbitrary [`InternalAddress`].
    pub fn arb_internal_address() -> impl Strategy<Value = InternalAddress> {
        // This is here for match exhaustion check to remind to add any new
        // internal addresses below.
        match InternalAddress::PoS {
            InternalAddress::PoS => {}
            InternalAddress::PosSlashPool => {}
            InternalAddress::Governance => {}
            InternalAddress::SlashFund => {}
            InternalAddress::Parameters => {}
            InternalAddress::Ibc => {}
            InternalAddress::IbcToken(_) => {}
            InternalAddress::IbcEscrow => {}
            InternalAddress::IbcBurn => {}
            InternalAddress::IbcMint => {}
            InternalAddress::EthBridge => {} /* Add new addresses in the
                                              * `prop_oneof` below. */
        };
        prop_oneof![
            Just(InternalAddress::PoS),
            Just(InternalAddress::PosSlashPool),
            Just(InternalAddress::Ibc),
            Just(InternalAddress::Parameters),
            Just(InternalAddress::Ibc),
            arb_ibc_token(),
            Just(InternalAddress::IbcEscrow),
            Just(InternalAddress::IbcBurn),
            Just(InternalAddress::IbcMint),
            Just(InternalAddress::Governance),
            Just(InternalAddress::SlashFund),
            Just(InternalAddress::EthBridge),
        ]
    }

    fn arb_ibc_token() -> impl Strategy<Value = InternalAddress> {
        // use sha2::{Digest, Sha256};
        ("[a-zA-Z0-9_]{2,128}", any::<u64>()).prop_map(|(id, counter)| {
            let mut hasher = sha2::Sha256::new();
            let s = format!(
                "{}/{}/{}",
                id,
                format_args!("channel-{}", counter),
                &nam()
            );
            hasher.update(&s);
            let hash =
                format!("{:.width$x}", hasher.finalize(), width = HASH_LEN);
            InternalAddress::IbcToken(hash)
        })
    }
}

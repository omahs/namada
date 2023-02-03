#![allow(missing_docs)]

pub mod generated;
mod types;

pub use types::{
    Dkg, Error, Signable, SignableEthMessage, Signed, SignedTxData, Tx,
};

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use generated::types::Tx;
    use prost::Message;

    use super::*;

    #[test]
    fn encoding_round_trip() {
        let tx = Tx {
            code: "wasm code".as_bytes().to_owned(),
            data: Some("arbitrary data".as_bytes().to_owned()),
            timestamp: Some(std::time::SystemTime::now().into()),
        };
        let mut tx_bytes = vec![];
        tx.encode(&mut tx_bytes).unwrap();
        let tx_hex = HEXLOWER.encode(&tx_bytes);
        let tx_from_hex = HEXLOWER.decode(tx_hex.as_ref()).unwrap();
        let tx_from_bytes = Tx::decode(&tx_from_hex[..]).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }
}

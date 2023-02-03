//! Helpers for making digital signatures using cryptographic keys from the
//! wallet.

use std::collections::HashMap;
use std::fs;

use borsh::{BorshSerialize};

use namada::ledger::parameters::storage as parameter_storage;
use namada::proto::Tx;
use namada::types::address::{Address, ImplicitAddress};
use namada::types::key::*;
use namada::types::storage::Epoch;
use namada::types::token;
use namada::types::token::Amount;
use namada::types::transaction::{hash_tx, Fee, WrapperTx, MIN_FEE};
use serde::{Serialize, Deserialize};

use super::rpc;
use crate::cli::context::{WalletAddress, WalletKeypair};
use crate::cli::{self, args, Context};
use crate::client::tendermint_rpc_types::TxBroadcastData;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::facade::tendermint_rpc::HttpClient;
use crate::wallet::Wallet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineSignature {
    pub sig: common::Signature,
    pub public_key: common::PublicKey
}

/// Find the public key for the given address and try to load the keypair
/// for it from the wallet. Panics if the key cannot be found or loaded.
pub async fn find_keypair(
    wallet: &mut Wallet,
    addr: &Address,
    ledger_address: TendermintAddress,
) -> common::SecretKey {
    match addr {
        Address::Established(_) => {
            println!(
                "Looking-up public key of {} from the ledger...",
                addr.encode()
            );
            let public_key = rpc::get_public_key(addr, 0, ledger_address)
                .await
                .unwrap_or_else(|| {
                    eprintln!(
                        "No public key found for the address {}",
                        addr.encode()
                    );
                    cli::safe_exit(1);
                });
            wallet.find_key_by_pk(&public_key).unwrap_or_else(|err| {
                eprintln!(
                    "Unable to load the keypair from the wallet for public \
                     key {}. Failed with: {}",
                    public_key, err
                );
                cli::safe_exit(1)
            })
        }
        Address::Implicit(ImplicitAddress(pkh)) => {
            wallet.find_key_by_pkh(pkh).unwrap_or_else(|err| {
                eprintln!(
                    "Unable to load the keypair from the wallet for the \
                     implicit address {}. Failed with: {}",
                    addr.encode(),
                    err
                );
                cli::safe_exit(1)
            })
        }
        Address::Internal(_) => {
            eprintln!(
                "Internal address {} doesn't have any signing keys.",
                addr
            );
            cli::safe_exit(1)
        }
    }
}

/// Carries types that can be directly/indirectly used to sign a transaction.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum TxSigningKey {
    // Do not sign any transaction
    None,
    // Obtain the actual keypair from wallet and use that to sign
    WalletKeypair(WalletKeypair),
    // Obtain the keypair corresponding to given address from wallet and sign
    WalletAddress(WalletAddress),
    // Directly use the given secret key to sign transactions
    SecretKey(common::SecretKey),
}

/// Given CLI arguments and some defaults, determine the rightful transaction
/// signer. Return the given signing key or public key of the given signer if
/// possible. If no explicit signer given, use the `default`. If no `default`
/// is given, panics.
pub async fn tx_signer(
    ctx: &mut Context,
    args: &args::Tx,
    mut default: TxSigningKey,
) -> common::SecretKey {
    // Override the default signing key source if possible
    if let Some(signing_key) = args.signing_keys.get(0) {
        default = TxSigningKey::WalletKeypair(signing_key.clone());
    } else if let Some(signer) = args.signers.get(0) {
        default = TxSigningKey::WalletAddress(signer.clone());
    }
    // Now actually fetch the signing key and apply it
    match default {
        TxSigningKey::WalletKeypair(signing_key) => {
            ctx.get_cached(&signing_key)
        }
        TxSigningKey::WalletAddress(signer) => {
            let signer = ctx.get(&signer);
            let signing_key = find_keypair(
                &mut ctx.wallet,
                &signer,
                args.ledger_address.clone(),
            )
            .await;
            // Check if the signer is implicit account that needs to reveal its
            // PK first
            if matches!(signer, Address::Implicit(_)) {
                let pk: common::PublicKey = signing_key.ref_to();
                super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
            }
            signing_key
        }
        TxSigningKey::SecretKey(signing_key) => {
            // Check if the signing key needs to reveal its PK first
            let pk: common::PublicKey = signing_key.ref_to();
            super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
            signing_key
        }
        TxSigningKey::None => {
            panic!(
                "All transactions must be signed; please either specify the \
                 key or the address from which to look up the signing key."
            );
        }
    }
}

pub async fn tx_signers(
    ctx: &mut Context,
    args: &args::Tx,
    mut default: Vec<TxSigningKey>,
) -> Vec<common::SecretKey> {
    if !args.signing_keys.is_empty() {
        default = args
            .signing_keys
            .iter()
            .map(|signing_key| TxSigningKey::WalletKeypair(signing_key.clone()))
            .collect();
    } else if !args.signers.is_empty() {
        default = args
            .signers
            .iter()
            .map(|signing_key| TxSigningKey::WalletAddress(signing_key.clone()))
            .collect();
    }

    let mut keys = Vec::new();

    for key in default {
        match key {
            TxSigningKey::WalletKeypair(signing_key) => {
                keys.push(ctx.get_cached(&signing_key));
            }
            TxSigningKey::WalletAddress(signer) => {
                let signer = ctx.get(&signer);
                let signing_key = find_keypair(
                    &mut ctx.wallet,
                    &signer,
                    args.ledger_address.clone(),
                )
                .await;
                // Check if the signer is implicit account that needs to reveal
                // its PK first
                if matches!(signer, Address::Implicit(_)) {
                    let pk: common::PublicKey = signing_key.ref_to();
                    super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
                }
                keys.push(signing_key);
            }
            TxSigningKey::SecretKey(signing_key) => {
                // Check if the signing key needs to reveal its PK first
                let pk: common::PublicKey = signing_key.ref_to();
                super::tx::reveal_pk_if_needed(ctx, &pk, args).await;
                keys.push(signing_key);
            }
            TxSigningKey::None => {
                panic!(
                    "All transactions must be signed; please either specify \
                     the key or the address from which to look up the signing \
                     key."
                );
            }
        }
    }

    keys
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// panics.
///
/// If this is not a dry run, the tx is put in a wrapper and returned along with
/// hashes needed for monitoring the tx on chain.
///
/// If it is a dry run, it is not put in a wrapper, but returned as is.
pub async fn sign_tx_multisignature(
    mut ctx: Context,
    tx: Tx,
    args: &args::Tx,
    pks_index_map: HashMap<common::PublicKey, u64>,
    default: Vec<TxSigningKey>,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> (Context, TxBroadcastData) {
    let keypairs = tx_signers(&mut ctx, args, default).await;
    let tx = match args.signatures.is_empty() {
        true => {
            tx.sign_multisignature(&keypairs, pks_index_map)
        },
        false => {
            let signatures = args.signatures.iter().map(|signature_path| {
                let content = fs::read(signature_path).expect("Signature file should exist.");
                let offline_signature: OfflineSignature = serde_json::from_slice(&content).expect("Signature should be deserializable.");
                (offline_signature.public_key, offline_signature.sig)
            }).collect::<Vec<(common::PublicKey, common::Signature)>>();
            println!("{:?}", signatures);
            println!("{:?}", pks_index_map);
            tx.add_signatures(signatures, pks_index_map)
        },
    };
    

    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.ledger_address.clone(),
    })
    .await;
    let broadcast_data = if args.dry_run {
        TxBroadcastData::DryRun(tx)
    } else {
        sign_wrapper(
            &ctx,
            args,
            epoch,
            tx,
            &keypairs[0],
            #[cfg(not(feature = "mainnet"))]
            requires_pow,
        )
        .await
    };
    (ctx, broadcast_data)
}

/// Create a wrapper tx from a normal tx. Get the hash of the
/// wrapper and its payload which is needed for monitoring its
/// progress on chain.
pub async fn sign_wrapper(
    ctx: &Context,
    args: &args::Tx,
    epoch: Epoch,
    tx: Tx,
    keypair: &common::SecretKey,
    #[cfg(not(feature = "mainnet"))] requires_pow: bool,
) -> TxBroadcastData {
    let client = HttpClient::new(args.ledger_address.clone()).unwrap();

    let fee_amount = if cfg!(feature = "mainnet") {
        Amount::from(MIN_FEE)
    } else {
        let wrapper_tx_fees_key = parameter_storage::get_wrapper_tx_fees_key();
        rpc::query_storage_value::<token::Amount>(&client, &wrapper_tx_fees_key)
            .await
            .unwrap_or_default()
    };
    let fee_token = ctx.get(&args.fee_token);
    let source = Address::from(&keypair.ref_to());
    let balance_key = token::balance_key(&fee_token, &source);
    let balance =
        rpc::query_storage_value::<token::Amount>(&client, &balance_key)
            .await
            .unwrap_or_default();
    if balance < fee_amount {
        eprintln!(
            "The wrapper transaction source doesn't have enough balance to \
             pay fee {fee_amount}, got {balance}."
        );
        if !args.force && cfg!(feature = "mainnet") {
            cli::safe_exit(1);
        }
    }

    #[cfg(not(feature = "mainnet"))]
    // A PoW solution can be used to allow zero-fee testnet transactions
    let pow_solution: Option<namada::core::ledger::testnet_pow::Solution> = {
        // If the address derived from the keypair doesn't have enough balance
        // to pay for the fee, allow to find a PoW solution instead.
        if requires_pow || balance < fee_amount {
            println!(
                "The transaction requires the completion of a PoW challenge."
            );
            // Obtain a PoW challenge for faucet withdrawal
            let challenge = rpc::get_testnet_pow_challenge(
                source,
                args.ledger_address.clone(),
            )
            .await;

            // Solve the solution, this blocks until a solution is found
            let solution = challenge.solve();
            Some(solution)
        } else {
            None
        }
    };

    let tx = {
        WrapperTx::new(
            Fee {
                amount: fee_amount,
                token: fee_token,
            },
            keypair,
            epoch,
            args.gas_limit.clone(),
            tx,
            // TODO: Actually use the fetched encryption key
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            pow_solution,
        )
    };

    // We use this to determine when the wrapper tx makes it on-chain
    let wrapper_hash = hash_tx(&tx.try_to_vec().unwrap()).to_string();
    // We use this to determine when the decrypted inner tx makes it
    // on-chain
    let decrypted_hash = tx.tx_hash.to_string();
    TxBroadcastData::Wrapper {
        tx: tx
            .sign(keypair)
            .expect("Wrapper tx signing keypair should be correct"),
        wrapper_hash,
        decrypted_hash,
    }
}

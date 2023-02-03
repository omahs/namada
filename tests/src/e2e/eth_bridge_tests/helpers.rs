//! Helper functionality for use in tests to do with the Ethereum bridge.

use std::num::NonZeroU64;

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXLOWER;
use eyre::{eyre, Context, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request, StatusCode};
use namada::ledger::eth_bridge::{
    wrapped_erc20s, ContractVersion, Contracts, EthereumBridgeConfig,
    MinimumConfirmations, UpgradeableContract,
};
use namada::types::address::{wnam, Address};
use namada::types::ethereum_events::EthAddress;
use namada_apps::config::ethereum_bridge;
use namada_core::ledger::eth_bridge;
use namada_core::types::ethereum_events::{EthereumEvent, TransferToNamada};
use namada_core::types::token;

use crate::e2e::helpers::{get_actor_rpc, strip_trailing_newline};
use crate::e2e::setup::{
    self, set_ethereum_bridge_mode, Bin, NamadaBgCmd, NamadaCmd, Test, Who,
};
use crate::{run, run_as};

/// Simple client for submitting fake Ethereum events to a Namada node.
pub struct EventsEndpointClient {
    // The client used to send HTTP requests to the Namada node.
    http: Client<HttpConnector, Body>,
    // The URL to which Borsh-serialized Ethereum events should be HTTP POSTed. e.g. "http://0.0.0.0:3030/eth_events"
    events_endpoint: String,
}

impl EventsEndpointClient {
    pub fn new(events_endpoint: String) -> Self {
        Self {
            http: Client::new(),
            events_endpoint,
        }
    }

    /// Sends an Ethereum event to the Namada node. Returns `Ok` iff the event
    /// was successfully sent.
    pub async fn send(&mut self, event: &EthereumEvent) -> Result<()> {
        let event = event.try_to_vec()?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.events_endpoint)
            .header("content-type", "application/octet-stream")
            .body(Body::from(event))?;

        let resp = self
            .http
            .request(req)
            .await
            .wrap_err_with(|| "sending event")?;

        if resp.status() != StatusCode::OK {
            return Err(eyre!("unexpected response status: {}", resp.status()));
        }
        Ok(())
    }
}

/// Sets up the necessary environment for a test involving a single Namada
/// validator that is exposing an endpoint for submission of fake Ethereum
/// events.
pub fn setup_single_validator_test() -> Result<(Test, NamadaBgCmd)> {
    let ethereum_bridge_params = EthereumBridgeConfig {
        min_confirmations: MinimumConfirmations::from(unsafe {
            // SAFETY: The only way the API contract of `NonZeroU64` can
            // be violated is if we construct values
            // of this type using 0 as argument.
            NonZeroU64::new_unchecked(10)
        }),
        contracts: Contracts {
            native_erc20: wnam(),
            bridge: UpgradeableContract {
                address: EthAddress([2; 20]),
                version: ContractVersion::default(),
            },
            governance: UpgradeableContract {
                address: EthAddress([3; 20]),
                version: ContractVersion::default(),
            },
        },
    };

    // use a network-config.toml with eth bridge parameters in it
    let test = setup::network(
        |mut genesis| {
            genesis.ethereum_bridge_params = Some(ethereum_bridge_params);
            genesis
        },
        None,
    )?;

    set_ethereum_bridge_mode(
        &test,
        &test.net.chain_id,
        &Who::Validator(0),
        ethereum_bridge::ledger::Mode::EventsEndpoint,
    );
    let mut ledger =
        run_as!(test, Who::Validator(0), Bin::Node, vec!["ledger"], Some(40))?;

    ledger.exp_string("Namada ledger node started")?;
    ledger.exp_string("This node is a validator")?;
    ledger.exp_regex(r"Committed block hash.*, height: [0-9]+")?;

    let bg_ledger = ledger.background();

    Ok((test, bg_ledger))
}

/// Sends a fake Ethereum event to a Namada node representing a transfer of
/// wrapped ERC20s.
pub async fn send_transfer(
    bg_ledger: NamadaBgCmd,
    transfer: TransferToNamada,
) -> Result<NamadaBgCmd> {
    let transfers = EthereumEvent::TransfersToNamada {
        nonce: 1.into(), // TODO: randomize nonce?
        transfers: vec![transfer.clone()],
    };

    // TODO(namada#1055): right now, we use a hardcoded Ethereum events endpoint
    // address that would only work for e2e tests involving a single
    // validator node - this should become an attribute of the validator under
    // test once the linked issue is implemented
    const ETHEREUM_EVENTS_ENDPOINT: &str = "http://0.0.0.0:3030/eth_events";
    let mut client =
        EventsEndpointClient::new(ETHEREUM_EVENTS_ENDPOINT.to_string());
    client.send(&transfers).await?;

    // wait until the transfer is definitely processed
    let mut ledger = bg_ledger.foreground();
    let TransferToNamada {
        receiver, amount, ..
    } = transfer;
    ledger.exp_string(&format!(
        "Minted wrapped ERC20s - (receiver - {receiver}, amount - {amount})",
    ))?;
    ledger.exp_string("Committed block hash")?;
    Ok(ledger.background())
}

/// Attempt to transfer some wrapped ERC20 from one Namada address to another.
/// This will fail if the keys for `signer` are not in the local wallet.
pub fn attempt_wrapped_erc20_transfer(
    test: &Test,
    node: &Who,
    asset: &EthAddress,
    from: &str,
    to: &str,
    signer: &str,
    amount: &token::Amount,
) -> Result<NamadaCmd> {
    let ledger_address = get_actor_rpc(test, node);

    let eth_bridge_addr = eth_bridge::ADDRESS.to_string();
    let sub_prefix = wrapped_erc20s::sub_prefix(asset).to_string();

    let amount = amount.to_string();
    let transfer_args = vec![
        "transfer",
        "--token",
        &eth_bridge_addr,
        "--sub-prefix",
        &sub_prefix,
        "--source",
        from,
        "--target",
        to,
        "--signer",
        signer,
        "--amount",
        &amount,
        "--ledger-address",
        &ledger_address,
    ];
    run!(test, Bin::Client, transfer_args, Some(40))
}

/// Find the balance of specific wrapped ERC20 for an account.
pub fn find_wrapped_erc20_balance(
    test: &Test,
    node: &Who,
    asset: &EthAddress,
    owner: &Address,
) -> Result<token::Amount> {
    let ledger_address = get_actor_rpc(test, node);

    let sub_prefix = wrapped_erc20s::sub_prefix(asset);
    let prefix =
        token::multitoken_balance_prefix(&eth_bridge::ADDRESS, &sub_prefix);
    let balance_key = token::multitoken_balance_key(&prefix, owner);
    let mut bytes = run!(
        test,
        Bin::Client,
        &[
            "query-bytes",
            "--storage-key",
            &balance_key.to_string(),
            "--ledger-address",
            &ledger_address,
        ],
        Some(10)
    )?;
    let (_, matched) = bytes.exp_regex("Found data: 0x.*")?;
    let data_str = strip_trailing_newline(&matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1[2..]
        .to_string();
    let amount =
        token::Amount::try_from_slice(&HEXLOWER.decode(data_str.as_bytes())?)?;
    bytes.assert_success();
    Ok(amount)
}

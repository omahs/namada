use core::time::Duration;
use std::collections::HashMap;
use std::str::FromStr;

pub use namada::core::ledger::ibc::actions;
use namada::core::types::chain::ChainId;
use namada::ibc::applications::transfer::acknowledgement::Acknowledgement;
use namada::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use namada::ibc::applications::transfer::packet::PacketData;
use namada::ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use namada::ibc::core::ics02_client::msgs::update_client::MsgUpdateClient;
use namada::ibc::core::ics02_client::msgs::upgrade_client::MsgUpgradeClient;
use namada::ibc::core::ics03_connection::connection::Counterparty as ConnCounterparty;
use namada::ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use namada::ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use namada::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use namada::ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use namada::ibc::core::ics03_connection::version::Version as ConnVersion;
use namada::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChanCounterparty, Order, State as ChanState,
};
use namada::ibc::core::ics04_channel::msgs::acknowledgement::MsgAcknowledgement;
use namada::ibc::core::ics04_channel::msgs::chan_close_confirm::MsgChannelCloseConfirm;
use namada::ibc::core::ics04_channel::msgs::chan_close_init::MsgChannelCloseInit;
use namada::ibc::core::ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck;
use namada::ibc::core::ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm;
use namada::ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
use namada::ibc::core::ics04_channel::msgs::chan_open_try::MsgChannelOpenTry;
use namada::ibc::core::ics04_channel::msgs::recv_packet::MsgRecvPacket;
use namada::ibc::core::ics04_channel::msgs::timeout::MsgTimeout;
use namada::ibc::core::ics04_channel::msgs::timeout_on_close::MsgTimeoutOnClose;
use namada::ibc::core::ics04_channel::packet::{Packet, Sequence};
use namada::ibc::core::ics04_channel::timeout::TimeoutHeight;
use namada::ibc::core::ics04_channel::Version as ChanVersion;
use namada::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use namada::ibc::mock::client_state::MockClientState;
use namada::ibc::mock::consensus_state::MockConsensusState;
use namada::ibc::mock::header::MockHeader;
use namada::ibc::proofs::{ConsensusProof, Proofs};
use namada::ibc::signer::Signer;
use namada::ibc::timestamp::Timestamp;
use namada::ibc::Height;
use namada::ibc_proto::cosmos::base::v1beta1::Coin;
use namada::ibc_proto::google::protobuf::Any;
use namada::ibc_proto::ibc::core::commitment::v1::MerkleProof;
use namada::ibc_proto::ibc::core::connection::v1::MsgConnectionOpenTry as RawMsgConnectionOpenTry;
use namada::ibc_proto::ics23::CommitmentProof;
use namada::ibc_proto::protobuf::Protobuf;
use namada::ledger::gas::VpGasMeter;
use namada::ledger::ibc::init_genesis_storage;
pub use namada::ledger::ibc::storage::{
    ack_key, capability_index_key, capability_key, channel_counter_key,
    channel_key, client_counter_key, client_state_key, client_type_key,
    commitment_key, connection_counter_key, connection_key,
    consensus_state_key, next_sequence_ack_key, next_sequence_recv_key,
    next_sequence_send_key, port_key, receipt_key,
};
use namada::ledger::ibc::vp::{
    get_dummy_header as tm_dummy_header, Ibc, IbcToken,
};
use namada::ledger::native_vp::{Ctx, NativeVp};
use namada::ledger::storage::mockdb::MockDB;
use namada::ledger::storage::Sha256Hasher;
use namada::ledger::tx_env::TxEnv;
use namada::proto::Tx;
use namada::types::address::{self, Address, InternalAddress};
use namada::types::storage::{self, BlockHash, BlockHeight, Key, TxIndex};
use namada::types::token::{self, Amount};
use namada::vm::{wasm, WasmCacheRwAccess};
use namada_tx_prelude::StorageWrite;
use prost::Message;

use crate::tx::{self, *};

const VP_ALWAYS_TRUE_WASM: &str = "../wasm_for_tests/vp_always_true.wasm";
const ADDRESS: Address = Address::Internal(InternalAddress::Ibc);

pub struct TestIbcVp<'a> {
    pub ibc: Ibc<'a, MockDB, Sha256Hasher, WasmCacheRwAccess>,
}

impl<'a> TestIbcVp<'a> {
    pub fn validate(
        &self,
        tx_data: &[u8],
    ) -> std::result::Result<bool, namada::ledger::ibc::vp::Error> {
        self.ibc.validate_tx(
            tx_data,
            self.ibc.ctx.keys_changed,
            self.ibc.ctx.verifiers,
        )
    }
}

pub struct TestIbcTokenVp<'a> {
    pub token: IbcToken<'a, MockDB, Sha256Hasher, WasmCacheRwAccess>,
}

impl<'a> TestIbcTokenVp<'a> {
    pub fn validate(
        &self,
        tx_data: &[u8],
    ) -> std::result::Result<bool, namada::ledger::ibc::vp::IbcTokenError> {
        self.token.validate_tx(
            tx_data,
            self.token.ctx.keys_changed,
            self.token.ctx.verifiers,
        )
    }
}

/// Validate an IBC transaction with IBC VP.
pub fn validate_ibc_vp_from_tx<'a>(
    tx_env: &'a TestTxEnv,
    tx: &'a Tx,
) -> std::result::Result<bool, namada::ledger::ibc::vp::Error> {
    let (verifiers, keys_changed) = tx_env
        .write_log
        .verifiers_and_changed_keys(&tx_env.verifiers);
    let addr = Address::Internal(InternalAddress::Ibc);
    if !verifiers.contains(&addr) {
        panic!(
            "IBC address {} isn't part of the tx verifiers set: {:#?}",
            addr, verifiers
        );
    }
    let (vp_wasm_cache, _vp_cache_dir) =
        wasm::compilation_cache::common::testing::cache();

    let ctx = Ctx::new(
        &ADDRESS,
        &tx_env.storage,
        &tx_env.write_log,
        tx,
        &TxIndex(0),
        VpGasMeter::new(0),
        &keys_changed,
        &verifiers,
        vp_wasm_cache,
    );
    let ibc = Ibc::new(ctx, &ChainId::default());

    TestIbcVp { ibc }.validate(tx.data.as_ref().unwrap())
}

/// Validate the native token VP for the given address
pub fn validate_token_vp_from_tx<'a>(
    tx_env: &'a TestTxEnv,
    tx: &'a Tx,
    target: &Key,
) -> std::result::Result<bool, namada::ledger::ibc::vp::IbcTokenError> {
    let (verifiers, keys_changed) = tx_env
        .write_log
        .verifiers_and_changed_keys(&tx_env.verifiers);
    if !keys_changed.contains(target) {
        panic!(
            "The given target address {} isn't part of the tx verifiers set: \
             {:#?}",
            target, keys_changed,
        );
    }
    let (vp_wasm_cache, _vp_cache_dir) =
        wasm::compilation_cache::common::testing::cache();

    let ctx = Ctx::new(
        &ADDRESS,
        &tx_env.storage,
        &tx_env.write_log,
        tx,
        &TxIndex(0),
        VpGasMeter::new(0),
        &keys_changed,
        &verifiers,
        vp_wasm_cache,
    );
    let token = IbcToken { ctx };

    TestIbcTokenVp { token }.validate(tx.data.as_ref().unwrap())
}

/// Initialize the test storage. Requires initialized [`tx_host_env::ENV`].
pub fn init_storage() -> (Address, Address) {
    tx_host_env::with(|env| {
        init_genesis_storage(&mut env.storage);
        // block header to check timeout timestamp
        env.storage.set_header(tm_dummy_header()).unwrap();
        env.storage
            .begin_block(BlockHash::default(), BlockHeight(1))
            .unwrap();
    });

    // initialize a token
    let code = std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");
    let token = tx::ctx().init_account(code.clone()).unwrap();

    // initialize an account
    let account = tx::ctx().init_account(code).unwrap();
    let key = token::balance_key(&token, &account);
    let init_bal = Amount::from(1_000_000_000u64);
    tx::ctx().write(&key, init_bal).unwrap();
    (token, account)
}

pub fn prepare_client() -> (ClientId, Any, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    let msg = msg_create_client();
    // client state
    let client_state = actions::decode_client_state(msg.client_state.clone())
        .expect("invalid client state");
    let client_id = actions::client_id(client_state.client_type(), 0)
        .expect("invalid client ID");
    let key = client_state_key(&client_id);
    let bytes = msg.client_state.encode_to_vec();
    writes.insert(key, bytes);
    // client type
    let key = client_type_key(&client_id);
    let client_type = client_state.client_type();
    let bytes = client_type.as_str().as_bytes().to_vec();
    writes.insert(key, bytes);
    // consensus state
    let height = client_state.latest_height();
    let key = consensus_state_key(&client_id, height);
    let bytes = msg.consensus_state.encode_to_vec();
    writes.insert(key, bytes);
    // client counter
    let key = client_counter_key();
    let bytes = 1_u64.to_be_bytes().to_vec();
    writes.insert(key, bytes);

    (client_id, msg.client_state, writes)
}

pub fn prepare_opened_connection(
    client_id: &ClientId,
) -> (ConnectionId, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    let conn_id = actions::connection_id(0);
    let key = connection_key(&conn_id);
    let msg = msg_connection_open_init(client_id.clone());
    let mut conn = actions::init_connection(&msg);
    actions::open_connection(&mut conn);
    let bytes = conn.encode_vec().expect("encoding failed");
    writes.insert(key, bytes);
    // connection counter
    let key = connection_counter_key();
    let bytes = 1_u64.to_be_bytes().to_vec();
    writes.insert(key, bytes);

    (conn_id, writes)
}

pub fn prepare_opened_channel(
    conn_id: &ConnectionId,
    is_ordered: bool,
) -> (PortId, ChannelId, HashMap<storage::Key, Vec<u8>>) {
    let mut writes = HashMap::new();

    // port
    let port_id = actions::port_id("test_port").expect("invalid port ID");
    let key = port_key(&port_id);
    writes.insert(key, 0_u64.to_be_bytes().to_vec());
    // capability
    let key = capability_key(0);
    let bytes = port_id.as_bytes().to_vec();
    writes.insert(key, bytes);
    // channel
    let channel_id = actions::channel_id(0);
    let port_channel_id =
        actions::port_channel_id(port_id.clone(), channel_id.clone());
    let key = channel_key(&port_channel_id);
    let msg = msg_channel_open_init(port_id.clone(), conn_id.clone());
    let mut channel = msg.chan_end_on_a;
    actions::open_channel(&mut channel);
    if !is_ordered {
        channel.ordering = Order::Unordered;
    }
    let bytes = channel.encode_vec().expect("encoding failed");
    writes.insert(key, bytes);

    (port_id, channel_id, writes)
}

pub fn msg_create_client() -> MsgCreateClient {
    let height = Height::new(0, 1).expect("invalid height");
    let header = MockHeader {
        height,
        timestamp: Timestamp::now(),
    };
    let client_state = MockClientState::new(header).into();
    let consensus_state = MockConsensusState::new(header).into();
    MsgCreateClient {
        client_state,
        consensus_state,
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_update_client(client_id: ClientId) -> MsgUpdateClient {
    let height = Height::new(0, 2).expect("invalid height");
    let header = MockHeader {
        height,
        timestamp: Timestamp::now(),
    }
    .into();
    MsgUpdateClient {
        client_id,
        header,
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_upgrade_client(client_id: ClientId) -> MsgUpgradeClient {
    let height = Height::new(0, 1).expect("invalid height");
    let header = MockHeader {
        height,
        timestamp: Timestamp::now(),
    };
    let client_state = MockClientState::new(header).into();
    let consensus_state = MockConsensusState::new(header).into();
    let proof_upgrade_client = MerkleProof {
        proofs: vec![CommitmentProof { proof: None }],
    };
    let proof_upgrade_consensus_state = MerkleProof {
        proofs: vec![CommitmentProof { proof: None }],
    };
    MsgUpgradeClient {
        client_id,
        client_state,
        consensus_state,
        proof_upgrade_client,
        proof_upgrade_consensus_state,
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_connection_open_init(client_id: ClientId) -> MsgConnectionOpenInit {
    MsgConnectionOpenInit {
        client_id_on_a: client_id,
        counterparty: dummy_connection_counterparty(),
        version: None,
        delay_period: Duration::new(100, 0),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_connection_open_try(
    client_id: ClientId,
    client_state: Any,
) -> MsgConnectionOpenTry {
    let proofs = dummy_proofs();
    let consensus_height = actions::decode_client_state(client_state.clone())
        .expect("invalid client state")
        .latest_height();
    // Convert a message from RawMsgConnectionOpenTry
    // because MsgConnectionOpenTry cannot be created directly
    #[allow(deprecated)]
    RawMsgConnectionOpenTry {
        client_id: client_id.as_str().to_string(),
        previous_connection_id: ConnectionId::default().to_string(),
        client_state: Some(client_state),
        counterparty: Some(dummy_connection_counterparty().into()),
        delay_period: 100000000,
        counterparty_versions: vec![ConnVersion::default().into()],
        proof_init: proofs.object_proof().clone().into(),
        proof_height: Some(proofs.height().into()),
        proof_consensus: proofs
            .consensus_proof()
            .unwrap()
            .proof()
            .clone()
            .into(),
        consensus_height: Some(consensus_height.into()),
        proof_client: proofs.client_proof().clone().unwrap().into(),
        signer: "test".to_string(),
    }
    .try_into()
    .expect("invalid message")
}

pub fn msg_connection_open_ack(
    connection_id: ConnectionId,
    client_state: Any,
) -> MsgConnectionOpenAck {
    let height = actions::decode_client_state(client_state.clone())
        .expect("invalid client")
        .latest_height();
    let counterparty_connection_id =
        ConnectionId::from_str("counterpart_test_connection")
            .expect("Creating a connection ID failed");
    let proofs = dummy_proofs();
    MsgConnectionOpenAck {
        conn_id_on_a: connection_id,
        conn_id_on_b: counterparty_connection_id,
        client_state_of_a_on_b: client_state,
        proof_conn_end_on_b: proofs.object_proof().clone(),
        proof_client_state_of_a_on_b: proofs.client_proof().clone().unwrap(),
        proof_consensus_state_of_a_on_b: proofs
            .consensus_proof()
            .unwrap()
            .proof()
            .clone(),
        proofs_height_on_b: proofs.height(),
        consensus_height_of_a_on_b: height,
        version: ConnVersion::default(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_connection_open_confirm(
    connection_id: ConnectionId,
) -> MsgConnectionOpenConfirm {
    let proofs = dummy_proofs();
    MsgConnectionOpenConfirm {
        conn_id_on_b: connection_id,
        proof_conn_end_on_a: proofs.object_proof().clone(),
        proof_height_on_a: proofs.height(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

fn dummy_proofs() -> Proofs {
    let height = Height::new(0, 1).expect("invalid height");
    let consensus_proof =
        ConsensusProof::new(vec![0].try_into().unwrap(), height).unwrap();
    Proofs::new(
        vec![0].try_into().unwrap(),
        Some(vec![0].try_into().unwrap()),
        Some(consensus_proof),
        None,
        height,
    )
    .unwrap()
}

fn dummy_connection_counterparty() -> ConnCounterparty {
    let counterpart_client_id = ClientId::from_str("counterpart_test_client")
        .expect("Creating a client ID failed");
    let counterpart_conn_id =
        ConnectionId::from_str("counterpart_test_connection")
            .expect("Creating a connection ID failed");
    actions::connection_counterparty(counterpart_client_id, counterpart_conn_id)
}

pub fn msg_channel_open_init(
    port_id: PortId,
    conn_id: ConnectionId,
) -> MsgChannelOpenInit {
    MsgChannelOpenInit {
        port_id_on_a: port_id,
        chan_end_on_a: dummy_channel(ChanState::Init, Order::Ordered, conn_id),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_channel_open_try(
    port_id: PortId,
    conn_id: ConnectionId,
) -> MsgChannelOpenTry {
    let proofs = dummy_proofs();
    #[allow(deprecated)]
    MsgChannelOpenTry {
        port_id_on_b: port_id,
        chan_end_on_b: dummy_channel(
            ChanState::TryOpen,
            Order::Ordered,
            conn_id,
        ),
        version_on_a: ChanVersion::ics20(),
        proof_chan_end_on_a: proofs.object_proof().clone(),
        proof_height_on_a: proofs.height(),
        signer: Signer::from_str("test").expect("invalid signer"),
        previous_channel_id: "dummy".to_string(),
    }
}

pub fn msg_channel_open_ack(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelOpenAck {
    let proofs = dummy_proofs();
    MsgChannelOpenAck {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        chan_id_on_b: dummy_channel_counterparty()
            .channel_id()
            .unwrap()
            .clone(),
        version_on_b: ChanVersion::ics20(),
        proof_chan_end_on_b: proofs.object_proof().clone(),
        proof_height_on_b: proofs.height(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_channel_open_confirm(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelOpenConfirm {
    let proofs = dummy_proofs();
    MsgChannelOpenConfirm {
        port_id_on_b: port_id,
        chan_id_on_b: channel_id,
        proof_chan_end_on_a: proofs.object_proof().clone(),
        proof_height_on_a: proofs.height(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_channel_close_init(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelCloseInit {
    MsgChannelCloseInit {
        port_id_on_a: port_id,
        chan_id_on_a: channel_id,
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_channel_close_confirm(
    port_id: PortId,
    channel_id: ChannelId,
) -> MsgChannelCloseConfirm {
    let proofs = dummy_proofs();
    MsgChannelCloseConfirm {
        port_id_on_b: port_id,
        chan_id_on_b: channel_id,
        proof_chan_end_on_a: proofs.object_proof().clone(),
        proof_height_on_a: proofs.height(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

fn dummy_channel(
    state: ChanState,
    order: Order,
    connection_id: ConnectionId,
) -> ChannelEnd {
    ChannelEnd::new(
        state,
        order,
        dummy_channel_counterparty(),
        vec![connection_id],
        ChanVersion::ics20(),
    )
}

pub fn dummy_channel_counterparty() -> ChanCounterparty {
    let counterpart_port_id = PortId::from_str("counterpart_test_port")
        .expect("Creating a port ID failed");
    let counterpart_channel_id = ChannelId::from_str("channel-42")
        .expect("Creating a channel ID failed");
    actions::channel_counterparty(counterpart_port_id, counterpart_channel_id)
}

pub fn unorder_channel(channel: &mut ChannelEnd) {
    channel.ordering = Order::Unordered;
}

pub fn msg_transfer(
    port_id: PortId,
    channel_id: ChannelId,
    token: String,
    sender: &Address,
) -> MsgTransfer {
    let timeout_timestamp =
        (Timestamp::now() + Duration::from_secs(100)).unwrap();
    MsgTransfer {
        source_port: port_id,
        source_channel: channel_id,
        token: Coin {
            denom: token,
            amount: 100u64.to_string(),
        },
        sender: Signer::from_str(&sender.to_string()).expect("invalid signer"),
        receiver: Signer::from_str(
            &address::testing::gen_established_address().to_string(),
        )
        .expect("invalid signer"),
        timeout_height: TimeoutHeight::Never,
        timeout_timestamp,
    }
}

pub fn set_timeout_timestamp(msg: &mut MsgTransfer) {
    msg.timeout_timestamp =
        (msg.timeout_timestamp - Duration::from_secs(101)).unwrap();
}

pub fn msg_packet_recv(packet: Packet) -> MsgRecvPacket {
    MsgRecvPacket {
        packet,
        proofs: dummy_proofs(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_packet_ack(packet: Packet) -> MsgAcknowledgement {
    let packet_ack = Acknowledgement::success();
    let acknowledgement = serde_json::to_vec(&packet_ack)
        .expect("Encoding acknowledgement shouldn't fail")
        .into();
    MsgAcknowledgement {
        packet,
        acknowledgement,
        proofs: dummy_proofs(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn received_packet(
    port_id: PortId,
    channel_id: ChannelId,
    sequence: Sequence,
    token: String,
    receiver: &Address,
) -> Packet {
    let counterparty = dummy_channel_counterparty();
    let timeout_timestamp =
        (Timestamp::now() + Duration::from_secs(100)).unwrap();
    let coin = actions::prefixed_coin(token, 100u64.to_string())
        .expect("invalid denom");
    let sender = address::testing::gen_established_address().to_string();
    let data = PacketData {
        token: coin,
        sender: Signer::from_str(&sender).expect("invalid signer"),
        receiver: Signer::from_str(&receiver.to_string())
            .expect("invalid signer"),
    };
    Packet {
        sequence,
        source_port: counterparty.port_id().clone(),
        source_channel: counterparty.channel_id().unwrap().clone(),
        destination_port: port_id,
        destination_channel: channel_id,
        data: serde_json::to_vec(&data).unwrap(),
        timeout_height: TimeoutHeight::Never,
        timeout_timestamp,
    }
}

pub fn msg_timeout(packet: Packet, next_sequence_recv: Sequence) -> MsgTimeout {
    MsgTimeout {
        packet,
        next_sequence_recv,
        proofs: dummy_proofs(),
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn msg_timeout_on_close(
    packet: Packet,
    next_sequence_recv: Sequence,
) -> MsgTimeoutOnClose {
    // add the channel proof
    let height = Height::new(0, 1).expect("invalid height");
    let consensus_proof =
        ConsensusProof::new(vec![0].try_into().unwrap(), height).unwrap();
    let proofs = Proofs::new(
        vec![0].try_into().unwrap(),
        Some(vec![0].try_into().unwrap()),
        Some(consensus_proof),
        Some(vec![0].try_into().unwrap()),
        height,
    )
    .unwrap();
    MsgTimeoutOnClose {
        packet,
        next_sequence_recv,
        proofs,
        signer: Signer::from_str("test").expect("invalid signer"),
    }
}

pub fn packet_from_message(
    msg: &MsgTransfer,
    sequence: Sequence,
    counterparty: &ChanCounterparty,
) -> Packet {
    let coin = actions::prefixed_coin(&msg.token.denom, &msg.token.amount)
        .expect("Converting coin failed");
    let packet_data = PacketData {
        token: coin,
        sender: msg.sender.clone(),
        receiver: msg.receiver.clone(),
    };
    let data =
        serde_json::to_vec(&packet_data).expect("Encoding PacketData failed");

    Packet {
        sequence,
        source_port: msg.source_port.clone(),
        source_channel: msg.source_channel.clone(),
        destination_port: counterparty.port_id.clone(),
        destination_channel: counterparty
            .channel_id()
            .expect("the counterparty channel should exist")
            .clone(),
        data,
        timeout_height: msg.timeout_height,
        timeout_timestamp: msg.timeout_timestamp,
    }
}

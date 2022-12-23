//! Functions to handle IBC modules

use std::str::FromStr;

use prost::Message;
use sha2::Digest;
use thiserror::Error;

use crate::ibc::applications::transfer::acknowledgement::{
    Acknowledgement, ACK_ERR_STR,
};
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::applications::transfer::{
    is_receiver_chain_source, is_sender_chain_source, Amount as TransferAmount,
    PrefixedCoin, PrefixedDenom, TracePrefix,
};
use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::clients::ics07_tendermint::header::Header as TmHeader;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::client_type::ClientType;
use crate::ibc::core::ics02_client::events::{
    CreateClient, UpdateClient, UpgradeClient,
};
use crate::ibc::core::ics02_client::header::Header;
use crate::ibc::core::ics02_client::height::Height;
use crate::ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use crate::ibc::core::ics02_client::msgs::update_client::MsgUpdateClient;
use crate::ibc::core::ics02_client::msgs::upgrade_client::MsgUpgradeClient;
use crate::ibc::core::ics02_client::msgs::ClientMsg;
use crate::ibc::core::ics03_connection::connection::{
    ConnectionEnd, Counterparty as ConnCounterparty, State as ConnState,
};
use crate::ibc::core::ics03_connection::events::{
    OpenAck as ConnOpenAck, OpenConfirm as ConnOpenConfirm,
    OpenInit as ConnOpenInit, OpenTry as ConnOpenTry,
};
use crate::ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use crate::ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use crate::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use crate::ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use crate::ibc::core::ics03_connection::msgs::ConnectionMsg;
use crate::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty as ChanCounterparty, Order, State as ChanState,
};
use crate::ibc::core::ics04_channel::commitment::PacketCommitment;
use crate::ibc::core::ics04_channel::events::{
    AcknowledgePacket, CloseConfirm as ChanCloseConfirm,
    CloseInit as ChanCloseInit, OpenAck as ChanOpenAck,
    OpenConfirm as ChanOpenConfirm, OpenInit as ChanOpenInit,
    OpenTry as ChanOpenTry, SendPacket, TimeoutPacket, WriteAcknowledgement,
};
use crate::ibc::core::ics04_channel::msgs::acknowledgement::MsgAcknowledgement;
use crate::ibc::core::ics04_channel::msgs::chan_close_confirm::MsgChannelCloseConfirm;
use crate::ibc::core::ics04_channel::msgs::chan_close_init::MsgChannelCloseInit;
use crate::ibc::core::ics04_channel::msgs::chan_open_ack::MsgChannelOpenAck;
use crate::ibc::core::ics04_channel::msgs::chan_open_confirm::MsgChannelOpenConfirm;
use crate::ibc::core::ics04_channel::msgs::chan_open_init::MsgChannelOpenInit;
use crate::ibc::core::ics04_channel::msgs::chan_open_try::MsgChannelOpenTry;
use crate::ibc::core::ics04_channel::msgs::recv_packet::MsgRecvPacket;
use crate::ibc::core::ics04_channel::msgs::timeout::MsgTimeout;
use crate::ibc::core::ics04_channel::msgs::timeout_on_close::MsgTimeoutOnClose;
use crate::ibc::core::ics04_channel::msgs::{ChannelMsg, PacketMsg};
use crate::ibc::core::ics04_channel::packet::{Packet, Sequence};
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use crate::ibc::core::ics24_host::error::ValidationError as Ics24Error;
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
};
use crate::ibc::core::ics26_routing::msgs::Ics26Envelope;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::client_state::MockClientState;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::consensus_state::MockConsensusState;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::header::MockHeader;
use crate::ibc::timestamp::Timestamp;
use crate::ibc_proto::google::protobuf::Any;
use crate::ibc_proto::protobuf::{Error as IbcProtobufError, Protobuf};
use crate::ledger::ibc::data::{
    Error as IbcDataError, IbcMessage, PacketReceipt,
};
use crate::ledger::ibc::storage;
use crate::ledger::storage_api;
use crate::tendermint::Time;
use crate::tendermint_proto::abci::Event as AbciEvent;
use crate::tendermint_proto::Protobuf as TmProtobuf;
use crate::types::address::{Address, InternalAddress};
use crate::types::ibc::IbcEvent as NamadaIbcEvent;
use crate::types::storage::{BlockHeight, Key};
use crate::types::time::Rfc3339String;
use crate::types::token::{self, Amount};

const COMMITMENT_PREFIX: &[u8] = b"ibc";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid client error: {0}")]
    ClientId(Ics24Error),
    #[error("Invalid port error: {0}")]
    PortId(Ics24Error),
    #[error("Updating a client error: {0}")]
    ClientUpdate(String),
    #[error("IBC data error: {0}")]
    IbcData(IbcDataError),
    #[error("Decoding prost data error: {0}")]
    Decoding(prost::DecodeError),
    #[error("Decoding IBC data error: {0}")]
    IbcDecoding(IbcProtobufError),
    #[error("Client error: {0}")]
    Client(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Counter error: {0}")]
    Counter(String),
    #[error("Sequence error: {0}")]
    Sequence(String),
    #[error("Time error: {0}")]
    Time(String),
    #[error("Invalid transfer message: {0}")]
    TransferMessage(token::TransferError),
    #[error("Sending a token error: {0}")]
    SendingToken(String),
    #[error("Receiving a token error: {0}")]
    ReceivingToken(String),
    #[error("IBC storage error: {0}")]
    IbcStorage(storage::Error),
}

// This is needed to use `ibc::Handler::Error` with `IbcActions` in
// `tx_prelude/src/ibc.rs`
impl From<Error> for storage_api::Error {
    fn from(err: Error) -> Self {
        storage_api::Error::new(err)
    }
}

/// for handling IBC modules
pub type Result<T> = std::result::Result<T, Error>;

/// IBC trait to be implemented in integration that can read and write
pub trait IbcActions {
    /// IBC action error
    type Error: From<Error>;

    /// Read IBC-related data
    fn read_ibc_data(
        &self,
        key: &Key,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    /// Write IBC-related data
    fn write_ibc_data(
        &mut self,
        key: &Key,
        data: impl AsRef<[u8]>,
    ) -> std::result::Result<(), Self::Error>;

    /// Delete IBC-related data
    fn delete_ibc_data(
        &mut self,
        key: &Key,
    ) -> std::result::Result<(), Self::Error>;

    /// Emit an IBC event
    fn emit_ibc_event(
        &mut self,
        event: NamadaIbcEvent,
    ) -> std::result::Result<(), Self::Error>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> std::result::Result<(), Self::Error>;

    /// Get the current height of this chain
    fn get_height(&self) -> std::result::Result<BlockHeight, Self::Error>;

    /// Get the current time of the tendermint header of this chain
    fn get_header_time(
        &self,
    ) -> std::result::Result<Rfc3339String, Self::Error>;

    /// dispatch according to ICS26 routing
    fn dispatch_ibc_action(
        &mut self,
        tx_data: &[u8],
    ) -> std::result::Result<(), Self::Error> {
        let ibc_msg = IbcMessage::decode(tx_data).map_err(Error::IbcData)?;
        match &ibc_msg {
            IbcMessage::Ics26(envelope) => match envelope {
                Ics26Envelope::Ics2Msg(ics02_msg) => match ics02_msg {
                    ClientMsg::CreateClient(msg) => self.create_client(msg),
                    ClientMsg::UpdateClient(msg) => self.update_client(msg),
                    ClientMsg::Misbehaviour(_msg) => todo!(),
                    ClientMsg::UpgradeClient(msg) => self.upgrade_client(msg),
                },
                Ics26Envelope::Ics3Msg(ics03_msg) => match ics03_msg {
                    ConnectionMsg::ConnectionOpenInit(msg) => {
                        self.init_connection(msg)
                    }
                    ConnectionMsg::ConnectionOpenTry(msg) => {
                        self.try_connection(msg)
                    }
                    ConnectionMsg::ConnectionOpenAck(msg) => {
                        self.ack_connection(msg)
                    }
                    ConnectionMsg::ConnectionOpenConfirm(msg) => {
                        self.confirm_connection(msg)
                    }
                },
                Ics26Envelope::Ics4ChannelMsg(ics04_msg) => match ics04_msg {
                    ChannelMsg::ChannelOpenInit(msg) => self.init_channel(msg),
                    ChannelMsg::ChannelOpenTry(msg) => self.try_channel(msg),
                    ChannelMsg::ChannelOpenAck(msg) => self.ack_channel(msg),
                    ChannelMsg::ChannelOpenConfirm(msg) => {
                        self.confirm_channel(msg)
                    }
                    ChannelMsg::ChannelCloseInit(msg) => {
                        self.close_init_channel(msg)
                    }
                    ChannelMsg::ChannelCloseConfirm(msg) => {
                        self.close_confirm_channel(msg)
                    }
                },
                Ics26Envelope::Ics4PacketMsg(ics04_msg) => match ics04_msg {
                    PacketMsg::AckPacket(msg) => self.acknowledge_packet(msg),
                    PacketMsg::RecvPacket(msg) => self.receive_packet(msg),
                    PacketMsg::TimeoutPacket(msg) => self.timeout_packet(msg),
                    PacketMsg::TimeoutOnClosePacket(msg) => {
                        self.timeout_on_close_packet(msg)
                    }
                },
            },
            IbcMessage::Ics20(msg) => self.send_token(msg),
        }
    }

    /// Create a new client
    fn create_client(
        &mut self,
        msg: &MsgCreateClient,
    ) -> std::result::Result<(), Self::Error> {
        let counter_key = storage::client_counter_key();
        let counter = self.get_and_inc_counter(&counter_key)?;
        let client_state = decode_client_state(msg.client_state.clone())?;
        let client_type = client_state.client_type();
        let client_id = client_id(client_type.clone(), counter)?;
        // client type
        let client_type_key = storage::client_type_key(&client_id);
        self.write_ibc_data(&client_type_key, client_type.as_str().as_bytes())?;
        // client state
        let client_state_key = storage::client_state_key(&client_id);
        self.write_ibc_data(
            &client_state_key,
            &msg.client_state.encode_to_vec(),
        )?;
        // consensus state
        let height = client_state.latest_height();
        let consensus_state_key =
            storage::consensus_state_key(&client_id, height);
        self.write_ibc_data(
            &consensus_state_key,
            &msg.consensus_state.encode_to_vec(),
        )?;
        // the creation time and height
        self.set_client_update_time(&client_id)?;

        let event = make_create_client_event(&client_id, msg)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Update a client
    fn update_client(
        &mut self,
        msg: &MsgUpdateClient,
    ) -> std::result::Result<(), Self::Error> {
        // get and update the client
        let client_id = msg.client_id.clone();
        let client_state_key = storage::client_state_key(&client_id);
        let value =
            self.read_ibc_data(&client_state_key)?.ok_or_else(|| {
                Error::Client(format!(
                    "The client to be updated doesn't exist: ID {}",
                    client_id
                ))
            })?;
        let any_client_state =
            Any::decode(&value[..]).map_err(Error::Decoding)?;
        let (new_client_state, new_consensus_state) =
            update_client(any_client_state, msg.header.clone())?;

        let client_state = decode_client_state(new_client_state.clone())?;
        let height = client_state.latest_height();
        self.write_ibc_data(
            &client_state_key,
            new_client_state.encode_to_vec(),
        )?;
        let consensus_state_key =
            storage::consensus_state_key(&client_id, height);
        self.write_ibc_data(
            &consensus_state_key,
            new_consensus_state.encode_to_vec(),
        )?;

        self.set_client_update_time(&client_id)?;

        let event = make_update_client_event(&client_id, msg)
            .try_into()
            .unwrap();
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Upgrade a client
    fn upgrade_client(
        &mut self,
        msg: &MsgUpgradeClient,
    ) -> std::result::Result<(), Self::Error> {
        let client_state_key = storage::client_state_key(&msg.client_id);
        let client_state = decode_client_state(msg.client_state.clone())?;
        let height = client_state.latest_height();
        let consensus_state_key =
            storage::consensus_state_key(&msg.client_id, height);
        self.write_ibc_data(
            &client_state_key,
            msg.client_state.encode_to_vec(),
        )?;
        self.write_ibc_data(
            &consensus_state_key,
            msg.consensus_state.encode_to_vec(),
        )?;

        self.set_client_update_time(&msg.client_id)?;

        let event = make_upgrade_client_event(&msg.client_id, msg)
            .try_into()
            .unwrap();
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Initialize a connection for ConnectionOpenInit
    fn init_connection(
        &mut self,
        msg: &MsgConnectionOpenInit,
    ) -> std::result::Result<(), Self::Error> {
        let counter_key = storage::connection_counter_key();
        let counter = self.get_and_inc_counter(&counter_key)?;
        // new connection
        let conn_id = connection_id(counter);
        let conn_key = storage::connection_key(&conn_id);
        let connection = init_connection(msg);
        self.write_ibc_data(
            &conn_key,
            connection.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_init_connection_event(&conn_id, msg);
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Initialize a connection for ConnectionOpenTry
    fn try_connection(
        &mut self,
        msg: &MsgConnectionOpenTry,
    ) -> std::result::Result<(), Self::Error> {
        let counter_key = storage::connection_counter_key();
        let counter = self.get_and_inc_counter(&counter_key)?;
        // new connection
        let conn_id = connection_id(counter);
        let conn_key = storage::connection_key(&conn_id);
        let connection = try_connection(msg);
        self.write_ibc_data(
            &conn_key,
            connection.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_try_connection_event(&conn_id, msg)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Open the connection for ConnectionOpenAck
    fn ack_connection(
        &mut self,
        msg: &MsgConnectionOpenAck,
    ) -> std::result::Result<(), Self::Error> {
        let conn_key = storage::connection_key(&msg.conn_id_on_a);
        let value = self.read_ibc_data(&conn_key)?.ok_or_else(|| {
            Error::Connection(format!(
                "The connection to be opened doesn't exist: ID {}",
                msg.conn_id_on_a
            ))
        })?;
        let mut connection =
            ConnectionEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        open_connection(&mut connection);
        let mut counterparty = connection.counterparty().clone();
        counterparty.connection_id = Some(msg.conn_id_on_b.clone());
        connection.set_counterparty(counterparty.clone());
        self.write_ibc_data(
            &conn_key,
            connection.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_ack_connection_event(
            connection.client_id(),
            counterparty.client_id(),
            msg,
        );
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Open the connection for ConnectionOpenConfirm
    fn confirm_connection(
        &mut self,
        msg: &MsgConnectionOpenConfirm,
    ) -> std::result::Result<(), Self::Error> {
        let conn_key = storage::connection_key(&msg.conn_id_on_b);
        let value = self.read_ibc_data(&conn_key)?.ok_or_else(|| {
            Error::Connection(format!(
                "The connection to be opend doesn't exist: ID {}",
                msg.conn_id_on_b
            ))
        })?;
        let mut connection =
            ConnectionEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        open_connection(&mut connection);
        self.write_ibc_data(
            &conn_key,
            connection.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_confirm_connection_event(
            connection.client_id(),
            &connection.counterparty(),
            msg,
        )?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Initialize a channel for ChannelOpenInit
    fn init_channel(
        &mut self,
        msg: &MsgChannelOpenInit,
    ) -> std::result::Result<(), Self::Error> {
        self.bind_port(&msg.port_id_on_a)?;
        let counter_key = storage::channel_counter_key();
        let counter = self.get_and_inc_counter(&counter_key)?;
        let channel_id = channel_id(counter);
        let port_channel_id =
            port_channel_id(msg.port_id_on_a.clone(), channel_id.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        self.write_ibc_data(
            &channel_key,
            msg.chan_end_on_a
                .encode_vec()
                .expect("encoding shouldn't fail"),
        )?;

        let event = make_open_init_channel_event(&channel_id, msg);
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Initialize a channel for ChannelOpenTry
    fn try_channel(
        &mut self,
        msg: &MsgChannelOpenTry,
    ) -> std::result::Result<(), Self::Error> {
        self.bind_port(&msg.port_id_on_b)?;
        let counter_key = storage::channel_counter_key();
        let counter = self.get_and_inc_counter(&counter_key)?;
        let channel_id = channel_id(counter);
        let port_channel_id =
            port_channel_id(msg.port_id_on_b.clone(), channel_id.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        self.write_ibc_data(
            &channel_key,
            msg.chan_end_on_b
                .encode_vec()
                .expect("encoding shouldn't fail"),
        )?;

        let event = make_open_try_channel_event(&channel_id, msg)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Open the channel for ChannelOpenAck
    fn ack_channel(
        &mut self,
        msg: &MsgChannelOpenAck,
    ) -> std::result::Result<(), Self::Error> {
        let port_channel_id =
            port_channel_id(msg.port_id_on_a.clone(), msg.chan_id_on_a.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be opened doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        channel.set_counterparty_channel_id(msg.chan_id_on_b.clone());
        open_channel(&mut channel);
        self.write_ibc_data(
            &channel_key,
            channel.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_ack_channel_event(msg, &channel)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Open the channel for ChannelOpenConfirm
    fn confirm_channel(
        &mut self,
        msg: &MsgChannelOpenConfirm,
    ) -> std::result::Result<(), Self::Error> {
        let port_channel_id =
            port_channel_id(msg.port_id_on_b.clone(), msg.chan_id_on_b.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be opened doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        open_channel(&mut channel);
        self.write_ibc_data(
            &channel_key,
            channel.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_open_confirm_channel_event(msg, &channel)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Close the channel for ChannelCloseInit
    fn close_init_channel(
        &mut self,
        msg: &MsgChannelCloseInit,
    ) -> std::result::Result<(), Self::Error> {
        let port_channel_id =
            port_channel_id(msg.port_id_on_a.clone(), msg.chan_id_on_a.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        close_channel(&mut channel);
        self.write_ibc_data(
            &channel_key,
            channel.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_close_init_channel_event(msg, &channel)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Close the channel for ChannelCloseConfirm
    fn close_confirm_channel(
        &mut self,
        msg: &MsgChannelCloseConfirm,
    ) -> std::result::Result<(), Self::Error> {
        let port_channel_id =
            port_channel_id(msg.port_id_on_b.clone(), msg.chan_id_on_b.clone());
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        close_channel(&mut channel);
        self.write_ibc_data(
            &channel_key,
            channel.encode_vec().expect("encoding shouldn't fail"),
        )?;

        let event = make_close_confirm_channel_event(msg, &channel)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Send a packet
    fn send_packet(
        &mut self,
        port_channel_id: PortChannelId,
        data: Vec<u8>,
        timeout_height: TimeoutHeight,
        timeout_timestamp: Timestamp,
    ) -> std::result::Result<(), Self::Error> {
        // get and increment the next sequence send
        let seq_key = storage::next_sequence_send_key(&port_channel_id);
        let sequence = self.get_and_inc_sequence(&seq_key)?;

        // get the channel for the destination info.
        let channel_key = storage::channel_key(&port_channel_id);
        let channel = self
            .read_ibc_data(&channel_key)?
            .expect("cannot get the channel to be closed");
        let channel =
            ChannelEnd::decode_vec(&channel).expect("cannot get the channel");
        let counterparty = channel.counterparty();

        // make a packet
        let packet = Packet {
            sequence,
            source_port: port_channel_id.port_id.clone(),
            source_channel: port_channel_id.channel_id.clone(),
            destination_port: counterparty.port_id.clone(),
            destination_channel: counterparty
                .channel_id()
                .expect("the counterparty channel should exist")
                .clone(),
            data,
            timeout_height,
            timeout_timestamp,
        };
        // store the commitment of the packet
        let commitment_key = storage::commitment_key(
            &port_channel_id.port_id,
            &port_channel_id.channel_id,
            packet.sequence,
        );
        let commitment = commitment(&packet);
        self.write_ibc_data(&commitment_key, commitment.into_vec())?;

        let connection_id =
            channel.connection_hops().first().ok_or_else(|| {
                Error::Channel(format!(
                    "No connection ID for the channel exists: port {}, \
                     channel {}",
                    port_channel_id.port_id, port_channel_id.channel_id
                ))
            })?;
        let event =
            make_send_packet_event(packet, channel.ordering(), connection_id)?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Receive a packet
    fn receive_packet(
        &mut self,
        msg: &MsgRecvPacket,
    ) -> std::result::Result<(), Self::Error> {
        // check the packet data
        let packet_ack =
            if let Ok(data) = serde_json::from_slice(&msg.packet.data) {
                match self.receive_token(&msg.packet, &data) {
                    Ok(_) => Acknowledgement::success(),
                    Err(_) => Acknowledgement::Error(format!(
                        "{}: {}",
                        ACK_ERR_STR,
                        "receiving a token failed".to_string(),
                    )),
                }
            } else {
                Acknowledgement::Error(format!(
                    "{}: {}",
                    ACK_ERR_STR,
                    "unknown packet data".to_string()
                ))
            };

        // store the receipt
        let receipt_key = storage::receipt_key(
            &msg.packet.destination_port,
            &msg.packet.destination_channel,
            msg.packet.sequence,
        );
        self.write_ibc_data(&receipt_key, PacketReceipt::default().as_bytes())?;

        // store the ack
        let ack_key = storage::ack_key(
            &msg.packet.destination_port,
            &msg.packet.destination_channel,
            msg.packet.sequence,
        );
        let ack = serde_json::to_vec(&packet_ack)
            .expect("Encoding acknowledgement shouldn't fail");
        let ack_commitment = sha2::Sha256::digest(&ack).to_vec();
        self.write_ibc_data(&ack_key, ack_commitment)?;

        // increment the next sequence receive
        let port_channel_id = port_channel_id(
            msg.packet.destination_port.clone(),
            msg.packet.destination_channel.clone(),
        );
        let seq_key = storage::next_sequence_recv_key(&port_channel_id);
        self.get_and_inc_sequence(&seq_key)?;

        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        let connection_id =
            channel.connection_hops().first().ok_or_else(|| {
                Error::Channel(format!(
                    "No connection ID for the channel exists: port {}, \
                     channel {}",
                    port_channel_id.port_id, port_channel_id.channel_id
                ))
            })?;
        let event = make_write_ack_event(
            msg.packet.clone(),
            &packet_ack,
            connection_id,
        )?;
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Receive a acknowledgement
    fn acknowledge_packet(
        &mut self,
        msg: &MsgAcknowledgement,
    ) -> std::result::Result<(), Self::Error> {
        if msg.acknowledgement().as_bytes()
            != Acknowledgement::success().as_ref()
        {
            match serde_json::from_slice::<PacketData>(&msg.packet.data) {
                Ok(data) => self.refund_token(&msg.packet, &data)?,
                Err(e) => {
                    return Err(Error::Channel(format!(
                        "Packet of MsgAcknowledgement has unknown data : \
                         error {}",
                        e
                    ))
                    .into());
                }
            }
        }

        let commitment_key = storage::commitment_key(
            &msg.packet.source_port,
            &msg.packet.source_channel,
            msg.packet.sequence,
        );
        self.delete_ibc_data(&commitment_key)?;

        // get and increment the next sequence ack
        let port_channel_id = port_channel_id(
            msg.packet.source_port.clone(),
            msg.packet.source_channel.clone(),
        );
        let seq_key = storage::next_sequence_ack_key(&port_channel_id);
        self.get_and_inc_sequence(&seq_key)?;

        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        let connection_id =
            channel.connection_hops().first().ok_or_else(|| {
                Error::Channel(format!(
                    "No connection ID for the channel exists: port {}, \
                     channel {}",
                    port_channel_id.port_id, port_channel_id.channel_id
                ))
            })?;
        let event = make_ack_event(
            msg.packet.clone(),
            channel.ordering(),
            &connection_id,
        );
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Receive a timeout
    fn timeout_packet(
        &mut self,
        msg: &MsgTimeout,
    ) -> std::result::Result<(), Self::Error> {
        // check the packet data
        if let Ok(data) = serde_json::from_slice(&msg.packet.data) {
            self.refund_token(&msg.packet, &data)?;
        }

        // delete the commitment of the packet
        let commitment_key = storage::commitment_key(
            &msg.packet.source_port,
            &msg.packet.source_channel,
            msg.packet.sequence,
        );
        self.delete_ibc_data(&commitment_key)?;

        // close the channel
        let port_channel_id = port_channel_id(
            msg.packet.source_port.clone(),
            msg.packet.source_channel.clone(),
        );
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        if channel.order_matches(&Order::Ordered) {
            close_channel(&mut channel);
            self.write_ibc_data(
                &channel_key,
                channel.encode_vec().expect("encoding shouldn't fail"),
            )?;
        }

        let event = make_timeout_event(msg.packet.clone(), channel.ordering())
            .try_into()
            .unwrap();
        self.emit_ibc_event(event)?;

        Ok(())
    }

    /// Receive a timeout for TimeoutOnClose
    fn timeout_on_close_packet(
        &mut self,
        msg: &MsgTimeoutOnClose,
    ) -> std::result::Result<(), Self::Error> {
        // check the packet data
        if let Ok(data) = serde_json::from_slice(&msg.packet.data) {
            self.refund_token(&msg.packet, &data)?;
        }

        // delete the commitment of the packet
        let commitment_key = storage::commitment_key(
            &msg.packet.source_port,
            &msg.packet.source_channel,
            msg.packet.sequence,
        );
        self.delete_ibc_data(&commitment_key)?;

        // close the channel
        let port_channel_id = port_channel_id(
            msg.packet.source_port.clone(),
            msg.packet.source_channel.clone(),
        );
        let channel_key = storage::channel_key(&port_channel_id);
        let value = self.read_ibc_data(&channel_key)?.ok_or_else(|| {
            Error::Channel(format!(
                "The channel to be closed doesn't exist: Port/Channel {}",
                port_channel_id
            ))
        })?;
        let mut channel =
            ChannelEnd::decode_vec(&value).map_err(Error::IbcDecoding)?;
        if channel.order_matches(&Order::Ordered) {
            close_channel(&mut channel);
            self.write_ibc_data(
                &channel_key,
                channel.encode_vec().expect("encoding shouldn't fail"),
            )?;
        }

        Ok(())
    }

    /// Set the timestamp and the height for the client update
    fn set_client_update_time(
        &mut self,
        client_id: &ClientId,
    ) -> std::result::Result<(), Self::Error> {
        let time = Time::parse_from_rfc3339(&self.get_header_time()?.0)
            .map_err(|e| {
                Error::Time(format!("The time of the header is invalid: {}", e))
            })?;
        let key = storage::client_update_timestamp_key(client_id);
        self.write_ibc_data(
            &key,
            time.encode_vec().expect("encoding shouldn't fail"),
        )?;

        // the revision number is always 0
        let height = Height::new(0, self.get_height()?.0)
            .expect("The conversion shouldn't fail");
        let height_key = storage::client_update_height_key(client_id);
        // write the current height as u64
        self.write_ibc_data(
            &height_key,
            height.encode_vec().expect("Encoding shouldn't fail"),
        )?;

        Ok(())
    }

    /// Get and increment the counter
    fn get_and_inc_counter(
        &mut self,
        key: &Key,
    ) -> std::result::Result<u64, Self::Error> {
        let value = self.read_ibc_data(key)?.ok_or_else(|| {
            Error::Counter(format!("The counter doesn't exist: {}", key))
        })?;
        let value: [u8; 8] = value.try_into().map_err(|_| {
            Error::Counter(format!("The counter value wasn't u64: Key {}", key))
        })?;
        let counter = u64::from_be_bytes(value);
        self.write_ibc_data(key, (counter + 1).to_be_bytes())?;
        Ok(counter)
    }

    /// Get and increment the sequence
    fn get_and_inc_sequence(
        &mut self,
        key: &Key,
    ) -> std::result::Result<Sequence, Self::Error> {
        let index = match self.read_ibc_data(key)? {
            Some(v) => {
                let index: [u8; 8] = v.try_into().map_err(|_| {
                    Error::Sequence(format!(
                        "The sequence index wasn't u64: Key {}",
                        key
                    ))
                })?;
                u64::from_be_bytes(index)
            }
            // when the sequence has never been used, returns the initial value
            None => 1,
        };
        self.write_ibc_data(key, (index + 1).to_be_bytes())?;
        Ok(index.into())
    }

    /// Bind a new port
    fn bind_port(
        &mut self,
        port_id: &PortId,
    ) -> std::result::Result<(), Self::Error> {
        let port_key = storage::port_key(port_id);
        match self.read_ibc_data(&port_key)? {
            Some(_) => {}
            None => {
                // create a new capability and claim it
                let index_key = storage::capability_index_key();
                let cap_index = self.get_and_inc_counter(&index_key)?;
                self.write_ibc_data(&port_key, cap_index.to_be_bytes())?;
                let cap_key = storage::capability_key(cap_index);
                self.write_ibc_data(&cap_key, port_id.as_bytes())?;
            }
        }
        Ok(())
    }

    /// Send the specified token by escrowing or burning
    fn send_token(
        &mut self,
        msg: &MsgTransfer,
    ) -> std::result::Result<(), Self::Error> {
        // update the deom if it has IbcToken
        let denom = if let Some(hash) =
            storage::token_hash_from_denom(&msg.token.denom)
                .map_err(Error::IbcStorage)?
        {
            let denom_key = storage::ibc_denom_key(hash);
            let denom_bytes =
                self.read_ibc_data(&denom_key)?.ok_or_else(|| {
                    Error::SendingToken(format!(
                        "No original denom: denom_key {}",
                        denom_key
                    ))
                })?;
            let denom = std::str::from_utf8(&denom_bytes).map_err(|e| {
                Error::SendingToken(format!(
                    "Decoding the denom failed: denom_key {}, error {}",
                    denom_key, e
                ))
            })?;
            denom.to_string()
        } else {
            msg.token.denom.clone()
        };
        let coin = PrefixedCoin {
            denom: PrefixedDenom::from_str(&denom).map_err(|e| {
                Error::SendingToken(format!(
                    "Decoding the denom failed: denom {}, error {}",
                    denom, e
                ))
            })?,
            amount: TransferAmount::from_str(&msg.token.amount).map_err(
                |e| {
                    Error::SendingToken(format!(
                        "Decoding the amount failed: amount {}, error {}",
                        msg.token.amount, e
                    ))
                },
            )?,
        };
        let token = storage::token(&coin).map_err(Error::IbcStorage)?;

        let source_addr = Address::decode(&msg.sender).map_err(|e| {
            Error::SendingToken(format!(
                "Invalid sender address: sender {}, error {}",
                msg.sender, e
            ))
        })?;

        let amount = storage::amount(&coin).map_err(Error::IbcStorage)?;

        let (source, target) = if is_sender_chain_source(
            msg.source_port.clone(),
            msg.source_channel.clone(),
            &coin.denom,
        ) {
            // this chain is the source
            // escrow the amount of the token
            let src = if coin.denom.trace_path.is_empty() {
                token::balance_key(&token, &source_addr)
            } else {
                let key_prefix = storage::ibc_token_prefix(&coin)
                    .map_err(Error::IbcStorage)?;
                token::multitoken_balance_key(&key_prefix, &source_addr)
            };

            let key_prefix = storage::ibc_account_prefix(
                &msg.source_port,
                &msg.source_channel,
                &token,
            );
            let escrow = token::multitoken_balance_key(
                &key_prefix,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            (src, escrow)
        } else {
            // the receiver's chain was the source
            // transfer from the origin-specific account of the token
            let key_prefix =
                storage::ibc_token_prefix(&coin).map_err(Error::IbcStorage)?;
            let src = token::multitoken_balance_key(&key_prefix, &source_addr);

            let key_prefix = storage::ibc_account_prefix(
                &msg.source_port,
                &msg.source_channel,
                &token,
            );
            let burn = token::multitoken_balance_key(
                &key_prefix,
                &Address::Internal(InternalAddress::IbcBurn),
            );
            (src, burn)
        };
        self.transfer_token(&source, &target, amount)?;

        let data = PacketData {
            token: coin,
            sender: msg.sender.clone(),
            receiver: msg.receiver.clone(),
        };
        let packet_data =
            serde_json::to_vec(&data).expect("Encoding PacketData failed");

        // send a packet
        let port_channel_id = port_channel_id(
            msg.source_port.clone(),
            msg.source_channel.clone(),
        );
        self.send_packet(
            port_channel_id,
            packet_data,
            msg.timeout_height,
            msg.timeout_timestamp,
        )
    }

    /// Receive the specified token by unescrowing or minting
    fn receive_token(
        &mut self,
        packet: &Packet,
        data: &PacketData,
    ) -> std::result::Result<(), Self::Error> {
        let token = storage::token(&data.token).map_err(Error::IbcStorage)?;
        let amount = storage::amount(&data.token).map_err(Error::IbcStorage)?;

        // The receiver should be an address because the origin-specific account
        // key should be assigned internally
        let dest_addr = Address::decode(&data.receiver).map_err(|e| {
            Error::ReceivingToken(format!(
                "Invalid receiver address: receiver {}, error {}",
                data.receiver, e
            ))
        })?;

        let mut coin = data.token.clone();
        let (source, target) = if is_receiver_chain_source(
            packet.source_port.clone(),
            packet.source_channel.clone(),
            &coin.denom,
        ) {
            // unescrow the token because this chain was the source
            let escrow_prefix = storage::ibc_account_prefix(
                &packet.destination_port,
                &packet.destination_channel,
                &token,
            );
            let escrow = token::multitoken_balance_key(
                &escrow_prefix,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            let dest = if coin.denom.trace_path.is_empty() {
                token::balance_key(&token, &dest_addr)
            } else {
                let key_prefix = storage::ibc_token_prefix(&coin)
                    .map_err(Error::IbcStorage)?;
                token::multitoken_balance_key(&key_prefix, &dest_addr)
            };
            (escrow, dest)
        } else {
            // mint the token because the sender chain is the source
            let key_prefix = storage::ibc_account_prefix(
                &packet.destination_port,
                &packet.destination_channel,
                &token,
            );
            let mint = token::multitoken_balance_key(
                &key_prefix,
                &Address::Internal(InternalAddress::IbcMint),
            );

            // prefix the denom with the this chain port and channel
            let prefix = TracePrefix::new(
                packet.destination_port.clone(),
                packet.destination_channel.clone(),
            );
            coin.denom.add_trace_prefix(prefix);
            let key_prefix =
                storage::ibc_token_prefix(&coin).map_err(Error::IbcStorage)?;
            let dest = token::multitoken_balance_key(&key_prefix, &dest_addr);

            // store the prefixed denom as String
            let token_hash = storage::calc_hash(&coin.denom.to_string());
            let denom_key = storage::ibc_denom_key(token_hash);
            self.write_ibc_data(&denom_key, coin.denom.to_string().as_bytes())?;

            (mint, dest)
        };
        self.transfer_token(&source, &target, amount)?;

        Ok(())
    }

    /// Refund the specified token by unescrowing or minting
    fn refund_token(
        &mut self,
        packet: &Packet,
        data: &PacketData,
    ) -> std::result::Result<(), Self::Error> {
        let token = storage::token(&data.token).map_err(Error::IbcStorage)?;
        let amount = storage::amount(&data.token).map_err(Error::IbcStorage)?;

        let dest_addr = Address::decode(&data.sender).map_err(|e| {
            Error::SendingToken(format!(
                "Invalid sender address: sender {}, error {}",
                data.sender, e
            ))
        })?;

        let coin = &data.token;
        let (source, target) = if is_sender_chain_source(
            packet.source_port.clone(),
            packet.source_channel.clone(),
            &data.token.denom,
        ) {
            // unescrow the token because the acount was escrowed
            let dest = if coin.denom.trace_path.is_empty() {
                token::balance_key(&token, &dest_addr)
            } else {
                let key_prefix = storage::ibc_token_prefix(coin)
                    .map_err(Error::IbcStorage)?;
                token::multitoken_balance_key(&key_prefix, &dest_addr)
            };

            let key_prefix = storage::ibc_account_prefix(
                &packet.source_port,
                &packet.source_channel,
                &token,
            );
            let escrow = token::multitoken_balance_key(
                &key_prefix,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            (escrow, dest)
        } else {
            // mint the token because the amount was burned
            let key_prefix = storage::ibc_account_prefix(
                &packet.source_port,
                &packet.source_channel,
                &token,
            );
            let mint = token::multitoken_balance_key(
                &key_prefix,
                &Address::Internal(InternalAddress::IbcMint),
            );
            let key_prefix =
                storage::ibc_token_prefix(coin).map_err(Error::IbcStorage)?;
            let dest = token::multitoken_balance_key(&key_prefix, &dest_addr);
            (mint, dest)
        };
        self.transfer_token(&source, &target, amount)?;

        Ok(())
    }
}

/// Update a client with the given state and headers
pub fn update_client(client_state: Any, header: Any) -> Result<(Any, Any)> {
    if let Ok(cs) = TmClientState::try_from(client_state.clone()) {
        if let Ok(h) = TmHeader::try_from(header.clone()) {
            let new_client_state = cs
                .with_header(h.clone())
                .map_err(|e| Error::ClientUpdate(e.to_string()))?;
            let new_consensus_state = TmConsensusState::from(h);
            return Ok((new_client_state.into(), new_consensus_state.into()));
        }
    }

    #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
    if let Ok(_) = MockClientState::try_from(client_state.clone()) {
        if let Ok(h) = MockHeader::try_from(header) {
            let new_client_state = MockClientState::new(h);
            let new_consensus_state = MockConsensusState::new(h);
            return Ok((new_client_state.into(), new_consensus_state.into()));
        }
    }

    Err(Error::ClientUpdate(
        "The client state or header type is unknown".to_owned(),
    ))
}

/// Returns a new client ID
pub fn client_id(client_type: ClientType, counter: u64) -> Result<ClientId> {
    ClientId::new(client_type, counter).map_err(Error::ClientId)
}

/// Returns a new connection ID
pub fn connection_id(counter: u64) -> ConnectionId {
    ConnectionId::new(counter)
}

/// Make a connection end from the init message
pub fn init_connection(msg: &MsgConnectionOpenInit) -> ConnectionEnd {
    ConnectionEnd::new(
        ConnState::Init,
        msg.client_id_on_a.clone(),
        msg.counterparty.clone(),
        vec![msg.version.clone().unwrap_or_default()],
        msg.delay_period,
    )
}

/// Make a connection end from the try message
pub fn try_connection(msg: &MsgConnectionOpenTry) -> ConnectionEnd {
    ConnectionEnd::new(
        ConnState::TryOpen,
        msg.client_id_on_b.clone(),
        msg.counterparty.clone(),
        msg.versions_on_a.clone(),
        msg.delay_period,
    )
}

/// Open the connection
pub fn open_connection(conn: &mut ConnectionEnd) {
    conn.set_state(ConnState::Open);
}

/// Returns a new channel ID
pub fn channel_id(counter: u64) -> ChannelId {
    ChannelId::new(counter)
}

/// Open the channel
pub fn open_channel(channel: &mut ChannelEnd) {
    channel.set_state(ChanState::Open);
}

/// Close the channel
pub fn close_channel(channel: &mut ChannelEnd) {
    channel.set_state(ChanState::Closed);
}

/// Returns a port ID
pub fn port_id(id: &str) -> Result<PortId> {
    PortId::from_str(id).map_err(Error::PortId)
}

/// Returns a pair of port ID and channel ID
pub fn port_channel_id(
    port_id: PortId,
    channel_id: ChannelId,
) -> PortChannelId {
    PortChannelId {
        port_id,
        channel_id,
    }
}

/// Returns a sequence
pub fn sequence(index: u64) -> Sequence {
    Sequence::from(index)
}

/// Returns a commitment from the given packet
pub fn commitment(packet: &Packet) -> PacketCommitment {
    let timeout = packet.timeout_timestamp.nanoseconds().to_be_bytes();
    let revision_number = packet
        .timeout_height
        .commitment_revision_number()
        .to_be_bytes();
    let revision_height = packet
        .timeout_height
        .commitment_revision_height()
        .to_be_bytes();
    let data = sha2::Sha256::digest(&packet.data);
    let input = [
        &timeout,
        &revision_number,
        &revision_height,
        data.as_slice(),
    ]
    .concat();
    sha2::Sha256::digest(&input).to_vec().into()
}

/// Returns a counterparty of a connection
pub fn connection_counterparty(
    client_id: ClientId,
    conn_id: ConnectionId,
) -> ConnCounterparty {
    ConnCounterparty::new(client_id, Some(conn_id), commitment_prefix())
}

/// Returns a counterparty of a channel
pub fn channel_counterparty(
    port_id: PortId,
    channel_id: ChannelId,
) -> ChanCounterparty {
    ChanCounterparty::new(port_id, Some(channel_id))
}

/// Returns Namada commitment prefix
pub fn commitment_prefix() -> CommitmentPrefix {
    CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
        .expect("the conversion shouldn't fail")
}

/// Makes CreateClient event
pub fn make_create_client_event(
    client_id: &ClientId,
    msg: &MsgCreateClient,
) -> Result<NamadaIbcEvent> {
    let client_state = decode_client_state(msg.client_state.clone())?;
    Ok(AbciEvent::from(CreateClient::new(
        client_id.clone(),
        client_state.client_type(),
        client_state.latest_height(),
    ))
    .into())
}

/// Makes UpdateClient event
pub fn make_update_client_event(
    client_id: &ClientId,
    msg: &MsgUpdateClient,
) -> NamadaIbcEvent {
    let header = decode_header(msg.header.clone()).unwrap();
    AbciEvent::from(UpdateClient::new(
        client_id.clone(),
        header.client_type(),
        Height::new(0, 0).unwrap(),
        vec![header.height()],
        msg.header.clone(),
    ))
    .into()
}

/// Makes UpgradeClient event
pub fn make_upgrade_client_event(
    client_id: &ClientId,
    msg: &MsgUpgradeClient,
) -> NamadaIbcEvent {
    let client_state = decode_client_state(msg.client_state.clone()).unwrap();
    AbciEvent::from(UpgradeClient::new(
        client_id.clone(),
        client_state.client_type(),
        client_state.latest_height(),
    ))
    .into()
}

/// Makes OpenInitConnection event
pub fn make_open_init_connection_event(
    conn_id: &ConnectionId,
    msg: &MsgConnectionOpenInit,
) -> NamadaIbcEvent {
    AbciEvent::from(ConnOpenInit::new(
        conn_id.clone(),
        msg.client_id_on_a.clone(),
        msg.counterparty.client_id().clone(),
    ))
    .into()
}

/// Makes OpenTryConnection event
pub fn make_open_try_connection_event(
    conn_id: &ConnectionId,
    msg: &MsgConnectionOpenTry,
) -> Result<NamadaIbcEvent> {
    let counterparty_conn_id =
        msg.counterparty.connection_id().ok_or_else(|| {
            Error::Connection("No counterparty connection".to_string())
        })?;
    Ok(AbciEvent::from(ConnOpenTry::new(
        conn_id.clone(),
        msg.client_id_on_b.clone(),
        counterparty_conn_id.clone(),
        msg.counterparty.client_id().clone(),
    ))
    .into())
}

/// Makes OpenAckConnection event
pub fn make_open_ack_connection_event(
    client_id: &ClientId,
    counterparty_client_id: &ClientId,
    msg: &MsgConnectionOpenAck,
) -> NamadaIbcEvent {
    AbciEvent::from(ConnOpenAck::new(
        msg.conn_id_on_a.clone(),
        client_id.clone(),
        msg.conn_id_on_b.clone(),
        counterparty_client_id.clone(),
    ))
    .into()
}

/// Makes OpenConfirmConnection event
pub fn make_open_confirm_connection_event(
    client_id: &ClientId,
    counterparty: &ConnCounterparty,
    msg: &MsgConnectionOpenConfirm,
) -> Result<NamadaIbcEvent> {
    let counterparty_conn_id =
        counterparty.connection_id().ok_or_else(|| {
            Error::Connection("No counterparty connection".to_string())
        })?;
    Ok(AbciEvent::from(ConnOpenConfirm::new(
        msg.conn_id_on_b.clone(),
        client_id.clone(),
        counterparty_conn_id.clone(),
        counterparty.client_id().clone(),
    ))
    .into())
}

/// Makes OpenInitChannel event
pub fn make_open_init_channel_event(
    channel_id: &ChannelId,
    msg: &MsgChannelOpenInit,
) -> NamadaIbcEvent {
    let connection_id = match msg.chan_end_on_a.connection_hops().get(0) {
        Some(c) => c.clone(),
        None => ConnectionId::default(),
    };
    AbciEvent::from(ChanOpenInit::new(
        msg.port_id_on_a.clone(),
        channel_id.clone(),
        msg.port_id_on_a.clone(),
        connection_id,
        msg.chan_end_on_a.version().clone(),
    ))
    .into()
}

/// Makes OpenTryChannel event
pub fn make_open_try_channel_event(
    channel_id: &ChannelId,
    msg: &MsgChannelOpenTry,
) -> Result<NamadaIbcEvent> {
    let connection_id = match msg.chan_end_on_b.connection_hops().get(0) {
        Some(c) => c.clone(),
        None => ConnectionId::default(),
    };
    let counterparty = msg.chan_end_on_b.counterparty();
    let counterparty_channel_id = counterparty
        .channel_id()
        .ok_or_else(|| Error::Channel("No counterparty channel".to_string()))?;
    Ok(AbciEvent::from(ChanOpenTry::new(
        msg.port_id_on_b.clone(),
        channel_id.clone(),
        counterparty.port_id().clone(),
        counterparty_channel_id.clone(),
        connection_id,
        msg.version_on_a.clone(),
    ))
    .into())
}

/// Makes OpenAckChannel event
pub fn make_open_ack_channel_event(
    msg: &MsgChannelOpenAck,
    channel: &ChannelEnd,
) -> Result<NamadaIbcEvent> {
    let conn_id = get_connection_id_from_channel(channel)?;
    let counterparty = channel.counterparty();
    let counterparty_channel_id = counterparty
        .channel_id()
        .ok_or_else(|| Error::Channel("No counterparty channel".to_string()))?;
    Ok(AbciEvent::from(ChanOpenAck::new(
        msg.port_id_on_a.clone(),
        msg.chan_id_on_a.clone(),
        counterparty.port_id().clone(),
        counterparty_channel_id.clone(),
        conn_id.clone(),
    ))
    .into())
}

/// Makes OpenConfirmChannel event
pub fn make_open_confirm_channel_event(
    msg: &MsgChannelOpenConfirm,
    channel: &ChannelEnd,
) -> Result<NamadaIbcEvent> {
    let conn_id = get_connection_id_from_channel(channel)?;
    let counterparty = channel.counterparty();
    let counterparty_channel_id = counterparty
        .channel_id()
        .ok_or_else(|| Error::Channel("No counterparty channel".to_string()))?;
    Ok(AbciEvent::from(ChanOpenConfirm::new(
        msg.port_id_on_b.clone(),
        msg.chan_id_on_b.clone(),
        counterparty.port_id().clone(),
        counterparty_channel_id.clone(),
        conn_id.clone(),
    ))
    .into())
}

/// Makes CloseInitChannel event
pub fn make_close_init_channel_event(
    msg: &MsgChannelCloseInit,
    channel: &ChannelEnd,
) -> Result<NamadaIbcEvent> {
    let conn_id = get_connection_id_from_channel(channel)?;
    let counterparty = channel.counterparty();
    let counterparty_channel_id = counterparty
        .channel_id()
        .ok_or_else(|| Error::Channel("No counterparty channel".to_string()))?;
    Ok(AbciEvent::from(ChanCloseInit::new(
        msg.port_id_on_a.clone(),
        msg.chan_id_on_a.clone(),
        counterparty.port_id().clone(),
        counterparty_channel_id.clone(),
        conn_id.clone(),
    ))
    .into())
}

/// Makes CloseConfirmChannel event
pub fn make_close_confirm_channel_event(
    msg: &MsgChannelCloseConfirm,
    channel: &ChannelEnd,
) -> Result<NamadaIbcEvent> {
    let conn_id = get_connection_id_from_channel(channel)?;
    let counterparty = channel.counterparty();
    let counterparty_channel_id = counterparty
        .channel_id()
        .ok_or_else(|| Error::Channel("No counterparty channel".to_string()))?;
    Ok(AbciEvent::from(ChanCloseConfirm::new(
        msg.port_id_on_b.clone(),
        msg.chan_id_on_b.clone(),
        counterparty.port_id().clone(),
        counterparty_channel_id.clone(),
        conn_id.clone(),
    ))
    .into())
}

fn get_connection_id_from_channel(
    channel: &ChannelEnd,
) -> Result<&ConnectionId> {
    channel.connection_hops().get(0).ok_or_else(|| {
        Error::Channel("No connection for the channel".to_owned())
    })
}

/// Makes SendPacket event
pub fn make_send_packet_event(
    packet: Packet,
    order: &Order,
    connection_id: &ConnectionId,
) -> Result<NamadaIbcEvent> {
    let abci_event = AbciEvent::try_from(SendPacket::new(
        packet,
        order.clone(),
        connection_id.clone(),
    ))
    .map_err(|e| {
        Error::SendingToken(format!(
            "Conversion of SendPacket event failed: error {}",
            e
        ))
    })?;
    Ok(abci_event.into())
}

/// Makes WriteAcknowledgement event
pub fn make_write_ack_event(
    packet: Packet,
    ack: &Acknowledgement,
    connection_id: &ConnectionId,
) -> Result<NamadaIbcEvent> {
    let abci_event = AbciEvent::try_from(WriteAcknowledgement::new(
        packet,
        ack.as_ref().to_vec().into(),
        connection_id.clone(),
    ))
    .map_err(|e| {
        Error::ReceivingToken(format!(
            "Conversion of packet data or acknowledgment failed: error {}",
            e
        ))
    })?;
    Ok(abci_event.into())
}

/// Makes AcknowledgePacket event
pub fn make_ack_event(
    packet: Packet,
    order: &Order,
    connection_id: &ConnectionId,
) -> NamadaIbcEvent {
    let abci_event = AbciEvent::try_from(AcknowledgePacket::new(
        packet,
        order.clone(),
        connection_id.clone(),
    ))
    .expect("The conversion shouldn't fail");
    abci_event.into()
}

/// Makes TimeoutPacket event
pub fn make_timeout_event(packet: Packet, order: &Order) -> NamadaIbcEvent {
    let abci_event =
        AbciEvent::try_from(TimeoutPacket::new(packet, order.clone()))
            .expect("The conversion shouldn't fail");
    abci_event.into()
}

fn decode_client_state(any_client_state: Any) -> Result<Box<dyn ClientState>> {
    if let Ok(client_state) = TmClientState::try_from(any_client_state.clone())
    {
        return Ok(client_state.into_box());
    }

    #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
    if let Ok(client_state) = MockClientState::try_from(any_client_state) {
        return Ok(client_state.into_box());
    }

    Err(Error::Client("Unknown client state was given".to_string()))
}

fn decode_header(any_header: Any) -> Result<Box<dyn Header>> {
    if let Ok(header) = TmHeader::try_from(any_header.clone()) {
        return Ok(header.into_box());
    }

    #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
    if let Ok(header) = MockHeader::try_from(any_header.clone()) {
        return Ok(header.into_box());
    }

    Err(Error::Client("Unknown header was given".to_string()))
}

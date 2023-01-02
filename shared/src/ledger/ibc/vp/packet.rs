//! IBC validity predicate for packets

use namada_core::ledger::ibc::actions::{
    self, make_send_packet_event, make_timeout_event, prefixed_coin,
};
use namada_core::ledger::ibc::data::{Error as IbcDataError, IbcMessage};
use namada_core::ledger::ibc::storage::{
    ibc_denom_key, port_channel_sequence_id, token_hash_from_denom,
    Error as IbcStorageError,
};
use thiserror::Error;

use super::{Ibc, StateChange};
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::core::ics02_client::height::Height;
use crate::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty, Order, State,
};
use crate::ibc::core::ics04_channel::commitment::PacketCommitment;
use crate::ibc::core::ics04_channel::context::ChannelReader;
use crate::ibc::core::ics04_channel::error::Error as Ics04Error;
use crate::ibc::core::ics04_channel::handler::verify::{
    verify_channel_proofs, verify_next_sequence_recv,
    verify_packet_acknowledgement_proofs, verify_packet_receipt_absence,
    verify_packet_recv_proofs,
};
use crate::ibc::core::ics04_channel::msgs::acknowledgement::{
    Acknowledgement, MsgAcknowledgement,
};
use crate::ibc::core::ics04_channel::msgs::recv_packet::MsgRecvPacket;
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics04_channel::packet::{Packet, Sequence};
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, PortChannelId, PortId,
};
use crate::ibc::core::ics26_routing::msgs::Ics26Envelope;
use crate::ibc::proofs::Proofs;
use crate::ledger::native_vp::VpEnv;
use crate::ledger::storage::{self, StorageHasher};
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("State change error: {0}")]
    InvalidStateChange(String),
    #[error("Client error: {0}")]
    InvalidClient(String),
    #[error("Connection error: {0}")]
    InvalidConnection(String),
    #[error("Channel error: {0}")]
    InvalidChannel(String),
    #[error("Port error: {0}")]
    InvalidPort(String),
    #[error("Packet error: {0}")]
    InvalidPacket(String),
    #[error("Proof verification error: {0}")]
    ProofVerificationFailure(Ics04Error),
    #[error("Decoding TX data error: {0}")]
    DecodingTxData(std::io::Error),
    #[error("IBC data error: {0}")]
    InvalidIbcData(IbcDataError),
    #[error("IBC storage error: {0}")]
    IbcStorage(IbcStorageError),
    #[error("IBC event error: {0}")]
    IbcEvent(String),
    #[error("IBC proof error: {0}")]
    Proof(String),
    #[error("IBC denom error: {0}")]
    Denom(String),
}

/// IBC packet functions result
pub type Result<T> = std::result::Result<T, Error>;

enum Phase {
    Send,
    Recv,
    Ack,
}

impl<'a, DB, H, CA> Ibc<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub(super) fn validate_commitment(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<()> {
        let commitment_key = port_channel_sequence_id(key)?;
        match self
            .get_state_change(key)
            .map_err(|e| Error::InvalidStateChange(e.to_string()))?
        {
            StateChange::Created => {
                // sending a packet
                let ibc_msg = IbcMessage::decode(tx_data)?;
                let msg = ibc_msg.msg_transfer()?;
                // make a packet
                let channel = self
                    .channel_end(&commitment_key.0, &commitment_key.1)
                    .map_err(|e| Error::InvalidChannel(e.to_string()))?;
                let packet = self.packet_from_message(
                    &msg,
                    commitment_key.2,
                    channel.counterparty(),
                )?;
                let commitment = self
                    .get_packet_commitment(
                        &commitment_key.0,
                        &commitment_key.1,
                        commitment_key.2,
                    )
                    .map_err(|_| {
                        Error::InvalidPacket(format!(
                            "The commitement doesn't exist: Port {}, Channel \
                             {}, Sequence {}",
                            commitment_key.0,
                            commitment_key.1,
                            commitment_key.2,
                        ))
                    })?;
                self.validate_packet_commitment(&packet, commitment)
                    .map_err(|e| Error::InvalidPacket(e.to_string()))?;

                self.validate_send_packet(&commitment_key, &packet)?;

                let conn_id =
                    channel.connection_hops().first().ok_or_else(|| {
                        Error::InvalidConnection(format!(
                            "No connection for the channel: Port {}, Channel \
                             {}",
                            commitment_key.0, commitment_key.1
                        ))
                    })?;
                let event =
                    make_send_packet_event(packet, channel.ordering(), conn_id)
                        .map_err(|e| Error::IbcEvent(e.to_string()))?;
                self.check_emitted_event(event)
                    .map_err(|e| Error::IbcEvent(e.to_string()))
            }
            StateChange::Deleted => {
                // check the channel state
                let channel = self
                    .channel_end(&commitment_key.0, &commitment_key.1)
                    .map_err(|_| {
                        Error::InvalidChannel(format!(
                            "The channel doesn't exist: Port {}, Channel {}",
                            commitment_key.0, commitment_key.1,
                        ))
                    })?;
                let ibc_msg = IbcMessage::decode(tx_data)?;
                match channel.state() {
                    State::Open => {
                        // "PacketAcknowledgement" or timeout for the unordered
                        // channel
                        match &ibc_msg {
                            IbcMessage::Ics26(
                                Ics26Envelope::Ics4PacketMsg(
                                    PacketMsg::AckPacket(msg),
                                ),
                            ) => self.validate_ack_packet(&commitment_key, msg),
                            IbcMessage::Ics26(
                                Ics26Envelope::Ics4PacketMsg(
                                    PacketMsg::TimeoutPacket(_),
                                ),
                            )
                            | IbcMessage::Ics26(
                                Ics26Envelope::Ics4PacketMsg(
                                    PacketMsg::TimeoutOnClosePacket(_),
                                ),
                            ) => {
                                self.validate_timeout(&commitment_key, &ibc_msg)
                            }
                            _ => Err(Error::InvalidChannel(format!(
                                "The channel state is invalid: Port {}, \
                                 Channel {}",
                                commitment_key.0, commitment_key.1
                            ))),
                        }
                    }
                    State::Closed => {
                        self.validate_timeout(&commitment_key, &ibc_msg)
                    }
                    _ => Err(Error::InvalidChannel(format!(
                        "The channel state is invalid: Port {}, Channel {}",
                        commitment_key.0, commitment_key.1
                    ))),
                }
            }
            _ => Err(Error::InvalidStateChange(format!(
                "The state change of the commitment is invalid: Key {}",
                key
            ))),
        }
    }

    pub(super) fn validate_receipt(
        &self,
        key: &Key,
        tx_data: &[u8],
    ) -> Result<()> {
        match self
            .get_state_change(key)
            .map_err(|e| Error::InvalidStateChange(e.to_string()))?
        {
            StateChange::Created => {
                let receipt_key = port_channel_sequence_id(key)?;
                let ibc_msg = IbcMessage::decode(tx_data)?;
                let msg = ibc_msg.msg_recv_packet()?;
                self.validate_recv_packet(&receipt_key, &msg)
            }
            _ => Err(Error::InvalidStateChange(
                "The state change of the receipt is invalid".to_owned(),
            )),
        }
    }

    pub(super) fn validate_ack(&self, key: &Key) -> Result<()> {
        match self
            .get_state_change(key)
            .map_err(|e| Error::InvalidStateChange(e.to_string()))?
        {
            StateChange::Created => {
                let ack_key = port_channel_sequence_id(key)?;
                // The receipt should have been stored
                self.get_packet_receipt(&ack_key.0, &ack_key.1, ack_key.2)
                    .map_err(|_| {
                        Error::InvalidPacket(format!(
                            "The receipt doesn't exist: Port {}, Channel {}, \
                             Sequence {}",
                            ack_key.0, ack_key.1, ack_key.2,
                        ))
                    })?;
                // The packet is validated in the receipt validation
                Ok(())
            }
            _ => Err(Error::InvalidStateChange(
                "The state change of the acknowledgment is invalid".to_owned(),
            )),
        }
    }

    fn validate_send_packet(
        &self,
        port_channel_seq_id: &(PortId, ChannelId, Sequence),
        packet: &Packet,
    ) -> Result<()> {
        self.validate_packet(port_channel_seq_id, packet, Phase::Send)?;

        self.get_packet_commitment(
            &port_channel_seq_id.0,
            &port_channel_seq_id.1,
            port_channel_seq_id.2,
        )
        .map_err(|_| {
            Error::InvalidPacket(format!(
                "The commitment doesn't exist: Port {}, Channel {}, Sequence \
                 {}",
                port_channel_seq_id.0,
                port_channel_seq_id.1,
                port_channel_seq_id.2
            ))
        })?;

        Ok(())
    }

    fn validate_recv_packet(
        &self,
        port_channel_seq_id: &(PortId, ChannelId, Sequence),
        msg: &MsgRecvPacket,
    ) -> Result<()> {
        self.validate_packet(port_channel_seq_id, &msg.packet, Phase::Recv)?;

        self.get_packet_receipt(
            &port_channel_seq_id.0,
            &port_channel_seq_id.1,
            port_channel_seq_id.2,
        )
        .map_err(|_| {
            Error::InvalidPacket(format!(
                "The receipt doesn't exist: Port {}, Channel {}, Sequence {}",
                port_channel_seq_id.0,
                port_channel_seq_id.1,
                port_channel_seq_id.2
            ))
        })?;
        self.get_packet_acknowledgement(
            &port_channel_seq_id.0,
            &port_channel_seq_id.1,
            port_channel_seq_id.2,
        )
        .map_err(|_| {
            Error::InvalidPacket(format!(
                "The acknowledgement doesn't exist: Port {}, Channel {}, \
                 Sequence {}",
                port_channel_seq_id.0,
                port_channel_seq_id.1,
                port_channel_seq_id.2
            ))
        })?;
        let port_channel_id = PortChannelId {
            port_id: port_channel_seq_id.0.clone(),
            channel_id: port_channel_seq_id.1,
        };
        self.verify_recv_proof(
            &port_channel_id,
            msg.proofs.height(),
            &msg.packet,
            &msg.proofs,
        )
    }

    fn validate_ack_packet(
        &self,
        port_channel_seq_id: &(PortId, ChannelId, Sequence),
        msg: &MsgAcknowledgement,
    ) -> Result<()> {
        self.validate_packet(port_channel_seq_id, &msg.packet, Phase::Ack)?;

        let prev_commitment = self
            .get_packet_commitment_pre(port_channel_seq_id)
            .map_err(|e| Error::InvalidPacket(e.to_string()))?;
        self.validate_packet_commitment(&msg.packet, prev_commitment)?;

        if self
            .get_packet_commitment(
                &port_channel_seq_id.0,
                &port_channel_seq_id.1,
                port_channel_seq_id.2,
            )
            .is_ok()
        {
            return Err(Error::InvalidPacket(
                "The commitment hasn't been deleted yet".to_owned(),
            ));
        }

        let port_channel_id = PortChannelId {
            port_id: port_channel_seq_id.0.clone(),
            channel_id: port_channel_seq_id.1,
        };
        self.verify_ack_proof(
            &port_channel_id,
            msg.proofs.height(),
            &msg.packet,
            msg.acknowledgement.clone(),
            &msg.proofs,
        )
    }

    fn validate_packet(
        &self,
        port_channel_seq_id: &(PortId, ChannelId, Sequence),
        packet: &Packet,
        phase: Phase,
    ) -> Result<()> {
        let (port_id, channel_id, sequence) = port_channel_seq_id;
        let port_channel_id = match phase {
            Phase::Send | Phase::Ack => {
                if *port_id != packet.source_port
                    || *channel_id != packet.source_channel
                    || *sequence != packet.sequence
                {
                    return Err(Error::InvalidPacket(
                        "The packet info invalid".to_owned(),
                    ));
                }
                PortChannelId {
                    port_id: packet.source_port.clone(),
                    channel_id: packet.source_channel,
                }
            }
            Phase::Recv => {
                if *port_id != packet.destination_port
                    || *channel_id != packet.destination_channel
                    || *sequence != packet.sequence
                {
                    return Err(Error::InvalidPacket(
                        "The packet info invalid".to_owned(),
                    ));
                }
                PortChannelId {
                    port_id: packet.destination_port.clone(),
                    channel_id: packet.destination_channel,
                }
            }
        };

        // port authentication
        self.authenticated_capability(&port_channel_id.port_id)
            .map_err(|e| {
                Error::InvalidPort(format!(
                    "The port is not owned: Port {}, {}",
                    port_channel_id.port_id, e
                ))
            })?;

        let channel = self
            .channel_end(&port_channel_id.port_id, &port_channel_id.channel_id)
            .map_err(|_| {
                Error::InvalidChannel(format!(
                    "The channel doesn't exist: Port/Channel {}",
                    port_channel_id,
                ))
            })?;
        if !channel.is_open() {
            return Err(Error::InvalidChannel(format!(
                "The channel isn't open: Port/Channel {}",
                port_channel_id
            )));
        }

        let connection = self
            .connection_from_channel(&channel)
            .map_err(|e| Error::InvalidConnection(e.to_string()))?;
        if !connection.is_open() {
            return Err(Error::InvalidConnection(
                "The connection isn't open".to_owned(),
            ));
        }

        // counterparty consistency
        let counterparty = match phase {
            Phase::Send | Phase::Ack => Counterparty::new(
                packet.destination_port.clone(),
                Some(packet.destination_channel),
            ),
            Phase::Recv => Counterparty::new(
                packet.source_port.clone(),
                Some(packet.source_channel),
            ),
        };
        if !channel.counterparty_matches(&counterparty) {
            return Err(Error::InvalidPacket(
                "The counterpart port or channel is mismatched".to_owned(),
            ));
        }

        // check timeout
        match phase {
            Phase::Send => {
                let client_id = connection.client_id();
                let height = match self.client_state(client_id) {
                    Ok(s) => s.latest_height(),
                    Err(_) => {
                        return Err(Error::InvalidClient(format!(
                            "The client state doesn't exist: ID {}",
                            client_id
                        )));
                    }
                };
                self.check_timeout(client_id, height, packet)
                    .map_err(|e| Error::InvalidPacket(e.to_string()))?;
            }
            Phase::Recv => {
                if packet.timed_out(&self.host_timestamp(), self.host_height())
                {
                    return Err(Error::InvalidPacket(
                        "The packet has timed out".to_owned(),
                    ));
                }
            }
            Phase::Ack => (),
        }

        Ok(())
    }

    fn validate_packet_commitment(
        &self,
        packet: &Packet,
        commitment: PacketCommitment,
    ) -> Result<()> {
        if commitment == actions::commitment(packet) {
            Ok(())
        } else {
            Err(Error::InvalidPacket(
                "The commitment and the packet are mismatched".to_owned(),
            ))
        }
    }

    fn verify_recv_proof(
        &self,
        port_channel_id: &PortChannelId,
        height: Height,
        packet: &Packet,
        proofs: &Proofs,
    ) -> Result<()> {
        let channel = self
            .channel_end(&port_channel_id.port_id, &port_channel_id.channel_id)
            .map_err(|_| {
                Error::InvalidChannel(format!(
                    "The channel doesn't exist: Port/Channel {}",
                    port_channel_id,
                ))
            })?;
        let connection = self
            .connection_from_channel(&channel)
            .map_err(|e| Error::InvalidConnection(e.to_string()))?;

        verify_packet_recv_proofs(self, height, packet, &connection, proofs)
            .map_err(Error::ProofVerificationFailure)
    }

    fn verify_ack_proof(
        &self,
        port_channel_id: &PortChannelId,
        height: Height,
        packet: &Packet,
        ack: Acknowledgement,
        proofs: &Proofs,
    ) -> Result<()> {
        let channel = self
            .channel_end(&port_channel_id.port_id, &port_channel_id.channel_id)
            .map_err(|_| {
                Error::InvalidChannel(format!(
                    "The channel doesn't exist: Port/Channel {}",
                    port_channel_id,
                ))
            })?;
        let connection = self
            .connection_from_channel(&channel)
            .map_err(|e| Error::InvalidConnection(e.to_string()))?;

        verify_packet_acknowledgement_proofs(
            self,
            height,
            packet,
            ack,
            &connection,
            proofs,
        )
        .map_err(Error::ProofVerificationFailure)
    }

    fn validate_timeout(
        &self,
        commitment_key: &(PortId, ChannelId, Sequence),
        ibc_msg: &IbcMessage,
    ) -> Result<()> {
        let (height, proofs, packet, next_sequence_recv) = match &ibc_msg {
            IbcMessage::Ics26(Ics26Envelope::Ics4PacketMsg(
                PacketMsg::TimeoutPacket(msg),
            )) => (
                msg.proofs.height(),
                msg.proofs.clone(),
                msg.packet.clone(),
                msg.next_sequence_recv,
            ),
            IbcMessage::Ics26(Ics26Envelope::Ics4PacketMsg(
                PacketMsg::TimeoutOnClosePacket(msg),
            )) => (
                msg.proofs.height(),
                msg.proofs.clone(),
                msg.packet.clone(),
                msg.next_sequence_recv,
            ),
            _ => {
                return Err(Error::InvalidChannel(format!(
                    "Unexpected message was given for timeout: Port/Channel \
                     {}/{}",
                    commitment_key.0, commitment_key.1,
                )));
            }
        };
        // deleted commitment should be for the packet sent from this channel
        let commitment = self
            .get_packet_commitment_pre(commitment_key)
            .map_err(|e| Error::InvalidPacket(e.to_string()))?;
        self.validate_packet_commitment(&packet, commitment)
            .map_err(|e| Error::InvalidPacket(e.to_string()))?;

        self.authenticated_capability(&packet.source_port)
            .map_err(|e| Error::InvalidPort(e.to_string()))?;

        // the counterparty should be equal to that of the channel
        let port_channel_id = PortChannelId {
            port_id: packet.source_port.clone(),
            channel_id: packet.source_channel,
        };
        let channel = self
            .channel_end(&port_channel_id.port_id, &port_channel_id.channel_id)
            .map_err(|_| {
                Error::InvalidChannel(format!(
                    "The channel doesn't exist: Port/Channel {}",
                    port_channel_id
                ))
            })?;
        let counterparty = Counterparty::new(
            packet.destination_port.clone(),
            Some(packet.destination_channel),
        );
        if !channel.counterparty_matches(&counterparty) {
            return Err(Error::InvalidPacket(format!(
                "The packet is invalid for the counterparty: Port/Channel \
                 {}/{}",
                packet.destination_port, packet.destination_channel
            )));
        }

        let connection = self
            .connection_from_channel(&channel)
            .map_err(|e| Error::InvalidConnection(e.to_string()))?;
        let client_id = connection.client_id().clone();

        // check if the packet actually timed out
        match self.check_timeout(&client_id, proofs.height(), &packet) {
            Ok(()) => {
                // "TimedoutOnClose" because the packet didn't time out
                // check that the counterpart channel has been closed
                let expected_my_side = Counterparty::new(
                    packet.source_port.clone(),
                    Some(packet.source_channel),
                );
                let counterparty = connection.counterparty();
                let conn_id =
                    counterparty.connection_id().ok_or_else(|| {
                        Error::InvalidConnection(
                            "The counterparty doesn't have a connection ID"
                                .to_owned(),
                        )
                    })?;
                let expected_conn_hops = vec![conn_id.clone()];
                let expected_channel = ChannelEnd::new(
                    State::Closed,
                    *channel.ordering(),
                    expected_my_side,
                    expected_conn_hops,
                    channel.version().clone(),
                );

                let proofs_closed = make_proofs_for_channel(&proofs)?;
                verify_channel_proofs(
                    self,
                    height,
                    &channel,
                    &connection,
                    &expected_channel,
                    &proofs_closed,
                )
                .map_err(Error::ProofVerificationFailure)?;
            }
            Err(_) => {
                // the packet timed out
                let event =
                    make_timeout_event(packet.clone(), channel.ordering());
                self.check_emitted_event(event)
                    .map_err(|e| Error::IbcEvent(e.to_string()))?;
            }
        }

        if channel.order_matches(&Order::Ordered) {
            if !channel.state_matches(&State::Closed) {
                return Err(Error::InvalidChannel(format!(
                    "The channel hasn't been closed yet: Port/Channel {}",
                    port_channel_id
                )));
            }
            if packet.sequence < next_sequence_recv {
                return Err(Error::InvalidPacket(
                    "The sequence is invalid. The packet might have been \
                     already received"
                        .to_owned(),
                ));
            }
            match verify_next_sequence_recv(
                self,
                height,
                &connection,
                packet,
                next_sequence_recv,
                &proofs,
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::ProofVerificationFailure(e)),
            }
        } else {
            match verify_packet_receipt_absence(
                self,
                height,
                &connection,
                packet,
                &proofs,
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(Error::ProofVerificationFailure(e)),
            }
        }
    }

    pub(super) fn check_timeout(
        &self,
        client_id: &ClientId,
        current_height: Height,
        packet: &Packet,
    ) -> Result<()> {
        // timeout timestamp
        let consensus_state =
            match self.client_consensus_state(client_id, current_height) {
                Ok(c) => c,
                Err(_) => {
                    return Err(Error::InvalidClient(format!(
                        "The client consensus state doesn't exist: ID {}, \
                         Height {}",
                        client_id, current_height
                    )));
                }
            };
        let current_timestamp = consensus_state.timestamp();

        if packet.timed_out(&current_timestamp, current_height) {
            Err(Error::InvalidPacket(format!(
                "The packet has timed out: Timeout height {}, Timeout \
                 timestamp {}, Current height {}, Current timestamp {}",
                packet.timeout_height,
                packet.timeout_timestamp,
                current_height,
                current_timestamp
            )))
        } else {
            Ok(())
        }
    }

    fn packet_data_from_message(self, msg: &MsgTransfer) -> Result<PacketData> {
        let denom = match token_hash_from_denom(&msg.token.denom)
            .map_err(|e| Error::Denom(format!("Invalid denom: error {}", e)))?
        {
            Some(hash) => {
                let denom_key = ibc_denom_key(hash);
                let denom_bytes = match self.ctx.read_bytes_pre(&denom_key) {
                    Ok(Some(v)) => v,
                    _ => {
                        return Err(Error::Denom(format!(
                            "No original denom: denom_key {}",
                            denom_key
                        )));
                    }
                };
                let denom = std::str::from_utf8(&denom_bytes).map_err(|e| {
                    Error::Denom(format!(
                        "Decoding the denom failed: denom_key {}, error {}",
                        denom_key, e
                    ))
                })?;
                denom.to_string()
            }
            None => msg.token.denom.clone(),
        };
        let coin = prefixed_coin(&denom, &msg.token.amount)
            .map_err(|e| Error::Denom(e.to_string()))?;

        Ok(PacketData {
            token: coin,
            sender: msg.sender.clone(),
            receiver: msg.receiver.clone(),
        })
    }

    pub(super) fn packet_from_message(
        &self,
        msg: &MsgTransfer,
        sequence: Sequence,
        counterparty: &Counterparty,
    ) -> Result<Packet> {
        let data = self.packet_data_from_message(msg)?;
        let data =
            serde_json::to_vec(&data).expect("Encoding PacketData failed");
        let destination_channel = counterparty
            .channel_id()
            .ok_or_else(|| {
                Error::InvalidChannel(format!(
                    "The counterparty channel doesn't exist: Port/Channel \
                     {}/{}",
                    msg.source_port, msg.source_channel
                ))
            })?
            .clone();

        Ok(Packet {
            sequence,
            source_port: msg.source_port.clone(),
            source_channel: msg.source_channel,
            destination_port: counterparty.port_id.clone(),
            destination_channel,
            data,
            timeout_height: msg.timeout_height,
            timeout_timestamp: msg.timeout_timestamp,
        })
    }
}

/// The proof for the counterpart channel should be in proofs.other_proof
/// `verify_channel_proofs()` requires the proof is in proofs.object_proof
fn make_proofs_for_channel(proofs: &Proofs) -> Result<Proofs> {
    let proof_closed = match proofs.other_proof() {
        Some(p) => p.clone(),
        None => {
            return Err(Error::Proof(
                "No proof for the counterpart channel".to_string(),
            ));
        }
    };
    Proofs::new(proof_closed, None, None, None, proofs.height()).map_err(|e| {
        Error::Proof(format!(
            "Creating Proofs for the counterpart channel failed: error {}",
            e
        ))
    })
}

impl From<IbcStorageError> for Error {
    fn from(err: IbcStorageError) -> Self {
        Self::IbcStorage(err)
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

//! IBC-related data definitions.
use std::convert::TryFrom;

use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::msgs::transfer::{self, MsgTransfer};
use crate::ibc::core::ics02_client::msgs::create_client::MsgCreateClient;
use crate::ibc::core::ics02_client::msgs::misbehaviour::MsgSubmitMisbehaviour;
use crate::ibc::core::ics02_client::msgs::update_client::MsgUpdateClient;
use crate::ibc::core::ics02_client::msgs::upgrade_client::MsgUpgradeClient;
use crate::ibc::core::ics02_client::msgs::ClientMsg;
use crate::ibc::core::ics03_connection::msgs::conn_open_ack::MsgConnectionOpenAck;
use crate::ibc::core::ics03_connection::msgs::conn_open_confirm::MsgConnectionOpenConfirm;
use crate::ibc::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
use crate::ibc::core::ics03_connection::msgs::conn_open_try::MsgConnectionOpenTry;
use crate::ibc::core::ics03_connection::msgs::ConnectionMsg;
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
use crate::ibc::core::ics04_channel::packet::Receipt;
use crate::ibc::core::ics26_routing::msgs::Ics26Envelope;
use crate::ibc::downcast;
use crate::ibc_proto::google::protobuf::Any;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding IBC data error: {0}")]
    DecodingData(prost::DecodeError),
    #[error("Decoding Json data error: {0}")]
    DecodingJsonData(serde_json::Error),
    #[error("Decoding message error: {0}")]
    DecodingMessage(String),
    #[error("Downcast error: {0}")]
    Downcast(String),
}

/// Decode result for IBC data
pub type Result<T> = std::result::Result<T, Error>;

/// IBC Message
#[derive(Debug, Clone)]
pub enum IbcMessage {
    /// ICS20 message to transfer a token
    Ics20(MsgTransfer),
    /// ICS26 envelope to handle IBC modules
    Ics26(Ics26Envelope),
}

impl TryFrom<Any> for IbcMessage {
    type Error = Error;

    fn try_from(message: Any) -> Result<Self> {
        match message.type_url.as_str() {
            transfer::TYPE_URL => {
                let msg = MsgTransfer::try_from(message)
                    .map_err(|e| Error::DecodingMessage(e.to_string()))?;
                Ok(Self::Ics20(msg))
            }
            _ => {
                let envelope = Ics26Envelope::try_from(message)
                    .map_err(|e| Error::DecodingMessage(e.to_string()))?;
                Ok(Self::Ics26(envelope))
            }
        }
    }
}

impl IbcMessage {
    /// Decode an IBC message from transaction data
    pub fn decode(tx_data: &[u8]) -> Result<Self> {
        let msg = Any::decode(tx_data).map_err(Error::DecodingData)?;
        msg.try_into()
    }

    /// Get the IBC message of CreateClient
    pub fn msg_create_any_client(self) -> Result<MsgCreateClient> {
        let ics02_msg = self.ics02_msg()?;
        downcast!(ics02_msg => ClientMsg::CreateClient).ok_or_else(|| {
            Error::Downcast(
                "The message is not a CreateClient message".to_string(),
            )
        })
    }

    /// Get the IBC message of UpdateClient
    pub fn msg_update_any_client(self) -> Result<MsgUpdateClient> {
        let ics02_msg = self.ics02_msg()?;
        downcast!(ics02_msg => ClientMsg::UpdateClient).ok_or_else(|| {
            Error::Downcast(
                "The message is not a UpdateClient message".to_string(),
            )
        })
    }

    /// Get the IBC message of Misbehaviour
    pub fn msg_submit_any_misbehaviour(self) -> Result<MsgSubmitMisbehaviour> {
        let ics02_msg = self.ics02_msg()?;
        downcast!(ics02_msg => ClientMsg::Misbehaviour).ok_or_else(|| {
            Error::Downcast(
                "The message is not a Misbehaviour message".to_string(),
            )
        })
    }

    /// Get the IBC message of UpgradeClient
    pub fn msg_upgrade_any_client(self) -> Result<MsgUpgradeClient> {
        let ics02_msg = self.ics02_msg()?;
        downcast!(ics02_msg => ClientMsg::UpgradeClient).ok_or_else(|| {
            Error::Downcast(
                "The message is not a UpgradeClient message".to_string(),
            )
        })
    }

    /// Get the IBC message of ConnectionOpenInit
    pub fn msg_connection_open_init(self) -> Result<MsgConnectionOpenInit> {
        let ics03_msg = self.ics03_msg()?;
        downcast!(ics03_msg => ConnectionMsg::ConnectionOpenInit).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ConnectionOpenInit message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ConnectionOpenTry
    pub fn msg_connection_open_try(self) -> Result<Box<MsgConnectionOpenTry>> {
        let ics03_msg = self.ics03_msg()?;
        downcast!(ics03_msg => ConnectionMsg::ConnectionOpenTry).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ConnectionOpenTry message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ConnectionOpenAck
    pub fn msg_connection_open_ack(self) -> Result<Box<MsgConnectionOpenAck>> {
        let ics03_msg = self.ics03_msg()?;
        downcast!(ics03_msg => ConnectionMsg::ConnectionOpenAck).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ConnectionOpenAck message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ConnectionOpenConfirm
    pub fn msg_connection_open_confirm(
        self,
    ) -> Result<MsgConnectionOpenConfirm> {
        let ics03_msg = self.ics03_msg()?;
        downcast!(ics03_msg => ConnectionMsg::ConnectionOpenConfirm).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ConnectionOpenAck message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ChannelOpenInit
    pub fn msg_channel_open_init(self) -> Result<MsgChannelOpenInit> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelOpenInit).ok_or_else(|| {
            Error::Downcast(
                "The message is not a ChannelOpenInit message".to_string(),
            )
        })
    }

    /// Get the IBC message of ChannelOpenTry
    pub fn msg_channel_open_try(self) -> Result<MsgChannelOpenTry> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelOpenTry).ok_or_else(|| {
            Error::Downcast(
                "The message is not a ChannelOpenTry message".to_string(),
            )
        })
    }

    /// Get the IBC message of ChannelOpenAck
    pub fn msg_channel_open_ack(self) -> Result<MsgChannelOpenAck> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelOpenAck).ok_or_else(|| {
            Error::Downcast(
                "The message is not a ChannelOpenAck message".to_string(),
            )
        })
    }

    /// Get the IBC message of ChannelOpenConfirm
    pub fn msg_channel_open_confirm(self) -> Result<MsgChannelOpenConfirm> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelOpenConfirm).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ChannelOpenConfirm message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ChannelCloseInit
    pub fn msg_channel_close_init(self) -> Result<MsgChannelCloseInit> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelCloseInit).ok_or_else(|| {
            Error::Downcast(
                "The message is not a ChannelCloseInit message".to_string(),
            )
        })
    }

    /// Get the IBC message of ChannelCloseConfirm
    pub fn msg_channel_close_confirm(self) -> Result<MsgChannelCloseConfirm> {
        let ics04_msg = self.ics04_channel_msg()?;
        downcast!(ics04_msg => ChannelMsg::ChannelCloseConfirm).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a ChannelCloseInit message".to_string(),
                )
            },
        )
    }

    /// Get the IBC message of RecvPacket
    pub fn msg_recv_packet(self) -> Result<MsgRecvPacket> {
        let ics04_msg = self.ics04_packet_msg()?;
        downcast!(ics04_msg => PacketMsg::RecvPacket).ok_or_else(|| {
            Error::Downcast(
                "The message is not a RecvPacket message".to_string(),
            )
        })
    }

    /// Get the IBC message of Acknowledgement
    pub fn msg_acknowledgement(self) -> Result<MsgAcknowledgement> {
        let ics04_msg = self.ics04_packet_msg()?;
        downcast!(ics04_msg => PacketMsg::AckPacket).ok_or_else(|| {
            Error::Downcast(
                "The message is not an Acknowledgement message".to_string(),
            )
        })
    }

    /// Get the IBC message of TimeoutPacket
    pub fn msg_timeout(self) -> Result<MsgTimeout> {
        let ics04_msg = self.ics04_packet_msg()?;
        downcast!(ics04_msg => PacketMsg::TimeoutPacket).ok_or_else(|| {
            Error::Downcast(
                "The message is not a TimeoutPacket message".to_string(),
            )
        })
    }

    /// Get the IBC message of TimeoutPacketOnClose
    pub fn msg_timeout_on_close(self) -> Result<MsgTimeoutOnClose> {
        let ics04_msg = self.ics04_packet_msg()?;
        downcast!(ics04_msg => PacketMsg::TimeoutOnClosePacket).ok_or_else(
            || {
                Error::Downcast(
                    "The message is not a TimeoutPacketOnClose message"
                        .to_string(),
                )
            },
        )
    }

    /// Get the IBC message of ICS20
    pub fn msg_transfer(self) -> Result<MsgTransfer> {
        downcast!(self => Self::Ics20).ok_or_else(|| {
            Error::Downcast("The message is not an ICS20 message".to_string())
        })
    }

    fn ics26_envelop(self) -> Result<Ics26Envelope> {
        downcast!(self => Self::Ics26).ok_or_else(|| {
            Error::Downcast("The message is not an ICS02 message".to_string())
        })
    }

    fn ics02_msg(self) -> Result<ClientMsg> {
        let envelope = self.ics26_envelop()?;
        downcast!(envelope => Ics26Envelope::Ics2Msg).ok_or_else(|| {
            Error::Downcast("The message is not an ICS02 message".to_string())
        })
    }

    fn ics03_msg(self) -> Result<ConnectionMsg> {
        let envelope = self.ics26_envelop()?;
        downcast!(envelope => Ics26Envelope::Ics3Msg).ok_or_else(|| {
            Error::Downcast("The message is not an ICS03 message".to_string())
        })
    }

    fn ics04_channel_msg(self) -> Result<ChannelMsg> {
        let envelope = self.ics26_envelop()?;
        downcast!(envelope => Ics26Envelope::Ics4ChannelMsg).ok_or_else(|| {
            Error::Downcast(
                "The message is not an ICS04 channel message".to_string(),
            )
        })
    }

    fn ics04_packet_msg(self) -> Result<PacketMsg> {
        let envelope = self.ics26_envelop()?;
        downcast!(envelope => Ics26Envelope::Ics4PacketMsg).ok_or_else(|| {
            Error::Downcast(
                "The message is not an ICS04 packet message".to_string(),
            )
        })
    }
}

/// Receipt for a packet
#[derive(Clone, Debug)]
pub struct PacketReceipt(pub Receipt);

impl PacketReceipt {
    /// Return bytes
    pub fn as_bytes(&self) -> &[u8] {
        // same as ibc-go
        &[1_u8]
    }
}

impl Default for PacketReceipt {
    fn default() -> Self {
        Self(Receipt::Ok)
    }
}

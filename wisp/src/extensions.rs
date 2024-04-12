//! Wisp protocol extensions.

use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    ws::{LockedWebSocketWrite, WebSocketRead},
    Role, WispError,
};

/// Type-erased protocol extension that implements Clone.
#[derive(Debug)]
pub struct AnyProtocolExtension(Box<dyn ProtocolExtension + Sync + Send>);

impl AnyProtocolExtension {
    /// Create a new type-erased protocol extension.
    pub fn new<T: ProtocolExtension + Sync + Send + 'static>(extension: T) -> Self {
        Self(Box::new(extension))
    }
}

impl Deref for AnyProtocolExtension {
    type Target = dyn ProtocolExtension;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for AnyProtocolExtension {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl Clone for AnyProtocolExtension {
    fn clone(&self) -> Self {
        Self(self.0.box_clone())
    }
}

impl From<AnyProtocolExtension> for Bytes {
    fn from(value: AnyProtocolExtension) -> Self {
        let mut bytes = BytesMut::with_capacity(5);
        let payload = value.encode();
        bytes.put_u8(value.get_id());
        bytes.put_u32_le(payload.len() as u32);
        bytes.extend(payload);
        bytes.freeze()
    }
}

/// A Wisp protocol extension.
///
/// See [the
/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#protocol-extensions).
#[async_trait]
pub trait ProtocolExtension: std::fmt::Debug {
    /// Get the protocol extension ID.
    fn get_id(&self) -> u8;
    /// Get the protocol extension's supported packets.
    ///
    /// Used to decide whether to call the protocol extension's packet handler.
    fn get_supported_packets(&self) -> &'static [u8];

    /// Encode self into Bytes.
    fn encode(&self) -> Bytes;

    /// Handle the handshake part of a Wisp connection.
    ///
    /// This should be used to send or receive data before any streams are created.
    async fn handle_handshake(
        &mut self,
        read: &mut dyn WebSocketRead,
        write: &LockedWebSocketWrite,
    ) -> Result<(), WispError>;

    /// Handle receiving a packet.
    async fn handle_packet(
        &mut self,
        packet: Bytes,
        read: &mut dyn WebSocketRead,
        write: &LockedWebSocketWrite,
    ) -> Result<(), WispError>;

    /// Clone the protocol extension.
    fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send>;
}

/// Trait to build a Wisp protocol extension for the client.
pub trait ProtocolExtensionBuilder {
    /// Get the protocol extension ID.
    ///
    /// Used to decide whether this builder should be used.
    fn get_id(&self) -> u8;

    /// Build a protocol extension from the extension's metadata.
    fn build(&self, bytes: Bytes, role: Role) -> AnyProtocolExtension;
}

pub mod udp {
    //! UDP protocol extension.
    //!
    //! # Example
    //! ```
    //! let (mux, fut) = ServerMux::new(
    //!     rx,
    //!     tx,
    //!     128,
    //!     Some(vec![UdpProtocolExtension().into()]),
    //!     Some(&[&UdpProtocolExtensionBuilder()])
    //! );
    //! ```
    //! See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md#0x01---udp)
    use async_trait::async_trait;
    use bytes::Bytes;

    use crate::{
        ws::{LockedWebSocketWrite, WebSocketRead},
        WispError,
    };

    use super::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder};

    #[derive(Debug)]
    /// UDP protocol extension.
    pub struct UdpProtocolExtension();

    impl UdpProtocolExtension {
        /// UDP protocol extension ID.
        pub const ID: u8 = 0x01;
    }

    #[async_trait]
    impl ProtocolExtension for UdpProtocolExtension {
        fn get_id(&self) -> u8 {
            Self::ID
        }

        fn get_supported_packets(&self) -> &'static [u8] {
            &[]
        }

        fn encode(&self) -> Bytes {
            Bytes::new()
        }

        async fn handle_handshake(
            &mut self,
            _: &mut dyn WebSocketRead,
            _: &LockedWebSocketWrite,
        ) -> Result<(), WispError> {
            Ok(())
        }

        /// Handle receiving a packet.
        async fn handle_packet(
            &mut self,
            _: Bytes,
            _: &mut dyn WebSocketRead,
            _: &LockedWebSocketWrite,
        ) -> Result<(), WispError> {
            Ok(())
        }

        fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
            Box::new(Self())
        }
    }

    impl From<UdpProtocolExtension> for AnyProtocolExtension {
        fn from(value: UdpProtocolExtension) -> Self {
            AnyProtocolExtension(Box::new(value))
        }
    }

    /// UDP protocol extension builder.
    pub struct UdpProtocolExtensionBuilder();

    impl ProtocolExtensionBuilder for UdpProtocolExtensionBuilder {
        fn get_id(&self) -> u8 {
            0x01
        }

        fn build(&self, _: Bytes, _: crate::Role) -> AnyProtocolExtension {
            AnyProtocolExtension(Box::new(UdpProtocolExtension()))
        }
    }
}

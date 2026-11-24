//! Wisp protocol extensions.
#[cfg(feature = "certificate")]
pub mod cert;
pub mod motd;
pub mod password;
pub mod udp;

use std::{
	any::TypeId,
	ops::{Deref, DerefMut},
	ptr,
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes};

use crate::{
	packet::CloseReason,
	ws::{PayloadMut, TransportRead, TransportWrite},
	Role, WispError,
};

mod private {
	pub struct Sealed;
}

/// Type-erased protocol extension.
#[derive(Debug)]
pub struct AnyProtocolExtension(Box<dyn ProtocolExtension>);

impl AnyProtocolExtension {
	/// Create a new type-erased protocol extension.
	pub fn new<T: ProtocolExtension>(extension: T) -> Self {
		Self(Box::new(extension))
	}

	/// Downcast the protocol extension.
	pub fn downcast<T: ProtocolExtension>(self) -> Result<Box<T>, Self> {
		self.0.__downcast().map_err(Self)
	}

	/// Downcast the protocol extension.
	pub fn downcast_ref<T: ProtocolExtension>(&self) -> Option<&T> {
		self.0.__downcast_ref()
	}

	/// Downcast the protocol extension.
	pub fn downcast_mut<T: ProtocolExtension>(&mut self) -> Option<&mut T> {
		self.0.__downcast_mut()
	}
}

impl Deref for AnyProtocolExtension {
	type Target = dyn ProtocolExtension;
	fn deref(&self) -> &Self::Target {
		&*self.0
	}
}

impl DerefMut for AnyProtocolExtension {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut *self.0
	}
}

impl Clone for AnyProtocolExtension {
	fn clone(&self) -> Self {
		Self(self.0.box_clone())
	}
}

impl AnyProtocolExtension {
	pub(crate) fn encode_into(&self, packet: &mut PayloadMut) {
		let payload = self.encode();
		packet.put_u8(self.get_id());
		packet.put_u32_le(payload.len() as u32);
		packet.extend(payload);
	}
}

impl<T: ProtocolExtension> From<T> for AnyProtocolExtension {
	fn from(value: T) -> Self {
		Self::new(value)
	}
}

/// A Wisp protocol extension.
///
/// See [the
/// docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#protocol-extensions).
#[async_trait]
pub trait ProtocolExtension: std::fmt::Debug + Sync + Send + 'static {
	/// Get the protocol extension ID.
	fn get_id(&self) -> u8;
	/// Get the protocol extension's supported packets.
	///
	/// Used to decide whether to call the protocol extension's packet handler.
	fn get_supported_packets(&self) -> &[u8] {
		&[]
	}
	/// Get stream types that should be treated as TCP.
	///
	/// Used to decide whether to handle congestion control for that stream type.
	fn get_congestion_stream_types(&self) -> &[u8] {
		&[]
	}

	/// Encode self into Bytes.
	fn encode(&self) -> Bytes;

	/// Handle the handshake part of a Wisp connection.
	///
	/// This should be used to send or receive data and possibly reject the handshake before it
	/// finishes. Rejections need both a close reason and an error to reject the connection future with.
	async fn handle_handshake(
		&mut self,
		read: &mut dyn TransportRead,
		write: &mut dyn TransportWrite,
	) -> Result<Option<(CloseReason, WispError)>, WispError> {
		let _ = (read, write);
		Ok(None)
	}

	/// Handle receiving a packet.
	async fn handle_packet(
		&mut self,
		packet_type: u8,
		stream_id: u32,
		packet: Bytes,
		read: &mut dyn TransportRead,
		write: &mut dyn TransportWrite,
	) -> Result<(), WispError> {
		let _ = (packet_type, stream_id, packet, read, write);
		Ok(())
	}

	/// Clone the protocol extension.
	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send>;

	#[doc(hidden)]
	/// Do not override.
	fn __internal_type_id(&self, _: private::Sealed) -> TypeId {
		TypeId::of::<Self>()
	}
}

impl dyn ProtocolExtension {
	fn __is<T: ProtocolExtension>(&self) -> bool {
		let t = TypeId::of::<T>();
		self.__internal_type_id(private::Sealed) == t
	}

	fn __downcast<T: ProtocolExtension>(self: Box<Self>) -> Result<Box<T>, Box<Self>> {
		if self.__is::<T>() {
			unsafe {
				let raw: *mut dyn ProtocolExtension = Box::into_raw(self);
				Ok(Box::from_raw(raw.cast::<T>()))
			}
		} else {
			Err(self)
		}
	}

	fn __downcast_ref<T: ProtocolExtension>(&self) -> Option<&T> {
		if self.__is::<T>() {
			unsafe { Some(&*ptr::from_ref::<dyn ProtocolExtension>(self).cast::<T>()) }
		} else {
			None
		}
	}

	fn __downcast_mut<T: ProtocolExtension>(&mut self) -> Option<&mut T> {
		if self.__is::<T>() {
			unsafe { Some(&mut *ptr::from_mut::<dyn ProtocolExtension>(self).cast::<T>()) }
		} else {
			None
		}
	}
}

/// Trait to build a Wisp protocol extension from a payload.
pub trait ProtocolExtensionBuilder: Sync + Send + 'static {
	/// Get the protocol extension ID.
	///
	/// Used to decide whether this builder should be used.
	fn get_id(&self) -> u8;

	/// Build a protocol extension from the extension's metadata.
	///
	/// This is called second on the server and first on the client.
	fn build_from_bytes(
		&mut self,
		bytes: Bytes,
		role: Role,
	) -> Result<AnyProtocolExtension, WispError>;

	/// Build a protocol extension to send to the other side.
	///
	/// This is called first on the server and second on the client.
	fn build_to_extension(&mut self, role: Role) -> Result<AnyProtocolExtension, WispError>;

	#[doc(hidden)]
	/// Do not override.
	fn __internal_type_id(&self, _sealed: private::Sealed) -> TypeId {
		TypeId::of::<Self>()
	}
}

impl dyn ProtocolExtensionBuilder {
	fn __is<T: ProtocolExtensionBuilder>(&self) -> bool {
		let t = TypeId::of::<T>();
		self.__internal_type_id(private::Sealed) == t
	}

	fn __downcast<T: ProtocolExtensionBuilder>(self: Box<Self>) -> Result<Box<T>, Box<Self>> {
		if self.__is::<T>() {
			unsafe {
				let raw: *mut dyn ProtocolExtensionBuilder = Box::into_raw(self);
				Ok(Box::from_raw(raw.cast::<T>()))
			}
		} else {
			Err(self)
		}
	}

	fn __downcast_ref<T: ProtocolExtensionBuilder>(&self) -> Option<&T> {
		if self.__is::<T>() {
			unsafe { Some(&*ptr::from_ref::<dyn ProtocolExtensionBuilder>(self).cast::<T>()) }
		} else {
			None
		}
	}

	fn __downcast_mut<T: ProtocolExtensionBuilder>(&mut self) -> Option<&mut T> {
		if self.__is::<T>() {
			unsafe { Some(&mut *ptr::from_mut::<dyn ProtocolExtensionBuilder>(self).cast::<T>()) }
		} else {
			None
		}
	}
}

/// Type-erased protocol extension builder.
pub struct AnyProtocolExtensionBuilder(Box<dyn ProtocolExtensionBuilder>);

impl AnyProtocolExtensionBuilder {
	/// Create a new type-erased protocol extension builder.
	pub fn new<T: ProtocolExtensionBuilder>(extension: T) -> Self {
		Self(Box::new(extension))
	}

	/// Downcast the protocol extension builder.
	pub fn downcast<T: ProtocolExtensionBuilder>(self) -> Result<Box<T>, Self> {
		self.0.__downcast().map_err(Self)
	}

	/// Downcast the protocol extension builder.
	pub fn downcast_ref<T: ProtocolExtensionBuilder>(&self) -> Option<&T> {
		self.0.__downcast_ref()
	}

	/// Downcast the protocol extension builder.
	pub fn downcast_mut<T: ProtocolExtensionBuilder>(&mut self) -> Option<&mut T> {
		self.0.__downcast_mut()
	}
}

impl Deref for AnyProtocolExtensionBuilder {
	type Target = dyn ProtocolExtensionBuilder;
	fn deref(&self) -> &Self::Target {
		&*self.0
	}
}

impl DerefMut for AnyProtocolExtensionBuilder {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut *self.0
	}
}

impl<T: ProtocolExtensionBuilder> From<T> for AnyProtocolExtensionBuilder {
	fn from(value: T) -> Self {
		Self::new(value)
	}
}

/// Helper functions for `[AnyProtocolExtensionBuilder]`
pub trait ProtocolExtensionBuilderListExt {
	/// Returns a reference to the protocol extension builder specified, if it was found.
	fn find_extension<T: ProtocolExtensionBuilder>(&self) -> Option<&T>;
	/// Returns a mutable reference to the protocol extension builder specified, if it was found.
	fn find_extension_mut<T: ProtocolExtensionBuilder>(&mut self) -> Option<&mut T>;
}

/// Helper functions for `Vec<AnyProtocolExtensionBuilder>`
pub trait ProtocolExtensionBuilderVecExt {
	/// Removes any instances of the protocol extension builder specified, if it was found.
	fn remove_extension<T: ProtocolExtensionBuilder>(&mut self);
}

impl ProtocolExtensionBuilderListExt for [AnyProtocolExtensionBuilder] {
	fn find_extension<T: ProtocolExtensionBuilder>(&self) -> Option<&T> {
		self.iter().find_map(|x| x.downcast_ref::<T>())
	}
	fn find_extension_mut<T: ProtocolExtensionBuilder>(&mut self) -> Option<&mut T> {
		self.iter_mut().find_map(|x| x.downcast_mut::<T>())
	}
}

impl ProtocolExtensionBuilderListExt for Vec<AnyProtocolExtensionBuilder> {
	fn find_extension<T: ProtocolExtensionBuilder>(&self) -> Option<&T> {
		self.as_slice().find_extension()
	}
	fn find_extension_mut<T: ProtocolExtensionBuilder>(&mut self) -> Option<&mut T> {
		self.as_mut_slice().find_extension_mut()
	}
}

impl ProtocolExtensionBuilderVecExt for Vec<AnyProtocolExtensionBuilder> {
	fn remove_extension<T: ProtocolExtensionBuilder>(&mut self) {
		self.retain(|x| x.downcast_ref::<T>().is_none());
	}
}

/// Helper functions for `[AnyProtocolExtension]`
pub trait ProtocolExtensionListExt {
	/// Returns a reference to the protocol extension specified, if it was found.
	fn find_extension<T: ProtocolExtension>(&self) -> Option<&T>;
	/// Returns a mutable reference to the protocol extension specified, if it was found.
	fn find_extension_mut<T: ProtocolExtension>(&mut self) -> Option<&mut T>;
}

/// Helper functions for `Vec<AnyProtocolExtension>`
pub trait ProtocolExtensionVecExt {
	/// Removes any instances of the protocol extension specified, if it was found.
	fn remove_extension<T: ProtocolExtension>(&mut self);
}

impl ProtocolExtensionListExt for [AnyProtocolExtension] {
	fn find_extension<T: ProtocolExtension>(&self) -> Option<&T> {
		self.iter().find_map(|x| x.downcast_ref::<T>())
	}
	fn find_extension_mut<T: ProtocolExtension>(&mut self) -> Option<&mut T> {
		self.iter_mut().find_map(|x| x.downcast_mut::<T>())
	}
}

impl ProtocolExtensionListExt for Vec<AnyProtocolExtension> {
	fn find_extension<T: ProtocolExtension>(&self) -> Option<&T> {
		self.as_slice().find_extension()
	}

	fn find_extension_mut<T: ProtocolExtension>(&mut self) -> Option<&mut T> {
		self.as_mut_slice().find_extension_mut()
	}
}

impl ProtocolExtensionVecExt for Vec<AnyProtocolExtension> {
	fn remove_extension<T: ProtocolExtension>(&mut self) {
		self.retain(|x| x.downcast_ref::<T>().is_none());
	}
}

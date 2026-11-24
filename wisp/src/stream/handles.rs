use std::{future::poll_fn, sync::Arc};

use bytes::BufMut;
use futures::SinkExt;

use crate::{
	WispError,
	packet::CloseReason,
	stream_chan::{StreamChanCloser, StreamChanSend},
	ws::{PayloadMut, PayloadRef},
};

use super::StreamInfo;

/// Close handle for a multiplexor stream.
#[derive(Clone)]
pub struct MuxStreamCloser {
	pub(crate) info: Arc<StreamInfo>,
	pub(crate) chan: StreamChanCloser,
}

impl MuxStreamCloser {
	/// Close the stream. You will no longer be able to write or read after this has been called.
	pub async fn close(&mut self, reason: CloseReason) -> Result<(), WispError> {
		if self.info.closed() {
			return Err(WispError::StreamAlreadyClosed);
		}

		poll_fn(|cx| self.chan.poll_send_close(reason, cx)).await
	}

	/// Get the stream's close reason, if it was closed.
	pub fn get_close_reason(&self) -> Option<CloseReason> {
		self.info.get_reason()
	}
}

/// Stream for sending arbitrary protocol extension packets.
pub struct MuxProtocolExtensionStream {
	pub(crate) info: Arc<StreamInfo>,
	pub(crate) chan: StreamChanSend,
}

impl MuxProtocolExtensionStream {
	/// Send a protocol extension packet with this stream's ID.
	pub async fn send(&mut self, packet_type: u8, data: PayloadRef<'_>) -> Result<(), WispError> {
		if (0..=0x05).contains(&packet_type) {
			return Err(WispError::InvalidPacketType(packet_type));
		}

		if self.info.closed() {
			return Err(WispError::StreamAlreadyClosed);
		}

		let mut encoded = PayloadMut::with_capacity(1 + 4 + data.len());
		encoded.put_u8(packet_type);
		encoded.put_u32_le(self.info.id);
		encoded.extend(data.as_ref());

		poll_fn(|cx| self.chan.poll_ready_unpin(cx)).await?;
		self.chan.start_send_ext(encoded.into())?;
		poll_fn(|cx| self.chan.poll_flush_unpin(cx)).await
	}
}

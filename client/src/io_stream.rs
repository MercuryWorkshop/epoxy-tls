use bytes::{buf::UninitSlice, BufMut, BytesMut};
use futures_util::{io::WriteHalf, lock::Mutex, AsyncReadExt, AsyncWriteExt, SinkExt, StreamExt};
use js_sys::{Function, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use wisp_mux::MuxStreamIoSink;

use crate::{
	stream_provider::{ProviderAsyncRW, ProviderUnencryptedStream},
	utils::convert_body,
	EpoxyError, EpoxyHandlers,
};

#[wasm_bindgen]
pub struct EpoxyIoStream {
	tx: Mutex<WriteHalf<ProviderAsyncRW>>,
	onerror: Function,
}

#[wasm_bindgen]
impl EpoxyIoStream {
	pub(crate) fn connect(stream: ProviderAsyncRW, handlers: EpoxyHandlers) -> Self {
		let (mut rx, tx) = stream.split();
		let tx = Mutex::new(tx);

		let EpoxyHandlers {
			onopen,
			onclose,
			onerror,
			onmessage,
		} = handlers;

		let onerror_cloned = onerror.clone();

		// similar to tokio_util::io::ReaderStream
		spawn_local(async move {
			let mut buf = BytesMut::with_capacity(4096);
			loop {
				match rx
					.read(unsafe {
						std::mem::transmute::<&mut UninitSlice, &mut [u8]>(buf.chunk_mut())
					})
					.await
				{
					Ok(cnt) => {
						if cnt > 0 {
							unsafe { buf.advance_mut(cnt) };

							let _ = onmessage
								.call1(&JsValue::null(), &Uint8Array::from(buf.split().as_ref()));
						}
					}
					Err(err) => {
						let _ = onerror.call1(&JsValue::null(), &JsError::from(err).into());
						break;
					}
				}
			}
			let _ = onclose.call0(&JsValue::null());
		});

		let _ = onopen.call0(&JsValue::null());

		Self {
			tx,
			onerror: onerror_cloned,
		}
	}

	pub async fn send(&self, payload: JsValue) -> Result<(), EpoxyError> {
		let ret: Result<(), EpoxyError> = async move {
			let payload = convert_body(payload)
				.await
				.map_err(|_| EpoxyError::InvalidPayload)?
				.0
				.to_vec();
			Ok(self.tx.lock().await.write_all(&payload).await?)
		}
		.await;

		match ret {
			Ok(ok) => Ok(ok),
			Err(err) => {
				let _ = self
					.onerror
					.call1(&JsValue::null(), &err.to_string().into());
				Err(err)
			}
		}
	}

	pub async fn close(&self) -> Result<(), EpoxyError> {
		match self.tx.lock().await.close().await {
			Ok(ok) => Ok(ok),
			Err(err) => {
				let _ = self
					.onerror
					.call1(&JsValue::null(), &err.to_string().into());
				Err(err.into())
			}
		}
	}
}

#[wasm_bindgen]
pub struct EpoxyUdpStream {
	tx: Mutex<MuxStreamIoSink>,
	onerror: Function,
}

#[wasm_bindgen]
impl EpoxyUdpStream {
	pub(crate) fn connect(stream: ProviderUnencryptedStream, handlers: EpoxyHandlers) -> Self {
		let (mut rx, tx) = stream.into_split();

		let EpoxyHandlers {
			onopen,
			onclose,
			onerror,
			onmessage,
		} = handlers;

		let onerror_cloned = onerror.clone();

		spawn_local(async move {
			while let Some(packet) = rx.next().await {
				match packet {
					Ok(buf) => {
						let _ = onmessage.call1(&JsValue::null(), &Uint8Array::from(buf.as_ref()));
					}
					Err(err) => {
						let _ = onerror.call1(&JsValue::null(), &JsError::from(err).into());
						break;
					}
				}
			}
			let _ = onclose.call0(&JsValue::null());
		});

		let _ = onopen.call0(&JsValue::null());

		Self {
			tx: tx.into(),
			onerror: onerror_cloned,
		}
	}

	pub async fn send(&self, payload: JsValue) -> Result<(), EpoxyError> {
		let ret: Result<(), EpoxyError> = async move {
			let payload = convert_body(payload)
				.await
				.map_err(|_| EpoxyError::InvalidPayload)?
				.0
				.to_vec();
			Ok(self
				.tx
				.lock()
				.await
				.send(BytesMut::from(payload.as_slice()))
				.await?)
		}
		.await;

		match ret {
			Ok(ok) => Ok(ok),
			Err(err) => {
				let _ = self
					.onerror
					.call1(&JsValue::null(), &err.to_string().into());
				Err(err)
			}
		}
	}

	pub async fn close(&self) -> Result<(), EpoxyError> {
		match self.tx.lock().await.close().await {
			Ok(ok) => Ok(ok),
			Err(err) => {
				let _ = self
					.onerror
					.call1(&JsValue::null(), &err.to_string().into());
				Err(err.into())
			}
		}
	}
}

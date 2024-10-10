use std::pin::Pin;

use bytes::{Bytes, BytesMut};
use futures_util::{AsyncReadExt, AsyncWriteExt, Sink, SinkExt, Stream, TryStreamExt};
use js_sys::{Object, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_streams::{ReadableStream, WritableStream};

use crate::{
	stream_provider::{ProviderAsyncRW, ProviderUnencryptedStream},
	utils::{convert_body, object_set, ReaderStream},
	EpoxyError,
};

#[wasm_bindgen(typescript_custom_section)]
const IO_STREAM_RET: &'static str = r#"
type EpoxyIoStream = {
	read: ReadableStream<Uint8Array>,
	write: WritableStream<Uint8Array>,
}
"#;

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(typescript_type = "EpoxyIoStream")]
	pub type EpoxyIoStream;
}

fn create_iostream(
	stream: Pin<Box<dyn Stream<Item = Result<Bytes, EpoxyError>>>>,
	sink: Pin<Box<dyn Sink<BytesMut, Error = EpoxyError>>>,
) -> EpoxyIoStream {
	let read = ReadableStream::from_stream(
		stream
			.map_ok(|x| Uint8Array::from(x.as_ref()).into())
			.map_err(Into::into),
	)
	.into_raw();
	let write = WritableStream::from_sink(
		sink.with(|x| async {
			convert_body(x)
				.await
				.map_err(|_| EpoxyError::InvalidPayload)
				.map(|x| BytesMut::from(x.0.to_vec().as_slice()))
		})
		.sink_map_err(Into::into),
	)
	.into_raw();

	let out = Object::new();
	object_set(&out, "read", read.into());
	object_set(&out, "write", write.into());
	JsValue::from(out).into()
}

pub fn iostream_from_asyncrw(asyncrw: ProviderAsyncRW) -> EpoxyIoStream {
	let (rx, tx) = asyncrw.split();
	create_iostream(
		Box::pin(ReaderStream::new(Box::pin(rx)).map_err(EpoxyError::Io)),
		Box::pin(tx.into_sink().sink_map_err(EpoxyError::Io)),
	)
}

pub fn iostream_from_stream(stream: ProviderUnencryptedStream) -> EpoxyIoStream {
	let (rx, tx) = stream.into_split();
	create_iostream(
		Box::pin(rx.map_err(EpoxyError::Io)),
		Box::pin(tx.sink_map_err(EpoxyError::Io)),
	)
}

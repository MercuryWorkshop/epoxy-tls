use std::{
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{buf::UninitSlice, BufMut, Bytes, BytesMut};
use futures_util::{ready, AsyncRead, Future, Stream, TryStreamExt};
use http::{HeaderValue, Uri};
use hyper::{body::Body, rt::Executor};
use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use pin_project_lite::pin_project;
use wasm_bindgen::{prelude::*, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::EpoxyError;

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(js_namespace = console, js_name = log)]
	pub fn js_console_log(s: &str);
}

#[macro_export]
macro_rules! console_log {
	($($expr:expr),*) => {
		$crate::utils::js_console_log(&format!($($expr),*));
	};
}

pub trait UriExt {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError>;
}

impl UriExt for Uri {
	fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, EpoxyError> {
		let new_uri = location.to_str()?.parse::<hyper::Uri>()?;
		let mut new_parts: http::uri::Parts = new_uri.into();
		if new_parts.scheme.is_none() {
			new_parts.scheme = self.scheme().cloned();
		}
		if new_parts.authority.is_none() {
			new_parts.authority = self.authority().cloned();
		}

		Ok(Uri::from_parts(new_parts)?)
	}
}

#[derive(Clone)]
pub struct WasmExecutor;

impl<F> Executor<F> for WasmExecutor
where
	F: Future + Send + 'static,
	F::Output: Send + 'static,
{
	fn execute(&self, future: F) {
		wasm_bindgen_futures::spawn_local(async move {
			let _ = future.await;
		});
	}
}

pin_project! {
	pub struct IncomingBody {
		#[pin]
		incoming: hyper::body::Incoming,
	}
}

impl IncomingBody {
	pub fn new(incoming: hyper::body::Incoming) -> IncomingBody {
		IncomingBody { incoming }
	}
}

impl Stream for IncomingBody {
	type Item = std::io::Result<Bytes>;
	fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = self.project();
		let ret = this.incoming.poll_frame(cx);
		match ret {
			Poll::Ready(item) => Poll::<Option<Self::Item>>::Ready(match item {
				Some(frame) => frame
					.map(|x| {
						x.into_data()
							.map_err(|_| std::io::Error::other("not data frame"))
					})
					.ok(),
				None => None,
			}),
			Poll::Pending => Poll::<Option<Self::Item>>::Pending,
		}
	}
}

pin_project! {
	#[derive(Debug)]
	pub struct ReaderStream<R> {
		#[pin]
		reader: Option<R>,
		buf: BytesMut,
		capacity: usize,
	}
}

impl<R: AsyncRead> ReaderStream<R> {
	pub fn new(reader: R) -> Self {
		ReaderStream {
			reader: Some(reader),
			buf: BytesMut::new(),
			capacity: 4096,
		}
	}
}

pub fn poll_read_buf<T: AsyncRead + ?Sized, B: BufMut>(
	io: Pin<&mut T>,
	cx: &mut Context<'_>,
	buf: &mut B,
) -> Poll<std::io::Result<usize>> {
	if !buf.has_remaining_mut() {
		return Poll::Ready(Ok(0));
	}

	let n = {
		let dst = buf.chunk_mut();

		let dst = unsafe { std::mem::transmute::<&mut UninitSlice, &mut [u8]>(dst) };
		ready!(io.poll_read(cx, dst)?)
	};

	unsafe {
		buf.advance_mut(n);
	}

	Poll::Ready(Ok(n))
}

impl<R: AsyncRead> Stream for ReaderStream<R> {
	type Item = std::io::Result<Bytes>;
	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let mut this = self.as_mut().project();

		let reader = match this.reader.as_pin_mut() {
			Some(r) => r,
			None => return Poll::Ready(None),
		};

		if this.buf.capacity() == 0 {
			this.buf.reserve(*this.capacity);
		}

		match poll_read_buf(reader, cx, &mut this.buf) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(Err(err)) => {
				self.project().reader.set(None);
				Poll::Ready(Some(Err(err)))
			}
			Poll::Ready(Ok(0)) => {
				self.project().reader.set(None);
				Poll::Ready(None)
			}
			Poll::Ready(Ok(_)) => {
				let chunk = this.buf.split();
				Poll::Ready(Some(Ok(chunk.freeze())))
			}
		}
	}
}

pub fn is_redirect(code: u16) -> bool {
	[301, 302, 303, 307, 308].contains(&code)
}

pub fn is_null_body(code: u16) -> bool {
	[101, 204, 205, 304].contains(&code)
}

pub fn object_get(obj: &Object, key: &str) -> Option<JsValue> {
	Reflect::get(obj, &key.into()).ok()
}

pub fn object_set(obj: &Object, key: &JsValue, value: &JsValue) -> Result<(), EpoxyError> {
	if Reflect::set(obj, key, value).map_err(|_| EpoxyError::RawHeaderSetFailed)? {
		Ok(())
	} else {
		Err(EpoxyError::RawHeaderSetFailed)
	}
}

pub async fn convert_body(val: JsValue) -> Result<(Uint8Array, web_sys::Request), JsValue> {
	let mut request_init = web_sys::RequestInit::new();
	request_init.method("POST").body(Some(&val));
	object_set(&request_init, &"duplex".into(), &"half".into())?;
	let req = web_sys::Request::new_with_str_and_init("/", &request_init)?;
	Ok((
		JsFuture::from(req.array_buffer()?)
			.await?
			.dyn_into::<ArrayBuffer>()
			.map(|x| Uint8Array::new(&x))?,
		req,
	))
}

pub fn entries_of_object(obj: &Object) -> Vec<Vec<String>> {
	Object::entries(obj)
		.to_vec()
		.iter()
		.filter_map(|val| {
			Array::from(val)
				.to_vec()
				.iter()
				.map(|val| val.as_string())
				.collect::<Option<Vec<_>>>()
		})
		.collect::<Vec<Vec<_>>>()
}

pub fn define_property_obj(value: JsValue, writable: bool) -> Result<Object, JsValue> {
	let entries: Array = [
		Array::of2(&"value".into(), &value),
		Array::of2(&"writable".into(), &writable.into()),
	]
	.iter()
	.collect::<Array>();
	Object::from_entries(&entries)
}

pub fn asyncread_to_readablestream_stream<R: AsyncRead>(
	read: R,
) -> impl Stream<Item = Result<JsValue, JsValue>> {
	ReaderStream::new(read)
		.map_ok(|x| Uint8Array::from(x.as_ref()).into())
		.map_err(|x| EpoxyError::from(x).into())
}

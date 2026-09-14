use std::{
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use bytes::Bytes;
use futures::{StreamExt, lock::Mutex};
use http::Uri;
use http_body::{Body, Frame, SizeHint};
use hyper::{Request, Response, body::Incoming, rt::Executor};
#[cfg(feature = "full")]
use hyper_util::client::pool::negotiate;
#[cfg(feature = "full")]
use hyper_util::client::pool::singleton;
use hyper_util::client::pool::{cache, map};
use js_sys::Uint8Array;
use tower::{Service, ServiceBuilder, ServiceExt, service_fn, util::MapResponseLayer};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::{
	EpoxyError,
	provider::{HttpIo, StreamProviderService},
	send_wrapper::SendWrapper,
};

mod conn;
mod h1;

#[derive(Clone)]
pub struct WasmExecutor;
impl<T: Future<Output = ()> + 'static> Executor<T> for WasmExecutor {
	fn execute(&self, fut: T) {
		spawn_local(fut);
	}
}

struct DelayedRelease<S> {
	inner: Option<S>,
}

impl<S> DelayedRelease<S> {
	fn new(inner: S) -> Self {
		Self { inner: Some(inner) }
	}
}

impl<Req, S> Service<Req> for DelayedRelease<S>
where
	S: Service<Req> + Send + 'static,
	S::Future: Send + 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future =
		Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner
			.as_mut()
			.expect("DelayedRelease polled after inner service was consumed")
			.poll_ready(cx)
	}

	fn call(&mut self, req: Req) -> Self::Future {
		let mut inner = self
			.inner
			.take()
			.expect("DelayedRelease called more than once");
		let fut = inner.call(req);

		Box::pin(async move {
			let result = fut.await;
			spawn_local(async move {
				let _ = ServiceExt::ready(&mut inner).await;
			});
			result
		})
	}
}

pub enum EpoxyBody {
	Empty,
	Stream {
		current: SendWrapper<wasm_streams::readable::IntoStream<'static>>,
		tee: web_sys::ReadableStream,
		length: Option<u64>,
	},
}
impl EpoxyBody {
	pub fn new(stream: web_sys::ReadableStream, length: Option<u64>) -> Self {
		let (a, b) = wasm_streams::ReadableStream::from_raw(stream).tee();

		Self::Stream {
			current: SendWrapper(a.into_stream()),
			tee: b.into_raw(),
			length,
		}
	}
}
impl Body for EpoxyBody {
	type Data = Bytes;
	type Error = EpoxyError;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		match &mut *self {
			Self::Empty => Poll::Ready(None),
			Self::Stream { current, .. } => current
				.0
				.poll_next_unpin(cx)
				.map_ok(|x| {
					let u8array = x.unchecked_into::<Uint8Array>();
					Frame::data(Bytes::from(u8array.to_vec()))
				})
				.map_err(EpoxyError::js_error),
		}
	}

	fn is_end_stream(&self) -> bool {
		matches!(self, Self::Empty)
	}

	fn size_hint(&self) -> SizeHint {
		match self {
			Self::Empty => SizeHint::with_exact(0),
			Self::Stream { length, .. } => {
				length.map(|x| SizeHint::with_exact(x)).unwrap_or_default()
			}
		}
	}
}
impl Default for EpoxyBody {
	fn default() -> Self {
		Self::Empty
	}
}
impl Clone for EpoxyBody {
	fn clone(&self) -> Self {
		match self {
			Self::Empty => Self::Empty,
			Self::Stream {
				current: _,
				tee,
				length,
			} => {
				let (a, b) = wasm_streams::ReadableStream::from_raw(tee.clone()).tee();

				Self::Stream {
					current: SendWrapper(a.into_stream()),
					tee: b.into_raw(),
					length: *length,
				}
			}
		}
	}
}

pub(super) type BoxError = crate::EpoxyBoxError;

type OriginKey = (Option<http::uri::Scheme>, Option<http::uri::Authority>);

pub type HyperRequest = Request<EpoxyBody>;
pub type HyperResponse = Response<Incoming>;
pub type HyperClient =
	impl Service<HyperRequest, Response = HyperResponse, Error = EpoxyError> + Clone;

#[define_opaque(HyperClient)]
pub fn build_hyper_client(provider: StreamProviderService) -> HyperClient {
	let pools = map::Map::builder::<Uri>()
		.keys(scheme_and_auth)
		.values(move |_| build_origin_service(provider.clone()))
		.build();
	let pools = Arc::new(Mutex::new(pools));

	service_fn(move |req: HyperRequest| {
		let pools = pools.clone();
		async move {
			let uri = req.uri().clone();
			let pooled = {
				let mut pools = pools.lock().await;
				pools.service(&uri).clone()
			};

			let client = pooled.oneshot(uri).await?;
			client.oneshot(req).await
		}
	})
}

type OriginServiceRet = impl Service<
		HyperRequest,
		Response = HyperResponse,
		Error = EpoxyError,
		Future = impl Future<Output = Result<HyperResponse, EpoxyError>> + Send,
	> + Send;

fn h1_pool_layer<S>(
	svc: S,
) -> impl Service<
	Uri,
	Response = impl Service<
		HyperRequest,
		Response = HyperResponse,
		Error = BoxError,
		Future = impl Future<Output = Result<HyperResponse, BoxError>> + Send,
	> + Send,
	Error = BoxError,
> + Clone
where
	S: Service<Uri, Response = HttpIo, Error = BoxError> + Clone + Send + 'static,
	S::Future: Send + 'static,
{
	ServiceBuilder::new()
		.layer(MapResponseLayer::new(|x| {
			ServiceBuilder::new()
				.layer_fn(DelayedRelease::new)
				.layer_fn(h1::SetHost::new)
				.layer_fn(h1::RequestTarget::new)
				.layer_fn(h1::DropPriority::new)
				.service(x)
		}))
		.layer_fn(|x| cache::builder().executor(WasmExecutor).build(x))
		.layer(conn::http1())
		.service(svc)
}

#[define_opaque(OriginServiceRet)]
#[cfg(feature = "full")]
fn build_origin_service(
	provider: StreamProviderService,
) -> impl Service<
	Uri,
	Response = OriginServiceRet,
	Error = EpoxyError,
	Future = impl Future<Output = Result<OriginServiceRet, EpoxyError>>,
> + Clone {
	let http1 = tower_layer::layer_fn(h1_pool_layer);
	let http2 = tower_layer::layer_fn(move |svc| {
		ServiceBuilder::new()
			.layer_fn(singleton::Singleton::new)
			.layer(conn::http2())
			.service(svc)
	});
	let pool = negotiate::builder()
		.connect(provider)
		.inspect(|conn: &HttpIo| conn.is_negotiated_h2())
		.fallback(http1)
		.upgrade(http2)
		.build::<Uri>();

	pool.map_response(|client| client.map_err(EpoxyError::from_box_error))
		.map_err(|x| EpoxyError::from_box_error(x.into()))
}

#[define_opaque(OriginServiceRet)]
#[cfg(not(feature = "full"))]
fn build_origin_service(
	provider: StreamProviderService,
) -> impl Service<
	Uri,
	Response = OriginServiceRet,
	Error = EpoxyError,
	Future = impl Future<Output = Result<OriginServiceRet, EpoxyError>>,
> + Clone {
	h1_pool_layer(provider.map_err(|x| Box::new(x) as BoxError))
		.map_response(|client| client.map_err(EpoxyError::from_box_error))
		.map_err(EpoxyError::from_box_error)
}

fn scheme_and_auth(uri: &Uri) -> OriginKey {
	(uri.scheme().cloned(), uri.authority().cloned())
}

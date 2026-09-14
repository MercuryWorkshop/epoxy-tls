use std::{
	error::Error as StdError,
	future::Future,
	pin::Pin,
	task::{Context, Poll},
};

use http::{Request, Response, Uri};
use hyper::{body::Incoming, client::conn, rt::Executor};
use tower::{Service, ServiceExt, service_fn, util::BoxCloneService};
use tower_layer::Layer;

use crate::provider::HttpIo;

use super::{BoxError, WasmExecutor};

type ConnFuture<T> = Pin<Box<dyn Future<Output = Result<T, BoxError>> + Send>>;

pub(super) struct Http1Send<B>(hyper::client::conn::http1::SendRequest<B>);
#[cfg(feature = "full")]
pub(super) struct Http2Send<B>(hyper::client::conn::http2::SendRequest<B>);

#[cfg(feature = "full")]
impl<B> Clone for Http2Send<B> {
	fn clone(&self) -> Self {
		Self(self.0.clone())
	}
}

pub(super) fn http1<S, B>()
-> impl Layer<S, Service = BoxCloneService<Uri, Http1Send<B>, BoxError>> + Clone
where
	S: Service<Uri, Response = HttpIo, Error = BoxError> + Clone + Send + 'static,
	S::Future: Send + 'static,
	B: hyper::body::Body + Send + Unpin + 'static,
	B::Data: Send,
	B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
	tower::layer::layer_fn(move |connector: S| {
		BoxCloneService::new(service_fn(move |dst: Uri| {
			let connector = connector.clone();
			Box::pin(async move {
				let io = connector.oneshot(dst).await?;
				let mut builder = conn::http1::Builder::new();
				builder.http09_responses(true).preserve_header_case(true);
				let (tx, conn) = builder
					.handshake(io)
					.await
					.map_err(|err| -> BoxError { Box::new(err) })?;
				WasmExecutor.execute(async move {
					let _ = conn.with_upgrades().await;
				});

				Ok(Http1Send(tx))
			}) as ConnFuture<Http1Send<B>>
		}))
	})
}

#[cfg(feature = "full")]
pub(super) fn http2<S, B>()
-> impl Layer<S, Service = BoxCloneService<(), Http2Send<B>, BoxError>> + Clone
where
	S: Service<(), Response = HttpIo, Error = BoxError> + Clone + Send + 'static,
	S::Future: Send + 'static,
	B: hyper::body::Body + Send + Unpin + 'static,
	B::Data: Send,
	B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
	tower::layer::layer_fn(move |connector: S| {
		BoxCloneService::new(service_fn(move |_: ()| {
			let connector = connector.clone();
			Box::pin(async move {
				let io = connector.oneshot(()).await?;
				debug_assert!(io.is_negotiated_h2());

				// Chrome's SETTINGS frame, its connection-level WINDOW_UPDATE,
				// and nothing else. The h2 preface is as much of a fingerprint
				// as the ClientHello is -- Cloudflare reads both -- and hyper's
				// defaults are visibly not a browser's:
				//
				//   Chrome  1:65536;2:0;4:6291456;6:262144  window +15663105
				//   hyper   2:0;4:2097152;5:16384;6:16384   window  +5177345
				//
				// `initial_connection_window_size` is the whole window, not the
				// increment: h2 sends the difference from the 65535 default, so
				// 15728640 here is the 15663105 on the wire.
				//
				// `max_frame_size(None)` suppresses SETTINGS 5 entirely, which
				// Chrome does not send at all. Left at hyper's default it is one
				// more field that says "not a browser".
				//
				// Still different afterwards, and not reachable from here: h2
				// orders the pseudo-headers `:method :scheme :authority :path`
				// where Chrome sends `:method :authority :scheme :path`, and
				// Chrome sets the PRIORITY flag on its HEADERS frame. Both are
				// inside the h2 crate.
				let (tx, conn) = conn::http2::Builder::new(WasmExecutor)
					.header_table_size(65536)
					.initial_stream_window_size(6291456)
					.initial_connection_window_size(15728640)
					.max_header_list_size(262144)
					.max_frame_size(None)
					.handshake(io)
					.await
					.map_err(|err| -> BoxError { Box::new(err) })?;
				WasmExecutor.execute(async move {
					let _ = conn.await;
				});

				Ok(Http2Send(tx))
			}) as ConnFuture<Http2Send<B>>
		}))
	})
}

impl<B> Service<Request<B>> for Http1Send<B>
where
	B: hyper::body::Body + Send + Unpin + 'static,
	B::Data: Send,
	B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
	type Response = Response<Incoming>;
	type Error = BoxError;
	type Future = ConnFuture<Self::Response>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.0
			.poll_ready(cx)
			.map_err(|err| -> BoxError { Box::new(err) })
	}

	fn call(&mut self, req: Request<B>) -> Self::Future {
		let fut = self.0.send_request(req);
		Box::pin(async move { fut.await.map_err(|err| -> BoxError { Box::new(err) }) })
	}
}

#[cfg(feature = "full")]
impl<B> Service<Request<B>> for Http2Send<B>
where
	B: hyper::body::Body + Send + Unpin + 'static,
	B::Data: Send,
	B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
	type Response = Response<Incoming>;
	type Error = BoxError;
	type Future = ConnFuture<Self::Response>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.0
			.poll_ready(cx)
			.map_err(|err| -> BoxError { Box::new(err) })
	}

	fn call(&mut self, req: Request<B>) -> Self::Future {
		let fut = self.0.send_request(req);
		Box::pin(async move { fut.await.map_err(|err| -> BoxError { Box::new(err) }) })
	}
}

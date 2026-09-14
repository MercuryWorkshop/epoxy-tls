//! https://github.com/hyperium/hyper-util/tree/client-http1-middleware
//! Middleware services for normalizing request URIs and Host headers.
#![allow(dead_code)]

use std::task::{Context, Poll};

use http::{
	HeaderName, Method, Request, Uri,
	header::{HOST, HeaderValue},
};
use tower_service::Service;

/// A middleware that ensures the Host header matches the URI's authority.
///
/// Particularly useful for HTTP/1 clients and proxies, where the Host
/// header is mandatory and should be derived from the request URI.
#[derive(Clone, Debug)]
pub struct SetHost<S> {
	inner: S,
}

/// A middleware that modifies the request target for HTTP/1 semantics.
///
/// Ensures CONNECT uses authority-form, and all other methods use origin-form.
#[derive(Clone, Debug)]
pub struct RequestTarget<S> {
	inner: S,
}

/// A middleware that drops the `priority` header.
///
/// RFC 9218 extensible priorities are an HTTP/2 and HTTP/3 signal, and a
/// browser sends the header there and nowhere else: measured against Chromium
/// 155, the same navigation to the same server carries `priority: u=0, i` over
/// h2 and carries no such header over HTTP/1.1.
///
/// The caller cannot make that distinction -- whether the connection ends up
/// h2 or h1 is ALPN's answer, settled long after the request was composed --
/// so it sets the header for the h2 case and this drops it again on the branch
/// where a browser would not have sent one.
#[derive(Clone, Debug)]
pub struct DropPriority<S> {
	inner: S,
}

// ===== impl SetHost =====

impl<S> SetHost<S> {
	/// Create a new `SetHost` middleware wrapping the given service.
	pub fn new(inner: S) -> Self {
		SetHost { inner }
	}

	/// Access the inner service.
	pub fn inner(&self) -> &S {
		&self.inner
	}
}

impl<S, ReqBody> Service<Request<ReqBody>> for SetHost<S>
where
	S: Service<Request<ReqBody>>,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = S::Future;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
		if req.uri().authority().is_some() {
			let uri = req.uri().clone();
			req.headers_mut().entry(HOST).or_insert_with(|| {
				let hostname = uri.host().expect("authority implies host");
				if let Some(port) = get_non_default_port(&uri) {
					let s = format!("{hostname}:{port}");
					HeaderValue::from_str(&s)
				} else {
					HeaderValue::from_str(hostname)
				}
				.expect("uri host is valid header value")
			});
		}
		self.inner.call(req)
	}
}

fn get_non_default_port(uri: &Uri) -> Option<http::uri::Port<&str>> {
	match (uri.port().map(|p| p.as_u16()), is_schema_secure(uri)) {
		(Some(443), true) => None,
		(Some(80), false) => None,
		_ => uri.port(),
	}
}

fn is_schema_secure(uri: &Uri) -> bool {
	uri.scheme_str()
		.map(|scheme_str| matches!(scheme_str, "wss" | "https"))
		.unwrap_or_default()
}

// ===== impl Http1RequestTarget =====

impl<S> RequestTarget<S> {
	/// Create a new `Http1RequestTarget` middleware wrapping the given service.
	pub fn new(inner: S) -> Self {
		RequestTarget { inner }
	}

	/// Access the inner service.
	pub fn inner(&self) -> &S {
		&self.inner
	}
}

impl<S, ReqBody> Service<Request<ReqBody>> for RequestTarget<S>
where
	S: Service<Request<ReqBody>>,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = S::Future;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
		// CONNECT always sends authority-form, so check it first...
		if req.method() == Method::CONNECT {
			authority_form(req.uri_mut());
		} else {
			origin_form(req.uri_mut());
		}
		self.inner.call(req)
	}
}

fn origin_form(uri: &mut Uri) {
	let path = match uri.path_and_query() {
		Some(path) if path.as_str() != "/" => {
			let mut parts = ::http::uri::Parts::default();
			parts.path_and_query = Some(path.clone());
			Uri::from_parts(parts).expect("path is valid uri")
		}
		_none_or_just_slash => {
			debug_assert!(Uri::default() == "/");
			Uri::default()
		}
	};
	*uri = path
}

fn authority_form(uri: &mut Uri) {
	*uri = match uri.authority() {
		Some(auth) => {
			let mut parts = ::http::uri::Parts::default();
			parts.authority = Some(auth.clone());
			Uri::from_parts(parts).expect("authority is valid")
		}
		None => {
			unreachable!("authority_form with relative uri");
		}
	};
}

// ===== impl DropPriority =====

const PRIORITY: HeaderName = HeaderName::from_static("priority");

impl<S> DropPriority<S> {
	/// Create a new `DropPriority` middleware wrapping the given service.
	pub fn new(inner: S) -> Self {
		DropPriority { inner }
	}

	/// Access the inner service.
	pub fn inner(&self) -> &S {
		&self.inner
	}
}

impl<S, ReqBody> Service<Request<ReqBody>> for DropPriority<S>
where
	S: Service<Request<ReqBody>>,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = S::Future;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
		req.headers_mut().remove(PRIORITY);
		self.inner.call(req)
	}
}

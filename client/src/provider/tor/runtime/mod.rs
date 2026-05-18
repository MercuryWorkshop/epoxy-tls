//! A `tor_rtcompat::Runtime` implementation that runs inside a wasm-bindgen
//! environment, delegating its TCP connections to a [`StreamProviderBackendService`].
//!
//! This is the glue that lets `arti-client` operate on `wasm32-unknown-unknown`
//! without `tokio`, `async-std`, or any direct OS networking primitives.

use std::{fmt, future::Future, sync::Arc};

use futures::task::{FutureObj, Spawn, SpawnError};
use tor_rtcompat::Blocking;
use wasm_bindgen_futures::spawn_local;

use crate::{EpoxyError, provider::StreamProviderBackendService};

mod net;
mod sleep;
mod tls;
mod udp;

/// Shared inner state for [`WasmTorRuntime`].
struct Inner {
	socket_provider: Arc<StreamProviderBackendService>,
	tls: tls::WasmTlsProvider,
}

/// A wasm-bindgen-friendly runtime suitable for use with `arti-client`.
#[derive(Clone)]
pub struct WasmTorRuntime {
	inner: Arc<Inner>,
}

impl WasmTorRuntime {
	pub fn new(socket_provider: StreamProviderBackendService) -> Result<Self, EpoxyError> {
		let tls = tls::WasmTlsProvider::new()?;
		Ok(Self {
			inner: Arc::new(Inner {
				socket_provider: Arc::new(socket_provider),
				tls,
			}),
		})
	}

	pub(crate) fn socket_provider(&self) -> Arc<StreamProviderBackendService> {
		self.inner.socket_provider.clone()
	}

	pub(crate) fn tls_provider(&self) -> tls::WasmTlsProvider {
		self.inner.tls.clone()
	}
}

impl fmt::Debug for WasmTorRuntime {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WasmTorRuntime").finish_non_exhaustive()
	}
}

impl Spawn for WasmTorRuntime {
	#[track_caller]
	fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), SpawnError> {
		// `FutureObj` is `Send`, but on `wasm32-unknown-unknown` everything runs
		// on the main thread anyway. `spawn_local` doesn't require `Send`.
		spawn_local(future);
		Ok(())
	}
}

impl Blocking for WasmTorRuntime {
	type ThreadHandle<T: Send + 'static> = std::future::Ready<T>;

	#[track_caller]
	fn spawn_blocking<F, T>(&self, f: F) -> Self::ThreadHandle<T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		// No real threads on wasm32-unknown-unknown — run inline.
		std::future::ready(f())
	}

	#[track_caller]
	fn reenter_block_on<F>(&self, _future: F) -> F::Output
	where
		F: Future,
		F::Output: Send + 'static,
	{
		// Only the onion-service `pow` and CLI subcommands call this — we don't
		// support either on wasm.
		panic!("WasmTorRuntime does not support reenter_block_on()");
	}

	#[track_caller]
	fn blocking_io<F, T>(&self, f: F) -> impl Future<Output = T>
	where
		F: FnOnce() -> T + Send + 'static,
		T: Send + 'static,
	{
		std::future::ready(f())
	}
}

use std::sync::Arc;

use bytes::Bytes;
use futures::{
	Sink, Stream,
	lock::{Mutex, OwnedMutexGuard},
};
use js_sys::{Array, Function};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::spawn_local;
use wisp_mux::{ClientMux, WispError, packet::StreamType};

use crate::{
	EpoxyError, EpoxyJsValErrorExt,
	client::ws_protocol,
	js_types::{JsWispV2ConnectionPrefs, WispExtensionList},
	provider::{
		service::{WasmProvider, WasmWispProvider},
		wisp::extension::{JsWispV2Handshake, RefScope, extension_to_jsval, to_wisp_v2_handshake},
	},
	send_wrapper::SendWrapper,
};

use super::{
	ProviderServiceReq, ProviderUnencryptedStream,
	service::{BoxProviderService, ProviderService},
};

pub mod builtin_extension;
pub mod extension;
pub mod js_extension;

type WispProviderRead = Box<dyn Stream<Item = Result<Bytes, WispError>> + Send + Unpin>;
type WispProviderWrite = Box<dyn Sink<Bytes, Error = WispError> + Send + Unpin>;
pub struct WispProviderStream {
	pub read: WispProviderRead,
	pub write: WispProviderWrite,
}

pub struct WispProviderReq {
	pub server: String,
	pub protocol: Option<String>,
}

struct WispProviderLocked {
	generation: usize,
	service: BoxProviderService<WispProviderReq, WispProviderStream, EpoxyError>,
	mux: Option<ClientMux<WispProviderWrite>>,
}

type V2Func = Box<dyn Fn() -> Result<Option<JsWispV2Handshake>, EpoxyError>>;
struct WispProviderInner {
	locked: Arc<Mutex<WispProviderLocked>>,

	server: String,
	v2: SendWrapper<V2Func>,
}

impl WispProviderInner {
	pub fn new(
		service: BoxProviderService<WispProviderReq, WispProviderStream, EpoxyError>,
		server: String,
		v2: Option<JsWispV2ConnectionPrefs>,
	) -> Self {
		let v2 = match v2 {
			Some(func) => {
				let func: Function = func.unchecked_into();
				Box::new(move || {
					let v2 = func.call0(&JsValue::NULL).js_error()?;

					if v2.is_null_or_undefined() {
						Ok(None)
					} else {
						Ok(Some(to_wisp_v2_handshake(v2)))
					}
				}) as V2Func
			}
			None => Box::new(|| Ok(None)) as V2Func,
		};
		Self {
			locked: Arc::new(Mutex::new(WispProviderLocked {
				generation: 0,
				service,
				mux: None,
			})),
			server,
			v2: SendWrapper(v2),
		}
	}

	pub async fn replace_mux(&self) -> Result<(), EpoxyError> {
		self.create_mux(&mut *self.locked.lock().await).await
	}

	pub async fn get_extensions(&self) -> Option<WispProtocolExtensions> {
		let locked = self.locked.clone().lock_owned().await;
		if locked.mux.is_some() {
			Some(WispProtocolExtensions {
				locked,
				scope: RefScope::new(),
			})
		} else {
			None
		}
	}

	async fn create_mux(&self, guard: &mut WispProviderLocked) -> Result<(), EpoxyError> {
		let v2 = (self.v2.0)()?;
		let stream = guard
			.service
			.call(WispProviderReq {
				server: self.server.clone(),
				protocol: v2.is_some().then(ws_protocol),
			})
			.await?;
		let (mux, fut) = ClientMux::new(stream.read, stream.write, v2.map(|x| x.0)).await?;

		guard.generation = guard.generation.wrapping_add(1);
		let generation = guard.generation;
		let mux_lock = self.locked.clone();
		spawn_local(async move {
			let _ = fut.await;
			let mut locked = mux_lock.lock().await;
			if generation == locked.generation {
				locked.mux.take();
			}
		});

		guard.mux.replace(mux);

		Ok(())
	}

	async fn call(&self, req: ProviderServiceReq) -> Result<ProviderUnencryptedStream, EpoxyError> {
		let mut guard = self.locked.lock().await;
		if guard.mux.is_none() {
			self.create_mux(&mut guard).await?;
		}
		let mux = guard.mux.as_mut().unwrap();

		let stream = mux.new_stream(StreamType::Tcp, req.host, req.port).await?;
		let (read, write) = stream.into_async_rw().into_split();

		Ok(ProviderUnencryptedStream {
			read: Box::new(read),
			write: Box::new(write),
		})
	}
}

#[wasm_bindgen]
pub struct WispProtocolExtensions {
	locked: OwnedMutexGuard<WispProviderLocked>,
	scope: RefScope,
}
#[wasm_bindgen]
impl WispProtocolExtensions {
	pub fn arr(&mut self) -> WispExtensionList {
		let arr = Array::new();
		for ext in self.locked.mux.as_mut().unwrap().get_extensions_mut() {
			arr.push(&extension_to_jsval(ext, self.scope.token()));
		}
		arr.unchecked_into()
	}
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WispProvider(Arc<WispProviderInner>);

#[wasm_bindgen]
impl WispProvider {
	pub fn new(
		provider: WasmWispProvider,
		server: String,
		wisp_v2: Option<JsWispV2ConnectionPrefs>,
	) -> Self {
		Self(Arc::new(WispProviderInner::new(
			provider.0, server, wisp_v2,
		)))
	}

	pub fn r#box(self) -> WasmProvider {
		WasmProvider(BoxProviderService::new(self))
	}

	pub async fn replace_mux(&self) -> Result<(), EpoxyError> {
		self.0.replace_mux().await
	}

	pub async fn get_extensions(&self) -> Option<WispProtocolExtensions> {
		self.0.get_extensions().await
	}

	pub fn dup(&self) -> Self {
		self.clone()
	}
}

impl ProviderService<ProviderServiceReq> for WispProvider {
	type Response = ProviderUnencryptedStream;
	type Error = EpoxyError;
	type Future = impl Future<Output = Result<Self::Response, Self::Error>> + Send;

	fn call(&self, req: ProviderServiceReq) -> Self::Future {
		let inner = self.0.clone();
		SendWrapper(async move { inner.call(req).await })
	}
}

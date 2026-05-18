use std::sync::Arc;

use arti_client::{
	TorClient, TorClientConfig,
	config::{BoolOrAuto, BridgeConfigBuilder},
};
use futures::{AsyncReadExt, StreamExt};
use js_sys::{Function, Object, Reflect};
use tor_config_path::CfgPath;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::spawn_local;

use crate::{
	EpoxyError,
	provider::{
		ProviderServiceReq, ProviderUnencryptedStream,
		service::{BoxProviderService, ProviderService, WasmProvider},
		tor::{
			dir_store::WasmDirStoreBuilder, runtime::WasmTorRuntime,
			state_mgr::WasmStateMgrBuilder,
		},
	},
	send_wrapper::SendWrapper,
};

mod dir_store;
pub mod js_types;
mod runtime;
mod state_mgr;

fn status_to_js(status: &arti_client::status::BootstrapStatus) -> JsValue {
	let obj = Object::new();
	let _ = Reflect::set(
		&obj,
		&"frac".into(),
		&JsValue::from_f64(f64::from(status.as_frac())),
	);
	let _ = Reflect::set(
		&obj,
		&"ready".into(),
		&JsValue::from_bool(status.ready_for_traffic()),
	);
	let _ = Reflect::set(
		&obj,
		&"description".into(),
		&JsValue::from_str(&status.to_string()),
	);
	let blocked = match status.blocked() {
		Some(b) => {
			let bobj = Object::new();
			let _ = Reflect::set(
				&bobj,
				&"kind".into(),
				&JsValue::from_str(&b.kind().to_string()),
			);
			let _ = Reflect::set(
				&bobj,
				&"message".into(),
				&JsValue::from_str(&b.message().to_string()),
			);
			bobj.into()
		}
		None => JsValue::NULL,
	};
	let _ = Reflect::set(&obj, &"blocked".into(), &blocked);
	obj.into()
}

#[wasm_bindgen]
pub struct TorSocketProvider {
	inner: Arc<TorSocketProviderInner>,
}

struct TorSocketProviderInner {
	client: SendWrapper<TorClient<WasmTorRuntime>>,
}

#[wasm_bindgen]
impl TorSocketProvider {
	/// Construct a new `TorSocketProvider`.
	///
	/// `socket` is the underlying transport `WasmProvider` that the embedded
	/// `arti-client` will use for TCP connections to guards.
	///
	/// `state` is the JS-backed persistent state manager — see
	/// `TorStateMgrCallbacks` in the TypeScript bindings.
	///
	/// `bridges` is an optional list of bridge lines, in the same syntax as
	/// torrc's `Bridge` directive (e.g.
	/// `"192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"`). When
	/// supplied, arti will route all guard traffic through those bridges. The
	/// JS layer passes a fake-IP+real-fingerprint bridge line when
	/// snowflake mode is selected, so every guard connection is intercepted
	/// by the snowflake-tunneling `WasmProvider`.
	#[wasm_bindgen(constructor)]
	pub fn new(
		socket: WasmProvider,
		state: js_types::JsStateMgrCallbacks,
		bridges: Option<Vec<String>>,
	) -> Result<Self, EpoxyError> {
		let state_mgr = state_mgr::JsStateMgr::from_callbacks(state)?;

		let runtime = WasmTorRuntime::new(socket.0)?;
		let builder = WasmStateMgrBuilder::new(state_mgr);

		// `${ARTI_LOCAL_DATA}` and `${ARTI_CACHE}` can't be resolved on
		// `wasm32-unknown-unknown` (no real filesystem). Pin the dirs to literal
		// paths — our `JsStateMgr` is what actually persists data, and the
		// in-memory dir cache will be rebuilt on each fresh load.
		let mut config_builder = TorClientConfig::builder();
		config_builder
			.storage()
			.state_dir(CfgPath::new_literal("/wasm/state"))
			.cache_dir(CfgPath::new_literal("/wasm/cache"));
		// The keystore defaults to Native, which calls
		// `ArtiNativeKeystore::from_path_and_mistrust(state_dir.join("keystore"))`
		// — that fails on wasm because the path isn't real. Disable it; we
		// don't run hidden services or other key-using code from this client.
		config_builder
			.storage()
			.keystore()
			.enabled(BoolOrAuto::Explicit(false));
		// Allow `.onion` addresses by default. The
		// `onion-service-client` feature is on; without this flag arti
		// rejects onion targets at the address-filter layer.
		config_builder.address_filter().allow_onion_addrs(true);
		// Optional bridge list (snowflake uses this to force every channel
		// through our intercepting SocketProvider).
		if let Some(lines) = bridges
			&& !lines.is_empty()
		{
			config_builder
				.bridges()
				.enabled(BoolOrAuto::Explicit(true));
			for line in lines {
				let bridge: BridgeConfigBuilder = line
					.parse()
					.map_err(|e: arti_client::config::BridgeParseError| {
						EpoxyError::Unknown(e.into())
					})?;
				config_builder.bridges().bridges().push(bridge);
			}
		}

		let config = config_builder
			.build()
			.map_err(|e| EpoxyError::Unknown(e.into()))?;

		let client = TorClient::with_runtime(runtime)
			.config(config)
			.state_mgr_builder(Arc::new(builder))
			.dirmgr_store_builder(Arc::new(WasmDirStoreBuilder))
			.create_unbootstrapped()
			.map_err(|e| EpoxyError::Unknown(e.into()))?;

		Ok(Self {
			inner: Arc::new(TorSocketProviderInner {
				client: SendWrapper(client),
			}),
		})
	}

	/// Eagerly bootstrap the embedded `TorClient`.
	///
	/// If you skip this, the first `connect` will block until bootstrap
	/// finishes (the `BootstrapBehavior::OnDemand` default).
	pub async fn bootstrap(&self) -> Result<(), EpoxyError> {
		let inner = self.inner.clone();
		SendWrapper(async move {
			inner
				.client
				.0
				.bootstrap()
				.await
				.map_err(|e| EpoxyError::Unknown(e.into()))
		})
		.await
	}

	/// Subscribe to bootstrap progress updates.
	///
	/// `cb` is invoked with a `TorBootstrapProgress` object every time the
	/// underlying `TorClient`'s status changes — typical fields are
	/// `frac` (0-1), `ready` (boolean), `description` (human-readable),
	/// and `blocked` (`{ kind, message } | null`). The current snapshot is
	/// dispatched synchronously before this method returns.
	///
	/// Calling this more than once replaces the previous callback.
	pub fn on_progress(
		&self,
		cb: js_types::JsBootstrapCallback,
	) -> Result<(), EpoxyError> {
		let cb: Function = cb.unchecked_into();
		let inner = self.inner.clone();

		// Dispatch the current snapshot immediately so callers can render
		// initial state without waiting for the next event.
		let snap = inner.client.0.bootstrap_status();
		let _ = cb.call1(&JsValue::NULL, &status_to_js(&snap));

		let cb = SendWrapper(cb);
		spawn_local(async move {
			// `bootstrap_events()` returns a `postage::watch::Receiver` whose
			// `Stream` impl yields the current value each time it changes.
			let mut events = inner.client.0.bootstrap_events();
			while let Some(status) = SendWrapper(events.next()).await {
				let _ = cb.0.call1(&JsValue::NULL, &status_to_js(&status));
			}
		});

		Ok(())
	}

	/// Box this provider as a `WasmProvider` so it can be passed wherever a
	/// `SocketProvider` is expected.
	pub fn r#box(self) -> WasmProvider {
		WasmProvider(BoxProviderService::new(TorSocketProviderService {
			inner: self.inner,
		}))
	}
}

#[derive(Clone)]
struct TorSocketProviderService {
	inner: Arc<TorSocketProviderInner>,
}

impl ProviderService<ProviderServiceReq> for TorSocketProviderService {
	type Response = ProviderUnencryptedStream;
	type Error = EpoxyError;
	type Future = impl Future<Output = Result<Self::Response, Self::Error>> + Send;

	fn call(&self, request: ProviderServiceReq) -> Self::Future {
		let inner = self.inner.clone();
		SendWrapper(async move {
			let stream = inner
				.client
				.0
				.connect((request.host.as_str(), request.port))
				.await
				.map_err(|e| EpoxyError::Unknown(e.into()))?;

			let (read, write) = AsyncReadExt::split(stream);
			Ok(ProviderUnencryptedStream {
				read: Box::new(SendWrapper(read)),
				write: Box::new(SendWrapper(write)),
			})
		})
	}
}

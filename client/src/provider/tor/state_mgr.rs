use std::sync::Arc;

use arti_client::{
	ErrorDetail, StateMgrBuilder, TorClientConfig, UsingStateMgr,
};
use js_sys::{Function, Reflect};
use tor_persist::{
	Action as PersistAction, DynStateMgr, Error as PersistError, ErrorSource as PersistErrorSource,
	JsonValue, LockStatus,
};
use wasm_bindgen::{JsCast, JsValue};

use crate::{
	EpoxyError, EpoxyJsValErrorExt, jsval_debug,
	provider::tor::js_types::JsStateMgrCallbacks,
	send_wrapper::SendWrapper,
};

pub(crate) struct JsStateMgr {
	load: SendWrapper<Function>,
	store: SendWrapper<Function>,
}

impl JsStateMgr {
	pub fn from_callbacks(callbacks: JsStateMgrCallbacks) -> Result<Arc<Self>, EpoxyError> {
		let obj: JsValue = callbacks.into();
		let load: Function = Reflect::get(&obj, &"load".into())
			.js_error()?
			.dyn_into()
			.map_err(|x| EpoxyError::InvalidJsValue(jsval_debug(x)))?;
		let store: Function = Reflect::get(&obj, &"store".into())
			.js_error()?
			.dyn_into()
			.map_err(|x| EpoxyError::InvalidJsValue(jsval_debug(x)))?;

		Ok(Arc::new(Self {
			load: SendWrapper(load),
			store: SendWrapper(store),
		}))
	}
}

fn to_persist_err(msg: impl std::fmt::Display, action: PersistAction) -> PersistError {
	PersistError::from_dyn_mgr(
		PersistErrorSource::IoError(Arc::new(std::io::Error::other(msg.to_string()))),
		action,
	)
}

fn jsvalue_err(e: JsValue, action: PersistAction) -> PersistError {
	to_persist_err(jsval_debug(e), action)
}

impl DynStateMgr for JsStateMgr {
	fn load_json(&self, key: &str) -> Result<Option<JsonValue>, PersistError> {
		let result = self
			.load
			.0
			.call1(&JsValue::NULL, &key.into())
			.map_err(|e| jsvalue_err(e, PersistAction::Loading))?;

		if result.is_null() || result.is_undefined() {
			return Ok(None);
		}

		let s = result.as_string().ok_or_else(|| {
			to_persist_err(
				"JsStateMgr load callback returned non-string",
				PersistAction::Loading,
			)
		})?;

		let val: JsonValue =
			serde_json::from_str(&s).map_err(|e| to_persist_err(e, PersistAction::Loading))?;
		Ok(Some(val))
	}

	fn store_json(&self, key: &str, val: JsonValue) -> Result<(), PersistError> {
		let s = serde_json::to_string(&val).map_err(|e| to_persist_err(e, PersistAction::Storing))?;
		self.store
			.0
			.call2(&JsValue::NULL, &key.into(), &s.into())
			.map_err(|e| jsvalue_err(e, PersistAction::Storing))?;
		Ok(())
	}

	fn can_store(&self) -> bool {
		true
	}

	fn try_lock(&self) -> Result<LockStatus, PersistError> {
		Ok(LockStatus::AlreadyHeld)
	}

	fn unlock(&self) -> Result<(), PersistError> {
		Ok(())
	}
}

pub(crate) struct WasmStateMgrBuilder {
	mgr: Arc<dyn DynStateMgr>,
}

impl WasmStateMgrBuilder {
	pub fn new(mgr: Arc<dyn DynStateMgr>) -> Self {
		Self { mgr }
	}
}

impl StateMgrBuilder for WasmStateMgrBuilder {
	fn build(&self, _config: &TorClientConfig) -> Result<UsingStateMgr, ErrorDetail> {
		Ok(UsingStateMgr::Custom(self.mgr.clone()))
	}
}

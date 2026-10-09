use js_sys::{Array, Function, Promise};
use std::sync::{
	Arc,
	atomic::{AtomicBool, Ordering},
};
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use wisp_mux::{
	WispError, WispV2Handshake,
	extensions::{AnyProtocolExtension, AnyProtocolExtensionBuilder},
};

use crate::{
	EpoxyError, js_types::JsWispV2Middleware, provider::wisp::js_extension::JsProtocolExtension,
	send_wrapper::SendWrapper,
};

use super::{
	builtin_extension::{
		CertAuthProtocolExtension as JsCertAuthProtocolExtension,
		CertAuthProtocolExtensionBuilder as JsCertAuthProtocolExtensionBuilder,
		CertAuthProtocolExtensionBuilderRef as JsCertAuthProtocolExtensionBuilderRef,
		MotdProtocolExtension as JsMotdProtocolExtension,
		MotdProtocolExtensionBuilder as JsMotdProtocolExtensionBuilder,
		MotdProtocolExtensionBuilderRef as JsMotdProtocolExtensionBuilderRef,
		PasswordProtocolExtension as JsPasswordProtocolExtension,
		PasswordProtocolExtensionBuilder as JsPasswordProtocolExtensionBuilder,
		PasswordProtocolExtensionBuilderRef as JsPasswordProtocolExtensionBuilderRef,
		UdpProtocolExtension as JsUdpProtocolExtension,
		UdpProtocolExtensionBuilder as JsUdpProtocolExtensionBuilder,
		UdpProtocolExtensionBuilderRef as JsUdpProtocolExtensionBuilderRef,
	},
	js_extension::JsProtocolExtensionBuilder,
};
use wisp_mux::extensions::{
	cert::{
		CertAuthProtocolExtension as WispCertAuthProtocolExtension,
		CertAuthProtocolExtensionBuilder as WispCertAuthProtocolExtensionBuilder,
	},
	motd::{
		MotdProtocolExtension as WispMotdProtocolExtension,
		MotdProtocolExtensionBuilder as WispMotdProtocolExtensionBuilder,
	},
	password::{
		PasswordProtocolExtension as WispPasswordProtocolExtension,
		PasswordProtocolExtensionBuilder as WispPasswordProtocolExtensionBuilder,
	},
	udp::{
		UdpProtocolExtension as WispUdpProtocolExtension,
		UdpProtocolExtensionBuilder as WispUdpProtocolExtensionBuilder,
	},
};

#[macro_export]
macro_rules! refstruct {
	($name:ty, $refname:ident) => {
		#[wasm_bindgen::prelude::wasm_bindgen]
		pub struct $refname {
			inner: *mut $name,
			scope: std::sync::Arc<std::sync::atomic::AtomicBool>,
		}
		impl From<(&mut $name, std::sync::Arc<std::sync::atomic::AtomicBool>)> for $refname {
			fn from(value: (&mut $name, std::sync::Arc<std::sync::atomic::AtomicBool>)) -> Self {
				Self {
					inner: &raw mut *value.0,
					scope: value.1,
				}
			}
		}
		impl $refname {
			#[allow(dead_code)]
			fn inner(&self) -> Result<&mut $name, crate::EpoxyError> {
				if !self.scope.load(std::sync::atomic::Ordering::Acquire) {
					return Err(crate::EpoxyError::InvalidJsValue(format!(
						"{} escaped its valid scope",
						stringify!($refname)
					)));
				}

				Ok(unsafe { &mut *self.inner })
			}
		}
	};
}

pub struct RefScope(Arc<AtomicBool>);
impl RefScope {
	pub fn new() -> Self {
		Self(Arc::new(AtomicBool::new(true)))
	}

	pub fn token(&self) -> Arc<AtomicBool> {
		self.0.clone()
	}
}
impl Drop for RefScope {
	fn drop(&mut self) {
		self.0.store(false, Ordering::Release);
	}
}

#[wasm_bindgen(inline_js = "export let to_wisp_v2_handshake = x => x;")]
extern "C" {
	pub fn to_wisp_v2_handshake(val: JsValue) -> JsWispV2Handshake;
}

#[wasm_bindgen]
pub struct ProtocolExtensionBuilders(Vec<AnyProtocolExtensionBuilder>);
#[wasm_bindgen]
impl ProtocolExtensionBuilders {
	#[wasm_bindgen(constructor)]
	pub fn new() -> Self {
		Self(vec![])
	}

	pub fn js(&mut self, builder: JsProtocolExtensionBuilder) {
		self.0.push(AnyProtocolExtensionBuilder::new(builder));
	}

	pub fn udp(&mut self, builder: JsUdpProtocolExtensionBuilder) {
		self.0.push(AnyProtocolExtensionBuilder::new(builder.0));
	}

	pub fn motd(&mut self, builder: JsMotdProtocolExtensionBuilder) {
		self.0.push(AnyProtocolExtensionBuilder::new(builder.0));
	}

	pub fn password(&mut self, builder: JsPasswordProtocolExtensionBuilder) {
		self.0.push(AnyProtocolExtensionBuilder::new(builder.0));
	}

	pub fn cert(&mut self, builder: JsCertAuthProtocolExtensionBuilder) {
		self.0.push(AnyProtocolExtensionBuilder::new(builder.0));
	}
}

pub fn extension_to_jsval(ext: &mut AnyProtocolExtension, scope: Arc<AtomicBool>) -> JsValue {
	if let Some(js) = ext.downcast_mut::<JsProtocolExtension>() {
		js.js_host.clone()
	} else if let Some(udp) = ext.downcast_mut::<WispUdpProtocolExtension>() {
		let udp: JsUdpProtocolExtension = (udp, scope).into();
		udp.into()
	} else if let Some(motd) = ext.downcast_mut::<WispMotdProtocolExtension>() {
		let motd: JsMotdProtocolExtension = (motd, scope).into();
		motd.into()
	} else if let Some(password) = ext.downcast_mut::<WispPasswordProtocolExtension>() {
		let password: JsPasswordProtocolExtension = (password, scope).into();
		password.into()
	} else if let Some(cert) = ext.downcast_mut::<WispCertAuthProtocolExtension>() {
		let cert: JsCertAuthProtocolExtension = (cert, scope).into();
		cert.into()
	} else {
		unreachable!()
	}
}

fn builder_to_jsval(
	extension: &mut AnyProtocolExtensionBuilder,
	scope: Arc<AtomicBool>,
) -> JsValue {
	if let Some(js) = extension.downcast_mut::<JsProtocolExtensionBuilder>() {
		js.js_host.clone()
	} else if let Some(udp) = extension.downcast_mut::<WispUdpProtocolExtensionBuilder>() {
		let udp: JsUdpProtocolExtensionBuilderRef = (udp, scope).into();
		udp.into()
	} else if let Some(motd) = extension.downcast_mut::<WispMotdProtocolExtensionBuilder>() {
		let motd: JsMotdProtocolExtensionBuilderRef = (motd, scope).into();
		motd.into()
	} else if let Some(password) = extension.downcast_mut::<WispPasswordProtocolExtensionBuilder>()
	{
		let password: JsPasswordProtocolExtensionBuilderRef = (password, scope).into();
		password.into()
	} else if let Some(cert) = extension.downcast_mut::<WispCertAuthProtocolExtensionBuilder>() {
		let cert: JsCertAuthProtocolExtensionBuilderRef = (cert, scope).into();
		cert.into()
	} else {
		unreachable!()
	}
}

#[wasm_bindgen]
pub struct JsWispV2Handshake {
	#[wasm_bindgen(skip)]
	pub handshake: WispV2Handshake,
	#[wasm_bindgen(skip)]
	pub required: Vec<u8>,
}

#[wasm_bindgen]
impl JsWispV2Handshake {
	#[wasm_bindgen(constructor)]
	pub fn new(builders: ProtocolExtensionBuilders, required: Vec<u8>, middleware: JsWispV2Middleware) -> Self {
		let middleware: Function = middleware.unchecked_into();
		let closure: Box<wisp_mux::WispV2Middleware> =
			Box::new(move |extensions: &mut Vec<AnyProtocolExtensionBuilder>| {
				let middleware = middleware.clone();
				Box::pin(async move {
					let scope = RefScope::new();
					let array = Array::new();
					for extension in extensions {
						array.push(&builder_to_jsval(extension, scope.token()));
					}

					let output = middleware
						.call1(&JsValue::NULL, &array.clone().into())
						.map_err(|x| {
							WispError::ExtensionImplError(Box::new(EpoxyError::js_error(x)))
						})?;

					SendWrapper(JsFuture::from(output.unchecked_into::<Promise>()))
						.await
						.map_err(|x| {
							WispError::ExtensionImplError(Box::new(EpoxyError::js_error(x)))
						})?;

					Ok(())
				})
			});

		Self {
			handshake: WispV2Handshake::new(builders.0).with_middleware(closure),
			required,
		}
	}
}

use std::{
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

use futures::Future;
use js_sys::{Function, Promise};
use tor_rtcompat::{CoarseInstant, CoarseTimeProvider, RealCoarseTimeProvider, SleepProvider};
use wasm_bindgen::{JsCast, JsValue, prelude::Closure};
use wasm_bindgen_futures::JsFuture;

use crate::send_wrapper::SendWrapper;

use super::WasmTorRuntime;

#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function tor_setTimeout(callback, ms) {
	return setTimeout(callback, ms);
}
"#)]
extern "C" {
	#[wasm_bindgen(js_name = tor_setTimeout)]
	fn tor_set_timeout(callback: &Function, ms: f64) -> JsValue;
}

pub struct WasmSleep {
	inner: SendWrapper<JsFuture>,
}

impl WasmSleep {
	fn new(duration: Duration) -> Self {
		let ms = duration.as_secs_f64() * 1000.0;
		let promise = Promise::new(&mut |resolve, _reject| {
			let cb = Closure::once_into_js(move || {
				let _ = resolve.call0(&JsValue::NULL);
			});
			let _ = tor_set_timeout(cb.unchecked_ref::<Function>(), ms);
		});
		Self {
			inner: SendWrapper(JsFuture::from(promise)),
		}
	}
}

impl Future for WasmSleep {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		// SAFETY: SendWrapper preserves pinning of its inner field.
		let inner = unsafe { self.map_unchecked_mut(|s| &mut s.inner.0) };
		match inner.poll(cx) {
			Poll::Ready(_) => Poll::Ready(()),
			Poll::Pending => Poll::Pending,
		}
	}
}

impl SleepProvider for WasmTorRuntime {
	type SleepFuture = WasmSleep;

	fn sleep(&self, duration: Duration) -> Self::SleepFuture {
		WasmSleep::new(duration)
	}
}

impl CoarseTimeProvider for WasmTorRuntime {
	fn now_coarse(&self) -> CoarseInstant {
		RealCoarseTimeProvider::new().now_coarse()
	}
}

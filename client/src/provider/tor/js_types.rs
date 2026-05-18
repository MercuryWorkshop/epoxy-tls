use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const TOR_JS_TYPES_TS: &str = r#"
export type TorStateMgrCallbacks = {
	load: (key: string) => string | null | undefined;
	store: (key: string, value: string) => void;
};

export type TorBootstrapBlockage = {
	kind: string;
	message: string;
};
export type TorBootstrapProgress = {
	/** 0–1, rough progress estimate. */
	frac: number;
	/** True once the client can serve traffic. */
	ready: boolean;
	/** Human-readable status string (don't parse this). */
	description: string;
	/** Set when the client is stuck; `null` otherwise. */
	blocked: TorBootstrapBlockage | null;
};
export type TorBootstrapCallback = (progress: TorBootstrapProgress) => void;
"#;

#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(typescript_type = "TorStateMgrCallbacks")]
	pub type JsStateMgrCallbacks;

	#[wasm_bindgen(typescript_type = "TorBootstrapCallback")]
	pub type JsBootstrapCallback;
}

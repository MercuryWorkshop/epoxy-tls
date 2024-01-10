use wasm_bindgen::prelude::*;

use js_sys::{Array, Object};

pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    pub fn console_debug(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(s: &str);
    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(s: &str);
}

macro_rules! debug {
    ($($t:tt)*) => (utils::console_debug(&format_args!($($t)*).to_string()))
}

macro_rules! log {
    ($($t:tt)*) => (utils::console_log(&format_args!($($t)*).to_string()))
}

macro_rules! error {
    ($($t:tt)*) => (utils::console_error(&format_args!($($t)*).to_string()))
}

macro_rules! nerr {
    ($expr:expr) => (JsError::new($expr))
}

pub fn entries_of_object(obj: &Object) -> Vec<Vec<String>> {
    js_sys::Object::entries(obj)
        .to_vec()
        .iter()
        .map(|val| {
            Array::from(val)
                .to_vec()
                .iter()
                .map(|val| {
                    val.as_string()
                        .expect_throw("failed to get string from object entry")
                })
                .collect()
        })
        .collect::<Vec<Vec<_>>>()
}

pub trait ReplaceErr {
    type Ok;

    fn replace_err(self, err: &str) -> Result<Self::Ok, JsError>;
}

impl<T, E> ReplaceErr for Result<T, E> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.map_err(|_| JsError::new(err))
    }
}

impl<T> ReplaceErr for Option<T> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.ok_or_else(|| JsError::new(err))
    }
}

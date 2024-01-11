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

#[allow(unused_macros)]
macro_rules! debug {
    ($($t:tt)*) => (utils::console_debug(&format_args!($($t)*).to_string()))
}

#[allow(unused_macros)]
macro_rules! log {
    ($($t:tt)*) => (utils::console_log(&format_args!($($t)*).to_string()))
}

#[allow(unused_macros)]
macro_rules! error {
    ($($t:tt)*) => (utils::console_error(&format_args!($($t)*).to_string()))
}

#[allow(unused_macros)]
macro_rules! jerr {
    ($expr:expr) => {
        JsError::new($expr)
    };
}

#[allow(unused_macros)]
macro_rules! jval {
    ($expr:expr) => {
        JsValue::from($expr)
    };
}

pub trait ReplaceErr {
    type Ok;

    fn replace_err(self, err: &str) -> Result<Self::Ok, JsError>;
    fn replace_err_jv(self, err: &str) -> Result<Self::Ok, JsValue>;
}

impl<T, E> ReplaceErr for Result<T, E> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.map_err(|_| jerr!(err))
    }

    fn replace_err_jv(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsValue> {
        self.map_err(|_| jval!(err))
    }
}

impl<T> ReplaceErr for Option<T> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.ok_or_else(|| jerr!(err))
    }

    fn replace_err_jv(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsValue> {
        self.ok_or_else(|| jval!(err))
    }
}

pub fn entries_of_object(obj: &Object) -> Vec<Vec<String>> {
    js_sys::Object::entries(obj)
        .to_vec()
        .iter()
        .filter_map(|val| {
            Array::from(val)
                .to_vec()
                .iter()
                .map(|val| val.as_string())
                .collect::<Option<Vec<_>>>()
        })
        .collect::<Vec<Vec<_>>>()
}

pub fn define_property_obj(value: JsValue, writable: bool) -> Result<Object, JsValue> {
    let entries: Array = [
        Array::of2(&jval!("value"), &jval!(value)),
        Array::of2(&jval!("writable"), &jval!(writable)),
    ]
    .iter().collect::<Array>();
    Object::from_entries(&entries)
}

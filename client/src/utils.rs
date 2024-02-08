use wasm_bindgen::prelude::*;

use hyper::rt::Executor;
use hyper::{header::HeaderValue, Uri};
use js_sys::{Array, Object};
use std::future::Future;

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

impl<T, E: std::fmt::Debug> ReplaceErr for Result<T, E> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.map_err(|oe| jerr!(&format!("{}, original error: {:?}", err, oe)))
    }

    fn replace_err_jv(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsValue> {
        self.map_err(|oe| jval!(&format!("{}, original error: {:?}", err, oe)))
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

pub trait UriExt {
    fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, JsError>;
    fn is_same_host(&self, other: &Uri) -> bool;
}

impl UriExt for Uri {
    fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, JsError> {
        let new_uri = location.to_str()?.parse::<hyper::Uri>()?;
        let mut new_parts: http::uri::Parts = new_uri.into();
        if new_parts.scheme.is_none() {
            new_parts.scheme = self.scheme().cloned();
        }
        if new_parts.authority.is_none() {
            new_parts.authority = self.authority().cloned();
        }

        Ok(Uri::from_parts(new_parts)?)
    }
    fn is_same_host(&self, other: &Uri) -> bool {
        self.host() == other.host() && self.port() == other.port()
    }
}

#[derive(Clone)]
pub struct WasmExecutor;

impl<F> Executor<F> for WasmExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        wasm_bindgen_futures::spawn_local(async move {
            let _ = future.await;
        });
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
    .iter()
    .collect::<Array>();
    Object::from_entries(&entries)
}

pub fn is_redirect(code: u16) -> bool {
    [301, 302, 303, 307, 308].contains(&code)
}

pub fn get_is_secure(url: &Uri) -> Result<bool, JsError> {
    let url_scheme_str = url.scheme_str().replace_err("URL must have a scheme")?;
    match url_scheme_str {
        "https" | "wss" => Ok(true),
        _ => Ok(false),
    }
}

pub fn get_url_port(url: &Uri) -> Result<u16, JsError> {
    if let Some(port) = url.port() {
        Ok(port.as_u16())
    } else if get_is_secure(url)? {
        Ok(443)
    } else {
        Ok(80)
    }
}

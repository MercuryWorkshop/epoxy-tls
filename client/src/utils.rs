use wasm_bindgen::{intern, prelude::*};

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

macro_rules! debug {
    ($($t:tt)*) => (utils::console_debug(&format_args!($($t)*).to_string()))
}

#[allow(unused_macros)]
macro_rules! log {
    ($($t:tt)*) => (utils::console_log(&format_args!($($t)*).to_string()))
}

macro_rules! error {
    ($($t:tt)*) => (utils::console_error(&format_args!($($t)*).to_string()))
}

macro_rules! jerr {
    ($expr:expr) => {
        JsError::new($expr)
    };
}

macro_rules! jval {
    ($expr:expr) => {
        JsValue::from($expr)
    };
}

macro_rules! jerri {
    ($expr:expr) => {
        JsError::new(intern($expr))
    };
}

macro_rules! jvali {
    ($expr:expr) => {
        JsValue::from(intern($expr))
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
        self.map_err(|_| jerri!(err))
    }

    fn replace_err_jv(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsValue> {
        self.map_err(|_| jvali!(err))
    }
}

impl<T> ReplaceErr for Option<T> {
    type Ok = T;

    fn replace_err(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsError> {
        self.ok_or_else(|| jerri!(err))
    }

    fn replace_err_jv(self, err: &str) -> Result<<Self as ReplaceErr>::Ok, JsValue> {
        self.ok_or_else(|| jvali!(err))
    }
}

// the... BOOLINATOR!
impl ReplaceErr for bool {
    type Ok = ();

    fn replace_err(self, err: &str) -> Result<(), JsError> {
        if !self {
            Err(jerri!(err))
        } else {
            Ok(())
        }
    }

    fn replace_err_jv(self, err: &str) -> Result<(), JsValue> {
        if !self {
            Err(jvali!(err))
        } else {
            Ok(())
        }
    }
}

// the... BOOLINATOR!
pub trait Boolinator {
    fn flatten(self, err: &str) -> Result<(), JsError>;
}

impl Boolinator for Result<bool, JsValue> {
    fn flatten(self, err: &str) -> Result<(), JsError> {
        if !self.replace_err(err)? {
            Err(jerri!(err))
        } else {
            Ok(())
        }
    }
}

pub trait UriExt {
    fn get_redirect(&self, location: &HeaderValue) -> Result<Uri, JsError>;
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
        Array::of2(&jval!(intern("value")), &value),
        Array::of2(&jval!(intern("writable")), &jval!(writable)),
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

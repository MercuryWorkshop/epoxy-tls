use default_env::default_env;
use epoxy_client::EpoxyClient;
use js_sys::{JsString, Object, Reflect, Uint8Array, JSON};
use tokio::sync::OnceCell;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;
use web_sys::{FormData, Headers, Response, UrlSearchParams};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

static USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
static EPOXY_CLIENT: OnceCell<EpoxyClient> = OnceCell::const_new();

async fn get_client_w_ua(useragent: &str, redirect_limit: usize) -> EpoxyClient {
    EpoxyClient::new(
        "ws://localhost:4000".into(),
        useragent.into(),
        redirect_limit,
    )
    .await
    .ok()
    .expect("Failed to create client")
}

macro_rules! fetch {
    ($url:expr, $opts:expr) => {
        EPOXY_CLIENT
            .get_or_init(|| get_client_w_ua(USER_AGENT, 10))
            .await
            .fetch($url, $opts)
            .await
            .ok()
            .expect("Failed to fetch")
    };
}
macro_rules! httpbin {
    ($url:literal) => {
        concat!(default_env!("HTTPBIN_URL", "https://httpbin.org/"), $url)
    };
}

async fn get_body_json(resp: &Response) -> JsValue {
    JsFuture::from(resp.json().unwrap()).await.unwrap()
}
async fn get_body_text(resp: &Response) -> JsValue {
    JsFuture::from(resp.text().unwrap()).await.unwrap()
}

fn get_header(body: &JsValue, header: &str) -> Result<JsValue, JsValue> {
    Reflect::get(body, &JsValue::from("headers"))
        .and_then(|x| Reflect::get(&x, &JsValue::from(header)))
}
fn get_resp_body(body: &JsValue) -> Result<JsValue, JsValue> {
    Reflect::get(body, &JsValue::from("data"))
}
fn get_resp_form(body: &JsValue) -> Result<JsValue, JsValue> {
    Reflect::get(body, &JsValue::from("form"))
}

fn check_resp(resp: &Response, url: &str, status: u16, status_text: &str) {
    assert_eq!(resp.url(), url);
    assert_eq!(resp.status(), status);
    assert_eq!(resp.status_text(), status_text);
}

#[wasm_bindgen_test]
async fn get() {
    let url = httpbin!("get");
    let resp = fetch!(url.into(), Object::new());

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_header(&body, "User-Agent"),
        Ok(JsValue::from(USER_AGENT))
    );
}

#[wasm_bindgen_test]
async fn gzip() {
    let url = httpbin!("gzip");
    let resp = fetch!(url.into(), Object::new());

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_header(&body, "Accept-Encoding"),
        Ok(JsValue::from("gzip, br"))
    );
}

#[wasm_bindgen_test]
async fn brotli() {
    let url = httpbin!("brotli");
    let resp = fetch!(url.into(), Object::new());

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_header(&body, "Accept-Encoding"),
        Ok(JsValue::from("gzip, br"))
    );
}

#[wasm_bindgen_test]
async fn redirect() {
    let url = httpbin!("redirect/2");
    let resp = fetch!(url.into(), Object::new());

    check_resp(&resp, httpbin!("get"), 200, "OK");

    get_body_json(&resp).await;
}

#[wasm_bindgen_test]
async fn redirect_limit() {
    // new client created due to redirect limit difference
    let client = get_client_w_ua(USER_AGENT, 2).await;
    let url = httpbin!("redirect/3");
    let resp = client
        .fetch(url.into(), Object::new())
        .await
        .ok()
        .expect("Failed to fetch");

    check_resp(&resp, httpbin!("relative-redirect/1"), 302, "Found");

    assert_eq!(get_body_text(&resp).await, JsValue::from(""));
}

#[wasm_bindgen_test]
async fn redirect_manual() {
    let url = httpbin!("redirect/2");

    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from("redirect"), &JsValue::from("manual")).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 302, "Found");

    get_body_text(&resp).await;
}

#[wasm_bindgen_test]
async fn post_string() {
    let url = httpbin!("post");
    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from("method"), &JsValue::from("POST")).unwrap();
    Reflect::set(&obj, &JsValue::from("body"), &JsValue::from("epoxy body")).unwrap();
    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(get_resp_body(&body), Ok(JsValue::from("epoxy body")));
}

#[wasm_bindgen_test]
async fn post_arraybuffer() {
    let url = httpbin!("post");

    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from("method"), &JsValue::from("POST")).unwrap();
    let req_body = b"epoxy body";
    let u8array = Uint8Array::new_with_length(req_body.len().try_into().unwrap());
    u8array.copy_from(req_body);
    Reflect::set(&obj, &JsValue::from("body"), &u8array).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(get_resp_body(&body), Ok(JsValue::from("epoxy body")));
}

#[wasm_bindgen_test]
async fn post_formdata() {
    let url = httpbin!("post");

    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from("method"), &JsValue::from("POST")).unwrap();
    let req_body = FormData::new().unwrap();
    req_body.set_with_str("a", "b").unwrap();
    Reflect::set(&obj, &JsValue::from("body"), &req_body).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_resp_form(&body).and_then(|x| JSON::stringify(&x)),
        Ok(JsString::from(r#"{"a":"b"}"#))
    );
    assert!(JsString::from(get_header(&body, "Content-Type").unwrap())
        .includes("multipart/form-data", 0));
}

#[wasm_bindgen_test]
async fn post_urlsearchparams() {
    let url = httpbin!("post");

    let obj = Object::new();
    Reflect::set(&obj, &JsValue::from("method"), &JsValue::from("POST")).unwrap();
    let req_body = UrlSearchParams::new_with_str("a=b").unwrap();
    Reflect::set(&obj, &JsValue::from("body"), &req_body).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_resp_form(&body).and_then(|x| JSON::stringify(&x)),
        Ok(JsString::from(r#"{"a":"b"}"#))
    );
    assert!(JsString::from(get_header(&body, "Content-Type").unwrap())
        .includes("application/x-www-form-urlencoded", 0));
}

#[wasm_bindgen_test]
async fn headers_obj() {
    let url = httpbin!("get");

    let obj = Object::new();
    let headers = Object::new();
    Reflect::set(
        &headers,
        &JsValue::from("x-header-one"),
        &JsValue::from("value"),
    )
    .unwrap();
    Reflect::set(&obj, &JsValue::from("headers"), &headers).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_header(&body, "X-Header-One"),
        Ok(JsValue::from("value"))
    );
}

#[wasm_bindgen_test]
async fn headers_headers() {
    let url = httpbin!("get");

    let obj = Object::new();
    let headers = Headers::new().unwrap();
    headers.set("x-header-one", "value").unwrap();
    Reflect::set(&obj, &JsValue::from("headers"), &headers).unwrap();

    let resp = fetch!(url.into(), obj);

    check_resp(&resp, url, 200, "OK");

    let body: Object = get_body_json(&resp).await.into();
    assert_eq!(
        get_header(&body, "X-Header-One"),
        Ok(JsValue::from("value"))
    );
}

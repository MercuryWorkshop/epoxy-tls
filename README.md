# epoxy
Epoxy is an encrypted proxy for browser javascript. It allows you to make requests that bypass cors without compromising security, by running SSL/TLS inside webassembly.

Simple usage example for making a secure GET request to httpbin.org:
```javascript
import epoxy from "@mercuryworkshop/epoxy-tls";

const { EpoxyClient } = await epoxy();
let client = await new EpoxyClient("wss://localhost:4000", navigator.userAgent, 10);

let response = await client.fetch("https://httpbin.org/get");
await response.text();

```

Epoxy also allows you to make arbitrary end to end encrypted TCP connections safely directly from the browser.

## Building

### Server

1. Generate certs with `mkcert` and place the public certificate in `./server/src/pem.pem` and private certificate in `./server/src/key.pem`
2. Run `cargo r --bin epoxy-server`, optionally with `-r` flag for release

### Client
Note: Building the client is only supported on linux

1. Make sure you have the `wasm32-unknown-unknown` target installed, `wasm-bindgen` and `wasm-opt` executables installed, and `bash`, `python3` packages (`python3` is used for `http.server` module)
2. Run `pnpm build`

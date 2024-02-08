# epoxy
Epoxy is an encrypted proxy for browser javascript. It allows you to make requests that bypass cors without compromising security, by running SSL/TLS inside webassembly.

## Using the client
Epoxy must be run from within a web worker and must be served with the [security headers needed for `SharedArrayBuffer`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements). Here is a simple usage example:
```javascript
importScripts("epoxy-bundled.js");

const { EpoxyClient } = await epoxy();
let client = await new EpoxyClient("wss://localhost:4000", navigator.userAgent, 10);

let response = await client.fetch("https://httpbin.org/get");
await response.text();
```

## Using the server
```
$ cargo r -r --bin epoxy-server -- --help
Implementation of the Wisp protocol in Rust, made for epoxy.

Usage: epoxy-server [OPTIONS] --pubkey <PUBKEY> --privkey <PRIVKEY>

Options:
      --prefix <PREFIX>    [default: ]
  -l, --port <PORT>        [default: 4000]
  -p, --pubkey <PUBKEY>    
  -P, --privkey <PRIVKEY>  
  -h, --help               Print help
  -V, --version            Print version
```

## Building
Rust nightly is required.

### Server
```
cargo b -r --bin epoxy-server
```
The executable will be placed at `target/release/epoxy-server`.

### Client
> [!IMPORTANT]
> Building the client is only supported on Linux.

Make sure you have the `wasm32-unknown-unknown` rust target, the `rust-std` component, and the `wasm-bindgen`, `wasm-opt`, and `base64` binaries installed.

In the `client` directory:
```
bash build.sh
```

To host a local server with the required headers:
```
python3 serve.py
```

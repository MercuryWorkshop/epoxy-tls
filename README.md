# epoxy
Epoxy is an encrypted proxy for browser javascript. It allows you to make requests that bypass CORS without compromising security, by running SSL/TLS inside webassembly.

## Using the client
Here is a simple usage example:
```javascript
import epoxy from "./epoxy-module-bundled.js";

const { EpoxyClient, EpoxyClientOptions } = await epoxy();

let options = new EpoxyClientOptions();
options.user_agent = navigator.userAgent;

let client = await new EpoxyClient("wss://localhost:4000", options);

let response = await client.fetch("https://httpbin.org/get");
console.log(await response.text());
```
See `client/demo.js` for more examples.

## Using the server
See the [server readme](server/README.md).

## Building

### Server
See the [server readme](server/README.md).

### Client
> [!IMPORTANT]
> Building the client is only supported on Linux.

Make sure you have the `wasm32-unknown-unknown` rust target, the `rust-std` component, and the `wasm-bindgen`, `wasm-opt`, `jq`, and `base64` binaries installed.

In the `client` directory:
```
bash build.sh
```

To host a local server: 
```
python3 -m http.server
```

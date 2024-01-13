# wsproxy-rust

## Building

### Server

1. Generate certs with `mkcert` and place the public certificate in `./server/src/pem.pem` and private certificate in `./server/src/key.pem`
2. Run `cargo r --bin wstcp-server`, optionally with `-r` flag for release

### Client

1. Make sure you have the `wasm32-unknown-unknown` target installed, `wasm-bindgen` and `wasm-opt` executables installed, and `bash`, `python3` packages (`python3` is used for `http.server` module)
2. Run `bash build.sh` to build without wasm-opt and start a webserver

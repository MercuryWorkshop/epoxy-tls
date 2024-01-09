# wsproxy-rust

## Building

### Server
1. Place your certs in the source folder, public named `pem.pem` and private named `key.pem`
2. Run `cargo r --bin wstcp-server`, optionally with `-r` flag for release

### Client
1. Make sure you have the `wasm32-unknown-unknown` target installed, `wasm-bindgen` executable installed, and `bash`, `python3` packages (`python3` is used for `http.server` module)
2. Run `bash build.sh` to build and start a webserver

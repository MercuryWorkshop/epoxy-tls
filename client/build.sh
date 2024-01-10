#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

rm -rf out/ || true
mkdir out/
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --weak-refs --no-typescript --target no-modules --out-dir out/ ../target/wasm32-unknown-unknown/release/wstcp_client.wasm
cp -r src/web/* out/
(cd out; python3 -m http.server)

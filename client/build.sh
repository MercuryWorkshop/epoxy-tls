#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

rm -rf out/ || true
mkdir out/
cargo build --target wasm32-unknown-unknown --release
wasm-bindgen --weak-refs --no-typescript --target no-modules --out-dir out/ ../target/wasm32-unknown-unknown/release/wstcp_client.wasm
if [[ "$#" > 0 ]]; then
  mv out/wstcp_client_bg.wasm out/wstcp_client_unoptimized.wasm
  wasm-opt -O4 out/wstcp_client_unoptimized.wasm -o out/wstcp_client_bg.wasm
fi
cp -r src/web/* out/
(cd out; python3 -m http.server)

#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

rm -rf out/ || true
mkdir out/

cargo build --target wasm32-unknown-unknown --release
echo "[ws] built rust"
wasm-bindgen --weak-refs --no-typescript --target no-modules --out-dir out/ ../target/wasm32-unknown-unknown/release/wstcp_client.wasm
echo "[ws] bindgen finished"

mv out/wstcp_client_bg.wasm out/wstcp_client_unoptimized.wasm
wasm-opt out/wstcp_client_unoptimized.wasm -o out/wstcp_client_bg.wasm
echo "[ws] optimized"

AUTOGENERATED_SOURCE=$(<"out/wstcp_client.js")
WASM_BASE64=$(base64 -w0 out/wstcp_client_bg.wasm)
echo "${AUTOGENERATED_SOURCE//__wbg_init(input) \{/__wbg_init(input) \{input=\'data:application/wasm;base64,$WASM_BASE64\'}" > out/wstcp_client_bundled.js

cp -r src/web/* out/
echo "[ws] done!"
(cd out; python3 -m http.server)

#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

mkdir out/ || true
rm -r pkg/ || true
mkdir pkg/

RUSTFLAGS='-C target-feature=+atomics,+bulk-memory -Zlocation-detail=none' cargo build --target wasm32-unknown-unknown -Z build-std=panic_abort,std -Z build-std-features=panic_immediate_abort,optimize_for_size --release "$@"
echo "[epx] cargo finished"
wasm-bindgen --target web --out-dir out/ ../target/wasm32-unknown-unknown/release/epoxy_client.wasm
echo "[epx] wasm-bindgen finished"

if ! [ "${RELEASE:-0}" = "1" ]; then
	WASMOPTFLAGS="-g"
else
	WASMOPTFLAGS=""
fi

mv out/epoxy_client_bg.wasm out/epoxy_client_unoptimized.wasm
time wasm-opt $WASMOPTFLAGS -Oz --vacuum --dce --enable-threads --enable-bulk-memory out/epoxy_client_unoptimized.wasm -o out/epoxy_client_bg.wasm
echo "[epx] wasm-opt finished"

# === js ===

AUTOGENERATED_SOURCE=$(<"out/epoxy_client.js")

AUTOGENERATED_SNIPPET_PATH=$(<"out/epoxy_client.js")
# remove everything before the snippet path quote (which is the first quote in the file)
AUTOGENERATED_SNIPPET_PATH=${AUTOGENERATED_SNIPPET_PATH#*$'\''}
# remove everything after the snippet path quote (which is the second quote in the file)
AUTOGENERATED_SNIPPET_PATH=${AUTOGENERATED_SNIPPET_PATH%%$'\''*}

# replace a dot at the start of the var with out
AUTOGENERATED_SNIPPET=$(base64 -w0 ${AUTOGENERATED_SNIPPET_PATH/#./out})

AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//${AUTOGENERATED_SNIPPET_PATH}/data:application/javascript$';'base64,${AUTOGENERATED_SNIPPET}}

# patch for websocket sharedarraybuffer error
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//getObject(arg0).send(getArrayU8FromWasm0(arg1, arg2)/getObject(arg0).send(new Uint8Array(getArrayU8FromWasm0(arg1, arg2)).buffer}
# patch for safari OOM errors on safari iOS 16/older devices
# also lowers maximum memory from default of 1GB to 512M on non-iOS and to 256M on iOS
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//maximum:16384,shared:true/maximum:/iPad|iPhone|iPod/.test(navigator.userAgent)?4096:8192,shared:true}
# patch to set proper wasm path
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//'_bg.wasm'/'.wasm'}
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//'epoxy_client.wasm'/'epoxy.wasm'}

# delete initSync export
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//export $'{' initSync $'}\n'/}

# don't export internals
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//return __wbg_finalize_init/__wbg_finalize_init}

echo "$AUTOGENERATED_SOURCE" > pkg/epoxy.js

WASM_BASE64=$(base64 -w0 out/epoxy_client_bg.wasm)
AUTOGENERATED_SOURCE=${AUTOGENERATED_SOURCE//__wbg_init(input, maybe_memory) \{/__wbg_init(maybe_memory) \{$'\n'let input=\'data:application/wasm;base64,$WASM_BASE64\'}

echo "$AUTOGENERATED_SOURCE" > pkg/epoxy-bundled.js

# === types ===

AUTOGENERATED_TYPES=$(<"out/epoxy_client.d.ts")

AUTOGENERATED_TYPES=${AUTOGENERATED_TYPES//$'\n'export interface InitOutput*InitOutput;$'\n'/}
AUTOGENERATED_TYPES=${AUTOGENERATED_TYPES//Promise<InitOutput>/Promise<void>}

echo "$AUTOGENERATED_TYPES" > pkg/epoxy.d.ts

# remove useless comment
AUTOGENERATED_TYPES=${AUTOGENERATED_TYPES//$'\n*' If $'`'module_or_path*$'}' module_or_path/}
AUTOGENERATED_TYPES=${AUTOGENERATED_TYPES//module_or_path*, /}

echo "$AUTOGENERATED_TYPES" > pkg/epoxy-bundled.d.ts

cp out/epoxy_client_bg.wasm pkg/epoxy.wasm

rm -r out/
echo "[epx] done!"

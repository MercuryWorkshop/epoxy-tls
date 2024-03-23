#!/usr/bin/env bash
# https://aweirdimagination.net/2020/06/28/kill-child-jobs-on-script-exit/
cleanup() {
    pkill -P $$
}

for sig in INT QUIT HUP TERM; do
  trap "
    cleanup
    trap - $sig EXIT
    kill -s $sig "'"$$"' "$sig"
done
trap cleanup EXIT

set -euo pipefail
shopt -s inherit_errexit

(cd ..; cargo b --bin epoxy-server) 
../target/debug/epoxy-server &
server_pid=$!
sleep 1
echo "server_pid: $server_pid"

GECKODRIVER=$(which geckodriver) cargo test --target wasm32-unknown-unknown
CHROMEDRIVER=$(which chromedriver) cargo test --target wasm32-unknown-unknown

#!/usr/bin/env bash
(cd ..; cargo b --bin epoxy-server) 
../target/debug/epoxy-server &
server_pid=$!
sleep 1
echo "server_pid: $server_pid"

cargo test --target wasm32-unknown-unknown

kill $server_pid

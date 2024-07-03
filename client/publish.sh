#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

rm -r full minimal || true

cargo clean
bash build.sh
mv pkg full
bash build.sh --no-default-features
mv pkg minimal

#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

export RELEASE=1

rm -r full minimal || true

cargo clean
bash build.sh
mv pkg full
MINIMAL=1 bash build.sh
mv pkg minimal

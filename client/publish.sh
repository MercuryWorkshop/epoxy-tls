#!/usr/bin/env bash
set -euo pipefail
shopt -s inherit_errexit

cd "$(dirname "${BASH_SOURCE[0]}")"

export RELEASE="${RELEASE:-1}"

rm -r full minimal || true

bash build.sh
mv pkg full
MINIMAL=1 bash build.sh
mv pkg minimal

#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"${ROOT}/scripts/test_roundtrip.sh"
PORT=17774 "${ROOT}/scripts/test_negative_garbage.sh"
echo "Все тесты прошли."

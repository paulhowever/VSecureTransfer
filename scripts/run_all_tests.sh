#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
if [[ -n "${VSECURE_UNIT_TESTS:-}" ]] && [[ -x "${VSECURE_UNIT_TESTS}" ]]; then
  echo "=== Юнит-тесты (ctest) ==="
  (cd "${ROOT}/build" && ctest --output-on-failure)
fi
export VSECURE_SKIP_REBUILD=1
"${ROOT}/scripts/test_roundtrip.sh"
PORT=17774 "${ROOT}/scripts/test_negative_garbage.sh"
echo "Все тесты прошли."

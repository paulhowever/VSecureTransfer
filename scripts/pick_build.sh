#!/usr/bin/env bash
# Единая логика: при наличии cmake — сборка в build/, иначе Makefile в корне.
# shellcheck source=scripts/pick_build.sh — подключать: source "${ROOT}/scripts/pick_build.sh"
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

if [[ "${VSECURE_SKIP_REBUILD:-}" == "1" ]] && [[ -n "${VSECURE_SENDER:-}" ]] && [[ -x "${VSECURE_SENDER}" ]] &&
  [[ -n "${VSECURE_RECEIVER:-}" ]] && [[ -x "${VSECURE_RECEIVER}" ]]; then
  if [[ -x "${ROOT}/build/vsecure_unit_tests" ]]; then
    export VSECURE_UNIT_TESTS="${ROOT}/build/vsecure_unit_tests"
  else
    unset VSECURE_UNIT_TESTS 2>/dev/null || true
  fi
  if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    exit 0
  fi
  return 0
fi

if command -v cmake >/dev/null 2>&1; then
  BUILDD="${ROOT}/build"
  mkdir -p "${BUILDD}"
  cmake -S "${ROOT}" -B "${BUILDD}" -DCMAKE_BUILD_TYPE=Release -DVSECURE_BUILD_TESTS=ON >/dev/null
  cmake --build "${BUILDD}" -j >/dev/null
  export VSECURE_SENDER="${BUILDD}/vsecure_sender"
  export VSECURE_RECEIVER="${BUILDD}/vsecure_receiver"
  if [[ -x "${BUILDD}/vsecure_unit_tests" ]]; then
    export VSECURE_UNIT_TESTS="${BUILDD}/vsecure_unit_tests"
  else
    unset VSECURE_UNIT_TESTS 2>/dev/null || true
  fi
else
  make -C "${ROOT}" -j >/dev/null
  export VSECURE_SENDER="${ROOT}/vsecure_sender"
  export VSECURE_RECEIVER="${ROOT}/vsecure_receiver"
  unset VSECURE_UNIT_TESTS 2>/dev/null || true
fi

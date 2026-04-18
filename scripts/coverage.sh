#!/usr/bin/env bash
# Сборка с --coverage, ctest и краткий отчёт gcov/lcov (gcc/clang).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
BUILD="${ROOT}/build_cov"
rm -rf "${BUILD}"
if ! command -v cmake >/dev/null 2>&1; then
  echo "Нужен cmake для покрытия (FetchContent Catch2)." >&2
  exit 1
fi
cmake -S "${ROOT}" -B "${BUILD}" -DCMAKE_BUILD_TYPE=Debug \
  -DVSECURE_BUILD_TESTS=ON -DVSECURE_ENABLE_COVERAGE=ON
cmake --build "${BUILD}" -j
(
  cd "${BUILD}"
  ctest --output-on-failure
)
echo ""
echo "=== gcda (фрагмент) ==="
find "${BUILD}" -name "*.gcda" 2>/dev/null | head -20 || true
if command -v lcov >/dev/null 2>&1; then
  lcov --capture --directory "${BUILD}" --output-file "${BUILD}/coverage.info" --ignore-errors mismatch,unused
  echo ""
  echo "=== lcov --summary ==="
  lcov --summary "${BUILD}/coverage.info" 2>/dev/null || true
fi
echo ""
echo "Артефакты: ${BUILD}/coverage.info (если установлен lcov), иначе gcov по объектным файлам в ${BUILD}."

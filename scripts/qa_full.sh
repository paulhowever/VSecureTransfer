#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
echo "=== QA: сборка ==="
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
export VSECURE_SKIP_REBUILD=1
echo "=== QA: базовые и негативные тесты ==="
./scripts/run_all_tests.sh
echo "=== QA: крупный файл ==="
./scripts/test_large_roundtrip.sh
echo "=== QA: повтор пакета (replay) ==="
./scripts/test_replay_packet.sh
echo "=== QA: неверный публичный ключ отправителя ==="
./scripts/test_wrong_sender_pubkey.sh
echo "=== Все проверки QA пройдены ==="

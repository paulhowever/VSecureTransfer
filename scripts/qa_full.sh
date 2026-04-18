#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
echo "=== QA: сборка ==="
make clean && make -j
echo "=== QA: базовые и негативные тесты ==="
./scripts/run_all_tests.sh
echo "=== QA: крупный файл ==="
./scripts/test_large_roundtrip.sh
echo "=== QA: повтор пакета (replay) ==="
./scripts/test_replay_packet.sh
echo "=== QA: неверный публичный ключ отправителя ==="
./scripts/test_wrong_sender_pubkey.sh
echo "=== Все проверки QA пройдены ==="

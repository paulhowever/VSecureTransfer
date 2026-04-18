#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17771}"
OUT="${ROOT}/build_recv_out"
KEYS="${ROOT}/keys"

mkdir -p "${OUT}" "${KEYS}"
if [[ ! -f "${KEYS}/sender_sign_priv.pem" ]]; then
  "${ROOT}/scripts/gen_keys.sh"
fi

if command -v cmake >/dev/null 2>&1; then
  BUILD="${ROOT}/build"
  mkdir -p "${BUILD}"
  cmake -S "${ROOT}" -B "${BUILD}" -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "${BUILD}" -j
  SENDER="${BUILD}/vsecure_sender"
  RECEIVER="${BUILD}/vsecure_receiver"
else
  make -C "${ROOT}" -j
  SENDER="${ROOT}/vsecure_sender"
  RECEIVER="${ROOT}/vsecure_receiver"
fi

SRC="/tmp/vsecure_test_$$.mkv"
TEST_FILE="${SRC}"
head -c 65535 /dev/urandom > "${TEST_FILE}"

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen.txt" &
RPID=$!
sleep 0.4

"${SENDER}" --file "${TEST_FILE}" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"

wait "${RPID}" || true

OUTF="${OUT}/$(basename "${TEST_FILE}")"
if cmp -s "${TEST_FILE}" "${OUTF}"; then
  echo "OK: round-trip, файлы идентичны."
  rm -f "${SRC}"
  exit 0
fi
echo "FAIL: файлы отличаются"
rm -f "${SRC}"
exit 1

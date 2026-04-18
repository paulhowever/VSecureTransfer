#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17777}"
OUT="${ROOT}/.qa_out/large_$$"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
[[ -f "${KEYS}/sender_sign_priv.pem" ]] || "${ROOT}/scripts/gen_keys.sh"
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"
RECEIVER="${VSECURE_RECEIVER}"

SRC="/tmp/vsecure_large_$$.mkv"
if ! dd if=/dev/urandom of="${SRC}" bs=1048576 count=4 status=none 2>/dev/null; then
  head -c $((4 * 1048576)) /dev/urandom > "${SRC}"
fi

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen.txt" &
RPID=$!
sleep 0.45

"${SENDER}" --file "${SRC}" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"

wait "${RPID}" || true
OUTF="${OUT}/$(basename "${SRC}")"
cmp -s "${SRC}" "${OUTF}"
rm -f "${SRC}"
echo "OK: крупный файл (~4 MiB), round-trip."

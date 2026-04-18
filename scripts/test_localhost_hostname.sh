#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17784}"
OUT="${ROOT}/build_recv_out_localhost"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
if [[ ! -f "${KEYS}/sender_sign_priv.pem" ]]; then
  "${ROOT}/scripts/gen_keys.sh"
fi
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"
RECEIVER="${VSECURE_RECEIVER}"

SRC="/tmp/vsecure_localhost_$$.mkv"
head -c 2048 /dev/urandom > "${SRC}"

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen_localhost.txt" &
RPID=$!
sleep 0.45

"${SENDER}" --file "${SRC}" --host localhost --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"

wait "${RPID}" || true

OUTF="${OUT}/$(basename "${SRC}")"
if cmp -s "${SRC}" "${OUTF}"; then
  echo "OK: round-trip с --host localhost."
  rm -f "${SRC}"
  exit 0
fi
echo "FAIL: файлы отличаются после передачи на localhost." >&2
rm -f "${SRC}"
exit 1

#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17773}"
OUT="${ROOT}/build_recv_out_neg"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
[[ -f "${KEYS}/sender_sign_pub.pem" ]] || "${ROOT}/scripts/gen_keys.sh"
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
RECEIVER="${VSECURE_RECEIVER}"

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen.txt" &
RPID=$!
sleep 0.4

python3 - <<PY
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int("${PORT}")), timeout=5.0)
s.sendall(struct.pack(">Q", 4) + b"abcd")
ack = s.recv(8)
s.close()
if len(ack) != 8 or ack[:4] != b"VACK":
    sys.exit(2)
code = int.from_bytes(ack[4:8], "big")
if code != 1:
    sys.exit(3)
PY

wait "${RPID}" || true
echo "OK: получатель отклонил мусорный фрейм (BAD_FORMAT)."

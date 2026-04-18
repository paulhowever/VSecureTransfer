#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17783}"
OUT="${ROOT}/build_recv_out_disc"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
if [[ ! -f "${KEYS}/sender_sign_priv.pem" ]]; then
  "${ROOT}/scripts/gen_keys.sh"
fi
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
RECEIVER="${VSECURE_RECEIVER}"

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen_disc.txt" &
RPID=$!
sleep 0.45

python3 - <<PY
import socket
import struct
import sys

host, port = "127.0.0.1", int("${PORT}")
s = socket.create_connection((host, port), timeout=5.0)
remain = 200_000
s.sendall(struct.pack(">Q", remain) + (b"A" * 400))
s.shutdown(socket.SHUT_WR)
ack = b""
while len(ack) < 8:
    chunk = s.recv(8 - len(ack))
    if not chunk:
        break
    ack += chunk
s.close()
if len(ack) != 8 or ack[:4] != b"VACK":
    sys.exit(2)
code = int.from_bytes(ack[4:8], "big")
if code != 8:
    sys.exit(3)
PY

wait "${RPID}" || true
echo "OK: EOF при приёме тела → ACK CONNECTION_ERROR (8)."

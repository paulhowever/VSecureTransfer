#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
P1="${PORT:-17820}"
P2=$((P1 + 1))
OUT="${ROOT}/.qa_out/replay_$$"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
[[ -f "${KEYS}/sender_sign_priv.pem" ]] || "${ROOT}/scripts/gen_keys.sh"
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"
RECEIVER="${VSECURE_RECEIVER}"
SEEN="${OUT}/seen.txt"
PKT="${OUT}/captured.bin"

SRC="/tmp/vsecure_replay_$$.mkv"
head -c 4096 /dev/urandom > "${SRC}"

"${RECEIVER}" --port "${P1}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${SEEN}" &
R1=$!
sleep 0.45

VSECURE_DUMP_PACKET="${PKT}" "${SENDER}" --file "${SRC}" --host 127.0.0.1 --port "${P1}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"

wait "${R1}" || true

"${RECEIVER}" --port "${P2}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${SEEN}" &
R2=$!
sleep 0.45

code="$(python3 "${ROOT}/scripts/resend_framed.py" "${PKT}" 127.0.0.1 "${P2}")"
wait "${R2}" || true

rm -f "${SRC}"
if [[ "${code}" != "3" ]]; then
  echo "FAIL: ожидался ACK REPLAY (3), получено: ${code}" >&2
  exit 1
fi
echo "OK: повтор того же пакета отклонён (REPLAY)."

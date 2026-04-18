#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17830}"
OUT="${ROOT}/.qa_out/wrongkey_$$"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
[[ -f "${KEYS}/sender_sign_priv.pem" ]] || "${ROOT}/scripts/gen_keys.sh"
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"
RECEIVER="${VSECURE_RECEIVER}"

SRC="/tmp/vsecure_wrong_$$.mkv"
head -c 8192 /dev/urandom > "${SRC}"

# Намеренно подставляем не тот публичный ключ (wrap вместо sign) — проверка подписи должна провалиться.
"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/receiver_wrap_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen.txt" &
RPID=$!
sleep 0.45

set +e
"${SENDER}" --file "${SRC}" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"
st=$?
set -e
wait "${RPID}" || true
rm -f "${SRC}"

if [[ "${st}" -eq 0 ]]; then
  echo "FAIL: отправитель не должен был завершиться с кодом 0." >&2
  exit 1
fi
echo "OK: неверный ключ проверки подписи — передача отклонена."

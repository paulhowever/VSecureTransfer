#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -eq 0 ]]; then
  echo "SKIP: test_readonly_outdir под root (chmod игнорируется)."
  exit 0
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17785}"
OUT="${ROOT}/.qa_out/ro_out_$$"
KEYS="${ROOT}/keys"
mkdir -p "${OUT}" "${KEYS}"
if [[ ! -f "${KEYS}/sender_sign_priv.pem" ]]; then
  "${ROOT}/scripts/gen_keys.sh"
fi
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"
RECEIVER="${VSECURE_RECEIVER}"

chmod a-w "${OUT}"

SRC="/tmp/vsecure_ro_$$.mkv"
head -c 4096 /dev/urandom > "${SRC}"

"${RECEIVER}" --port "${PORT}" --out-dir "${OUT}" \
  --sender-pub "${KEYS}/sender_sign_pub.pem" \
  --recv-priv "${KEYS}/receiver_wrap_priv.pem" \
  --seen-file "${OUT}/seen_ro.txt" &
RPID=$!
sleep 0.45

LOG="$(mktemp)"
set +e
"${SENDER}" --file "${SRC}" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem" >"${LOG}" 2>&1
st=$?
set -e

wait "${RPID}" || true
chmod u+w "${OUT}" 2>/dev/null || true
rm -f "${SRC}"

if [[ "${st}" -eq 0 ]]; then
  echo "FAIL: ожидалась ошибка отправителя при невозможности записи в out-dir." >&2
  cat "${LOG}" >&2
  rm -f "${LOG}"
  exit 1
fi
if ! grep -q "ошибка записи файла на диск" "${LOG}"; then
  echo "FAIL: ожидалось сообщение отправителя про запись на диск (ACK 7 IO_ERROR), см. лог:" >&2
  cat "${LOG}" >&2
  rm -f "${LOG}"
  exit 1
fi
rm -f "${LOG}"
echo "OK: передача отклонена (ACK 7), сообщение про запись на диск."
exit 0

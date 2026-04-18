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

set +e
"${SENDER}" --file "${SRC}" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"
st=$?
set -e

wait "${RPID}" || true
chmod u+w "${OUT}" 2>/dev/null || true
rm -f "${SRC}"

if [[ "${st}" -ne 0 ]]; then
  echo "OK: передача отклонена при каталоге назначения только для чтения."
  exit 0
fi
echo "FAIL: ожидалась ошибка отправителя при невозможности записи в out-dir." >&2
exit 1

#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-17782}"
KEYS="${ROOT}/keys"
mkdir -p "${KEYS}"
if [[ ! -f "${KEYS}/sender_sign_priv.pem" ]]; then
  "${ROOT}/scripts/gen_keys.sh"
fi
# shellcheck disable=SC1091
source "${ROOT}/scripts/pick_build.sh"
SENDER="${VSECURE_SENDER}"

set +e
"${SENDER}" --file "${ROOT}/no_such_file_$$.mkv" --host 127.0.0.1 --port "${PORT}" \
  --sign-key "${KEYS}/sender_sign_priv.pem" \
  --recv-pub "${KEYS}/receiver_wrap_pub.pem"
st=$?
set -e

if [[ "${st}" -ne 0 ]]; then
  echo "OK: отправитель завершился с ошибкой при отсутствии файла."
  exit 0
fi
echo "FAIL: ожидался ненулевой код выхода." >&2
exit 1

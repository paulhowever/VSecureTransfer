#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/sender_sign_priv.pem
openssl pkey -in keys/sender_sign_priv.pem -pubout -out keys/sender_sign_pub.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/receiver_wrap_priv.pem
openssl pkey -in keys/receiver_wrap_priv.pem -pubout -out keys/receiver_wrap_pub.pem
echo "Созданы ключи в каталоге keys/"

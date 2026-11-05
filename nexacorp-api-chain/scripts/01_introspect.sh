#!/usr/bin/env bash
# Introspection completa del schema GraphQL
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

echo "[*] Introspection completa..."

cat > /tmp/intro.json <<'EOF'
{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind ofType { name kind } } } } type { name kind ofType { name kind ofType { name } } } } } } }"}
EOF

curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/intro.json \
  | tee "${LOOT_DIR}/schema_full.json" \
  | jq '.data.__schema.types[] | select(.name=="Query" or .name=="Mutation" or .name=="User" or .name=="VaultSecret" or .name=="DebugInfo")'

echo
echo "[+] Schema completo guardado en ${LOOT_DIR}/schema_full.json"

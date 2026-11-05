#!/usr/bin/env bash
# Config compartida para todos los scripts del CTF NexaCorp
# Source este archivo: source ./00_config.sh

export TARGET_HOST="nexacorp.ine.local"
export API_PORT="8090"
export FRONT_PORT="1337"

export API_URL="http://${TARGET_HOST}:${API_PORT}"
export FRONT_URL="http://${TARGET_HOST}:${FRONT_PORT}"
export GQL_URL="${API_URL}/api/graphql"

# JWT recon_token recogido en Stage 1 (purpose: oauth_init)
export RECON_TOKEN="<paste-your-own-recon-token-here>"  # obtenido en Stage 1 via GraphQL debugInfo

# Directorio de loot
export LOOT_DIR="${HOME}/nexacorp-loot"
mkdir -p "${LOOT_DIR}"

# Helper: POST a GraphQL con o sin token
gql() {
  local query="$1"
  local token="${2:-}"
  if [[ -n "$token" ]]; then
    curl -s -X POST "${GQL_URL}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${token}" \
      -d "{\"query\":\"${query}\"}"
  else
    curl -s -X POST "${GQL_URL}" \
      -H "Content-Type: application/json" \
      -d "{\"query\":\"${query}\"}"
  fi
}

# Helper: GraphQL con payload desde archivo (evita problemas de escaping)
gql_file() {
  local file="$1"
  local token="${2:-}"
  if [[ -n "$token" ]]; then
    curl -s -X POST "${GQL_URL}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${token}" \
      --data-binary @"${file}"
  else
    curl -s -X POST "${GQL_URL}" \
      -H "Content-Type: application/json" \
      --data-binary @"${file}"
  fi
}

echo "[+] Config cargada"
echo "    GQL_URL=${GQL_URL}"
echo "    LOOT_DIR=${LOOT_DIR}"

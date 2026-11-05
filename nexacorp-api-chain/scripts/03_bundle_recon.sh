#!/usr/bin/env bash
# Extraer info útil del bundle JS del frontend
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

BUNDLE="${LOOT_DIR}/app.bundle.js"

echo "[*] Descargando bundle..."
curl -s "${FRONT_URL}/assets/app.bundle.js" -o "${BUNDLE}"
echo "    Tamaño: $(wc -c < "${BUNDLE}") bytes"
echo

echo "=========================================="
echo "[*] Emails encontrados:"
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] UUIDs encontrados:"
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] IDs / userId / uid en JSON-like:"
grep -oE '"(id|userId|user_id|uid|sub)"[[:space:]]*:[[:space:]]*"?[a-zA-Z0-9_.@-]+' "${BUNDLE}" | sort -u | head -50

echo
echo "=========================================="
echo "[*] Strings con admin/root/service/system:"
grep -oE '"[^"]*(admin|root|service|superuser|system|nexacorp)[^"]*"' "${BUNDLE}" | sort -u | head -30

echo
echo "=========================================="
echo "[*] Endpoints API descubiertos:"
grep -oE '"/api/[a-zA-Z0-9/_-]+"' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] JWTs en el bundle:"
grep -oE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] Secrets / keys / tokens en strings:"
grep -oE '"(secret|apiKey|api_key|token|password|jwt_secret|client_secret)"[[:space:]]*:[[:space:]]*"[^"]+"' "${BUNDLE}" | sort -u

echo
echo "[+] Bundle guardado en ${BUNDLE}"

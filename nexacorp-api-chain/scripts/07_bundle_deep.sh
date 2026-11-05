#!/usr/bin/env bash
# Análisis profundo del bundle JS — bundle minificado, hay que ser agresivo
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

BUNDLE="${LOOT_DIR}/app.bundle.js"
BUNDLE_PRETTY="${LOOT_DIR}/app.bundle.pretty.js"

if [[ ! -f "${BUNDLE}" ]]; then
  echo "[*] Bundle no existe, descargando..."
  curl -s "${FRONT_URL}/assets/app.bundle.js" -o "${BUNDLE}"
fi

# Pretty-print con js-beautify si está disponible (si no, usa prettier)
if command -v js-beautify >/dev/null 2>&1; then
  js-beautify "${BUNDLE}" > "${BUNDLE_PRETTY}" 2>/dev/null
elif command -v prettier >/dev/null 2>&1; then
  prettier --parser babel "${BUNDLE}" > "${BUNDLE_PRETTY}" 2>/dev/null
else
  echo "[!] Instala js-beautify: apt install -y jsbeautifier ; o pip install jsbeautifier"
  cp "${BUNDLE}" "${BUNDLE_PRETTY}"
fi

echo "=========================================="
echo "[*] Strings >= 6 chars (puede revelar secretos):"
strings -n 6 "${BUNDLE}" 2>/dev/null | grep -iE '(secret|token|password|api[_-]?key|client[_-]?id|client[_-]?secret|jwt|admin|root)' | sort -u | head -50

echo
echo "=========================================="
echo "[*] URLs y paths internos:"
grep -oE 'https?://[a-zA-Z0-9./_-]+|/api/[a-zA-Z0-9/_-]+|/auth/[a-zA-Z0-9/_-]+|/oauth/[a-zA-Z0-9/_-]+' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] Posibles userIds/emails en el bundle pretty:"
grep -oE '(user[Ii]d|userId|sub|email)["'\'']?[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{3,80}["'\'']' "${BUNDLE_PRETTY}" | sort -u | head -50

echo
echo "=========================================="
echo "[*] UUIDs en el bundle:"
grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] JWTs en el bundle:"
grep -oE 'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' "${BUNDLE}" | sort -u

echo
echo "=========================================="
echo "[*] Variables hardcodeadas (window.X, process.env, config):"
grep -oE 'window\.[A-Z_]+[[:space:]]*=[[:space:]]*["'\''][^"'\'']+["'\'']|process\.env\.[A-Z_]+|REACT_APP_[A-Z_]+' "${BUNDLE}" | sort -u | head -30

echo
echo "=========================================="
echo "[*] GraphQL queries/mutations hardcoded:"
grep -oE '(query|mutation)[[:space:]]+[a-zA-Z]+[[:space:]]*\([^)]*\)[[:space:]]*\{' "${BUNDLE}" | sort -u | head -20

echo
echo "=========================================="
echo "[*] Comments con info sensible:"
grep -oE '/\*[^*]*\*+([^/*][^*]*\*+)*/|//[^\n]*' "${BUNDLE_PRETTY}" 2>/dev/null | grep -iE '(todo|fixme|hack|secret|password|admin|user)' | head -20

echo
echo "=========================================="
echo "[+] Bundle pretty: ${BUNDLE_PRETTY}"
echo "    Para grep manual: grep -i 'KEYWORD' ${BUNDLE_PRETTY}"

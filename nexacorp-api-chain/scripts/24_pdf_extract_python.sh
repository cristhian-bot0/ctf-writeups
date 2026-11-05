#!/usr/bin/env bash
# Extracción de texto de PDFs sin pdftotext — usa Python stdlib (zlib + regex)
# Funciona en cualquier Kali sin instalar nada
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

OUT="${LOOT_DIR}/pdf_text_dump.txt"
: > "${OUT}"

shopt -s nullglob
files=("${LOOT_DIR}"/resp_*.bin)
[[ ${#files[@]} -eq 0 ]] && { echo "[!] No hay resp_*.bin — corre primero el 22"; exit 1; }

# Extractor en Python — descomprime streams FlateDecode y saca texto Tj/TJ
extract_pdf_text() {
  python3 - "$1" <<'PYEOF'
import sys, re, zlib

with open(sys.argv[1], 'rb') as f:
    pdf = f.read()

# 1) Streams comprimidos (la mayoría con FlateDecode)
streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL)
out = []
for s in streams:
    data = s.strip(b'\r\n ')
    try:
        decoded = zlib.decompress(data)
    except Exception:
        decoded = data
    # Strings literales entre paréntesis (PDF Tj) — escapadas con \(, \), \\
    for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)\s*(?:Tj|TJ|\')', decoded, re.DOTALL):
        try:
            t = m.decode('latin-1', errors='replace')
            t = t.replace('\\(', '(').replace('\\)', ')').replace('\\\\', '\\')
            if t.strip():
                out.append(t)
        except Exception:
            pass
    # Strings dentro de arrays TJ: [(foo)(bar)]TJ
    for arr in re.findall(rb'\[(.*?)\]\s*TJ', decoded, re.DOTALL):
        for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)', arr, re.DOTALL):
            try:
                t = m.decode('latin-1', errors='replace')
                if t.strip():
                    out.append(t)
            except Exception:
                pass
    # Hex strings <hexhex>Tj
    for m in re.findall(rb'<([0-9A-Fa-f\s]+)>\s*Tj', decoded):
        try:
            hx = bytes.fromhex(m.decode().replace(' ', '').replace('\n', ''))
            t = hx.decode('latin-1', errors='replace')
            if t.strip():
                out.append(t)
        except Exception:
            pass

if out:
    print(' '.join(out))
else:
    # Fallback: strings imprimibles del binario decomprimido
    raw = b''
    for s in streams:
        data = s.strip(b'\r\n ')
        try:
            raw += zlib.decompress(data) + b'\n'
        except Exception:
            raw += data + b'\n'
    # Filtra solo ASCII imprimible en líneas de >= 4 chars
    txt = re.findall(rb'[\x20-\x7e]{4,}', raw)
    print('\n'.join(t.decode('latin-1', errors='replace') for t in txt))
PYEOF
}

for f in "${files[@]}"; do
  name=$(basename "${f}" .bin)
  echo "###################### ${name} ######################" | tee -a "${OUT}"

  # Si es JSON, extrae el pdf_base64
  if head -c 1 "${f}" 2>/dev/null | grep -q '{'; then
    jq -r '.pdf_base64 // empty' "${f}" 2>/dev/null | base64 -d > /tmp/_p.pdf 2>/dev/null
  else
    cp "${f}" /tmp/_p.pdf
  fi

  if [[ -s /tmp/_p.pdf ]] && head -c 4 /tmp/_p.pdf 2>/dev/null | grep -q '%PDF'; then
    extract_pdf_text /tmp/_p.pdf | tee -a "${OUT}"
  else
    echo "[no PDF — raw response]" | tee -a "${OUT}"
    head -c 500 "${f}" | tee -a "${OUT}"
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
echo "[*] AWS keys:"
echo "=========================================="
grep -oE '(AKIA|ASIA)[A-Z0-9]{4,}' "${OUT}" | sort -u

echo
echo "=========================================="
echo "[*] Líneas con keywords sensibles:"
echo "=========================================="
grep -iE '(secret|password|credential|access_?key|token|expiration|vault|root_token|s3_|aws_)' "${OUT}" | sort -u | head -30

echo
echo "[+] Texto completo en ${OUT}"
echo "[+] Para revisar: less ${OUT}"

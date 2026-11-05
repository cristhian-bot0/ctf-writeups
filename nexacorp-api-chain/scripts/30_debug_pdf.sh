#!/usr/bin/env bash
# Debug: extraer streams crudos de un PDF para entender el formato
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

DIR="${LOOT_DIR}/stage4_pdfs"
TARGET="${DIR}/http___169_254_169_254_latest_meta-data_iam_security-credentials_nexacorp-prod-r.json"

[[ -f "${TARGET}" ]] || { echo "[!] ${TARGET} no existe"; exit 1; }

python3 <<PYEOF
import re, zlib, base64, json

d = json.load(open("${TARGET}"))
pdf = base64.b64decode(d['pdf_base64'])

with open("/tmp/_dump.pdf", "wb") as f:
    f.write(pdf)

print(f"PDF size: {len(pdf)}")
print(f"PDF sample (raw bytes 0-200): {pdf[:200]}")
print()

# Mostrar todos los streams descomprimidos
streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL)
print(f"Streams encontrados: {len(streams)}")
print()

for i, s in enumerate(streams):
    print(f"\n=== Stream {i} (size={len(s)}) ===")
    raw = s.strip(b'\r\n ')
    try:
        d = zlib.decompress(raw)
        print(f"[decompressed size={len(d)}]")
        # Mostrar primeros 1500 bytes
        print(d[:1500].decode('latin-1', errors='replace'))
    except Exception as e:
        print(f"[no zlib: {e}]")
        print(raw[:500].decode('latin-1', errors='replace'))
PYEOF

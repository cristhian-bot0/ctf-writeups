#!/usr/bin/env bash
# Decodificar los PDFs del barrido SSRF (script 25) buscando flags y secretos del Vault
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

DIR="${LOOT_DIR}/pdfs_internal"

if [[ ! -d "${DIR}" ]]; then
  echo "[!] Falta ${DIR} — corre primero el script 25"
  exit 1
fi

cd "${DIR}"

python3 <<'PYEOF'
import os, re, zlib, base64, json

def decode_shift(s):
    return ''.join(chr(ord(c)+29) if 33 <= ord(c) <= 95 and ord(c)+29 <= 126 else c for c in s)

def extract(pdf_bytes):
    streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf_bytes, re.DOTALL)
    chunks = []
    for s in streams:
        try: d = zlib.decompress(s.strip(b'\r\n '))
        except: continue
        for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)', d, re.DOTALL):
            try:
                t = m.decode('latin-1', errors='replace')
                t = t.replace('\\(', '(').replace('\\)', ')').replace('\\\\', '\\')
                chunks.append(t)
            except: pass
    return ' '.join(chunks)

flags = set()
big_files = []

for fname in sorted(os.listdir('.')):
    if not fname.endswith('.json'):
        continue
    try:
        d = json.load(open(fname))
        size = d.get('pdf_size_bytes', 0)
        b64 = d.get('pdf_base64', '')
        if not b64:
            continue
        pdf = base64.b64decode(b64)
        cipher = extract(pdf)
        plain = decode_shift(cipher)

        # Buscar flags
        for m in re.findall(r'FLAG\{[^}]+\}', plain):
            flags.add(m)

        # Solo imprime PDFs grandes
        if size > 5000:
            big_files.append((size, fname, plain))
    except Exception:
        pass

# Imprimir PDFs grandes (los más probables de tener contenido)
for size, fname, plain in sorted(big_files, key=lambda x: -x[0]):
    print(f"\n{'='*70}")
    print(f"FILE: {fname}")
    print(f"SIZE: {size}")
    print(f"{'='*70}")
    print(plain[:3000])

print()
print("="*70)
print(f"FLAGS ÚNICAS ENCONTRADAS: {len(flags)}")
print("="*70)
for f in sorted(flags):
    print(f"  {f}")

# También buscar texto sensible
print()
print("="*70)
print("KEYWORDS sensibles en cualquier PDF:")
print("="*70)
for fname in sorted(os.listdir('.')):
    if not fname.endswith('.json'): continue
    try:
        d = json.load(open(fname))
        b64 = d.get('pdf_base64', '')
        if not b64: continue
        pdf = base64.b64decode(b64)
        plain = decode_shift(extract(pdf))
        for kw in ['vault', 'secret', 'token', 'admin', 'flag', 'credential', 'master', 'aws', 'access_key']:
            for m in re.finditer(kw, plain, re.IGNORECASE):
                ctx = plain[max(0,m.start()-30):m.end()+80]
                print(f"  [{fname[:60]}] ...{ctx}...")
                break
    except: pass
PYEOF

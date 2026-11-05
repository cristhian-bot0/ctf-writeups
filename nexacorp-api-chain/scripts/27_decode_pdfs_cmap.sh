#!/usr/bin/env bash
# Decodificador de PDFs usando la CMap embebida (correcto para subset fonts)
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

DIR="${LOOT_DIR}/pdfs_internal"
[[ -d "${DIR}" ]] || { echo "[!] Falta ${DIR}"; exit 1; }

cd "${DIR}"

python3 <<'PYEOF'
import os, re, zlib, base64, json

def decompress_streams(pdf):
    """Devuelve todos los streams descomprimidos."""
    out = []
    for s in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL):
        try:
            out.append(zlib.decompress(s.strip(b'\r\n ')))
        except Exception:
            out.append(s)
    return out

def parse_cmap(streams):
    """Parsea bfchar y bfrange en CMap streams. Devuelve {hex_code: unicode_str}."""
    table = {}
    for s in streams:
        if b'beginbfchar' not in s and b'beginbfrange' not in s:
            continue
        try: text = s.decode('latin-1')
        except: continue

        # bfchar: <hexcode> <hexunicode>
        for block in re.findall(r'beginbfchar(.*?)endbfchar', text, re.DOTALL):
            for line in block.split('\n'):
                m = re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', line)
                for code, uni in m:
                    try:
                        c = int(code, 16)
                        u = bytes.fromhex(uni).decode('utf-16-be', errors='replace')
                        table[c] = u
                    except: pass

        # bfrange: <start> <end> <unicode_start>
        for block in re.findall(r'beginbfrange(.*?)endbfrange', text, re.DOTALL):
            for line in block.split('\n'):
                m = re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', line)
                for s_, e_, u_ in m:
                    try:
                        sn, en = int(s_, 16), int(e_, 16)
                        ub = bytes.fromhex(u_)
                        u_int = int.from_bytes(ub, 'big')
                        for i, code in enumerate(range(sn, en+1)):
                            table[code] = chr(u_int + i)
                    except: pass
    return table

def extract_with_cmap(pdf_bytes):
    streams = decompress_streams(pdf_bytes)
    cmap = parse_cmap(streams)

    out = []
    for s in streams:
        # Strings con Tj
        for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)\s*Tj', s, re.DOTALL):
            for byte in m:
                if byte in cmap:
                    out.append(cmap[byte])
                else:
                    out.append(chr(byte))
            out.append(' ')
        # Strings con TJ (array)
        for arr in re.findall(rb'\[(.*?)\]\s*TJ', s, re.DOTALL):
            for sm in re.findall(rb'\(((?:\\.|[^\\()])*)\)', arr, re.DOTALL):
                for byte in sm:
                    if byte in cmap:
                        out.append(cmap[byte])
                    else:
                        out.append(chr(byte))
                out.append(' ')
        # Hex strings <hexhex>Tj
        for m in re.findall(rb'<([0-9A-Fa-f\s]+)>\s*Tj', s):
            try:
                hx = bytes.fromhex(m.decode().replace(' ', '').replace('\n',''))
                # Hex strings pueden ser de 1 o 2 bytes por glyph
                for byte in hx:
                    if byte in cmap:
                        out.append(cmap[byte])
                    else:
                        out.append(chr(byte))
                # Probar 2-byte glyphs también
                for i in range(0, len(hx), 2):
                    pair = int.from_bytes(hx[i:i+2], 'big')
                    if pair in cmap:
                        out.append(cmap[pair])
                out.append(' ')
            except: pass

    return ''.join(out)

flags = set()
results = []

for fname in sorted(os.listdir('.')):
    if not fname.endswith('.json'): continue
    try:
        d = json.load(open(fname))
        size = d.get('pdf_size_bytes', 0)
        b64 = d.get('pdf_base64', '')
        if not b64 or size < 3000: continue

        pdf = base64.b64decode(b64)
        text = extract_with_cmap(pdf)
        results.append((size, fname, text))

        for m in re.findall(r'FLAG\{[^}]+\}', text):
            flags.add(m)
    except Exception as e:
        pass

# Imprimir los más grandes primero
for size, fname, text in sorted(results, key=lambda x: -x[0]):
    print(f"\n{'='*70}")
    print(f"FILE: {fname}  SIZE: {size}")
    print(f"{'='*70}")
    print(text[:3500])

print()
print("="*70)
print(f"FLAGS ENCONTRADAS: {len(flags)}")
print("="*70)
for f in sorted(flags):
    print(f"  {f}")
PYEOF

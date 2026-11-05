#!/usr/bin/env bash
# Decoder de PDFs Chromium con CMap Adobe-Identity-UCS (glyphs de 16-bit)
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

cd "${LOOT_DIR}/stage4_pdfs" 2>/dev/null || { echo "[!] Falta ${LOOT_DIR}/stage4_pdfs — corre primero el script 29"; exit 1; }

python3 <<'PYEOF'
import os, re, zlib, base64, json

def decompress_streams(pdf):
    out = []
    for s in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL):
        try: out.append(zlib.decompress(s.strip(b'\r\n ')))
        except: out.append(s)
    return out

def parse_cmap(streams):
    """Construye {glyph_id: unicode_char} desde los streams CMap."""
    table = {}
    for s in streams:
        if b'beginbfchar' not in s and b'beginbfrange' not in s: continue
        try: text = s.decode('latin-1')
        except: continue
        for block in re.findall(r'beginbfchar(.*?)endbfchar', text, re.DOTALL):
            for code, uni in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', block):
                try:
                    c = int(code, 16)
                    u_int = int(uni, 16)
                    table[c] = chr(u_int)
                except: pass
        for block in re.findall(r'beginbfrange(.*?)endbfrange', text, re.DOTALL):
            for s_, e_, u_ in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', block):
                try:
                    sn, en = int(s_, 16), int(e_, 16)
                    u_int = int(u_, 16)
                    for i, code in enumerate(range(sn, en+1)):
                        table[code] = chr(u_int + i)
                except: pass
    return table

def extract(pdf_bytes):
    streams = decompress_streams(pdf_bytes)
    cmap = parse_cmap(streams)
    out = []
    for s in streams:
        try: text = s.decode('latin-1')
        except: continue

        # Hex strings <hexhex>Tj — cada glyph es 4 hex chars (16-bit)
        for hex_str in re.findall(r'<([0-9A-Fa-f\s]+)>\s*Tj', text):
            hx = re.sub(r'\s+', '', hex_str)
            for i in range(0, len(hx), 4):
                if i + 4 <= len(hx):
                    glyph = int(hx[i:i+4], 16)
                    out.append(cmap.get(glyph, ''))
            out.append(' ')

        # Hex strings dentro de TJ array: [<hex>...]TJ
        for arr in re.findall(r'\[(.*?)\]\s*TJ', text, re.DOTALL):
            for hex_str in re.findall(r'<([0-9A-Fa-f\s]+)>', arr):
                hx = re.sub(r'\s+', '', hex_str)
                for i in range(0, len(hx), 4):
                    if i + 4 <= len(hx):
                        glyph = int(hx[i:i+4], 16)
                        out.append(cmap.get(glyph, ''))
            out.append(' ')

    return ''.join(out)

flags = set()
results = []

for fname in sorted(os.listdir('.')):
    if not fname.endswith('.json'): continue
    try:
        d = json.load(open(fname))
        b64 = d.get('pdf_base64', '')
        if not b64: continue
        pdf = base64.b64decode(b64)
        text = extract(pdf)
        results.append((d.get('pdf_size_bytes', 0), fname, text))
        for m in re.findall(r'FLAG\{[^}]+\}', text):
            flags.add(m)
    except Exception as e:
        print(f"[!] {fname}: {e}")

for size, fname, text in sorted(results, key=lambda x: -x[0]):
    print(f"\n{'='*70}")
    print(f"FILE: {fname}")
    print(f"PDF_SIZE: {size}")
    print(f"{'='*70}")
    print(text[:4000])

print()
print("="*70)
print(f"FLAGS ENCONTRADAS: {len(flags)}")
print("="*70)
for f in sorted(flags):
    print(f"  {f}")
PYEOF

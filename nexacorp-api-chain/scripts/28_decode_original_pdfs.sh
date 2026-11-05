#!/usr/bin/env bash
# Re-decodificar los PDFs originales del script 22 con CMap parser correcto
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

cd "${LOOT_DIR}"

python3 <<'PYEOF'
import os, re, zlib, base64, json

def decompress_streams(pdf):
    out = []
    for s in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL):
        try:
            out.append(zlib.decompress(s.strip(b'\r\n ')))
        except Exception:
            out.append(s)
    return out

def parse_cmap(streams):
    table = {}
    for s in streams:
        if b'beginbfchar' not in s and b'beginbfrange' not in s:
            continue
        try: text = s.decode('latin-1')
        except: continue
        for block in re.findall(r'beginbfchar(.*?)endbfchar', text, re.DOTALL):
            for line in block.split('\n'):
                for code, uni in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', line):
                    try:
                        c = int(code, 16)
                        u = bytes.fromhex(uni).decode('utf-16-be', errors='replace')
                        table[c] = u
                    except: pass
        for block in re.findall(r'beginbfrange(.*?)endbfrange', text, re.DOTALL):
            for line in block.split('\n'):
                for s_, e_, u_ in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', line):
                    try:
                        sn, en = int(s_, 16), int(e_, 16)
                        u_int = int.from_bytes(bytes.fromhex(u_), 'big')
                        for i, code in enumerate(range(sn, en+1)):
                            table[code] = chr(u_int + i)
                    except: pass
    return table

def extract(pdf_bytes):
    streams = decompress_streams(pdf_bytes)
    cmap = parse_cmap(streams)
    out = []
    for s in streams:
        for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)\s*Tj', s, re.DOTALL):
            for byte in m:
                out.append(cmap.get(byte, chr(byte)))
            out.append(' ')
        for arr in re.findall(rb'\[(.*?)\]\s*TJ', s, re.DOTALL):
            for sm in re.findall(rb'\(((?:\\.|[^\\()])*)\)', arr, re.DOTALL):
                for byte in sm:
                    out.append(cmap.get(byte, chr(byte)))
                out.append(' ')
        for m in re.findall(rb'<([0-9A-Fa-f\s]+)>\s*Tj', s):
            try:
                hx = bytes.fromhex(m.decode().replace(' ', '').replace('\n',''))
                for byte in hx:
                    out.append(cmap.get(byte, chr(byte)))
                out.append(' ')
            except: pass
    return ''.join(out)

flags = set()
results = []

for fname in sorted(os.listdir('.')):
    if not fname.startswith('resp_') or not fname.endswith('.bin'):
        continue
    try:
        with open(fname) as f:
            content = f.read()
        if content.startswith('{'):
            d = json.loads(content)
            b64 = d.get('pdf_base64', '')
            if not b64: continue
            pdf = base64.b64decode(b64)
        else:
            with open(fname, 'rb') as f:
                pdf = f.read()
        text = extract(pdf)
        results.append((len(pdf), fname, text))
        for m in re.findall(r'FLAG\{[^}]+\}', text):
            flags.add(m)
    except Exception as e:
        pass

for size, fname, text in sorted(results, key=lambda x: -x[0]):
    print(f"\n{'='*70}")
    print(f"FILE: {fname}  PDF_SIZE: {size}")
    print(f"{'='*70}")
    print(text[:3500])

print()
print("="*70)
print(f"FLAGS ENCONTRADAS: {len(flags)}")
print("="*70)
for f in sorted(flags):
    print(f"  {f}")
PYEOF

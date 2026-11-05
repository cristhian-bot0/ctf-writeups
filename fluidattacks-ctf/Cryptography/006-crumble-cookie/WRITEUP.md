# Write-up — Crumble Cookie

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | Cryptography |
| **Dificultad** | Easy |
| **Puntos** | 175 |
| **Flag** | `flag{2a81253c92a2d217}` |
| **Vulnerabilidad** | Hash Length Extension sobre un MAC `SHA256(secret‖message)` |

---

## 1. Enunciado

> SecureVault signs every download link so you can't grab the files you're not meant
> to. The dev team is very confident about this.

Adjunto: `public.zip` (AES, contraseña `infected`) con el código del servidor
(`app.py`). Instancia: `https://b8a49f64d30b01c0.chal.ctf.ae`.

---

## 2. Análisis del código

El servidor firma cada token de descarga así:

```python
def sign(message_bytes):
    return hashlib.sha256(SECRET_KEY.encode() + message_bytes).hexdigest()
```

`SECRET_KEY` tiene **16 caracteres**. La firma es `SHA256(SECRET_KEY ‖ mensaje)` — el
patrón **exacto** que rompe el *hash length extension attack* (SHA-256 es
Merkle–Damgård: conociendo `H(secret‖m)` y `len(secret)` se puede calcular
`H(secret‖m‖padding‖extra)` sin conocer el secreto).

`/files` entrega pares válidos `(token, sig)`:

```json
{"path":"public/notes.txt",
 "token":"action=download&file=public/notes.txt",
 "sig":"41f5...a66"}
```

`/download` valida la firma sobre los **bytes crudos** del token y luego lo parsea:

```python
def parse_token_params(token_bytes):
    parts = {}
    for segment in token_str.split("&"):
        if "=" in segment:
            key, _, value = segment.partition("=")
            parts[key] = value          # el ÚLTIMO 'file=' GANA
    return parts
...
if filepath == "private/flag.txt":
    return jsonify({"filename": "private/flag.txt", "content": FLAG})
```

Dos regalos: (a) si `file == private/flag.txt` devuelve el FLAG, y (b) como el parser
sobreescribe con el último valor, **basta añadir** `&file=private/flag.txt` al final del
mensaje firmado para redirigir la descarga.

---

## 3. El ataque (length extension)

Partiendo del par válido y con `key_length = 16`, se forja con `hashpumpy`:

```python
new_sig, new_msg = hashpumpy.hashpump(
    orig_sig,
    "action=download&file=public/notes.txt",
    "&file=private/flag.txt",
    16)
```

`new_msg` queda:

```
action=download&file=public/notes.txt \x80 \x00…\x00 \x01\xa8 &file=private/flag.txt
```

El bloque de padding (`\x80 … longitud`) se cuela como un segmento sin `=` (que el
parser ignora), y el `&file=private/flag.txt` final gana. `new_sig` es válida para ese
mensaje pese a no conocer `SECRET_KEY`.

---

## 4. El detalle que cuesta: transporte de los bytes

El servidor reconstruye `token_bytes = token.encode("latin-1")`. Para que esos bytes
sean exactamente `new_msg`, el string recibido debe tener como codepoints los bytes de
`new_msg`. Cómo transmitirlos por la URL depende de cómo el stack decodifica la query,
y **local y remoto se comportan distinto**:

| Entorno | Decodificación query | Encoding que funciona |
|---|---|---|
| Dev server local (Werkzeug 3.x directo) | latin-1 | bytes `<0x80` → `%XX`, bytes `≥0x80` → **crudos** |
| Instancia remota (gunicorn + Werkzeug UTF-8) | UTF-8 | `quote(new_msg.decode('latin-1'))` — pasa a UTF-8 y percent-encodea |

En el remoto, enviar los bytes altos crudos daba **500** (se decodifican como UTF-8
inválido → `U+FFFD` → `encode('latin-1')` lanza excepción). La solución es
percent-encodear la representación **UTF-8** de cada codepoint (`%C2%80` para `U+0080`,
etc.), que el servidor UTF-8-decodifica de vuelta al byte correcto:

```python
enc = quote(new_msg.decode("latin-1"), safe="")
path = b"/download?token=" + enc.encode() + b"&sig=" + new_sig.encode()
```

Se envía por socket crudo sobre TLS (443).

---

## 5. Resultado

```
{"content":"flag{2a81253c92a2d217}","filename":"private/flag.txt"}
```

```
flag{2a81253c92a2d217}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** autenticar mensajes con `H(secret ‖ message)` usando una función de
hash Merkle–Damgård (MD5/SHA-1/SHA-2). Esa construcción filtra suficiente estado en su
salida como para continuar el hash y firmar datos añadidos sin la clave.

**Cómo se arregla:**

- **Usar HMAC** (`hmac.new(key, msg, sha256)`), que está diseñado precisamente para
  resistir length extension. Las propias notas del reto lo insinúan: *"Migrate API auth
  to HMAC-based tokens"*.
- **Comparar firmas en tiempo constante** (`hmac.compare_digest`) para evitar timing.
- **No confiar en el parseo posterior a la validación:** rechazar tokens con claves
  duplicadas (`file=` repetido) y canonicalizar antes de firmar/validar.
- **Autorizar por ruta**: `private/*` no debería ser alcanzable por un token de
  descarga público bajo ninguna firma.

**Lección de CTF (Crypto):** en cuanto veas `sha256(secret + data).hexdigest()` como
"firma", piensa **length extension** (hashpump/hashpumpy). Y cuando el exploit funciona
en local pero da 500 en remoto, sospecha del **decoding de la query** (latin-1 vs UTF-8)
entre el dev server y el stack de producción.

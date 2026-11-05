# Holmes CTF 2026 — Sherlock 03: Whisper Chain ("The Voices Behind the Names")

**Categoría:** DFIR / OSINT / XMPP threat-intel
**Infra:** instancia HTB `10.129.4.51` — servidor XMPP **Prosody** (dominio `murknet.htb`)
**PDF:** solo narrativa; el título interno del PDF delata el tema → *"XMPP Threat Intelligence"*.
**Entorno de análisis:** Linux (Arch) + `slixmpp` en venv, `openssl`, Wayback Machine.

---

## 0. Recon del servidor

VPN de HTB arriba → `10.129.4.51` responde. Puertos: 443 (nginx), 5222 (c2s), 5269 (s2s), 5281 (Prosody http).
El certificado TLS revela el dominio y los vhosts:

```
CN=murknet.htb
SAN: murknet.htb, groups.murknet.htb (MUC), command.murknet.htb (PubSub), upload.murknet.htb (HTTP file share)
```

La web (todos los vhosts) sirve una página señuelo: *"Nothing remains but echoes"*.

## 1. Acceso: in-band registration abierto

`slixmpp` + XEP-0077 → self-registration habilitado. Registro `watsonir@murknet.htb`.
Salas públicas MUC: **rules, resources, infra, random** (tráfico de tapadera + disciplina OPSEC).

Fugas en las salas públicas:
- **infra**: `rattlesnake` postea passwords temporales antiguos → `KillBill2025! K4w4Bong424! Northwind225! TickTock24!` (doctor estalla: "asume que alguien todavía usa uno").
- **resources**: `dang` bromea *"imagina filtrar tu username en un PDF"*.

## 2. Q1 — Credenciales de un miembro APT (username-leak + reuse)

Se descargan los PDFs subidos (`upload.murknet.htb/file_share/<uuid>/...`) y se revisa metadata:

```
Operational_Onboarding_Guide_v3.2.pdf → Author: zytglogge88@murknet.htb   Creator: swissclock
```

(Zytglogge = torre del reloj de Berna → alias "swissclock".) swissclock dijo que rotaría "pronto"
pero nunca lo hizo. Fuerza bruta de su JID contra los 4 temp-passwords:

> **`zytglogge88@murknet.htb:TickTock24!`**  ✅ login OK

## 3. Enumeración como swissclock

- **Roster:** `snake6288` (rattlesnake), `doctor9091` (doctor), `spurio9`.
- **Salas ocultas members-only** (no salen en disco, pero un miembro puede entrar):
  `op_snatch@groups.murknet.htb` y `op_sparkling@groups.murknet.htb`.
- **command.murknet.htb** = servicio **PubSub** ("Command Dispatcher") con nodos `op_snatch` y `op_sparkling`
  (whitelist). Items cifrados con OpenSSL (`U2FsdGVkX1...` = `Salted__`), namespace `urn:murknet:command`.
- **MAM personal (DMs):** snake6288 → swissclock: *"We're rotating the key. The new key is **SHALLOWBLUE**"* (para Sparkling).

## 4. El decryptor filtrado (Wayback)

En `op_sparkling` los miembros descubren un informe de threat-intel que doxea a `rattlesnake`
(alias público **Porlock**) y **filtra el decryptor**. rattlesnake "borra" el blog, pero doctor:
*"nothing is ever truly deleted"*. Se recupera de **Wayback Machine**:

```
http://web.archive.org/web/20260805080606/http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution/
```

Sección **"More artifacts"** → script `decrypt_command.sh`:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass "pass:${KEY}"
```

- Passphrase hard-codeada (vieja, filtrada): `BLACKFENLOTTE`
- Passphrase nueva (rotada, del DM): `SHALLOWBLUE`

**Q2** sale de la sección de atribución del mismo informe:

> **`https://stonedforums.htb/@porlock`** (perfil social de Porlock = rattlesnake)

## 5. Descifrado del Command Dispatcher

`base64 -d | openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass pass:<KEY>`

### op_sparkling (operación PRIMERA/financiera → clave `BLACKFENLOTTE`)
```
Operation started
Evilginx server available at 185.203.11.109 - Use ONLY this server for phishing
BTC Addresses: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX - 1BcanTJpHtyNnRvPFpuTqGwN1BcxuXKGpN - 1BHoNZGGAkpLaNmVHbYdnoyib8NgodSkRD
XMR Address: 429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye
Bank account credentials must be sent here https://submit-creds.murknet.htb:9099
New C2 server for BalanceRAT 34.54.165.186
New disposable numbers - 447348624600 447424907088 447459603196 447424061435
Additional available domains for phishing: micr0soft-st0re.com update-vpn.azzure.com mailservice-gmail.com
```

### op_snatch (operación LATEST/secuestro → clave `SHALLOWBLUE`)
```
Operation started
Watson just left his house and got into his car: a red Ford Fiesta with license plate WT609DXT
He just stopped at Pembridge Square
Watson got back in the car and turned onto Bayswater Road. Stay right on his heels!
He's about to enter Victoria Station. He must not reach the tracks. Act NOW
Heading toward Silvertown, here are the coordinates: 51°30'17.6 N, 0°02'05.1 E.
Avoid Great Dover Street, it's full of police officers because of a demonstration.
Sector B. Row 6. Container number: 75JM77. Watchword: Chaos Is Order
Take the car to the junkyard. The junkyard is in Walton-on-Thames. Ask for Richard.
Start cleanup process IMMEDIATELY
```

Roles en op_snatch: **dynamite** = transporte (intercepta a Watson y lo entrega), **spur** = custodia
(luego entra en pánico cuando encuentran el sitio y huye → doctor ordena "cleanup").

---

## 6. Respuestas

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | Credenciales de un miembro APT | `zytglogge88@murknet.htb:TickTock24!` |
| 2 | URL red social de un miembro APT | `https://stonedforums.htb/@porlock` |
| 3 | Wallet XMR de la primera operación (Sparkling) | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` |
| 4 | Nick del afiliado que secuestró a Watson | `dynamite` |
| 5 | Dónde fue secuestrado Watson | `Victoria Station` (lugar del "Act NOW"; luego lo llevaron a Silvertown — contenedor `75JM77`, Sector B Fila 6, coords `51°30'17.6"N 0°02'05.1"E`) |
| 6 | Última operación planeada + objetivo | ⚠️ **SIN RESOLVER** — ver §8 |

Preguntas 1–5: **confirmadas / aceptadas**. La 6 sigue abierta.

## 7. Pregunta 6 — estado (SIN RESOLVER)

**Enunciado:** *"What is the name of the latest operation that the APT is planning, and what is its objective? (Operation name,Objective)"*

### Lo verificado en el servidor (reconexión a 10.129.4.69 como swissclock, 2026-09-19)
Enumeración completa (`allrooms.py`): roster, 4 salas públicas (rules/resources/infra/random),
2 salas ocultas members-only, 2 nodos PubSub y **todos** los DMs vía MAM. **Solo existen DOS operaciones**:

| Nodo/Sala | Identidad (disco#info) | PubSub node name | Inicio | Objetivo (texto literal en sala) |
|---|---|---|---|---|
| `op_sparkling` | **Operation Sparkling** | `OpSparkling Command Dispatcher` | 2026-08-04 | doctor: *"identify worthwhile victims, collect wallet material, online banking credentials and anything that can later be exchanged for funding"* (fraude financiero/cripto) |
| `op_snatch` | **Operation Snatch** | `OpSnatch Command Dispatcher` | 2026-08-07 | doctor: *"The objective has value far beyond what most of you understand… this isn't about money. No."* (compartimentado; el PubSub revela = secuestrar a Watson) |

- **La más reciente es Operation Snatch** (08-07 > 08-04; usa la clave rotada `SHALLOWBLUE`).
- En el DM con snake6288 (08-06 23:xx) se habla de *"the new Op… the biggest thing we've ever done"*, pero por cronología **ese "new Op" ES Operation Snatch** (arranca 08-07). **No hay una tercera operación** en los datos.
- La sala op_snatch termina con doctor: *"The operation now enters its next phase"* (12:34) — insinúa fase siguiente, pero **sin nombre**.

### Intentos RECHAZADOS por la plataforma
- `OpSnatch — secuestrar a Watson`
- `op_snatch,Kidnap Watson`
- `Operation Snatch,Kidnap Watson`
- Variantes de objetivo: `Kidnapping Watson`, `Abduct Watson`, `Kidnap Dr. Watson`, `Kidnapping Dr. John Watson`, `Use Watson as leverage against Sherlock Holmes`, `Capture/Lure Sherlock Holmes`

### Hipótesis pendientes de probar
1. La operación buscada podría ser **Operation Sparkling** si "planning" se interpreta como *la que sigue en curso/planeándose* (Snatch ya se ejecutó → Watson entregado). Sparkling **sí tiene objetivo enunciado literal** por doctor (fraude financiero) → probar:
   - `Operation Sparkling,identify worthwhile victims collect wallet material online banking credentials and anything that can later be exchanged for funding`
   - o forma corta: `Operation Sparkling,Steal cryptocurrency and banking credentials`
2. Confirmar si HTB da **hint de formato** al fallar (separador, mayúsculas, con/sin "Operation").
3. Revisar si tras Snatch hay una **fase/operación posterior con nombre propio** que no capté (releer salas públicas como swissclock + posibles nodos PubSub con ACL distinta).

**Credenciales para retomar:** `zytglogge88@murknet.htb:TickTock24!` (swissclock). Scripts: `opname.py` (nodos+decrypt), `rooms.py` / `allrooms.py` (salas+DMs). La box cambia de IP por instancia — actualizar `HOST=` en los scripts.

## 8. Lecciones
1. **Metadata de PDF** (Author) filtra el JID real → reuse de password temporal = acceso a cuenta APT.
2. **Salas MUC members-only** no aparecen en `disco#items`, pero un miembro autenticado puede entrar directamente.
3. El **PubSub XEP-0060** ("Command Dispatcher") es el canal encubierto de directivas; los items son OpenSSL `Salted__`.
4. **Wayback Machine** recupera el blog "nuked" con el `decrypt_command.sh` (AES-256-CBC, PBKDF2, 120000 iter, sha256).
5. **Dos claves**: la vieja filtrada `BLACKFENLOTTE` (Sparkling, pre-rotación) y la nueva `SHALLOWBLUE` (Snatch, post-rotación DM).

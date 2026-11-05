# Hollow Courier — Hack The Box Writeup

## Categoría

**Secure Coding**

## Objetivo

El objetivo del reto es corregir una vulnerabilidad relacionada con la confianza incorrecta en la procedencia del cliente dentro de la comunicación entre un reverse proxy Caddy y una aplicación Flask.

La arquitectura involucrada es:

```text
Cliente
   |
   v
 Caddy Reverse Proxy
   |
   v
 Flask Application
```

La descripción del reto indica:

> Restore trustworthy forwarded-client provenance across the Caddy and Flask boundary while preserving the legitimate internal route.

Esto nos orienta a revisar la configuración de headers reenviados y la forma en la que Flask determina la IP real del cliente.

---

# 1. Obtención del código fuente

Clonamos el repositorio proporcionado:

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git

cd core_application

git checkout -b developer
```

La estructura del proyecto:

```text
checkpoint/
├── app/
├── conf/
├── tests/
├── requirements.txt
└── seed.sql
```

---

# 2. Análisis del código

Buscamos referencias relacionadas con proxies, headers reenviados y validaciones internas:

```bash
rg "ProxyFix|Forwarded|remote_addr|trusted|internal" checkpoint
```

Encontramos una configuración importante en:

```text
checkpoint/app/__init__.py
```

con:

```python
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=2,
    x_proto=1,
    x_host=1
)
```

También encontramos en:

```text
checkpoint/app/gate.py
```

la función:

```python
def _origin_address() -> str:
    return request.remote_addr or ""
```

La aplicación utiliza `request.remote_addr` para tomar decisiones de confianza.

---

# 3. Análisis de la vulnerabilidad

## ProxyFix

`ProxyFix` permite que Flask confíe en información proporcionada por un proxy mediante headers como:

```http
X-Forwarded-For
X-Forwarded-Proto
X-Forwarded-Host
```

La configuración original:

```python
x_for=2
```

significa que Flask confía en dos niveles de proxies.

Sin embargo, la arquitectura real solamente tiene un proxy:

```text
Cliente
   |
   v
 Caddy
   |
   v
 Flask
```

Por lo tanto la aplicación estaba confiando en más saltos de los existentes.

---

# 4. Bypass de la validación interna

En `gate.py` encontramos:

```python
TRUSTED_ORIGINS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.2/32"),
]
```

La aplicación considera:

```text
127.0.0.2
```

como una dirección interna confiable.

La validación depende de:

```python
request.remote_addr
```

Por lo tanto, si un atacante consigue manipular este valor puede ser tratado como un usuario interno.

---

# 5. Explotación de la mala configuración

Un atacante puede enviar un header falso:

```http
X-Forwarded-For: 127.0.0.2
```

Debido a:

```python
x_for=2
```

Flask puede interpretar la dirección falsificada como la dirección real del cliente:

```python
request.remote_addr = 127.0.0.2
```

Esto permite evadir los controles internos basados en IP.

---

# 6. Corrección aplicada

La solución consiste en corregir la cantidad de proxies confiables.

## Configuración vulnerable

```python
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=2,
    x_proto=1,
    x_host=1
)
```

## Configuración corregida

```python
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)
```

---

# 7. Explicación del parche

Antes del cambio:

```text
Atacante

X-Forwarded-For: 127.0.0.2

        |
        v

ProxyFix(x_for=2)

        |
        v

Flask cree que el cliente es interno
```

Después del cambio:

```text
Atacante

X-Forwarded-For: 127.0.0.2

        |
        v

ProxyFix(x_for=1)

        |
        v

Flask solamente confía en el proxy inmediato
```

Ahora Flask únicamente acepta la información proveniente del proxy legítimo.

---

# 8. Pruebas

Ejecutamos los tests:

```bash
PYTHONPATH=. pytest
```

Inicialmente apareció un fallo:

```text
assert b">17<" in supplies.data
```

El problema no estaba relacionado con el parche de seguridad.

La causa era una base de datos SQLite persistente:

```text
gate.db
```

La aplicación utiliza esta base:

```python
DB_PATH = os.getenv(
    "GATE_DB",
    os.path.join(os.path.dirname(__file__), "..", "gate.db")
)
```

Como los tests modificaron datos anteriormente, la base quedó en un estado diferente al esperado.

Se eliminó:

```bash
rm gate.db
```

y se ejecutaron nuevamente las pruebas:

```bash
PYTHONPATH=. pytest
```

Resultado:

```text
25 passed in 1.46s
```

---

# 9. Commit y entrega

Se verificó el cambio:

```bash
git diff
```

El único archivo modificado fue:

```text
app/__init__.py
```

Se realizó el commit:

```bash
git add app/__init__.py

git commit -m "Fix trusted forwarded client provenance"
```

Luego se envió la rama:

```bash
git push -u origin developer
```

El Pull Request fue aceptado y la flag quedó disponible.

---

# Vulnerabilidad encontrada

## Tipo

**Improper Trust Boundary**

**Reverse Proxy Trust Misconfiguration**

---

# Impacto

La configuración incorrecta permitía:

- Manipular la identidad del cliente.
- Falsificar una dirección interna.
- Acceder a rutas destinadas únicamente a servicios internos.
- Romper la confianza entre Caddy y Flask.

---

# Mitigación aplicada

Buenas prácticas implementadas:

- Configurar correctamente `ProxyFix`.
- Confiar únicamente en proxies existentes.
- No confiar en headers reenviados directamente por usuarios.
- Mantener una frontera clara entre proxy y aplicación.

---

# Conclusión

El problema estaba causado por una configuración incorrecta del middleware `ProxyFix`.

La aplicación confiaba en dos proxies:

```python
x_for=2
```

pero únicamente existía un proxy real:

```text
Caddy → Flask
```

Esto permitía manipular la procedencia del cliente mediante headers reenviados.

La solución fue reducir la confianza a un único salto:

```python
x_for=1
```

Con este cambio se restauró una cadena de confianza correcta entre Caddy y Flask, manteniendo las rutas internas legítimas y bloqueando la suplantación de clientes externos.

---

## Flag

Recuperada desde `http://154.57.164.82:32151/flag` tras aceptarse el Pull Request:

```text
HTB{thr33_kn0ck5_0n_s34led_g4t3s_15d426db8fb81c14844fdda6cddc446d}
```

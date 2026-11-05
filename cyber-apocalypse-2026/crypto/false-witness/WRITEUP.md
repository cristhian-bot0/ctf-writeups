# False Witness — Writeup

**Evento:** HTB Cyber Apocalypse 2026 · **Categoría:** Crypto
**Flag:** `HTB{___l34k1ng_b1ts_0n3_by_0n3___}`

> *Caldrin Vowmark knows that not every seal deserves belief. Some marks still
> carry the weight of a living vow; others only imitate one well enough to pass a
> glance.*

El "sello vivo" es un hash real `H(x)`; el que "solo lo imita" es un valor
aleatorio. El reto consiste en construir un **distinguidor perfecto** entre ambos
para filtrar la clave AES bit a bit.

## El servicio

```python
P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
FLAG = open("flag.txt","rb").read().strip()
N = 256

KEY = secrets.token_bytes(32)                       # 256 bits secretos
KEY_BITS = list(map(int, f"{int.from_bytes(KEY):0256b}"))

def H(msg):
    return pow(G, msg, P)                            # G lo elige el jugador

class Oracle:
    def oracle(self, i):                             # cachea 1 valor por offset
        ret = (secrets.randbelow(2**N) if KEY_BITS[i] == 0
               else PK[i % len(PK)][secrets.randbelow(2)])
        ...

# La FLAG se entrega cifrada con la propia KEY:
print(AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16)).hex())

# El jugador fija G, luego consulta el oráculo tantas veces como quiera.
G = int(input("... give me the hashing generator: "))   # 1 < G < P
```

`keygen` produce `PK[j] = (H(sk[j][0]), H(sk[j][1]))`, o sea imágenes de `H`.

Para cada offset `i` (bit `i` de la clave), el oráculo devuelve:

| `KEY_BITS[i]` | valor devuelto                     | naturaleza          |
|:-------------:|------------------------------------|---------------------|
| `0`           | `secrets.randbelow(2**256)`        | aleatorio uniforme  |
| `1`           | `PK[i%256][rand]` = `pow(G, x, P)` | un hash real        |

Recuperar los 256 bits ⇒ reconstruir `KEY` ⇒ descifrar el AES-ECB ⇒ FLAG.

## La vulnerabilidad

El oráculo delata `KEY_BITS[i]` por **la forma** del valor: un `H(x)` real frente
a un entero uniforme. Normalmente ambos son indistinguibles (la imagen de
`pow(G, ·, P)` con `G` generador cubre casi todo `[1, P)`). Pero **el jugador
elige `G`**, y ahí está el fallo.

Elegimos un `G` de **orden multiplicativo pequeño**. El más limpio:

```
G = P - 1 ≡ -1 (mod P),   ord(G) = 2
```

Entonces, para cualquier `msg`:

```
pow(G, msg, P) = (-1)^msg mod P  ∈  {1, P-1}
```

La imagen de `H` colapsa a **solo dos valores**. Por tanto:

- resultado ∈ `{1, P-1}`  → bit = **1** (hash real, siempre cae dentro)
- resultado ∉ `{1, P-1}`  → bit = **0** (aleatorio; probabilidad de caer dentro
  ≈ `2 / 2²⁵⁶`, despreciable)

Distinguidor **perfecto** con **una consulta por bit** (256 en total).

> Generalización: sirve cualquier `G` cuyo orden `d` divida `P-1` y sea pequeño;
> el test genérico es `pow(val, d, P) == 1`. Con `d = 2` la imagen es literalmente
> `{1, P-1}`, lo que hace el chequeo trivial.

## Explotación

```python
P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
G = P - 1
INSIDE = {1, P - 1}

ct = bytes.fromhex(recv_ciphertext())     # AES-ECB(FLAG) bajo KEY
send(str(G))                              # fijamos el generador

bits = []
for i in range(256):
    val = query_oracle(i)                 # menú: 1 -> offset i
    bits.append(1 if val in INSIDE else 0)

KEY = int("".join(map(str, bits)), 2).to_bytes(32, "big")
flag = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
```

Contra el servicio remoto:

```
$ python solve.py 154.57.164.77 32234
KEY : e3fb475f953d8efa86669e9074d13e3a6397ccb2134a4e0c53ffb49c6d129b0a
FLAG: HTB{___l34k1ng_b1ts_0n3_by_0n3___}
```

## Lección

Nunca dejes que un atacante controle el **generador / base** de una construcción
donde la seguridad depende de que la salida sea indistinguible del azar. Un `G`
de orden pequeño (aquí `-1`, orden 2) reduce la imagen a un puñado de valores
reconocibles y rompe por completo la propiedad de ocultamiento — filtrando la
clave, como dice la flag, *one bit at a time*.

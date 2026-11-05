# The Ashen Field — Writeup

**Evento:** HTB Cyber Apocalypse 2026 · **Categoría:** Crypto
**Flag:** `HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}`

> *A public rite built from equations, guarded only by the silent calculations its
> keepers left behind.*

Un criptosistema **multivariante tipo HFE** (Hidden Field Equations) sobre GF(2)
que aparenta ser un sistema de ecuaciones de grado 4 intratable... pero cuyo mapa
central es en realidad **afín**. La clave AES sale con álgebra lineal.

## El esquema (`source.sage`)

Con `q = 2`, `N = 137`, `K = GF(2)`:

```python
R = PolynomialRing(K, [x1..x137])        # anillo multivariante
S = (S_A, S_B); T = (T_A, T_B)           # transformaciones afines secretas
Rv = S_A * x + S_B                        # formas afines en las variables

# GF(2^137) = GF(2)[t]/g(t), g irreducible de grado 137,
# pero con coeficientes en R (formas afines):
F = elemento cuyos "dígitos" son las entradas de Rv
F = F^(2q) + F^q + 1  =  F^4 + F^2 + 1    # <-- mapa central

PK = T_A * (dígitos de F) + T_B           # 137 polinomios públicos
```

Cifrado y flag:

```python
msg = KEY.bits()                          # 137 bits, LSB primero (nbits==137)
encrypted_key = PK(msg)                    # vector de 137 bits
AES_KEY = sha256(str(KEY)).digest()
enc_flag = AES-ECB(pad(FLAG))
```

`output.txt` entrega `PK`, `encrypted_key` y `enc_flag`.

## La debilidad: el mapa central es lineal

El núcleo del esquema es:

```
F^4 + F^2 + 1  =  (F^2 + F + 1)^2       (en característica 2)
```

Los exponentes del mapa central son **potencias de 2** (`4=2²`, `2=2¹`, `1=2⁰`).
Un polinomio con solo esos términos es un **polinomio linealizado**: sobre GF(2),
`x → x²` es el automorfismo de Frobenius, que es **GF(2)-lineal**. Por tanto
`F⁴ + F² + 1` es una función **GF(2)-afín** de `F` (parte lineal `F⁴+F²`,
constante `+1`).

Encadenando:
- `F` es afín en la entrada (transformación `S`),
- otra afín `T` se aplica encima,
- composición de afines = **afín**.

Y hay más: elevar al cuadrado una **forma lineal** en característica 2 elimina
los términos cruzados,

```
(a·x_i + b·x_j)²  =  a²·x_i² + b²·x_j²  =  a·x_i² + b·x_j²   (2ab·x_i·x_j = 0)
```

así que cada polinomio público es solo una combinación GF(2) de monomios
`x_j²` y `x_j⁴` (más constante), **sin productos entre variables distintas**.
Evaluado en bits `{0,1}`, donde `x_j² = x_j⁴ = x_j`, cada componente es afín:

```
PK_k(m) = const_k  XOR  ( XOR_{j : x_j aparece un nº impar de veces} m_j )
```

Es decir, todo el "cifrado" es un mapa afín `c = A·m + b` sobre GF(2). No hace
falta ni Sage ni resolver bases de Gröbner: se lee `A` y `b` **parseando** el PK
(paridad de cada variable por componente).

## La sutileza: la 2-a-1 de Artin–Schreier

`F → F² + F` es el mapa aditivo de **Artin–Schreier**, GF(2)-lineal, con núcleo
`{0, 1} = GF(2)`. No es inyectivo: cada salida tiene 2 preimágenes. Eso hace que
la matriz `A` sea **deficiente en rango** (aquí nulidad 2 → 4 preimágenes). Se
enumera el espacio nulo y se elige el candidato correcto por dos filtros: la KEY
debe tener `nbits == 137` y el descifrado AES debe tener padding válido / empezar
por `HTB{`.

## Explotación (Python puro, sin Sage)

```python
# 1) Parsear los 137 polinomios -> filas de A (bitmask de paridad) + b
for poly in PK:
    parity[j] ^= 1  para cada monomio x_j^k ; const ^= 1 por cada '1'

# 2) Resolver A m = c XOR b sobre GF(2) (Gauss-Jordan), enumerar null space
# 3) Por cada candidato:
KEY = sum(m[j] << j for j in range(137))          # x_{j+1} <-> bit j (LSB)
AES_KEY = sha256(str(KEY).encode()).digest()
FLAG = unpad(AES.new(AES_KEY, MODE_ECB).decrypt(enc_flag), 16)
# elegir el candidato con nbits==137 y padding válido
```

Ejecución:

```
$ python solve.py
[*] null space dim = 2 -> 4 candidate(s)
[-] KEY nbits=135 ...
[-] KEY nbits=135 ...
[+] KEY  : 110621486878801192554077110255801668498185  (nbits=137)
[+] FLAG : HTB{e1th3r_gr0bn3r_0r_v4r13ty___1t_st1ll_w0rks!th4nks_f4l4y_f0r_y0ur_4tt4ck_0n_HFE}
```

## Lección

La propia flag lo dice: *"either Gröbner or variety, it still works — thanks Faÿ
for your attack on HFE"*. En HFE, un mapa central formado por **monomios cuyos
exponentes son potencias de la característica** (polinomio linealizado) destruye
toda la no linealidad: el sistema público, que parece de grado alto, se reduce a
un mapa **afín** invertible con álgebra lineal — el corazón de los ataques de
Faugère–Faÿ / Gröbner sobre HFE. Nunca uses un polinomio central linealizado.

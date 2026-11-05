# Fractured Seal — Writeup

**Evento:** HTB Cyber Apocalypse 2026 · **Categoría:** Crypto
**Flag:** `HTB{r3c0v3r1ng_RSA_k3ys___l1k3___Me0w___me0o00o0o0w___Me0w}`

> *A seal doesn't have to be whole to still remember the door it once opened.*

Nos dan una **clave privada RSA (PEM PKCS#1) parcialmente tachada** y el flag
cifrado. Aunque falten trozos, sobreviven suficientes **bits altos de un primo**
para factorizar el módulo con **Coppersmith**.

## Los ficheros

`encrypt.py` es RSA de libro (2048 bits, `e=0x10001`), exporta la clave privada y
`flag.enc = m^e mod n`. El regalo es `fractured_seal.pem`: el PEM con partes
reemplazadas por `*` (y un gato ASCII de troll incrustado en el medio).

## Leyendo los fragmentos

Un PEM PKCS#1 es DER base64 de:

```
RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }
```

Las líneas base64 tienen 64 caracteres y cada `*` sustituye exactamente un
carácter, así que **la alineación base64 se conserva** en las líneas redactadas.
Reconstruyendo el flujo alineado (líneas 0–16; el gato ASCII rompe la alineación
pero está después de `q`) y decodificando grupo a grupo obtenemos:

- **`n` completo (2048 bits)** salvo su byte menos significativo. Pero el carácter
  base64 anterior a ese byte sobrevive, fijando sus **6 bits altos** → solo
  **4 candidatos** para `n`.
- El header DER de `q` (`02 81 81 00`) y **584 bits altos de `q`** (73 bytes tras
  el header; big-endian ⇒ los más significativos).

## Coppersmith: factorizar con bits altos de un factor

Escribimos `q = q_{high}·2^{440} + x` con `q_{high}` (584 bits) conocido y el
resto desconocido `0 ≤ x < 2^{440}`. Como `n = p·q` con `p, q ≈ n^{1/2}` (β = 0.5),
el teorema de Coppersmith permite recuperar un factor cuando se conoce **más de la
mitad** de sus bits. Aquí la incógnita es de **440 bits < 512** → dentro del límite
`x < n^{β²} = n^{0.25} = 2^{512}`, con margen.

Buscamos la raíz pequeña de

```
f(x) = (q_high · 2^440) + x  ≡  0   (mod q),   q | n
```

mediante **Howgrave-Graham** (Coppersmith univariante, grado 1): se construye una
red con los polinomios desplazados `N^{m-i} f(x)^i` y `x^j f(x)^m`, se reduce con
**LLL**, y el vector más corto da un polinomio con la raíz `x0` sobre los enteros.
Entonces `q = gcd(f(x0), n)`.

Como `n` tiene 4 candidatos, se prueba cada uno; solo el correcto (aquel del que
`q` es factor) produce una factorización. Después es RSA normal:

```python
p = n // q
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, d, n)                       # c = int(flag.enc)
flag = long_to_bytes(m)
```

## Explotación

Puntos prácticos:
- Extracción de `n` y de los bits altos de un primo **a nivel base64** (los `*`
  preservan la alineación de 64 chars/línea; el gato ASCII rompe la alineación
  pero está detrás del primo). Se obtienen 2 candidatos impares de `n` y **576
  bits altos** de `q` → incógnita `u = 448 < 512`.
- LLL con **fpylll** (bindings C de FPLLL): imprescindible; un LLL en Python puro
  con `Fraction` sobre una red dim-16 con entradas de ~16000 bits es inviable.
- Parámetros Coppersmith: `m = 8`, `t = 8` (dim 16), `X = 2^448`.
- **Extracción de la raíz sin coma flotante:** muchas filas reducidas por LLL se
  anulan exactamente en `x0`, así que el **GCD polinomial** de las más cortas
  contiene el factor `(x - x0)` → raíz entera exacta.

```
$ python solve.py
[*] 2 odd n candidate(s); known-high prime bits=576, unknown low bits u=448
[*] Coppersmith m=8 t=8 dim=16
    trying n=...9575
[+] FACTORED n=...9575
[+] FLAG: b'HTB{r3c0v3r1ng_RSA_k3ys___l1k3___Me0w___me0o00o0o0w___Me0w}'
```

## Nota de implementación (lo que costó horas)

El LLL recupera el vector correcto sin problema; el error estaba en **cómo se
extrae la raíz entera** del polinomio reducido. Usar `mpmath.polyroots` (coma
flotante) sobre un polinomio de grado 16 con coeficientes de miles de bits es
**numéricamente inestable** para `N` de 2048 bits: a veces encuentra la raíz, a
veces no. La forma robusta y exacta es aprovechar que **varias** filas reducidas
se anulan en `x0` y tomar su **GCD polinomial** (aritmética entera exacta) para
leer `(x - x0)` directamente. Diagnóstico decisivo y barato: reproducir el ataque
sobre una clave RSA generada con el **mismo layout DER** y `x0` conocido, y
verificar por separado extracción, LLL y root-finding.

## Lección

Una clave privada RSA no necesita estar completa para ser peligrosa: basta con
**más de la mitad de los bits de uno de los primos** para factorizar el módulo vía
Coppersmith/LLL. Redactar “casi toda” la clave (dejando ~56 % de un primo) no
protege nada. Los bits de un secreto criptográfico son todo-o-nada.

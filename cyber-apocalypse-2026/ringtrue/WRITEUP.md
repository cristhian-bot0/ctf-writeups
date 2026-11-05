# Ringtrue — Cyber Apocalypse CTF 2026 (reversing)

> La Casa Eastreach montó un artefacto alrededor de una esquirla del Signet y le enseñó a
> escuchar **una sola voz**: ocho tonos, cualquier valor. Pero dejó el aparato abierto,
> «con todo lo que le enseñaron escrito dentro en claro».

**Categoría:** reversing · **Handout:** `ringtrue` (ELF64 PIE, dinámico, *not stripped*)
**Flag:** `HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}`

## TL;DR

El binario mete tus 8 enteros por una **red neuronal entera de 3 capas densas** y exige que
la salida sea exactamente el vector `ECHO_S`. La activación es `f(v) = v if v>=0 else 2*v`,
que es **biyectiva**, así que la red entera es invertible: tres sistemas lineales 8×8 en
aritmética exacta y sale la entrada. Cero fuerza bruta.

```console
$ python3 solve.py
tones = 83 97 108 116 67 114 119 110
key   = b'SaltCrwn'
flag  = HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}
```

## Reconocimiento

El binario no está stripped, y la tabla de símbolos es media solución:

```console
$ readelf -sW ringtrue | grep OBJECT | grep -v UND
  0000000000005020     4 OBJECT  GLOBAL DEFAULT   25 VOW_LEN
  0000000000005030    30 OBJECT  GLOBAL DEFAULT   25 VOW_CIPHER
  0000000000005050    12 OBJECT  GLOBAL DEFAULT   25 W_SCALE
  0000000000005060    64 OBJECT  GLOBAL DEFAULT   25 ECHO_S
  00000000000050a0    32 OBJECT  GLOBAL DEFAULT   25 L2_B
  00000000000050c0    32 OBJECT  GLOBAL DEFAULT   25 L1_B
  00000000000050e0    32 OBJECT  GLOBAL DEFAULT   25 L0_B
  0000000000005100    64 OBJECT  GLOBAL DEFAULT   25 L2_W
  0000000000005140    64 OBJECT  GLOBAL DEFAULT   25 L1_W
  0000000000005180    64 OBJECT  GLOBAL DEFAULT   25 L0_W
  0000000000003a80   256 OBJECT  LOCAL   DEFAULT  18 K.0
```

`L{0,1,2}_W` / `L{0,1,2}_B` + una función local `dense` → tres capas densas.
`W_SCALE` (3 floats: `1/64`, `0.0078`, `0.0117`) son escalas de cuantización **que nunca se
referencian** en el código: el reto es aritmética entera pura, y eso es justo lo que lo hace
resoluble de forma exacta. `K.0` de 256 bytes que empieza en `428a2f98 71374491 b5c0fbcf` son
las constantes de ronda de **SHA-256** → ahí está el descifrado de la flag.

Las secciones están mapeadas identidad (`vaddr == file offset` para `.data` y `.rodata`), así
que los pesos se leen del fichero sin depurador ([`dump_model.py`](dump_model.py)).

## `dense()`

60 bytes, se lee de un tirón:

```asm
0000000000001309 <dense>:
    1309: mov    r11d,0x0                       ; j = 0
    130f: movsxd r9,DWORD PTR [rsi+r11*4]       ; acc = B[j]            (int32)
    1313: mov    r10,rdi                        ; row = &W[j*8]
    1316: mov    eax,0x0                        ; k = 0
    131b: movsx  r8,BYTE PTR [r10+rax*1]        ; W[j][k]               (int8)
    1320: imul   r8,QWORD PTR [rdx+rax*8]       ; * in[k]               (int64)
    1325: add    r9,r8
    1328: add    rax,0x1
    132c: cmp    rax,0x8
    1330: jne    131b
    1332: mov    QWORD PTR [rcx+r11*8],r9       ; out[j] = acc          (int64)
    1336: add    r11,0x1
    133a: add    rdi,0x8
    133e: cmp    r11,0x8
    1342: jne    130f
    1344: ret
```

```c
void dense(const int8_t *W, const int32_t *B, const int64_t *in, int64_t *out) {
    for (int j = 0; j < 8; j++) {
        int64_t acc = B[j];
        for (int k = 0; k < 8; k++) acc += W[j*8 + k] * in[k];
        out[j] = acc;
    }
}
```

Es decir `out = W @ in + B` con `W` 8×8 *row-major* de `int8`, sesgos `int32`, acumulación
en `int64`. **Sin overflow, sin float, sin redondeo** → exacto.

## La activación es el regalo

En `main`, entre capa y capa:

```asm
    1acb: mov    rax,QWORD PTR [rsp+rdx*1+0x70]
    1ad0: lea    rcx,[rax+rax*1]        ; rcx = 2*rax
    1ad4: test   rax,rax
    1ad7: cmovs  rax,rcx                ; si rax < 0 -> rax = 2*rax
    1adb: mov    QWORD PTR [rsp+rdx*1+0xb0],rax
```

O sea:

```c
int64_t act(int64_t v) { return v < 0 ? 2*v : v; }
```

Es una «leaky ReLU al revés»: en vez de **atenuar** el lado negativo (pendiente 0.01), lo
**amplifica** (pendiente 2). Eso la vuelve **estrictamente monótona creciente y biyectiva**, y
por tanto invertible sin ambigüedad:

```c
int64_t inv_act(int64_t y) { return y < 0 ? y/2 : y; }
```

Con una ReLU normal el reto sería duro: cada neurona apagada destruye información y habría que
resolver un problema combinatorio de patrones de activación (o pasar por un SMT). Aquí no se
pierde nada.

El flujo completo de `main` (`0x1a70`–`0x1b88`):

```c
sscanf(line, "%d %d %d %d %d %d %d %d", ...);   // exige 8 conversiones
int64_t x[8] = { in[0], ..., in[7] };           // sign-extend a int64
dense(L0_W, L0_B, x, h);  for (i) a[i] = act(h[i]);
dense(L1_W, L1_B, a, h);  for (i) a[i] = act(h[i]);
dense(L2_W, L2_B, a, out);                      // última capa: SIN activación
ok = 1; for (i) if (out[i] != ECHO_S[i]) ok = 0;
```

Y `ECHO_S` (8× `int64`) es el objetivo:

```
ECHO_S = [1542223, 574187, -2694563, -3518303, 383776, 576877, 2637871, -2518822]
```

## Inversión

Tres pasos hacia atrás, cada uno un sistema lineal 8×8:

```
L2_W @ a1 = ECHO_S - L2_B        ->  a1        (la salida no pasa por activación)
z1 = inv_act(a1)
L1_W @ a0 = z1 - L1_B            ->  a0
z0 = inv_act(a0)
L0_W @ x  = z0 - L0_B            ->  x
```

Gauss-Jordan con `fractions.Fraction` para que no haya ruido de coma flotante (los pivotes son
racionales feos, pero la solución final debe salir entera — y sale). Las tres matrices son
invertibles, así que la solución es **única**: no hay que elegir entre candidatos.

Resultado:

```
z0 = [4523, -293, 4655, 2996, 3385, -64, -2069, 2290]
x  = [83, 97, 108, 116, 67, 114, 119, 110]   ->  b'SaltCrwn'
```

Los ocho «tonos» son los bytes ASCII de `SaltCrwn` (*Salt Crown*, la Corona de Salmuera). Con
eso el enunciado se cierra: los valores no estaban acotados a `0..255`, pero la red sólo acepta
un punto y resulta ser texto.

## Sellado del vow

Si la comprobación pasa, `main` (`0x1bb2`–`0x1f03`) trunca los 8 enteros a `uint8`, los usa
como clave y genera el keystream con SHA-256 en modo contador (`K.0` son las constantes de
ronda, SHA-256 implementado inline):

```c
uint8_t key[8] = { (uint8_t)in[0], ..., (uint8_t)in[7] };
for (int i = 0; i < VOW_LEN; i++) {
    uint32_t ctr = i / 32;                                    // idiv por 0x20 en 0x1bfa
    uint8_t blk[32] = SHA256(key || (uint8_t[4])ctr);
    flag[i] = VOW_CIPHER[i] ^ blk[i % 32];
}
```

`VOW_LEN = 30` así que sólo se usa el bloque 0 (`ctr = 0`, y la endianness del contador da
igual con valor cero). Reproducirlo en Python es una línea:

```python
ks = hashlib.sha256(b"SaltCrwn" + struct.pack("<I", 0)).digest()
bytes(c ^ k for c, k in zip(VOW_CIPHER, ks))
# b'HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}'
```

## Verificación

```console
$ echo "83 97 108 116 67 114 119 110" | ./ringtrue | tail -4
  [32mvault-seal: OPEN    RESONANCE [##############################] 100%
  +-- ash-vault - sealed vow ---------------------------------+
  |  HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}                           |
  +-----------------------------------------------------------+
```

`solve.py` además reimplementa el forward pass y hace `assert forward(tones) == ECHO_S`, así
que la solución se valida sin ejecutar el binario.

**Flag:** `HTB{h3y_s1gn3t_1_4m_y0ur_k1ng}`

## Lecciones

- Un «neural network check» sólo es duro si la no linealidad **pierde información**. Antes de
  sacar el SMT, mira la activación: si es monótona y biyectiva (aquí `v<0 ? 2v : v`), la red
  es un cambio de variable invertible y el reto es álgebra lineal de instituto.
- Aritmética **entera** sin escalas ni redondeo = inversión exacta. `W_SCALE` estaba en `.data`
  pero sin una sola referencia en `.text`: comprobar con `objdump | grep <addr>` qué constantes
  se usan de verdad ahorra perseguir cuantización que no existe.
- `readelf -sW` en un binario *not stripped* con nombres como `L0_W`/`ECHO_S`/`K.0` describe la
  arquitectura entera antes de abrir un desensamblador; y 256 bytes que empiezan por
  `428a2f98` son SHA-256 sin necesidad de leer el código.

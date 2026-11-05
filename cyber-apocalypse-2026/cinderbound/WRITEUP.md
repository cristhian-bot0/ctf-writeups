# Cinderbound — Cyber Apocalypse CTF 2026 (reversing)

> Los Cinderbound dejaron de tallar sus votos en piedra: los más peligrosos los prensaron
> en «un motor extranjero, ilegible para cualquier sacerdote entrenado sólo con los viejos
> cinceles, y lo sellaron». Encontraste uno de esos votos.

**Categoría:** reversing · **Handout:** `cinderbound.mpy` (221 bytes)
**Flag:** `HTB{c1nd3rbound_v0w5}`

## TL;DR

El «motor extranjero» es **MicroPython**: el handout es un `.mpy` (bytecode MicroPython v6),
no un `.pyc` de CPython. Se desensambla con `tools/mpy-tool.py -d` del propio repo de
MicroPython y aparece una función `judge(syllable)` que cifra la entrada con un XOR de clave
autopropagada y la compara contra 16 constantes. El cifrado es invertible byte a byte:

```bash
python3 solve.py     # -> HTB{c1nd3rbound_v0w5}
```

## Reconocimiento

`file` no reconoce nada:

```console
$ file cinderbound.mpy
cinderbound.mpy: data
$ xxd cinderbound.mpy | head -3
00000000: 4d06 001f 0801 186a 7564 6765 5f73 7263  M......judge_src
00000010: 2e70 7900 0f0a 6a75 6467 6500 7910 7379  .py...judge.y.sy
00000020: 6c6c 6162 6c65 0081 5781 6f81 590a 1007  llable..W.o.Y...
```

Dos pistas inmediatas:

- El magic es `4D 06 00 1F` = `'M'`, versión 6, feature flags 0, `small_int_bits = 31`.
  Ése es exactamente el header de un fichero **`.mpy` de MicroPython** (formato v6,
  MicroPython 1.20 – 1.24). La extensión no mentía; lo que despista es que la gente asume
  «bytecode Python = `.pyc`» y `uncompyle6`/`decompyle3` no sirven aquí.
- Los qstr (tabla de strings del módulo) están en claro: `judge_src.py`, `judge`, `syllable`.
  Ya sabemos que hay una función `judge(syllable)`.

Los bytes ASCII sueltos del medio (`57`, `129`, `154`, …) son constantes enteras: en `.mpy`
los objetos `int` se serializan como **texto decimal**, así que las constantes del reto se
leen a ojo antes incluso de desensamblar.

## Desensamblado

MicroPython trae su propia herramienta. No hace falta compilar nada, sólo dos ficheros del
repo (`mpy-tool.py` importa `makeqstrdata` desde `../py`):

```bash
mkdir -p mp/tools mp/py
curl -so mp/tools/mpy-tool.py https://raw.githubusercontent.com/micropython/micropython/v1.22.2/tools/mpy-tool.py
curl -so mp/py/makeqstrdata.py https://raw.githubusercontent.com/micropython/micropython/v1.22.2/py/makeqstrdata.py
python3 mp/tools/mpy-tool.py -d cinderbound.mpy
```

Salida (recortada, completa en [`disasm.txt`](disasm.txt)):

```
source_file: judge_src.py
header: 4d:06:00:1f
qstr_table[8]:
    judge_src.py / <module> / judge / append / syllable / len / ord / list
obj_table: [(57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)]

simple_name: judge
  args: ['syllable']
  23:00       LOAD_CONST_OBJ (57, 129, 154, ...)   # tupla objetivo
  c1          STORE_FAST 1
  22:80:5a    LOAD_CONST_SMALL_INT 90              # clave inicial
  c2          STORE_FAST 2
  2b:00       BUILD_LIST 0
  c3          STORE_FAST 3                         # acumulador de salida
  12:05       LOAD_GLOBAL len
  b0          LOAD_FAST 0
  34:01       CALL_FUNCTION 1
  80          LOAD_CONST_SMALL_INT 0
  42:6b       JUMP 43                              # bucle while i < len(syllable)
  57          DUP_TOP
  c4          STORE_FAST 4                         # i
  12:06       LOAD_GLOBAL ord
  b0/b4/55    LOAD_FAST 0; LOAD_FAST 4; LOAD_SUBSCR
  34:01       CALL_FUNCTION 1                      # ord(syllable[i])
  b2          LOAD_FAST 2
  ee          BINARY_OP 23 __xor__                 #   ^ key
  b4          LOAD_FAST 4
  8d          LOAD_CONST_SMALL_INT 13
  f4          BINARY_OP 29 __mul__                 #   i * 13
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__                 #   & 255
  ee          BINARY_OP 23 __xor__
  c5          STORE_FAST 5
  b2          LOAD_FAST 2
  ...ord(syllable[i])...
  f2          BINARY_OP 27 __add__                 # key = (key + ord(...))
  22:81:7f    LOAD_CONST_SMALL_INT 255
  ef          BINARY_OP 24 __and__                 #        & 255
  c2          STORE_FAST 2
  b3/14:03    LOAD_FAST 3; LOAD_METHOD append
  b5/36:01    LOAD_FAST 5; CALL_METHOD 1
  ...
  b3          LOAD_FAST 3
  12:07/b1    LOAD_GLOBAL list; LOAD_FAST 1
  34:01       CALL_FUNCTION 1
  d9          BINARY_OP 2 __eq__                   # out == list(target)
  63          RETURN_VALUE
```

El fuente reconstruido ([`judge_src.py`](judge_src.py)):

```python
def judge(syllable):
    target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
    key = 90
    out = []
    i = 0
    while i < len(syllable):
        out.append(ord(syllable[i]) ^ key ^ ((i * 13) & 255))
        key = (key + ord(syllable[i])) & 255
        i += 1
    return out == list(target)
```

## El bug: el keystream depende del texto claro, no del cifrado… pero se reconstruye igual

El cifrado es un stream cipher casero con dos componentes por byte:

```
out[i] = s[i] ^ key_i ^ ((i * 13) & 255)
key_0   = 90
key_i+1 = (key_i + s[i]) & 255
```

La parte `(i*13) & 255` es pública (sólo depende de la posición). La clave `key_i` se
autopropaga sumando el **texto claro**, lo que a primera vista parece impedir el descifrado
directo… pero no: al descifrar el byte `i` obtenemos `s[i]`, y con `s[i]` calculamos `key_{i+1}`
antes de pasar al byte `i+1`. El keystream se va generando sobre la marcha, sin adivinar nada:

```python
key = 90
plain = []
for i, c in enumerate(target):
    b = c ^ key ^ ((i * 13) & 255)   # s[i]
    plain.append(b)
    key = (key + b) & 255            # key_{i+1}, ya conocido
```

No hace falta fuerza bruta ni siquiera byte a byte: es una pasada lineal de 16 iteraciones.

## Explotación

```console
$ python3 solve.py
syllable = c1nd3rbound_v0w5
flag     = HTB{c1nd3rbound_v0w5}
```

`solve.py` importa el `judge()` reconstruido y afirma `judge(syllable) is True`, así que la
verificación no depende de mi lectura del bytecode sino de la propia función del reto.

**Flag:** `HTB{c1nd3rbound_v0w5}`

## Lecciones

- `4D xx xx xx` al inicio de un binario pequeño y opaco con nombres Python dentro = `.mpy`.
  El desensamblador oficial (`tools/mpy-tool.py -d`) resuelve el reto sin escribir un parser.
- En `.mpy` la tabla de qstr y los `int` constantes van en **texto plano**: medio reto se lee
  con `xxd` antes de tocar el bytecode.
- Un keystream que se realimenta con el texto claro no aporta nada frente a un atacante que
  conoce el ciphertext completo y el estado inicial: se descifra igual, en línea.

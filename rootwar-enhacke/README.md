# RootWars 2026 — enHacke CTF

Workspace para el torneo. Plataforma CTFd en https://ctf.enhacke.com (usuario **ElPRESI**).
Formato de flag: `NHK{...}`.

## Estructura

- `FLAGS.md` — índice central: todos los retos, estado y flag conforme se resuelven.
- `challenges/<categoria>/<id>-<slug>/`
  - `NOTES.md` — enunciado, conexión/adjuntos, flag y notas de resolución.
  - `files/` — adjuntos descargados del reto.
- `_details/` — JSON crudo de cada reto (API CTFd), por si hace falta re-parsear.

## Categorías

| Categoría | Retos |
|---|---|
| Misceláneo / Trivia | 40 |
| ??? (ocultos/bloqueados) | 18 |
| Crypto | 15 |
| OSINT | 13 |
| Stego | 10 |
| Web | 10 |
| Linux | 1 |
| Iniciación | 1 ✅ |

## Infra de retos

- SSH (Linux): acceso a un servidor compartido del torneo (host/puerto omitidos aquí: infraestructura reutilizable entre cohortes, sin salida a Internet).
- Varios retos de crypto/web exponen servicios `nc`/HTTP contra ese mismo host.

## Reglas (del enunciado Linux)
- Server compartido: no atacar a otros jugadores ni al host; usar `mktemp -d` + `chmod 700`.

#!/usr/bin/env python3
"""Ringtrue — Cyber Apocalypse CTF 2026 (reversing).

El binario evalúa un MLP entero de 3 capas sobre los 8 enteros que introduces:

    z0 = L0_W @ x  + L0_B ;  a0 = act(z0)
    z1 = L1_W @ a0 + L1_B ;  a1 = act(z1)
    z2 = L2_W @ a1 + L2_B ;  acepta si z2 == ECHO_S

con act(v) = v if v >= 0 else 2*v  (biyectiva → la red entera es invertible).

Se invierte capa a capa resolviendo tres sistemas lineales 8x8 en racionales
exactos, sin fuerza bruta. Luego la flag = VOW_CIPHER ^ SHA256(key || u32(i//32)).
"""

import hashlib
import struct
from fractions import Fraction

from dump_model import load


def act(v):
    return v if v >= 0 else 2 * v


def inv_act(v):
    """Inversa de act: los negativos se dividen por 2 (act duplica los negativos)."""
    return v if v >= 0 else Fraction(v, 2)


def solve_linear(A, b):
    """Gauss-Jordan exacto en Fraction. A: 8x8, b: 8 → x tal que A @ x == b."""
    n = len(b)
    M = [[Fraction(A[i][j]) for j in range(n)] + [Fraction(b[i])] for i in range(n)]
    for c in range(n):
        piv = next(r for r in range(c, n) if M[r][c] != 0)
        M[c], M[piv] = M[piv], M[c]
        pv = M[c][c]
        M[c] = [v / pv for v in M[c]]
        for r in range(n):
            if r != c and M[r][c] != 0:
                f = M[r][c]
                M[r] = [a - f * b2 for a, b2 in zip(M[r], M[c])]
    return [M[i][n] for i in range(n)]


def forward(x, m):
    """Reimplementación de dense()+activación tal cual la hace el binario."""
    v = list(x)
    for W, B, last in ((m["L0_W"], m["L0_B"], False),
                       (m["L1_W"], m["L1_B"], False),
                       (m["L2_W"], m["L2_B"], True)):
        v = [B[j] + sum(W[j][k] * v[k] for k in range(8)) for j in range(8)]
        if not last:
            v = [act(t) for t in v]
    return v


def invert(m):
    # capa 2: L2_W @ a1 = ECHO_S - L2_B   (la salida no pasa por activación)
    a1 = solve_linear(m["L2_W"], [e - b for e, b in zip(m["ECHO_S"], m["L2_B"])])
    z1 = [inv_act(v) for v in a1]
    # capa 1
    a0 = solve_linear(m["L1_W"], [v - b for v, b in zip(z1, m["L1_B"])])
    z0 = [inv_act(v) for v in a0]
    # capa 0 → la entrada
    x = solve_linear(m["L0_W"], [v - b for v, b in zip(z0, m["L0_B"])])
    assert all(v.denominator == 1 for v in x), f"solución no entera: {x}"
    return [int(v) for v in x]


def unseal(key, m):
    """VOW_CIPHER ^ keystream, keystream[i] = SHA256(key || u32le(i//32))[i%32]."""
    out = bytearray()
    for i in range(m["VOW_LEN"]):
        block = hashlib.sha256(bytes(key) + struct.pack("<I", i // 32)).digest()
        out.append(m["VOW_CIPHER"][i] ^ block[i % 32])
    return bytes(out)


if __name__ == "__main__":
    m = load()
    tones = invert(m)
    assert forward(tones, m) == m["ECHO_S"], "la red no acepta los tonos recuperados"

    key = bytes(tones)
    print(f"tones = {' '.join(map(str, tones))}")
    print(f"key   = {key!r}")
    print(f"flag  = {unseal(tones, m).decode()}")

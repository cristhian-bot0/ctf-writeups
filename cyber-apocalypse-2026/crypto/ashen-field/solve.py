#!/usr/bin/env python3
"""
The Ashen Field - HTB Cyber Apocalypse 2026 (crypto)

Broken HFE-style scheme over GF(2), N=137.

Central map:  Y = F^4 + F^2 + 1   over GF(2^137).
All exponents are powers of two (4=2^2, 2=2^1, 1=2^0) => LINEARIZED polynomial.
Over GF(2), x -> x^2 is the Frobenius (GF(2)-linear), so F^4 + F^2 + 1 is
GF(2)-AFFINE in F.  F itself is affine (transform S), and another affine T is
applied on top.  Composition of affine maps is affine.

Also, squaring a linear form in char 2 kills all cross terms
((a x_i + b x_j)^2 = a x_i^2 + b x_j^2), so every public polynomial is only a
GF(2)-combination of {x_j^2, x_j^4} (+ optional constant), i.e. NO products
between distinct variables.  On boolean inputs x_j^2 = x_j^4 = x_j, so:

    PK_k(m) = const_k  XOR  ( XOR_{j : x_j appears odd #times in poly k} m_j )

=> the whole "encryption" is an affine map  c = A m + b  over GF(2).
Recover A,b by parsing (variable parity per component), then solve A m = c XOR b.

msg = KEY.bits() (LSB first, l=137), so x_i <-> bit (i-1) of KEY (weight 2^(i-1)).
"""
import re
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

N = 137


def parse_output(path):
    with open(path) as f:
        line_pk = f.readline().rstrip("\n")
        line_ct = f.readline().rstrip("\n")
        line_flag = f.readline().strip()

    # PK: "(poly1, poly2, ..., polyN)"  -- polys separated by ", " (no comma inside)
    pk_str = line_pk.strip()
    assert pk_str[0] == "(" and pk_str[-1] == ")"
    polys = pk_str[1:-1].split(", ")
    assert len(polys) == N, f"got {len(polys)} polys"

    # encrypted_key: "[b1, b2, ...]"
    ct = list(map(int, line_ct.strip()[1:-1].split(", ")))
    assert len(ct) == N

    enc_flag = bytes.fromhex(line_flag)
    return polys, ct, enc_flag


def poly_to_row(poly):
    """Return (mask, const) for a public polynomial evaluated on booleans.
    mask: int bit j set iff variable x_{j+1} appears an odd number of times.
    const: parity of standalone constant terms."""
    terms = poly.split(" + ")
    var_parity = [0] * N
    const = 0
    for t in terms:
        t = t.strip()
        m = re.fullmatch(r"x(\d+)(?:\^\d+)?", t)
        if m:
            idx = int(m.group(1)) - 1
            var_parity[idx] ^= 1
        elif t == "1":
            const ^= 1
        elif t == "0" or t == "":
            pass
        else:
            raise ValueError(f"unexpected term: {t!r}")
    mask = 0
    for j in range(N):
        if var_parity[j]:
            mask |= (1 << j)
    return mask, const


def solve_gf2_all(rows, rhs):
    """Solve A m = rhs over GF(2) via Gauss-Jordan, returning ALL solutions
    (enumerating the null space). Each eq packed as int: bits 0..N-1 coeffs,
    bit N = rhs. Rank deficiency here is 1 (Artin-Schreier kernel)."""
    n = N
    eqs = [rows[k] | (rhs[k] << n) for k in range(len(rows))]
    pivot_row = {}  # column -> reduced equation (int) pivoting on it
    used = [False] * len(eqs)
    for col in range(n):
        piv = -1
        for i in range(len(eqs)):
            if not used[i] and (eqs[i] >> col) & 1:
                piv = i
                break
        if piv == -1:
            continue
        used[piv] = True
        pe = eqs[piv]
        for i in range(len(eqs)):
            if i != piv and (eqs[i] >> col) & 1:
                eqs[i] ^= pe
        pivot_row[col] = piv
    for i in range(len(eqs)):
        if not used[i] and (eqs[i] & ((1 << n) - 1)) == 0 and (eqs[i] >> n) & 1:
            raise ValueError("inconsistent system")

    pivot_cols = set(pivot_row.keys())
    free_cols = [c for c in range(n) if c not in pivot_cols]

    solutions = []
    for combo in range(1 << len(free_cols)):
        m = [0] * n
        for bitidx, fc in enumerate(free_cols):
            m[fc] = (combo >> bitidx) & 1
        for col, piv in pivot_row.items():
            eq = eqs[piv]
            val = (eq >> n) & 1
            mm = eq & ((1 << n) - 1)
            mm &= ~(1 << col)
            j = 0
            while mm:
                if mm & 1:
                    val ^= m[j]
                mm >>= 1
                j += 1
            m[col] = val
        solutions.append(m)
    return solutions, free_cols


def main():
    polys, ct, enc_flag = parse_output("challenge/output.txt")

    rows = []
    b = []
    for p in polys:
        mask, const = poly_to_row(p)
        rows.append(mask)
        b.append(const)

    # c = A m + b  =>  A m = c XOR b
    rhs = [ct[k] ^ b[k] for k in range(N)]
    solutions, free_cols = solve_gf2_all(rows, rhs)
    print(f"[*] null space dim = {len(free_cols)} -> {len(solutions)} candidate(s)")

    for m in solutions:
        # KEY = sum m[j] * 2^j   (x_{j+1} <-> bit j of KEY, LSB first)
        KEY = 0
        for j in range(N):
            if m[j]:
                KEY |= (1 << j)
        AES_KEY = hashlib.sha256(str(KEY).encode()).digest()
        pt = AES.new(AES_KEY, AES.MODE_ECB).decrypt(enc_flag)
        try:
            unp = unpad(pt, 16)
        except ValueError:
            unp = None
        tag = "  <-- valid pad" if unp is not None else ""
        show = unp if unp is not None else pt
        printable = all(32 <= c < 127 for c in show[:20])
        if unp is not None and (b"HTB{" in unp or printable):
            print(f"[+] KEY   : {KEY}  (nbits={KEY.bit_length()})")
            print(f"[+] FLAG  : {unp.decode(errors='replace')}")
            return
        else:
            print(f"[-] KEY nbits={KEY.bit_length()}  pt[:16]={show[:16].hex()}{tag}")
    print("[!] no candidate produced a clean flag; dump above")


if __name__ == "__main__":
    main()

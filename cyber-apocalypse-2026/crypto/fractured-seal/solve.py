#!/usr/bin/env python3
"""
Fractured Seal - HTB Cyber Apocalypse 2026 (crypto)  --  self-contained solver.

Redacted PKCS#1 RSA private-key PEM. Surviving fragments give:
  - full modulus n (2048-bit) except its least-significant byte, of which the
    top 6 bits also survive  ->  only 4 candidates for n (2 are odd = valid).
  - the high 576 bits of a prime (its DER INTEGER, most-significant first);
    unknown low part = 1024-576 = 448 bits < prime^(1/2)=512  ->  Coppersmith
    (known MSBs of a factor) recovers the prime and factors n.

f(x) = (hi << 448) + x == 0 (mod prime), prime | n, 0 <= x < 2^448.
Howgrave-Graham univariate Coppersmith: LLL via fpylll, exact integer roots
via sympy.

Run:  ../false-witness/.venv/bin/python3 solve.py
"""
from math import gcd
from fpylll import IntegerMatrix, LLL
from sympy import Poly, Symbol, gcd as sgcd
from Crypto.Util.number import long_to_bytes

PEM = "challenge/fractured_seal.pem"
ENC = "challenge/flag.enc"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
IDX = {c: i for i, c in enumerate(B64)}


def extract():
    body = [l for l in open(PEM).read().splitlines() if not l.startswith("-----")]
    # lines 0..16 keep base64 alignment (64 chars each; '*' preserves position);
    # the ASCII-cat art after them breaks it but sits past the prime we need.
    stream = "".join(body[0:17])
    assert all(len(body[i]) == 64 for i in range(17))
    nbytes = len(stream) // 4 * 3
    known = [None] * nbytes
    for g in range(len(stream) // 4):          # decode full (unredacted) groups
        ch = stream[4 * g:4 * g + 4]
        if "*" in ch:
            continue
        v = [IDX[c] for c in ch]
        known[3 * g] = (v[0] << 2) | (v[1] >> 4)
        known[3 * g + 1] = ((v[1] & 0xF) << 4) | (v[2] >> 2)
        known[3 * g + 2] = ((v[2] & 3) << 6) | v[3]

    # ---- n: DER value bytes 11..267 (00 pad + 256-byte magnitude) ----
    n_full = known[11:267]                      # bytes 11..266 (fully known)
    assert None not in n_full
    top6 = IDX[stream[356]] << 2                # top 6 bits of magnitude LSB (byte 267)
    base_n = int.from_bytes(bytes(n_full), "big") << 8
    n_cands = [base_n | (top6 | lo) for lo in range(4)]
    n_cands = [x for x in n_cands if x & 1]     # n is odd

    # ---- prime q: header 02 81 81 00 at bytes 665..668, magnitude 669..796 ----
    assert bytes(known[665:669]) == bytes.fromhex("02818100")
    qm_start = 669
    kq = 0
    while qm_start + kq < nbytes and known[qm_start + kq] is not None:
        kq += 1
    hi = int.from_bytes(bytes(known[qm_start:qm_start + kq]), "big")
    u = (128 - kq) * 8                          # unknown low bits of the prime

    e = 0x10001
    c = int.from_bytes(open(ENC, "rb").read(), "big")
    return n_cands, hi, u, e, c


def coppersmith_msb(f_a, N, X, m, t):
    fa = f_a % N

    def fpow(i):
        coeffs = [1]
        for _ in range(i):
            nxt = [0] * (len(coeffs) + 1)
            for j, c in enumerate(coeffs):
                nxt[j] += c * fa
                nxt[j + 1] += c
            coeffs = nxt
        return coeffs

    polys = []
    for i in range(m):
        polys.append([x * pow(N, m - i) for x in fpow(i)])
    fm = fpow(m)
    for i in range(t):
        polys.append([0] * i + fm[:])

    dim = m + t
    B = IntegerMatrix(dim, dim)
    for r, c in enumerate(polys):
        for j in range(dim):
            B[r, j] = (c[j] if j < len(c) else 0) * (X ** j)
    LLL.reduction(B)

    # Many reduced rows vanish at the true root x0 over Z, so the polynomial gcd
    # of a few shortest rows contains the exact factor (x - x0). This is exact
    # (no floating point) -- mpmath root-finding was unstable for large N.
    xs = Symbol("x")
    Ps = []
    for r in range(min(dim, 4)):
        coeffs = [B[r, j] // (X ** j) for j in range(dim)]   # low -> high
        while len(coeffs) > 1 and coeffs[-1] == 0:
            coeffs.pop()
        if len(coeffs) > 1:
            Ps.append(Poly(coeffs[::-1], xs))                # high -> low
    if not Ps:
        return None
    g = Ps[0]
    for P in Ps[1:]:
        g = sgcd(g, P)
        if g.degree() <= 1:
            break
    if g.degree() < 1:
        return None
    for rt in g.all_roots():
        if rt.is_integer:
            x0 = int(rt)
            if abs(x0) <= X:
                d = gcd(f_a + x0, N)
                if 1 < d < N:
                    return x0, d
    return None


def main():
    n_cands, hi, u, e, c = extract()
    print(f"[*] {len(n_cands)} odd n candidate(s); known-high prime bits={128*8-u}, "
          f"unknown low bits u={u}")
    f_a = hi << u
    X = 1 << u
    for m, t in [(8, 8), (10, 10), (12, 12)]:
        print(f"[*] Coppersmith m={m} t={t} dim={m+t}")
        for N in n_cands:
            print(f"    trying n=...{hex(N)[-4:]}", flush=True)
            res = coppersmith_msb(f_a, N, X, m, t)
            if res is None:
                continue
            x0, q = res
            p = N // q
            assert p * q == N
            d = pow(e, -1, (p - 1) * (q - 1))
            flag = long_to_bytes(pow(c, d, N))
            print(f"[+] FACTORED n=...{hex(N)[-4:]}")
            print("[+] p =", hex(p))
            print("[+] q =", hex(q))
            print("[+] FLAG:", flag)
            return
    print("[!] not factored; increase m,t")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Cinderbound — Cyber Apocalypse CTF 2026 (reversing).

Invierte el cifrado de judge() (ver judge_src.py) para recuperar la `syllable`
que hace que judge() devuelva True, y verifica el resultado.
"""

from judge_src import judge

TARGET = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
KEY0 = 90


def solve(target=TARGET, key=KEY0):
    """out[i] = s[i] ^ key_i ^ ((i*13)&255)  =>  s[i] = out[i] ^ key_i ^ ((i*13)&255)

    key_0 = 90 y key_{i+1} = (key_i + s[i]) & 255, así que el keystream se
    reconstruye byte a byte mientras se descifra (no hay que adivinar nada).
    """
    plain = []
    for i, c in enumerate(target):
        b = c ^ key ^ ((i * 13) & 255)
        plain.append(b)
        key = (key + b) & 255
    return bytes(plain).decode()


if __name__ == "__main__":
    syllable = solve()
    assert judge(syllable), "judge() rechaza la sílaba recuperada"
    print(f"syllable = {syllable}")
    print(f"flag     = HTB{{{syllable}}}")

#!/usr/bin/env python3
"""secondhand - HTB Cyber Apocalypse 2026 (reversing).

Dos checks: b_roll (SEÑUELO -> HTB{secondhand_rough_cut_v3}) y threat_level_midnight
(el REAL, "the honest take got cut"). threat_level_midnight es un SPN de 10 rondas
sobre 16 bytes; el input que cifra al target de .rodata es la flag.

Cifrado (verificado byte-a-byte contra el binario vía gdb):
  round keys : splitmix(seed=0x9e3779b97f4a7c15) -> 176 bytes = RK0..RK10
  sbox[i]    = (27*i & 0xff) ^ 0x63
  state = input ^ RK0
  for r in 0..9:
      state ^= RK[r+1]
      state = sbox[state]                       # SubBytes
      state = [state[(5*j)%16] for j]           # ShiftRows (perm (5j)%16)
      k = (r ^ 0xa5) & 0xff                      # roll-mix con feedback aditivo
      for i in 0..15: nb=rol8(state[i]^k,(r+i)&7); state[i]=nb; k=(k+nb)&0xff
  compare state == TARGET
"""
M = (1 << 64) - 1
PRIME = 0x100000001b3
TARGET = bytes.fromhex('7ac4119e386df0528b2fd74019a663ec')

def keystream(n):
    st = 0x9e3779b97f4a7c15; out = []
    for _ in range(n):
        h = ((( st >> 30) ^ st) * PRIME) & M
        o = ((h >> 27) ^ h) & M
        out.append(o & 0xff); st = o
    return out

KS = keystream(176)
RK = [KS[i*16:i*16+16] for i in range(11)]
SBOX = [((27*i) & 0xff) ^ 0x63 for i in range(256)]
INV = [0]*256
for i, v in enumerate(SBOX): INV[v] = i

def rol8(v, n): n &= 7; return ((v << n) | (v >> (8-n))) & 0xff
def ror8(v, n): n &= 7; return ((v >> n) | (v << (8-n))) & 0xff

def enc(inp):
    s = [inp[i] ^ RK[0][i] for i in range(16)]
    for r in range(10):
        s = [s[i] ^ RK[r+1][i] for i in range(16)]
        s = [SBOX[b] for b in s]
        s = [s[(5*j) % 16] for j in range(16)]
        k = (r ^ 0xa5) & 0xff
        for i in range(16):
            nb = rol8(s[i] ^ k, (r+i) & 7); s[i] = nb; k = (k + nb) & 0xff
    return bytes(s)

def dec(ct):
    s = list(ct)
    for r in range(9, -1, -1):
        k0 = (r ^ 0xa5) & 0xff                       # invert roll-mix
        ks = [k0]
        for i in range(16): ks.append((ks[-1] + s[i]) & 0xff)
        s = [ror8(s[i], (r+i) & 7) ^ ks[i] for i in range(16)]
        inv = [0]*16                                  # invert ShiftRows
        for j in range(16): inv[(5*j) % 16] = s[j]
        s = inv
        s = [INV[b] for b in s]                        # invert SubBytes
        s = [s[i] ^ RK[r+1][i] for i in range(16)]     # invert AddRoundKey
    s = [s[i] ^ RK[0][i] for i in range(16)]
    return bytes(s)

flag = dec(TARGET)
assert enc(flag) == TARGET, "decrypt no invierte!"
print("flag (threat_level_midnight):", flag)

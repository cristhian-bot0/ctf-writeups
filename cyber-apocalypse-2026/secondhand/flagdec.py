#!/usr/bin/env python3
"""Descifra la flag real (ruta len==8) dado el seed x (8-byte input como u64 LE)."""
import sys
M = (1 << 64) - 1
CT = bytes.fromhex('55dd4eb0a2b16c88e3a2d4224a1b250e00000000000000')[:21]  # se sobreescribe abajo

def splitmix_stream(seed, nbytes):
    st = seed & M
    out = bytearray()
    while len(out) < nbytes:
        st = (st + 0x9e3779b97f4a7c15) & M
        z = st
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M
        z = z ^ (z >> 31)
        for j in range(8):
            out.append((z >> (8*j)) & 0xff)
    return bytes(out[:nbytes])

def flag_for(x, ct):
    ks = splitmix_stream(x, len(ct))
    return bytes(c ^ k for c, k in zip(ct, ks))

if __name__ == '__main__':
    ct = bytes.fromhex(open('ct.hex').read().strip())
    x = int(sys.argv[1], 0)
    print(f"x = {x:#018x}  bytes={x.to_bytes(8,'little')}")
    print("FLAG:", flag_for(x, ct))

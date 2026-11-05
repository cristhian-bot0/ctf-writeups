#!/usr/bin/env python3
"""
Overstrike (HTB Cyber Apocalypse 2026 - mobile)

The Godot/C# game (assets/.godot/mono/publish/arm64/Overstrike.dll) gates the flag
behind GameState.WorldIsAligned:

    void _Process(double d) { WorldSeal = Mix(CarriedMark); }
    bool WorldIsAligned    => WorldSeal == 0xD9A1BB0CABB52586;

Mix() is a plain splitmix64 finalizer (with the +GOLDEN_GAMMA step), i.e. a bijection
over 64 bits, so the "true seal" can simply be inverted to recover the mark that
produces it. The marks you can actually pick up in-game are worth {1,2,3,5,7}, so the
required CarriedMark is unreachable by playing: you have to forge it.

Archive.OnBodyEntered -> GameState.UnsealRegistry() then decrypts the embedded
SealedRecord blob with a SHA-256 based keystream keyed on CarriedMark:

    key = SHA256(BitConverter.GetBytes(CarriedMark))          # ulong, little endian
    ks  = SHA256(key || BitConverter.GetBytes(i)) for i=0,1..  # int32, little endian
    flag = SealedRecord ^ ks
"""

import hashlib
import struct

M = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
MUL1 = 0xBF58476D1CE4E5B9
MUL2 = 0x94D049BB133111EB

# GameState.WorldIsAligned target constant (IL: ldc.i8 -2764723033133996666)
TRUE_SEAL = 0xD9A1BB0CABB52586

# <PrivateImplementationDetails> 56-byte static array -> GameState.SealedRecord
SEALED_RECORD = bytes.fromhex(
    "0d563344126e440f363dec5e87cad5b6"
    "0401b6b596e4b87e79e0ecdc075299fb"
    "b36800572022033ca6607c32fd1f7cb3"
    "dc9d7873132f600b"
)


def mix(x: int) -> int:
    """GameState.Mix - splitmix64 finalizer."""
    x = (x + GAMMA) & M
    x ^= x >> 30
    x = (x * MUL1) & M
    x ^= x >> 27
    x = (x * MUL2) & M
    x ^= x >> 31
    return x


def _unxorshift(y: int, shift: int) -> int:
    """Invert x ^= x >> shift."""
    x = y
    for _ in range(64 // shift + 1):
        x = y ^ (x >> shift)
    return x & M


def unmix(y: int) -> int:
    """Inverse of Mix - splitmix64 is a bijection."""
    x = _unxorshift(y, 31)
    x = (x * pow(MUL2, -1, 1 << 64)) & M
    x = _unxorshift(x, 27)
    x = (x * pow(MUL1, -1, 1 << 64)) & M
    x = _unxorshift(x, 30)
    return (x - GAMMA) & M


def unseal(mark: int, blob: bytes) -> bytes:
    """GameState.UnsealRegistry."""
    key = hashlib.sha256(struct.pack("<Q", mark)).digest()
    out = bytearray()
    counter = 0
    while len(out) < len(blob):
        block = hashlib.sha256(key + struct.pack("<i", counter)).digest()
        for b in block:
            if len(out) == len(blob):
                break
            out.append(blob[len(out)] ^ b)
        counter += 1
    return bytes(out)


if __name__ == "__main__":
    mark = unmix(TRUE_SEAL)
    assert mix(mark) == TRUE_SEAL, "splitmix64 inversion failed"

    print(f"World seal (target) : 0x{TRUE_SEAL:016X}")
    print(f"Forged CarriedMark  : 0x{mark:016X}  ({mark})")
    print(f"Flag                : {unseal(mark, SEALED_RECORD).decode()}")

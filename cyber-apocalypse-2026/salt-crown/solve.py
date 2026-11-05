#!/usr/bin/env python3
r"""
SaltCrown (HTB Cyber Apocalypse 2026 - mobile)

Godot 4 + Mono (C#) game. The flag is minted in Director.Forge(), which only runs
once the counterfeit StrikePlate FRACTURES ("counterfeits fail under repetition"):

    // SaltCrown.Director
    void OnStruck(force):  _plate.Endure(force, SeatsBiting)   // fatigue += ...
    void OnFractured():    Forge(); ...
    void Forge():
        uint state = 0x811C9DC5;                               // FNV-1a offset basis
        foreach (seat in _seats.Where(s => s.Bites)            // only biting shards
                               .OrderBy(s => s.ChokeIndex))    // sorted by choke
            state = SaltCrownSpec.Measure(state, seat.ChokeIndex,
                                          Tolerances.PhaseBucket(seat.ChokeIndex));
        Crown = SaltCrownSpec.Unseal(state);                   // <- the flag

    Measure(s,a,b) = Mix(Mix(s,a), b)
    Mix(a,b): a^=b; a*=0x01000193; a^=a>>15; a*=0x85EBCA77; a^=a>>13   (uint32)

    Unseal(seed): state=seed; for i in 0..23: state=Mix(state,i);
                  out[i] = SealedSpec[i] ^ (state>>24);  return "HTB{"+ascii(out)+"}"

The valid choke buckets come from Tolerances.SeatsAtChoke: bucket i in 0..7 with
ChokeZ(i)=14-6*i and HalfWidthAt(z)<=8.1 (a "choke"). Solving the geometry, only
i in {3,4,5,6,7} are chokes -> exactly the "/5" shards the HUD counts. The winning
run seats one biting shard at each, so the fold runs over ChokeIndex = [3,4,5,6,7].

Tolerances.PhaseBucket(c) = WearLattice.AdmitBucket(c) = native AshVault.admit_bucket(
rubbing, c), implemented in libashvault (GDExtension). It reverse-engineers to a pure
function of the 256-byte res://rubbings/ashvault.dat and the bucket, returning one byte.
Reimplemented below from the x86_64 .so disassembly (offset 0x1dc30).

No emulator, no APK patching: recover the fracture seed offline and unseal.
"""
import struct

M = 0xFFFFFFFF
FNV_PRIME = 0x01000193
FNV_BASIS = 0x811C9DC5
MUL2 = 0x85EBCA77          # -2048144777 as uint32

# SaltCrown.Mechanism.SaltCrownSpec.SealedSpec (24 bytes, FieldRVA; name == sha256(blob))
SEALED_SPEC = bytes.fromhex("75c9ab6b9a53cfbf1fe97e4a939425e029cf87a9c280dedc")

def mix(a, b):
    a = (a ^ b) & M
    a = (a * FNV_PRIME) & M
    a ^= a >> 15
    a = (a * MUL2) & M
    a ^= a >> 13
    return a & M


def measure(s, a, b):
    return mix(mix(s, a), b)


def rol(x, r):
    x &= M
    return ((x << r) | (x >> (32 - r))) & M


def build_rubbing_table(rub):
    """Port of libashvault admit_bucket, table build (offset 0x1dc30).

    Returns the final 64-entry uint32 table after the 4096-round diffusion.
    Independent of the bucket argument, so compute it once.
    """
    n = len(rub)
    # --- phase 1: T[esi] = salted FNV-ish hash of the whole rubbing ---
    T = [0] * 64
    for salt in range(64):
        h = FNV_BASIS
        i = 0
        end = n & ~1
        while i < end:                     # pairs of bytes
            r = ((rub[i] + salt) & M) ^ h   # b0
            h = (r * FNV_PRIME) & M
            r = ((rub[i + 1] + salt) & M) ^ h  # b1
            h = ((h >> 11) ^ r) & M
            r = (h * FNV_PRIME) & M
            h = ((r >> 11) ^ r) & M
            i += 2
        if n & 1:                          # odd tail (n=256 here -> skipped)
            r = ((rub[i] + salt) & M) ^ h
            r = (r * FNV_PRIME) & M
            h = ((r >> 11) ^ r) & M
        T[salt] = h & M

    # --- phase 2: 4096 diffusion rounds over the 64-entry table ---
    for k in range(0x1000):
        rc = (k * 0x9E3779B9) & M           # r12d: 0, GAMMA, 2*GAMMA, ...
        new = [0] * 64
        for idx in range(64):
            a = T[(idx - 1) & 63]
            b = T[(idx + 1) & 63]
            c = T[idx]
            a = rol(a, 7)
            b = rol(b, 27)
            b ^= a
            b ^= c
            d = (b * MUL2) & M              # 0x85ebca77
            d = (d + rc) & M
            d = (d + idx) & M
            e = d
            e = (e >> 15) ^ d
            c = rol(c, 13)
            d = (e * 0xC2B2AE3D) & M
            c ^= d
            v = c
            v = (v >> 16) ^ c
            new[idx] = v & M
        T = new
    return T


def admit_bucket(table, bucket):
    """Final combine (offset 0x1dd9b): one byte out of the diffused table."""
    ia = (7 * bucket + 3) & 63
    ib = (23 * bucket + 41) & 63
    v = rol(table[ib], 11) ^ table[ia]
    v &= M
    v = ((v >> 5) ^ (v >> 13)) & 0xFF
    return v


def unseal(seed):
    out = bytearray(len(SEALED_SPEC))
    state = seed & M
    for i in range(len(SEALED_SPEC)):
        state = mix(state, i)
        out[i] = SEALED_SPEC[i] ^ ((state >> 24) & 0xFF)
    return "HTB{" + out.decode("ascii", "replace") + "}"


def load_rubbing():
    import os
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "native", "ashvault.dat")
    with open(p, "rb") as f:
        return f.read()


if __name__ == "__main__":
    rub = load_rubbing()
    assert len(rub) == 256, f"unexpected rubbing size {len(rub)}"
    table = build_rubbing_table(rub)

    chokes = [3, 4, 5, 6, 7]                 # the five valid choke buckets, OrderBy(ChokeIndex)
    seed = FNV_BASIS
    print("Fold over biting shards (ChokeIndex -> PhaseBucket):")
    for c in chokes:
        pb = admit_bucket(table, c)
        seed = measure(seed, c, pb)
        print(f"  choke={c}  phaseBucket={pb:3d} (0x{pb:02x})  state=0x{seed:08x}")

    print(f"\nFracture seed : 0x{seed:08x}")
    print(f"Flag          : {unseal(seed)}")

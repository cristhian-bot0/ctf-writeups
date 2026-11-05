# secondhand

**Cyber Apocalypse CTF 2026 — Reversing**

> This is a rough cut. What is playing is the version we agreed to air, not the version that happened.
> The honest take got cut. It is still in here, it is just not the one running.

## TL;DR

A Linux x64 binary with **three input-length branches**. `len==28` and `len==16` are decoys ("the rough
cut"). The real flag lives in the `len==8` path, gated by a self-modifying check that only passes when a
specific 8-byte key makes `c50(x)` equal a magic constant. That key seeds a **splitmix64** stream that
decrypts the flag out of `.data`.

## The three cuts

| input length | function | result |
|---|---|---|
| 28 | `b_roll` | decoy — `HTB{secondhand_rough_cut_v3}` |
| 16 | `threat_level_midnight` | decoy — a 10-round SPN whose target decrypts to binary |
| 8 | `0x401a40` | **the real flag** |

### b_roll (decoy)
`target[i] = rol((in[i] + 0x1f*i) & 0xff, 3) ^ key`, with a rolling `key = 0x5a + Σ in[..i]`. Trivially
invertible → `HTB{secondhand_rough_cut_v3}`.

### threat_level_midnight (decoy)
A neat 10-round SPN over 16 bytes: affine S-box `(27*i)^0x63`, `splitmix` round keys, a `(5*j)%16`
ShiftRows and an additive-feedback roll-mix layer. I reconstructed it byte-exact by patching the
anti-debug (`ptrace`/`TracerPid`) and using GDB as an encryption oracle — but decrypting its target gives
binary garbage. Another cut left on the floor.

## The honest take (len == 8)

The 8 input bytes are read as a little-endian `u64` seed. The gate is `c50(x) == d90(x)`:

- **`c50(x)`** is decrypted at runtime into an `mmap`'d page; it computes
  `~( rol(x ^ 0xa5a5a5a5deadbeef, 17) * 0x100000001b3 )`.
- **`d90`** is a polymorphic trampoline that jumps to `0x401dd0 + ((len & 0x1f) ^ 0xe)`. For `len == 8`
  that lands **mid-instruction** at `0x401dd6` — *"it only feeds clean if you start the page from the inner
  crease, not from the top."* There, `rax` already holds `c50(x)` and the code does
  `cmp rax, 0xb8491337c0debabe ; je → ret`. So if **`c50(x) == 0xb8491337c0debabe`**, `d90` returns
  `c50(x)` and the check passes **deterministically**.

Since `c50` is invertible:

```python
x = K1 ^ ror( (~0xb8491337c0debabe) * inv(0x100000001b3, 2**64), 17)
# = 0x28382f8d1780680f  ->  bytes 0f 68 80 17 8d 2f 38 28
```

With that seed the check passes; the program prints `H4D5_UP_Y0U_M4D3_IT` and then XOR-decrypts 21 bytes
from `.data` (`0x402520`) with a **splitmix64** keystream seeded by `x`:

```python
flag = data_0x402520[:21] ^ splitmix64_stream(x)
```

Verified against the untouched binary:

```
$ printf '\x0f\x68\x80\x17\x8d\x2f\x38\x28\n' | ./secondhand
H4D5_UP_Y0U_M4D3_IT
HTB{WHY_S00_345Y_H0N}
```

## Flag

```
HTB{WHY_S00_345Y_H0N}
```

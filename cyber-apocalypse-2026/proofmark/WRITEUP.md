# Proofmark — HTB Cyber Apocalypse 2026 (mobile)

**Flag:** `HTB{p3rf3ct_f4c3_tru3_sp1n3}`

> *"Vaultrune's assay decides which seals are inherited and which were cut from a Signet
> shard... Elric walks in with a ring he filed himself. One strike, no second."*

The anvil wants two things: a ring whose **face** matches the Signet exactly, and a
hallmark that proves the **spine** (the stress path) is genuine. The game can give you
neither — so you compute both offline.

## 1. Recon

`proofmark.apk` (57 MB) is a Godot 4 game, this time **GDScript** instead of C#, plus a
small custom **GDExtension**:

```bash
unzip -l proofmark.apk | grep -E 'assets/|libproofmark'
#   9800  lib/arm64-v8a/libproofmark.arm64.so
#  10376  lib/x86_64/libproofmark.x86_64.so
#    363  assets/proofmark.gdextension
#    561  assets/scripts/Anvil.gdc   ... (10 compiled scripts)
```

10 KB of stripped native code next to 76 MB of engine is where the challenge lives.

## 2. Reading the `.gdc` scripts

Godot 4.5 exports GDScript as a **binary token buffer**, not as encrypted data:

```
00000000: 4744 5343 6500 0000 1010 0000 28b5 2ffd   GDSCe.......(./.
          ^magic     ^ver=101  ^decompressed size  ^zstd frame
```

So it's `GDSC` + version + size + a zstd frame. Strip 12 bytes and inflate:

```bash
tail -c +13 GameState.gdc > x.zst && zstd -d x.zst -o GameState.bin
```

The decompressed buffer starts with four counts (identifiers, constants, token lines,
tokens), then the identifier table — where every character is a 32-bit word **XORed with
`0xB6B6B6B6`** (Godot's cheap obfuscation), then the constants encoded as Variants.
Dumping just those two tables (see `gdc_dump.py`) is enough to reconstruct the design:

```
GameState : wards:PackedInt32Array, bite:int, hallmark, _resync_hallmark -> ForgeClient.reseal(snapshot)
WardCutter: wards[ward_index] += dir, clampi(..., 0, 24)
ForgeClient: enum Verdict { REJECT_STATE, REJECT_TOKEN, ACCEPTED }; native class "Proofmark"
HUD       : "Ring  wards %d / %d / %d     bite %d"
            'PERFECT FACE. WRONG SPINE.'  /  'The cuts are flawless. The stress path is not.'
            'THE ASSAY CERTIFIES'         /  "Inherited. It cannot tell your shard..."
```

So the whole game is: file three wards (each 0..24), get a `hallmark` from the native
`reseal()`, then `strike()` once → `submit()` → verdict + certificate.

## 3. The native library

`libproofmark.x86_64.so` exports only `proofmark_library_init`, registers the class
`Proofmark` with methods `reseal` / `submit` and a `certificate` property. Three code
blocks matter:

### `0x1c10` — `reseal(w0,w1,w2,bite)`

Packs the four ints little-endian into 16 bytes and interprets a **95-byte bytecode
program** that is assembled onto the stack from five shuffled `.rodata` chunks. The
dispatcher is a `cmp`/jump-table interpreter with registers at `[rsp-0x20]`, a 16-bit
call stack, and two jump tables at `.rodata 0x560` / `0x600`. Recovering the 16 opcodes
from those tables (`vm_disasm.py`) gives a completely readable program:

```
0000: movi r0, 0x53437277        ; seed
0006: movi r1, 0
000c: len  r2
000e: jb   r1, r2, 0x0016        ; for each input byte
0013: jmp  0x002d
0016: ldb  r3, [r1]
0019: xor  r0, r3
001c: rol  r0, 5
001f: add  r0, 0x9e3779b9
0025: call 0x0037                ; fmix32
0028: inc  r1
002a: jmp  0x000e
002d: xori r0, 0xd1b54a33
0033: call 0x0037
0036: halt                       ; -> r0
0037: mov r3,r0 / shr r3,16 / xor r0,r3 / mul r0,0x85ebca6b
      mov r3,r0 / shr r3,13 / xor r0,r3 / mul r0,0xc2b2ae35
      mov r3,r0 / shr r3,16 / xor r0,r3 / ret          ; murmur3 fmix32
```

**But** the exit path is guarded (at `0x2054`):

```c
if (len != 16) goto scramble;
if (state[0] > 24 || state[1] < 0 || state[1] > 24 || state[2] < 0 || state[2] > 24) goto scramble;
if (state[3] != state[0] + 2*state[1] + 3*state[2]) goto scramble;   // the "stress path"
return r0;
scramble:
return fmix32(r0 ^ 0xa5a5a5a5) ^ 0x0badf00d;
```

That is the whole trick: **the VM always computes the right hallmark, but only hands it
over for a ring that is physically legal.**

### `0x20d0` — the assay proper

```c
int certify(const uint8_t *mark, size_t len, uint32_t hallmark, char *out, int outlen) {
    if (len != 16 || memcmp(mark, RODATA_0x530, 16)) return 0;   // REJECT_STATE
    uint32_t x = hallmark;
    for (int i = 0; i < 1200000; i++) x = fmix32(x + 0xC2B2AE35);   // key stretching
    uint32_t s = fmix32(x ^ 0x85EBCA6B);
    for (int i = 0; i < 28; i++) {                                  // keystream
        s += 0xC2B2AE35;
        uint32_t t = (s ^ (s >> 16)) * 0x85EBCA6B;
        uint32_t u = (t ^ (t >> 13)) * 0xC2B2AE35;
        s = u ^ (u >> 16);
        out[i] = RODATA_0x6A0[i] ^ (uint8_t)(u >> 24);
    }
    if (memcmp(out, "HTB{", 4)) return 1;                        // REJECT_TOKEN
    return 2;                                                    // ACCEPTED
}
```

The `HTB{` test at `0x21ce` (`cmp edx, 0x7b425448`) is what turns "wrong hallmark" into
verdict 1 — the plaintext simply isn't a flag.

### The demanded ring, at `.rodata 0x530`

```
00000530: 5300 0000 4300 0000 3700 0000 ce01 0000
```

→ wards **83 / 67 / 55**, bite **462**.

Two impossibilities at once:

* the wards are clamped to `0..24` in `WardCutter`, so 83/67/55 can never be filed in-game;
* `83 + 2·67 + 3·55 = 382 ≠ 462`, so that state fails the stress-path check — even if you
  could set it, `reseal()` would hand back a scrambled token → **PERFECT FACE. WRONG SPINE.**

## 4. Forging the proofmark

Run the VM yourself and ignore the guard. Two independent ways, both in this folder:

**(a) Dynamic — `harness.c`.** Manually map the Android `.so` into a Linux process (three
`PT_LOAD` segments, patch the `memcpy` GOT slot) and call the two routines directly. With
`-p` it also overwrites the guard at `0x2054` with `jmp 0x20b0` so the VM returns `r0`
unconditionally:

```
$ ./harness extracted/lib/x86_64/libproofmark.x86_64.so
[*] target mark : wards 83 / 67 / 55   bite 462
[*] hallmark    : 0xdc457bf0        <- what the game would give you
[*] verdict     : 1 (REJECT_TOKEN)

$ ./harness extracted/lib/x86_64/libproofmark.x86_64.so -p
[*] validator patched out (VM returns r0 unconditionally)
[*] hallmark    : 0x71d3a101
[*] verdict     : 2 (ACCEPTED)
[+] certificate : HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

**(b) Static — `solve.py`.** Reimplement the VM, the stretching and the keystream in pure
Python; no device, no emulator, no native execution:

```
$ python3 solve.py
target mark   : wards 83 / 67 / 55   bite 462
stress path   : 83 + 2*67 + 3*55 = 382  -> declared 462 (INVALID -> reseal() garbles it)
forged hallmark: 0x71d3a101 (1909694721)
certificate    : HTB{p3rf3ct_f4c3_tru3_sp1n3}
```

Both agree: the honest hallmark for that state is `0xdc457bf0`, the true one is
`0x71d3a101`.

## Takeaways

* Godot `.gdc` files are **not** encrypted by default: `GDSC` + zstd + a token buffer whose
  identifiers are XOR `0xB6B6B6B6`. Dumping the identifier and constant tables alone
  usually reconstructs the game's design.
* A stripped 10 KB GDExtension next to a 76 MB engine is always the payload.
* When a binary hides logic in a bytecode VM, the jump tables in `.rodata` hand you the
  opcode map: index arithmetic (`table[op - base]`) tells you exactly which byte means what.
* Brute force was off the table by design (2³² tokens × 1.2 M stretching rounds), so the
  VM had to be understood — but "map the `.so` and call the function" is a perfectly good
  shortcut to understanding it, and a good cross-check for the reimplementation.

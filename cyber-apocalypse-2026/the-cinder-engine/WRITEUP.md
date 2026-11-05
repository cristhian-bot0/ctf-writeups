# The Cinder Engine

**Cyber Apocalypse CTF 2026 — Reversing**

> Before the white fire, exactly one Cinderbound scribe understood how the Cinder Engine thought…
> He kept the opcode map in his head and nowhere else. The machine still runs. Nobody alive can tell you why.

## TL;DR

The binary is a custom **AArch64 bytecode VM** whose opcode map must be reverse-engineered. The bytecode
it runs is an **8-round substitution–permutation cipher** on a 32-byte block. Recover the S-box, round
keys and linear layer from the binary, **decrypt the embedded target**, and the resulting plaintext feeds
back through the VM to print the flag.

## Recon

```
$ file cinder
cinder: ELF 64-bit LSB executable, ARM aarch64, PIE, dynamically linked, stripped
```

No ARM64 disassembler was available, so I installed `capstone` in a venv and wrote a small linear
disassembler (`disasm_cinder.py`). Interesting strings: `bad opcode`, and a large blob in `.rodata`.

## The VM

`main` reads input, then runs an interpreter loop over a bytecode program stored in `.rodata` at
`0xe80` (size `0x131e`). Each instruction is 4 bytes:

| field | meaning |
|-------|---------|
| `byte3` | opcode |
| `byte2` | high nibble = `rd`, low nibble = `rs1` |
| `byte0` low nibble | `rs2` |
| `byte0 \| byte1<<8` | 16-bit immediate |

There are 16 registers at `0x13018` and a data-memory region at `0x13058`. Decoding the dispatch table
gives 23 opcodes:

```
0x00 HALT  0x11 MOV   0x3a SET(imm)
0x52 XOR   0x53 AND   0x54 OR   0x6b MUL  0x7c ADD  0x7d SUB  0x80 ADDI  0x90 CMP
0x29 ROL   0x2a ROR   0x2b SHL  0x2c SHR
0xa0 JMP   0xa1 JT    0xa2 JF
0xc4 LOADB 0xc5 STOREB 0xc6 LUT(rodata) 0xe0 INPUT 0xe1 OUT
```

## The bytecode = a block cipher

Disassembling the bytecode (`vmdis.py`) reveals a clean SPN over a 32-byte block:

```python
s = input ^ K0
for r in 1..8:
    s = SBOX[s]        # SubBytes,  SBOX[i] = (27*i) ^ 0x63
    s = Linear(s)      # 32×32 GF(2) linear diffusion (byte-wise XOR mixing)
    s ^= Kr            # AddRoundKey
if s == TARGET:        # 32-byte target in .rodata
    OUT  input[0:26] ^ OUTKEY     # <- prints the flag
```

All constants live in the bytecode region: **SBOX** `0x10c4`, **round keys** `0x11c4` (9×32), **TARGET**
`0x12e4`, **OUTKEY** `0x1304` — filling `.rodata` exactly to its end.

## Solve

The cipher is bijective, so instead of brute-forcing the input we **decrypt** the target:

- invert `SBOX` (affine, `27` is odd ⇒ invertible mod 256),
- extract the linear layer's 32×32 GF(2) matrix by parsing the XOR-reduction bytecode, then invert it
  with Gauss–Jordan,
- run the rounds backwards applying the inverse steps and round keys.

That yields the unique 32-byte input; `flag = input[0:26] ^ OUTKEY`. The solver (`solve.py`) also
**re-runs the recovered input through a full VM emulator** (`emu.py`) to confirm the engine prints:

```
HTB{c1nd3r_3ng1n3_unw0und}
```

## Flag

```
HTB{c1nd3r_3ng1n3_unw0und}
```

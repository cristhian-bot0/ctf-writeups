#!/usr/bin/env python3
"""
Proofmark (HTB Cyber Apocalypse 2026 - mobile)

Everything lives in the GDExtension lib/*/libproofmark.*.so (~10 KB, stripped).
It exposes a Godot class `Proofmark` with two methods:

  reseal(w0, w1, w2, bite) -> int
      Packs the four ints little-endian into a 16-byte "ring state" and runs an
      embedded 95-byte bytecode VM over it (murmur3 fmix32 rounds, seed
      0x53437277).  BUT before returning it validates the state:
          0 <= w_i <= 24   and   bite == w0 + 2*w1 + 3*w2
      If that "stress path" fails, the real result is discarded and a scrambled
      value (fmix32(r0 ^ 0xa5a5a5a5) ^ 0x0badf00d) is returned instead.

  submit(w0, w1, w2, bite, hallmark) -> Verdict, sets .certificate
      0 REJECT_STATE : the 16 bytes are not the Signet's own ring
      1 REJECT_TOKEN : hallmark wrong (decrypted blob doesn't start with "HTB{")
      2 ACCEPTED     : .certificate = decrypted 28-byte blob

The mark the anvil demands is hardcoded at .rodata 0x530: wards 83/67/55, bite 462.
Wards are clamped to 0..24 in-game, and 83 + 2*67 + 3*55 = 382 != 462, so that ring
can neither be filed in-game nor sealed by the game's own reseal() - the validator
garbles the token ("PERFECT FACE. WRONG SPINE.").

So we run the VM ourselves, without the validator, and forge the token.

This script reimplements all of it in pure Python: no device, no emulator.
"""

import struct

SO = "extracted/lib/x86_64/libproofmark.x86_64.so"
M = 0xFFFFFFFF
C1, C2 = 0x85EBCA6B, 0xC2B2AE35


# ---------------------------------------------------------------- the assay VM
# opcode table recovered from the two jump tables at .rodata 0x560 / 0x600
def run_vm(prog: bytes, data: bytes) -> int:
    u32 = lambda p: struct.unpack_from("<I", prog, p)[0]
    u16 = lambda p: prog[p] | (prog[p + 1] << 8)
    reg, stack, pc = [0] * 8, [], 0
    while True:
        op = prog[pc]
        if op == 0x02:                                            # mul  rd, imm32
            reg[prog[pc + 1]] = (reg[prog[pc + 1]] * u32(pc + 2)) & M; pc += 6
        elif op == 0x11:                                          # len  rd
            reg[prog[pc + 1]] = len(data); pc += 2
        elif op == 0x1A:                                          # call addr16
            if len(stack) <= 0x1F:
                stack.append(pc + 3)
            pc = u16(pc + 1)
        elif op == 0x29:                                          # mov  rd, rs
            reg[prog[pc + 1]] = reg[prog[pc + 2]]; pc += 3
        elif op == 0x3C:                                          # halt
            return reg[0]
        elif op == 0x4D:                                          # rol  rd, imm8
            v, c = reg[prog[pc + 1]], prog[pc + 2] & 31
            reg[prog[pc + 1]] = ((v << c) | (v >> (32 - c))) & M if c else v; pc += 3
        elif op == 0x5E:                                          # ldb  rd, [rs]
            i = reg[prog[pc + 2]]
            reg[prog[pc + 1]] = data[i] if i < len(data) else 0; pc += 3
        elif op == 0x68:                                          # jmp  addr16
            pc = u16(pc + 1)
        elif op == 0x7A:                                          # movi rd, imm32
            reg[prog[pc + 1]] = u32(pc + 2); pc += 6
        elif op == 0x84:                                          # xor  rd, rs
            reg[prog[pc + 1]] ^= reg[prog[pc + 2]]; pc += 3
        elif op == 0x9F:                                          # xori rd, imm32
            reg[prog[pc + 1]] ^= u32(pc + 2); pc += 6
        elif op == 0xB6:                                          # shr  rd, imm8
            reg[prog[pc + 1]] >>= prog[pc + 2]; pc += 3
        elif op == 0xC1:                                          # add  rd, imm32
            reg[prog[pc + 1]] = (reg[prog[pc + 1]] + u32(pc + 2)) & M; pc += 6
        elif op == 0xD3:                                          # jb   ra, rb, addr16
            pc = u16(pc + 3) if reg[prog[pc + 1]] < reg[prog[pc + 2]] else pc + 5
        elif op == 0xE7:                                          # inc  rd
            reg[prog[pc + 1]] = (reg[prog[pc + 1]] + 1) & M; pc += 2
        elif op == 0xF5:                                          # ret
            if not stack:
                return reg[0]
            pc = stack.pop()
        else:
            raise ValueError("unknown opcode %02x at %04x" % (op, pc))


def load_program(so: bytes) -> bytes:
    """The VM program is spread over five 16-byte .rodata chunks plus 15 immediate
    bytes; the loader at 0x1c10 copies them onto the stack in this order."""
    return (so[0x550:0x560] + so[0x500:0x510] + so[0x540:0x550]
            + so[0x520:0x530] + so[0x510:0x520]
            + bytes.fromhex("0035aeb2c2290300")   # movabs [rsp-0x30]
            + bytes.fromhex("b6031084")           # mov dword [rsp-0x28]
            + bytes.fromhex("0003")               # mov word  [rsp-0x24]
            + b"\xf5")                            # mov byte  [rsp-0x22]


# --------------------------------------------------------- certificate unsealing
def fmix32(x: int) -> int:
    x ^= x >> 16
    x = (x * C1) & M
    x ^= x >> 13
    x = (x * C2) & M
    x ^= x >> 16
    return x


def unseal(hallmark: int, blob: bytes) -> bytes:
    x = hallmark
    for _ in range(0x124F80):            # 1,200,000 stretching rounds
        x = fmix32((x + C2) & M)
    state = fmix32(x ^ C1)

    out = bytearray()
    for i in range(len(blob)):
        state = (state + C2) & M
        t = ((state ^ (state >> 16)) * C1) & M
        u = ((t ^ (t >> 13)) * C2) & M
        state = u ^ (u >> 16)
        out.append(blob[i] ^ ((u >> 24) & 0xFF))
    return bytes(out)


if __name__ == "__main__":
    so = open(SO, "rb").read()

    prog = load_program(so)
    mark = so[0x530:0x540]                       # the Signet's own ring state
    blob = so[0x6A0:0x6A0 + 28]                  # sealed certificate

    w = struct.unpack("<4i", mark)
    print("target mark   : wards %d / %d / %d   bite %d" % w)
    print("stress path   : %d + 2*%d + 3*%d = %d  -> declared %d (%s)"
          % (w[0], w[1], w[2], w[0] + 2 * w[1] + 3 * w[2], w[3],
             "valid" if w[0] + 2 * w[1] + 3 * w[2] == w[3] else "INVALID -> reseal() garbles it"))

    hallmark = run_vm(prog, mark)
    print("forged hallmark: 0x%08x (%d)" % (hallmark, hallmark))
    print("certificate    : %s" % unseal(hallmark, blob).decode())

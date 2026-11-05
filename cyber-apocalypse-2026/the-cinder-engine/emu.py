#!/usr/bin/env python3
"""Emulador de la Cinder Engine (VM del reto the_cinder_engine, ARM64).
Opcode map reverseado del intérprete (.text). Programa (bytecode) en rodata @0xe80.
"""
import sys

data = open('cinder', 'rb').read()
ROD_OFF = 0xe68            # file offset de .rodata (vaddr 0xe68)
PROG_VADDR = 0xe80
PROG_SIZE = 0x131e
# rodata cargada tal cual; el LUT (0xc6) usa base 0xe80 y mod 0x131e
rod = data                # indexamos por vaddr (file offset == vaddr para <0x13000)
PROG = data[PROG_VADDR:PROG_VADDR + PROG_SIZE]

MASK = 0xffffffff

def rol(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & MASK if n else v & MASK
def ror(v, n):
    n &= 31
    return ((v >> n) | (v << (32 - n))) & MASK if n else v & MASK

def run(inp, trace=False, maxsteps=5_000_000):
    reg = [0] * 16
    dmem = bytearray(0x10000)      # data memory (STOREB/LOADB base 0x13058)
    pc = 0                         # offset en PROG
    flag = 0
    inpos = 0
    out = bytearray()
    steps = 0
    while steps < maxsteps:
        steps += 1
        b0 = PROG[pc]; b1 = PROG[pc + 1]; b2 = PROG[pc + 2]; b3 = PROG[pc + 3]
        op = b3
        rd = (b2 >> 4) & 0xf
        rs1 = b2 & 0xf
        rs2 = b0 & 0xf
        imm = b0 | (b1 << 8)
        simm = imm - 0x10000 if imm & 0x8000 else imm
        word = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        sh = word & 0x1f
        pc += 4
        if trace:
            print(f"{pc-4:04x}: op={op:02x} rd={rd} rs1={rs1} rs2={rs2} imm={imm:#x} | regs={[hex(r) for r in reg]} flag={flag}")
        if op == 0x00:            # HALT
            break
        elif op == 0x11:          # MOV
            reg[rd] = reg[rs1]
        elif op == 0x3a:          # SET rd=imm
            reg[rd] = imm
        elif op == 0x52:          # XOR
            reg[rd] = reg[rs1] ^ reg[rs2]; flag = 1 if reg[rs1] == reg[rs2] else 0
        elif op == 0x53:          # AND
            reg[rd] = reg[rs1] & reg[rs2]; flag = 1 if reg[rd] == 0 else 0
        elif op == 0x54:          # OR
            reg[rd] = reg[rs1] | reg[rs2]; flag = 1 if reg[rd] == 0 else 0
        elif op == 0x6b:          # MUL
            reg[rd] = (reg[rs1] * reg[rs2]) & MASK; flag = 1 if reg[rd] == 0 else 0
        elif op == 0x7c:          # ADD
            reg[rd] = (reg[rs1] + reg[rs2]) & MASK; flag = 1 if reg[rd] == 0 else 0
        elif op == 0x7d:          # SUB
            reg[rd] = (reg[rs1] - reg[rs2]) & MASK; flag = 1 if reg[rs1] == reg[rs2] else 0
        elif op == 0x80:          # ADDI
            reg[rd] = (reg[rs1] + imm) & MASK; flag = 1 if reg[rd] == 0 else 0
        elif op == 0x90:          # CMP
            flag = 1 if reg[rs1] == reg[rs2] else 0
        elif op == 0x29:          # ROL
            reg[rd] = rol(reg[rs1], sh)
        elif op == 0x2a:          # ROR
            reg[rd] = ror(reg[rs1], sh)
        elif op == 0x2b:          # SHL
            reg[rd] = (reg[rs1] << sh) & MASK
        elif op == 0x2c:          # SHR
            reg[rd] = (reg[rs1] & MASK) >> sh
        elif op == 0xa0:          # JMP
            pc += simm
        elif op == 0xa1:          # JT (flag!=0)
            if flag: pc += simm
        elif op == 0xa2:          # JF (flag==0)
            if not flag: pc += simm
        elif op == 0xc4:          # LOADB rd = dmem[(imm+reg[rs1])&0xffff]
            reg[rd] = dmem[(imm + reg[rs1]) & 0xffff]
        elif op == 0xc5:          # STOREB dmem[(imm+reg[rs1])&0xffff] = reg[rd]&0xff
            dmem[(imm + reg[rs1]) & 0xffff] = reg[rd] & 0xff
        elif op == 0xc6:          # LUT rd = rod[0xe80 + (imm+reg[rs1]) % 0x131e]
            reg[rd] = rod[PROG_VADDR + ((imm + reg[rs1]) % PROG_SIZE)]
        elif op == 0xe0:          # INPUT
            if inpos < len(inp):
                reg[rd] = inp[inpos]; inpos += 1; flag = 0
            else:
                reg[rd] = 0; flag = 1
        elif op == 0xe1:          # OUT putc(reg[rs1]&0xff)
            out.append(reg[rs1] & 0xff)
        else:
            out += b"bad opcode\n"; break
    return bytes(out)


if __name__ == '__main__':
    test = sys.argv[1].encode() if len(sys.argv) > 1 else b"test_vow\n"
    print("input:", test)
    print("output:", run(test))

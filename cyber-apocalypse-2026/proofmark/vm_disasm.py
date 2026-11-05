import struct, sys

so = open('extracted/lib/x86_64/libproofmark.x86_64.so','rb').read()
r = lambda a,n: so[a:a+n]
prog = (r(0x550,0x10) + r(0x500,0x10) + r(0x540,0x10) + r(0x520,0x10) + r(0x510,0x10)
        + bytes.fromhex('0035aeb2c2290300') + bytes.fromhex('b6031084') + bytes.fromhex('0003') + b'\xf5')
assert len(prog)==0x5f, len(prog)
print("program (%d bytes): %s\n" % (len(prog), prog.hex()))

u32 = lambda p: struct.unpack_from('<I', prog, p)[0]
u16 = lambda p: prog[p] | (prog[p+1] << 8)

NAMES = {}
def disasm():
    pc = 0
    while pc < len(prog):
        op = prog[pc]
        if op == 0x02:   s, n = "mul   r%d, 0x%08x" % (prog[pc+1], u32(pc+2)), 6
        elif op == 0x11: s, n = "len   r%d" % prog[pc+1], 2
        elif op == 0x1a: s, n = "call  0x%04x" % u16(pc+1), 3
        elif op == 0x29: s, n = "mov   r%d, r%d" % (prog[pc+1], prog[pc+2]), 3
        elif op == 0x3c: s, n = "halt", 1
        elif op == 0x4d: s, n = "rol   r%d, %d" % (prog[pc+1], prog[pc+2]), 3
        elif op == 0x5e: s, n = "ldb   r%d, [r%d]" % (prog[pc+1], prog[pc+2]), 3
        elif op == 0x68: s, n = "jmp   0x%04x" % u16(pc+1), 3
        elif op == 0x7a: s, n = "movi  r%d, 0x%08x" % (prog[pc+1], u32(pc+2)), 6
        elif op == 0x84: s, n = "xor   r%d, r%d" % (prog[pc+1], prog[pc+2]), 3
        elif op == 0x9f: s, n = "xori  r%d, 0x%08x" % (prog[pc+1], u32(pc+2)), 6
        elif op == 0xb6: s, n = "shr   r%d, %d" % (prog[pc+1], prog[pc+2]), 3
        elif op == 0xc1: s, n = "add   r%d, 0x%08x" % (prog[pc+1], u32(pc+2)), 6
        elif op == 0xd3: s, n = "jb    r%d, r%d, 0x%04x" % (prog[pc+1], prog[pc+2], u16(pc+3)), 5
        elif op == 0xe7: s, n = "inc   r%d" % prog[pc+1], 2
        elif op == 0xf5: s, n = "ret", 1
        else:            s, n = "??? %02x" % op, 1
        print("  %04x: %-28s ; %s" % (pc, s, prog[pc:pc+n].hex()))
        pc += n

disasm()

M = 0xffffffff
def run(data, trace=False):
    reg = [0]*24
    stack = []
    pc = 0
    steps = 0
    while steps < 100000:
        steps += 1
        op = prog[pc]
        if   op == 0x02: reg[prog[pc+1]] = (reg[prog[pc+1]] * u32(pc+2)) & M; pc += 6
        elif op == 0x11: reg[prog[pc+1]] = len(data); pc += 2
        elif op == 0x1a:
            if len(stack) <= 0x1f: stack.append(pc+3)
            pc = u16(pc+1)
        elif op == 0x29: reg[prog[pc+1]] = reg[prog[pc+2]]; pc += 3
        elif op == 0x3c: return reg[0]
        elif op == 0x4d:
            v, c = reg[prog[pc+1]], prog[pc+2] & 31
            reg[prog[pc+1]] = ((v << c) | (v >> (32-c))) & M if c else v; pc += 3
        elif op == 0x5e:
            i = reg[prog[pc+2]]
            reg[prog[pc+1]] = data[i] if i < len(data) else 0; pc += 3
        elif op == 0x68: pc = u16(pc+1)
        elif op == 0x7a: reg[prog[pc+1]] = u32(pc+2); pc += 6
        elif op == 0x84: reg[prog[pc+1]] ^= reg[prog[pc+2]]; pc += 3
        elif op == 0x9f: reg[prog[pc+1]] ^= u32(pc+2); pc += 6
        elif op == 0xb6: reg[prog[pc+1]] >>= prog[pc+2]; pc += 3
        elif op == 0xc1: reg[prog[pc+1]] = (reg[prog[pc+1]] + u32(pc+2)) & M; pc += 6
        elif op == 0xd3:
            pc = u16(pc+3) if reg[prog[pc+1]] < reg[prog[pc+2]] else pc+5
        elif op == 0xe7: reg[prog[pc+1]] = (reg[prog[pc+1]]+1) & M; pc += 2
        elif op == 0xf5:
            if not stack: return reg[0]
            pc = stack.pop()
        else: raise ValueError("bad op %02x at %04x" % (op, pc))
    raise RuntimeError("runaway")

mark = so[0x530:0x540]
print("\nmark:", struct.unpack('<4i', mark))
print("r0 = 0x%08x" % run(mark))

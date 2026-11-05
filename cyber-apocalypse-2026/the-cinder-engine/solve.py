#!/usr/bin/env python3
"""the_cinder_engine - HTB Cyber Apocalypse 2026 (reversing).

La VM (ARM64, opcode map reverseado) implementa un SPN de 8 rondas sobre 32 bytes:
    s = input ^ K0
    for r in 1..8:  s = SBOX[s];  s = Linear(s);  s ^= Kr
    if s == TARGET:  out = input[0:26] ^ OUTKEY   (la flag)

Descifro TARGET para recuperar el input correcto y de ahí la flag.
Datos en el bytecode (rod @0xe80): SBOX@0x10c4, roundkeys@0x11c4 (9x32),
TARGET@0x12e4 (32), OUTKEY@0x1304 (26).
"""
data = open('cinder', 'rb').read()
PROG = 0xe80
rod = data
def R(off, n):  # leer n bytes del bytecode en offset relativo al programa
    return data[PROG + off: PROG + off + n]

SBOX = list(R(0x10c4, 256))
INV = [0] * 256
for i, v in enumerate(SBOX):
    INV[v] = i
KEYS = [list(R(0x11c4 + r * 32, 32)) for r in range(9)]
TARGET = list(R(0x12e4, 32))
OUTKEY = list(R(0x1304, 26))

# --- extraer la capa lineal parseando el bytecode 0x70..0x1018 ---
P = data[PROG:PROG + 0x131e]
def dec(pc):
    b0, b1, b2, b3 = P[pc], P[pc+1], P[pc+2], P[pc+3]
    return b3, (b2>>4)&0xf, b2&0xf, b0&0xf, b0|(b1<<8)

# recorro instrucciones; cada STOREB dmem[0x80+j]=r5 cierra un output j
S = [None]*32   # S[j] = lista de indices de entrada XOR-eados
cur = []
pc = 0x70
while pc < 0x1018:
    op, rd, rs1, rs2, imm = dec(pc)
    if op == 0xc4:            # LOADB r? = dmem[imm + r0]  (imm = indice de entrada)
        cur.append(imm)
    elif op == 0xc5:          # STOREB dmem[imm + r0] = r5  (imm = 0x80+j)
        j = imm - 0x80
        S[j] = cur
        cur = []
    pc += 4
assert all(s is not None for s in S), S

# matriz M (32x32) sobre GF(2): out_j = XOR_{i in S[j]} in_i
# como filas de bits (bit i)
M = [sum(1 << i for i in S[j]) for j in range(32)]

def matvec(rows, vec):  # vec: lista de 32 bytes -> aplica matriz binaria
    out = [0]*32
    for j, row in enumerate(rows):
        x = 0; r = row; i = 0
        while r:
            if r & 1:
                x ^= vec[i]
            r >>= 1; i += 1
        out[j] = x & 0xff
    return out

# invertir M sobre GF(2) (Gauss-Jordan sobre 32x32)
def invert_gf2(rows):
    n = 32
    A = [(rows[i] | (1 << (n + i))) for i in range(n)]  # [M | I]
    for col in range(n):
        piv = next((r for r in range(col, n) if (A[r] >> col) & 1), None)
        assert piv is not None, "matriz singular"
        A[col], A[piv] = A[piv], A[col]
        for r in range(n):
            if r != col and (A[r] >> col) & 1:
                A[r] ^= A[col]
    return [(A[i] >> n) & ((1 << n) - 1) for i in range(n)]

Minv = invert_gf2(M)

def linear(vec):     return matvec(M, vec)
def inv_linear(vec): return matvec(Minv, vec)

# --- cifrado forward (para verificar) ---
def encrypt(inp):
    s = [inp[i] ^ KEYS[0][i] for i in range(32)]
    for r in range(1, 9):
        s = [SBOX[b] for b in s]
        s = linear(s)
        s = [s[i] ^ KEYS[r][i] for i in range(32)]
    return s

def decrypt(ct):
    s = ct[:]
    for r in range(8, 0, -1):
        s = [s[i] ^ KEYS[r][i] for i in range(32)]
        s = inv_linear(s)
        s = [INV[b] for b in s]
    s = [s[i] ^ KEYS[0][i] for i in range(32)]
    return s

inp = decrypt(TARGET)
assert encrypt(inp) == TARGET, "decrypt no invierte encrypt!"
flag = bytes(inp[i] ^ OUTKEY[i] for i in range(26))
print("input (32B):", bytes(inp))
print("input hex  :", bytes(inp).hex())
print("FLAG       :", flag)

# verificación end-to-end con el emulador real
try:
    import emu
    out = emu.run(bytes(inp))
    print("emu output :", out)
except Exception as e:
    print("emu check skipped:", e)

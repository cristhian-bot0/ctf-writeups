#!/usr/bin/env python3
"""Decrypt a WinZip-AES (AE-2) single entry with a known password. Pure stdlib."""
import hashlib, struct, zlib

PASSWORD = b"infected"
ZIP = "public(1).zip"
OUT = "extracted/app.py"

# ---- minimal AES-256 (encrypt only; CTR needs only block-encrypt) ----
sbox = []
def _init_sbox():
    p = q = 1
    box = [0]*256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        xformed = q ^ ((q<<1)|(q>>7)) ^ ((q<<2)|(q>>6)) ^ ((q<<3)|(q>>5)) ^ ((q<<4)|(q>>4))
        box[p] = (xformed ^ 0x63) & 0xFF
        if p == 1: break
    box[0] = 0x63
    return box
sbox = _init_sbox()
Rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]

def xtime(a): return ((a<<1) ^ 0x1B) & 0xFF if a & 0x80 else (a<<1)
def key_expansion(key):
    Nk=8; Nr=14; w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,4*(Nr+1)):
        t=list(w[i-1])
        if i%Nk==0:
            t=t[1:]+t[:1]; t=[sbox[b] for b in t]; t[0]^=Rcon[i//Nk-1]
        elif i%Nk==4:
            t=[sbox[b] for b in t]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w
def encrypt_block(block, w):
    s=[list(block[i:i+4]) for i in range(0,16,4)]  # rows? use column-major state
    # state as 4x4 column-major
    state=[[block[r+4*c] for c in range(4)] for r in range(4)]
    def add_rk(rnd):
        for c in range(4):
            for r in range(4):
                state[r][c]^=w[rnd*4+c][r]
    add_rk(0)
    for rnd in range(1,14):
        for r in range(4):
            for c in range(4):
                state[r][c]=sbox[state[r][c]]
        for r in range(1,4):
            state[r]=state[r][r:]+state[r][:r]
        for c in range(4):
            a=[state[r][c] for r in range(4)]
            state[0][c]=xtime(a[0])^(xtime(a[1])^a[1])^a[2]^a[3]
            state[1][c]=a[0]^xtime(a[1])^(xtime(a[2])^a[2])^a[3]
            state[2][c]=a[0]^a[1]^xtime(a[2])^(xtime(a[3])^a[3])
            state[3][c]=(xtime(a[0])^a[0])^a[1]^a[2]^xtime(a[3])
        add_rk(rnd)
    for r in range(4):
        for c in range(4):
            state[r][c]=sbox[state[r][c]]
    for r in range(1,4):
        state[r]=state[r][r:]+state[r][:r]
    add_rk(14)
    return bytes(state[r][c] for c in range(4) for r in range(4))

# ---- parse zip ----
data=open(ZIP,"rb").read()
fnlen=struct.unpack("<H",data[26:28])[0]
extralen=struct.unpack("<H",data[28:30])[0]
comp_size=struct.unpack("<H",data[18:20])[0] | (struct.unpack("<H",data[20:22])[0]<<16)
extra=data[30+fnlen:30+fnlen+extralen]
strength=extra[8]; method=struct.unpack("<H",data[8:10])[0]
salt_len={1:8,2:12,3:16}[strength]; key_len={1:16,2:24,3:32}[strength]
off=30+fnlen+extralen
salt=data[off:off+salt_len]
enc=data[off+salt_len+2:off+comp_size-salt_len-2-10]  # exclude salt,pv(2),mac(10)
# derive keys
dk=hashlib.pbkdf2_hmac("sha1",PASSWORD,salt,1000,2*key_len+2)
aes_key=dk[:key_len]
w=key_expansion(aes_key)
# CTR decrypt: counter little-endian, starts at 1
out=bytearray()
counter=1
for i in range(0,len(enc),16):
    ctr=counter.to_bytes(16,"little")
    ks=encrypt_block(ctr,w)
    blk=enc[i:i+16]
    out+=bytes(blk[j]^ks[j] for j in range(len(blk)))
    counter+=1
# method 8 = deflate
if method==8:
    plain=zlib.decompress(bytes(out),-15)
else:
    plain=bytes(out)
open(OUT,"wb").write(plain)
print(f"[+] wrote {OUT} ({len(plain)} bytes)")
print("="*60)
print(plain.decode(errors="replace"))

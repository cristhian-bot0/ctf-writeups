#!/usr/bin/env python3
"""Decrypt ALL entries of a WinZip-AES zip with a known password. Pure stdlib."""
import hashlib, struct, zlib, os

PASSWORD = b"infected"
ZIP = "public.zip"
OUTDIR = "extracted"

# ---- minimal AES-256 block encrypt (for CTR) ----
def _init_sbox():
    p=q=1; box=[0]*256
    while True:
        p=p^((p<<1)&0xFF)^(0x1B if p&0x80 else 0)
        q^=q<<1;q^=q<<2;q^=q<<4;q&=0xFF
        if q&0x80:q^=0x09
        x=q^((q<<1)|(q>>7))^((q<<2)|(q>>6))^((q<<3)|(q>>5))^((q<<4)|(q>>4))
        box[p]=(x^0x63)&0xFF
        if p==1:break
    box[0]=0x63; return box
sbox=_init_sbox()
Rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]
def xtime(a): return ((a<<1)^0x1B)&0xFF if a&0x80 else (a<<1)
def key_expansion(key):
    Nk=8;Nr=14;w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,4*(Nr+1)):
        t=list(w[i-1])
        if i%Nk==0:
            t=t[1:]+t[:1];t=[sbox[b] for b in t];t[0]^=Rcon[i//Nk-1]
        elif i%Nk==4:
            t=[sbox[b] for b in t]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w
def encrypt_block(block,w):
    state=[[block[r+4*c] for c in range(4)] for r in range(4)]
    def add_rk(rnd):
        for c in range(4):
            for r in range(4): state[r][c]^=w[rnd*4+c][r]
    add_rk(0)
    for rnd in range(1,14):
        for r in range(4):
            for c in range(4): state[r][c]=sbox[state[r][c]]
        for r in range(1,4): state[r]=state[r][r:]+state[r][:r]
        for c in range(4):
            a=[state[r][c] for r in range(4)]
            state[0][c]=xtime(a[0])^(xtime(a[1])^a[1])^a[2]^a[3]
            state[1][c]=a[0]^xtime(a[1])^(xtime(a[2])^a[2])^a[3]
            state[2][c]=a[0]^a[1]^xtime(a[2])^(xtime(a[3])^a[3])
            state[3][c]=(xtime(a[0])^a[0])^a[1]^a[2]^xtime(a[3])
        add_rk(rnd)
    for r in range(4):
        for c in range(4): state[r][c]=sbox[state[r][c]]
    for r in range(1,4): state[r]=state[r][r:]+state[r][:r]
    add_rk(14)
    return bytes(state[r][c] for c in range(4) for r in range(4))

def ctr_decrypt(ct,w):
    out=bytearray();c=1
    for i in range(0,len(ct),16):
        ks=encrypt_block(c.to_bytes(16,"little"),w);blk=ct[i:i+16]
        out+=bytes(blk[j]^ks[j] for j in range(len(blk)));c+=1
    return bytes(out)

data=open(ZIP,"rb").read()
pos=0
while data[pos:pos+4]==b"PK\x03\x04":
    method=struct.unpack("<H",data[pos+8:pos+10])[0]
    comp=struct.unpack("<I",data[pos+18:pos+22])[0]
    fnlen=struct.unpack("<H",data[pos+26:pos+28])[0]
    extralen=struct.unpack("<H",data[pos+28:pos+30])[0]
    name=data[pos+30:pos+30+fnlen].decode(errors="replace")
    extra=data[pos+30+fnlen:pos+30+fnlen+extralen]
    strength=extra[8]
    salt_len={1:8,2:12,3:16}[strength];key_len={1:16,2:24,3:32}[strength]
    off=pos+30+fnlen+extralen
    salt=data[off:off+salt_len]
    ct=data[off+salt_len+2:off+comp-10]
    # actual compression method is in AES extra field (last 2 bytes)
    aes_method=struct.unpack("<H",extra[9:11])[0]
    dk=hashlib.pbkdf2_hmac("sha1",PASSWORD,salt,1000,2*key_len+2)
    w=key_expansion(dk[:key_len])
    raw=ctr_decrypt(ct,w)
    plain=zlib.decompress(raw,-15) if aes_method==8 else raw
    outpath=os.path.join(OUTDIR,name)
    os.makedirs(os.path.dirname(outpath),exist_ok=True)
    open(outpath,"wb").write(plain)
    print(f"[+] {name} ({len(plain)} bytes)")
    pos=off+comp
print("done")

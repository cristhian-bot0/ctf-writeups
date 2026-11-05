import base64, hashlib, sys
from Crypto.Cipher import AES
def evp(pw,salt,kl,il,md):
    d=b'';p=b''
    while len(d)<kl+il:
        h=hashlib.new(md);h.update(p+pw+salt);p=h.digest();d+=p
    return d[:kl],d[kl:kl+il]
def prn(b):
    s=b
    if s and 1<=s[-1]<=16: 
        pad=s[-1]
        if s[-pad:]==bytes([pad])*pad: s=s[:-pad]
    try:
        t=s.decode('utf-8')
        if all(c.isprintable() or c in '\n\t\r' for c in t) and len(t)>0: return t
    except: pass
    return None
def decrypt(blob,pw):
    raw=base64.b64decode(blob); 
    if raw[:8]!=b'Salted__': return None
    salt=raw[8:16];ct=raw[16:]
    for md in ['md5','sha256']:
        for kl in [32,16,24]:
            k,iv=evp(pw.encode(),salt,kl,16,md)
            try:
                t=prn(AES.new(k,AES.MODE_CBC,iv).decrypt(ct))
                if t: return (f"{kl*8}/{md}",t)
            except: pass
    # pbkdf2
    for kl in [32,16,24]:
        dk=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,10000,kl+16)
        try:
            t=prn(AES.new(dk[:kl],AES.MODE_CBC,dk[kl:kl+16]).decrypt(ct))
            if t: return (f"{kl*8}/pbkdf2",t)
        except: pass
    return None

keys=sys.argv[1:] or ["SHALLOWBLUE"]
for line in open("/tmp/blobs_tagged.txt"):
    node,blob=line.split()
    for pw in keys:
        r=decrypt(blob,pw)
        if r:
            print(f"[{node}] key={pw} ({r[0]}): {r[1]!r}")

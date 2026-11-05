import base64, hashlib
from Crypto.Cipher import AES
BL={'sparkling1':'U2FsdGVkX1+eZ2iJZ71h6gdc2J/oQwiAnnZZAowdpu5S4ac76UlWCLtop+iI6w5k',
    'snatch1':'U2FsdGVkX18BCUVwqg8o51c1MXZIPI7MGB9dsWLe82PEC1oG28R4ebRKdlATmZBK'}
def evp(pw,salt,kl,il,md):
    d=b'';p=b''
    while len(d)<kl+il:
        h=hashlib.new(md);h.update(p+pw+salt);p=h.digest();d+=p
    return d[:kl],d[kl:kl+il]
def ok(b):
    s=b
    if s and 1<=s[-1]<=16 and s[-s[-1]:]==bytes([s[-1]])*s[-1]: s=s[:-s[-1]]
    try:
        t=s.decode('utf-8')
        return t if all(c.isprintable() or c in '\n\t' for c in t) else None
    except: return None
def attempt(blob,pw):
    raw=base64.b64decode(blob); salt=raw[8:16];ct=raw[16:]
    res=[]
    for md in ['md5','sha1','sha256','sha512']:
        for kl in [16,24,32]:
            k,iv=evp(pw,salt,kl,16,md)
            t=ok(AES.new(k,AES.MODE_CBC,iv).decrypt(ct))
            if t: res.append((f"EVP-{md}-{kl*8}",t))
    for hsh in ['sha1','sha256','sha512']:
        for it in [1,1000,10000,100000]:
            for kl in [16,24,32]:
                dk=hashlib.pbkdf2_hmac(hsh,pw,salt,it,kl+16)
                t=ok(AES.new(dk[:kl],AES.MODE_CBC,dk[kl:kl+16]).decrypt(ct))
                if t: res.append((f"PBKDF2-{hsh}-{it}-{kl*8}",t))
    return res
for name,blob in BL.items():
    for pw in [b'SHALLOWBLUE',b'shallowblue',b'SHALLOWBLUE\n',b'ShallowBlue']:
        for m,t in attempt(blob,pw):
            print(f"[{name}] pw={pw} {m}: {t!r}")
print("brute complete")

import base64, hashlib, sys
from itertools import product
try:
    from Crypto.Cipher import AES, DES3, Blowfish, ARC4
    from Crypto.Util.Padding import unpad
    HAVE=True
except Exception:
    HAVE=False

def evp_bytestokey(password, salt, key_len, iv_len, md):
    d=b''; prev=b''
    while len(d) < key_len+iv_len:
        h=hashlib.new(md); h.update(prev+password+salt); prev=h.digest(); d+=prev
    return d[:key_len], d[key_len:key_len+iv_len]

def try_dec(blob_b64, password):
    raw=base64.b64decode(blob_b64)
    assert raw[:8]==b'Salted__'
    salt=raw[8:16]; ct=raw[16:]
    pw=password.encode()
    results=[]
    from Crypto.Cipher import AES
    for md in ['md5','sha256','sha1']:
        for klen in [16,24,32]:
            key,iv=evp_bytestokey(pw,salt,klen,16,md)
            try:
                pt=AES.new(key,AES.MODE_CBC,iv).decrypt(ct)
                results.append((f"aes{klen*8}-cbc/EVP-{md}", pt))
            except Exception: pass
    # PBKDF2 (openssl -pbkdf2 default sha256, 10000 iters)
    for klen in [16,24,32]:
        dk=hashlib.pbkdf2_hmac('sha256',pw,salt,10000,klen+16)
        key,iv=dk[:klen],dk[klen:klen+16]
        try:
            pt=AES.new(key,AES.MODE_CBC,iv).decrypt(ct)
            results.append((f"aes{klen*8}-cbc/PBKDF2",pt))
        except Exception: pass
    return results

def printable(b):
    try:
        s=b.rstrip(b'\x00')
        # strip pkcs7
        if s and s[-1]<=16: s=s[:-s[-1]]
        t=s.decode('utf-8')
        return t if sum(c.isprintable() or c in '\n\t' for c in t)>=len(t)*0.9 and len(t)>0 else None
    except Exception:
        return None

blob=sys.argv[1]; pw=sys.argv[2]
for mode,pt in try_dec(blob, pw):
    t=printable(pt)
    print(f"[{mode}] {'>> '+repr(t) if t else '(binary) '+pt[:16].hex()}")

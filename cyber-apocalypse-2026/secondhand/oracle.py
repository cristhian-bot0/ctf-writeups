import subprocess, re
GDB_SCRIPT='enc.gdb'
def encrypt(data16: bytes) -> bytes:
    assert len(data16)==16 and b'\n' not in data16 and b'\x00' not in data16
    p=subprocess.run(['gdb','-q','-batch','-x',GDB_SCRIPT,'./secondhand.patched'],
                     input=data16+b'\n', capture_output=True)
    out=p.stdout.decode(errors='replace')
    bts=[]
    for line in out.splitlines():
        m=re.search(r':\s*(.*)',line)
        if line.strip().startswith('0x') and '\t' in line:
            for tok in re.findall(r'0x([0-9a-f]{2})\b', line):
                bts.append(int(tok,16))
    return bytes(bts[:16])
if __name__=='__main__':
    import sys
    base=b'AAAAAAAAAAAAAAAA'
    E=encrypt
    e0=E(base)
    print('E(base)=',e0.hex())
    # test afinidad: a^b^c^d=0 -> E xor = 0
    d1=bytes([1]+[0]*15); d2=bytes([0,2]+[0]*14)
    a=base; b=bytes(x^y for x,y in zip(base,d1)); c=bytes(x^y for x,y in zip(base,d2))
    d=bytes(x^y for x,y in zip(base, bytes(p^q for p,q in zip(d1,d2))))
    Ea,Eb,Ec,Ed=E(a),E(b),E(c),E(d)
    x=bytes(p^q^r^s for p,q,r,s in zip(Ea,Eb,Ec,Ed))
    print('afin? XOR de los 4 =',x.hex(),'(cero => afin)')

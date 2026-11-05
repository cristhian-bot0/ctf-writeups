import sys, struct

TYPES={0:'NIL',1:'BOOL',2:'INT',3:'FLOAT',4:'STRING',5:'VECTOR2',21:'COLOR',
       28:'ARRAY',27:'DICTIONARY',29:'PACKED_BYTE_ARRAY',30:'PACKED_INT32_ARRAY',
       31:'PACKED_INT64_ARRAY',34:'PACKED_STRING_ARRAY'}

def dec(d,p):
    h,=struct.unpack_from('<I',d,p); p+=4
    t=h&0xffff; flags=h>>16
    if t==0: return None,p
    if t==1:
        v,=struct.unpack_from('<I',d,p); return bool(v),p+4
    if t==2:
        if flags&1:
            v,=struct.unpack_from('<q',d,p); return v,p+8
        v,=struct.unpack_from('<i',d,p); return v,p+4
    if t==3:
        if flags&1:
            v,=struct.unpack_from('<d',d,p); return v,p+8
        v,=struct.unpack_from('<f',d,p); return v,p+4
    if t==4:
        l,=struct.unpack_from('<I',d,p); p+=4
        s=d[p:p+l].decode('utf8','replace'); p+=l
        if l%4: p+=4-(l%4)
        return s,p
    if t==29:
        l,=struct.unpack_from('<I',d,p); p+=4
        b=d[p:p+l]; p+=l
        if l%4: p+=4-(l%4)
        return b,p
    if t==28:
        l,=struct.unpack_from('<I',d,p); p+=4
        out=[]
        for _ in range(l&0x7fffffff):
            v,p=dec(d,p); out.append(v)
        return out,p
    if t==27:
        l,=struct.unpack_from('<I',d,p); p+=4
        out={}
        for _ in range(l&0x7fffffff):
            k,p=dec(d,p); v,p=dec(d,p); out[repr(k)]=v
        return out,p
    raise ValueError("unhandled variant type %d at %d"%(t,p-4))

def parse(path):
    d=open(path,'rb').read()
    idc,cc,tlc,tcc=struct.unpack_from('<4I',d,0); p=16
    ids=[]
    for i in range(idc):
        l,=struct.unpack_from('<I',d,p); p+=4
        ids.append(''.join(chr(struct.unpack_from('<I',d,p+4*j)[0]^0xb6b6b6b6) for j in range(l))); p+=4*l
    consts=[]
    for i in range(cc):
        v,p=dec(d,p); consts.append(v)
    return ids,consts,d,p,tlc,tcc

if __name__=='__main__':
    for f in sys.argv[1:]:
        ids,consts,d,p,tlc,tcc=parse(f)
        print("\n########", f, "tokens=%d"%tcc)
        print("IDS:", ids)
        print("CONSTS:")
        for c in consts: print("   ", repr(c))

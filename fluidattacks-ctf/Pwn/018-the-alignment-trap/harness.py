#!/usr/bin/env python3
"""Harness de interaccion para cloudstorage (The Alignment Trap)."""
import sys, struct, subprocess, socket, ssl, select, time

p64 = lambda x: struct.pack("<Q", x)
u64 = lambda b: struct.unpack("<Q", b.ljust(8, b"\x00"))[0]

class IO:
    def __init__(self, mode, target):
        self.p = None; self.s = None; self.buf = b""
        if mode == "local":
            self.p = subprocess.Popen(target, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            host, port, tls = target
            raw = socket.create_connection((host, port), timeout=15)
            if tls:
                ctx = ssl._create_unverified_context()
                self.s = ctx.wrap_socket(raw, server_hostname=host)
            else:
                self.s = raw
    def _fd(self): return self.p.stdout.fileno() if self.p else self.s.fileno()
    def _rd(self, to=5):
        r,_,_ = select.select([self._fd()], [], [], to)
        if not r: return b""
        return self.p.stdout.read1(65536) if self.p else self.s.recv(65536)
    def until(self, delim, to=8):
        end=time.time()+to
        while delim not in self.buf and time.time()<end:
            d=self._rd(min(2,to))
            if not d and self.buf: break
            self.buf+=d
        i=self.buf.find(delim)
        if i<0: out,self.buf=self.buf,b""; return out
        i+=len(delim); out,self.buf=self.buf[:i],self.buf[i:]; return out
    def send(self, data):
        if self.p:
            self.p.stdin.write(data); self.p.stdin.flush()
        else:
            self.s.sendall(data)
    def sendline(self, data):
        if isinstance(data,int): data=str(data).encode()
        if isinstance(data,str): data=data.encode()
        self.send(data+b"\n")
    def recvall(self, t=3):
        end=time.time()+t; data=self.buf; self.buf=b""
        while time.time()<end:
            d=self._rd(0.5)
            if d: data+=d
        return data
    def recvn_after_marker(self, marker, n, to=8):
        """lee hasta marker, luego devuelve los siguientes n bytes crudos"""
        self.until(marker, to)
        end=time.time()+to
        while len(self.buf)<n and time.time()<end:
            self.buf+=self._rd(2)
        out=self.buf[:n]; self.buf=self.buf[n:]; return out

def menu(io): io.until(b"> ")

def create(io, align, size):
    menu(io); io.sendline(1)
    io.until(b"power of 2"); io.sendline(align)
    io.until(b"size:"); io.sendline(size)
    return io.until(b"\n")

def write(io, idx, data):
    menu(io); io.sendline(2)
    io.until(b"index:"); io.sendline(idx)
    io.until(b"max):")
    io.send(data)
    return io.buf

def read_block(io, idx, nbytes):
    menu(io); io.sendline(3)
    io.until(b"index:"); io.sendline(idx)
    return io.recvn_after_marker(b"bytes):\n", nbytes)

def delete(io, idx):
    menu(io); io.sendline(4)
    io.until(b"index:"); io.sendline(idx)
    return io.until(b"\n")

def make(mode="local"):
    if mode=="local":
        return IO("local", ["./ld-linux-x86-64.so.2","--library-path",".","./cloudstorage"])
    else:
        host=sys.argv[2]; port=int(sys.argv[3]) if len(sys.argv)>3 else 443
        return IO("remote",(host,port,True))

if __name__=="__main__":
    io=make("local" if len(sys.argv)<2 else sys.argv[1])
    print(create(io, 16, 32))
    print("status test done")

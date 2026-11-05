#!/usr/bin/env python3
"""
False Witness - HTB Cyber Apocalypse 2026 (crypto)

H(msg) = pow(G, msg, P), and WE choose G.
Oracle(i): KEY_BITS[i]==1 -> pow(G, x, P)          (a real "hash")
           KEY_BITS[i]==0 -> random in [0, 2**256)  (a "false witness")

Pick G = P-1 == -1 (mod P), which has order 2:
    pow(G, msg, P) in {1, P-1}  ALWAYS.
So:
    result in {1, P-1} -> bit = 1
    otherwise          -> bit = 0   (a uniform 256-bit int is ~never 1 or P-1)

Recover all 256 key bits (1 query each), rebuild KEY, decrypt AES-ECB.

Usage: solve.py HOST PORT
"""
import sys
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
G = P - 1
INSIDE = {1, P - 1}


class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.buf = b""

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def recv_line(self) -> bytes:
        return self.recv_until(b"\n")

    def send_line(self, data: bytes):
        self.s.sendall(data + b"\n")

    def close(self):
        self.s.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

    io = Conn(host, port)
    io.recv_until(b"Here is something for you:\n")
    ct = bytes.fromhex(io.recv_line().strip().decode())

    io.recv_until(b"give me the hashing generator: ")
    io.send_line(str(G).encode())

    bits = []
    for i in range(256):
        io.recv_until(b"> ")
        io.send_line(b"1")
        io.recv_until(b"Enter offset: ")
        io.send_line(str(i).encode())
        io.recv_until(b"Oracle result: ")
        val = int(io.recv_line().strip())
        bits.append(1 if val in INSIDE else 0)

    io.recv_until(b"> ")
    io.send_line(b"2")
    io.close()

    key_int = int("".join(map(str, bits)), 2)
    KEY = key_int.to_bytes(32, "big")

    pt = AES.new(KEY, AES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass
    print("KEY :", KEY.hex())
    print("FLAG:", pt.decode(errors="replace"))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Local mock of server.py to validate solve.py end-to-end."""
import socketserver
from hashlib import sha256
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import secrets

P = 0xCD4A96D3B7FA7251A1BB765933FB676FCAE8C9026682E34F779122DFD66915BB
FLAG = b"HTB{mock_false_witness_flag_0xC0FFEE}"
N = sha256().digest_size * 8


class Handler(socketserver.StreamRequestHandler):
    def wl(self, s):
        self.wfile.write((s + "\n").encode())

    def handle(self):
        KEY = secrets.token_bytes(32)
        KEY_BITS = list(map(int, f"{int.from_bytes(KEY):0256b}"))

        def H(msg, G):
            return pow(G, msg, P)

        self.wl("Here is something for you:")
        self.wl(AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16)).hex())

        G = None
        while True:
            self.wfile.write(b"Before we start, give me the hashing generator: ")
            G = int(self.rfile.readline().strip())
            if 1 < G < P:
                break

        SK = [(secrets.randbelow(2**N), secrets.randbelow(2**N)) for _ in range(N)]
        PK = [(H(s[0], G), H(s[1], G)) for s in SK]
        appeared = {}

        def oracle(i):
            if i in appeared:
                return appeared[i]
            ret = secrets.randbelow(2**N) if KEY_BITS[i] == 0 else PK[i % len(PK)][secrets.randbelow(2)]
            appeared[i] = ret
            return ret

        while True:
            self.wl("1. Oracle")
            self.wl("2. Exit")
            self.wfile.write(b"> ")
            ch = self.rfile.readline().strip().decode()
            if ch == "1":
                self.wfile.write(b"Enter offset: ")
                off = self.rfile.readline().strip()
                if not off:
                    continue
                offset = int(off)
                if 0 <= offset < len(KEY_BITS):
                    self.wl("Oracle result: " + str(oracle(offset)))
                else:
                    self.wl("ERROR")
            elif ch == "2":
                self.wl("bye")
                break


if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", 1337), Handler) as srv:
        srv.serve_forever()

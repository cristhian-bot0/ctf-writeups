#!/usr/bin/env python3
"""Crack WinZip-AES password using only the 2-byte password verification value.
Only needs PBKDF2-HMAC-SHA1 (hashlib, stdlib)."""
import hashlib, struct, sys, time

ZIP = "public.zip"
WORDLIST = "/home/project/Security/HTB/raptor/Connected/wordlists/rockyou.txt"

data = open(ZIP, "rb").read()
# Parse local file header
assert data[:4] == b"PK\x03\x04"
fnlen = struct.unpack("<H", data[26:28])[0]
extralen = struct.unpack("<H", data[28:30])[0]
name = data[30:30+fnlen].decode(errors="replace")
extra = data[30+fnlen:30+fnlen+extralen]
# AES extra field 0x9901: id(2) size(2) ver(2) vendor(2) strength(1) method(2)
strength = extra[8]
salt_len = {1:8, 2:12, 3:16}[strength]
off = 30 + fnlen + extralen
salt = data[off:off+salt_len]
pwv = data[off+salt_len:off+salt_len+2]  # password verification value
key_len = {1:16, 2:24, 3:32}[strength]
dklen = 2*key_len + 2
print(f"file={name} strength=AES-{key_len*8} salt={salt.hex()} pwv={pwv.hex()}")

start = time.time()
n = 0
with open(WORDLIST, "rb") as f:
    for line in f:
        pw = line.rstrip(b"\r\n")
        n += 1
        dk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000, dklen)
        if dk[-2:] == pwv:
            print(f"\n[+] FOUND password: {pw.decode(errors='replace')}  (after {n} tries, {time.time()-start:.1f}s)")
            sys.exit(0)
        if n % 200000 == 0:
            rate = n/(time.time()-start)
            print(f"  {n} tried  {rate:.0f}/s", flush=True)
print(f"[-] not found in wordlist ({n} tried)")

#!/usr/bin/env python3
"""Extrae offsets (vaddr) de símbolos, gadgets y /bin/sh de libc sin pwntools."""
import struct, subprocess, re, sys

LIBC = "extracted/libc.so.6"
data = open(LIBC, "rb").read()

# --- program headers para convertir file offset -> vaddr ---
e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
e_phentsize = struct.unpack("<H", data[0x36:0x38])[0]
e_phnum = struct.unpack("<H", data[0x38:0x3a])[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    p_type = struct.unpack("<I", data[off:off+4])[0]
    if p_type != 1:  # PT_LOAD
        continue
    p_offset = struct.unpack("<Q", data[off+8:off+16])[0]
    p_vaddr  = struct.unpack("<Q", data[off+16:off+24])[0]
    p_filesz = struct.unpack("<Q", data[off+32:off+40])[0]
    segs.append((p_offset, p_vaddr, p_filesz))

def foff_to_vaddr(fo):
    for p_offset, p_vaddr, p_filesz in segs:
        if p_offset <= fo < p_offset + p_filesz:
            return p_vaddr + (fo - p_offset)
    return None

# --- símbolos via readelf ---
def sym(name):
    out = subprocess.check_output(["readelf","-sW",LIBC]).decode()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[7] == name and parts[3] == "FUNC":
            return int(parts[1], 16)
    # fallback: any match
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[7].split("@")[0] == name:
            return int(parts[1], 16)
    return None

# --- gadgets: buscar secuencias, devolver vaddr ---
def gadget(seq):
    i = data.find(seq)
    while i >= 0:
        v = foff_to_vaddr(i)
        if v is not None:
            return v
        i = data.find(seq, i+1)
    return None

# --- /bin/sh ---
def find_str(s):
    i = data.find(s)
    return foff_to_vaddr(i) if i >= 0 else None

info = {
    "system": sym("system"),
    "pop_rdi": gadget(b"\x5f\xc3"),
    "ret":     gadget(b"\xc3"),
    "binsh":   find_str(b"/bin/sh\x00"),
}
for k,v in info.items():
    print(f"{k:10} = {hex(v) if v is not None else None}")

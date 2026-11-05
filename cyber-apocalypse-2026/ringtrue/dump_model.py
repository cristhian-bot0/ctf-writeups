#!/usr/bin/env python3
"""Extrae los pesos del MLP y los datos del vow directamente del ELF.

Las secciones .data/.rodata de `ringtrue` están mapeadas identidad (vaddr == file
offset), así que basta leer el fichero en las direcciones de los símbolos:

    readelf -sW ringtrue | grep OBJECT
"""

import struct

SYMS = {
    "VOW_LEN": (0x5020, 4),
    "VOW_CIPHER": (0x5030, 30),
    "W_SCALE": (0x5050, 12),
    "ECHO_S": (0x5060, 64),
    "L2_B": (0x50A0, 32),
    "L1_B": (0x50C0, 32),
    "L0_B": (0x50E0, 32),
    "L2_W": (0x5100, 64),
    "L1_W": (0x5140, 64),
    "L0_W": (0x5180, 64),
    "K.0": (0x3A80, 256),
}


def load(path="ringtrue"):
    with open(path, "rb") as f:
        blob = f.read()

    def sym(name):
        off, size = SYMS[name]
        return blob[off:off + size]

    def mat(name):  # 8x8 int8, row-major
        w = struct.unpack("<64b", sym(name))
        return [list(w[r * 8:r * 8 + 8]) for r in range(8)]

    return {
        "VOW_LEN": struct.unpack("<i", sym("VOW_LEN"))[0],
        "VOW_CIPHER": sym("VOW_CIPHER"),
        "ECHO_S": list(struct.unpack("<8q", sym("ECHO_S"))),
        "L0_W": mat("L0_W"), "L1_W": mat("L1_W"), "L2_W": mat("L2_W"),
        "L0_B": list(struct.unpack("<8i", sym("L0_B"))),
        "L1_B": list(struct.unpack("<8i", sym("L1_B"))),
        "L2_B": list(struct.unpack("<8i", sym("L2_B"))),
        "K": list(struct.unpack("<64I", sym("K.0"))),
    }


if __name__ == "__main__":
    m = load()
    for k, v in m.items():
        if k == "K":
            print(f"{k} = SHA-256 round constants ({[hex(x) for x in v[:4]]}...)")
        else:
            print(f"{k} = {v}")

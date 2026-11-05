#!/usr/bin/env python3
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data=open('cinder','rb').read()
TEXT_OFF=0x880; TEXT_ADDR=0x880; TEXT_SIZE=0x5d4
code=data[TEXT_OFF:TEXT_OFF+TEXT_SIZE]
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail=False
for ins in md.disasm(code, TEXT_ADDR):
    print(f"{ins.address:04x}:  {ins.mnemonic:8} {ins.op_str}")

#!/usr/bin/env python3
"""Desensamblador del bytecode de la Cinder Engine."""
data = open('cinder', 'rb').read()
PROG_VADDR = 0xe80; PROG_SIZE = 0x131e
P = data[PROG_VADDR:PROG_VADDR + PROG_SIZE]

OPS = {0x00:'HALT',0x11:'MOV',0x3a:'SET',0x52:'XOR',0x53:'AND',0x54:'OR',0x6b:'MUL',
       0x7c:'ADD',0x7d:'SUB',0x80:'ADDI',0x90:'CMP',0x29:'ROL',0x2a:'ROR',0x2b:'SHL',
       0x2c:'SHR',0xa0:'JMP',0xa1:'JT',0xa2:'JF',0xc4:'LOADB',0xc5:'STOREB',0xc6:'LUT',
       0xe0:'INPUT',0xe1:'OUT'}

def fmt(pc):
    b0,b1,b2,b3 = P[pc],P[pc+1],P[pc+2],P[pc+3]
    op=b3; rd=(b2>>4)&0xf; rs1=b2&0xf; rs2=b0&0xf
    imm=b0|(b1<<8); simm=imm-0x10000 if imm&0x8000 else imm
    sh=(b0)&0x1f
    name=OPS.get(op,f'?{op:02x}')
    if name in ('XOR','AND','OR','MUL','ADD','SUB'):
        return f"{name} r{rd} = r{rs1} {name.lower()} r{rs2}"
    if name=='MOV':   return f"MOV r{rd} = r{rs1}"
    if name=='CMP':   return f"CMP r{rs1}, r{rs2}"
    if name=='SET':   return f"SET r{rd} = {imm:#x}"
    if name=='ADDI':  return f"ADDI r{rd} = r{rs1} + {imm:#x}"
    if name in ('ROL','ROR','SHL','SHR'): return f"{name} r{rd} = r{rs1} by {sh}"
    if name=='JMP':   return f"JMP {pc+4+simm:#06x}   (off {simm:+d})"
    if name=='JT':    return f"JT  {pc+4+simm:#06x}   (if flag)"
    if name=='JF':    return f"JF  {pc+4+simm:#06x}   (if !flag)"
    if name=='LOADB': return f"LOADB r{rd} = dmem[{imm:#x} + r{rs1}]"
    if name=='STOREB':return f"STOREB dmem[{imm:#x} + r{rs1}] = r{rd}"
    if name=='LUT':   return f"LUT r{rd} = rod[{imm:#x} + r{rs1}]"
    if name=='INPUT': return f"INPUT r{rd}"
    if name=='OUT':   return f"OUT r{rs1}"
    if name=='HALT':  return "HALT"
    return f"?op={op:02x} rd={rd} rs1={rs1} rs2={rs2} imm={imm:#x}"

pc=0
while pc+4<=len(P):
    print(f"{pc:04x}: {fmt(pc)}")
    pc+=4

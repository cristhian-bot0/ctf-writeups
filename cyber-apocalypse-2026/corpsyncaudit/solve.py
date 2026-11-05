#!/usr/bin/env python3
"""CorpSyncAudit - HTB Cyber Apocalypse 2026 (reversing).

El .exe (audit tool con backdoor) esconde datos en los logs de "replicacion".
Cada linea de fecha `<weekday>, DD/MM/YYYY HH:MM:SS <AMPM> <TZ> | Region=<R>`
codifica 4 bytes de payload:

  idx     = tabla32[ fmix64(fnv1a_ror13(REGION)) ]        # 0..31 -> 5 bits (MSB first)
  xkey    = weekday_num (Monday=1..Sunday=7)
  si TZ=="GMT": mid=(h+m-s)>>1 ; (h,m,s)=(h-mid, mid, m-mid)   # scramble reversible
  r_hour  = h ^ 12  si bit0(idx)   else h
  r_min   = m ^ 30  si bit1(idx)   else m
  r_sec   = s ^ 30  si bit2(idx)   else s
  r_day   = D ^ 16  si bit3(idx)   else D
  r_month = M ^ 6   si bit4(idx)   else M
  val = (r_hour<<27)|(r_min<<21)|(r_sec<<15)|(r_day<<10)|(r_month<<6)|(Y-1990)
  out[j] = big_endian(val)[j] ^ xkey        (j=0..3)
  final[j] = out[j] ^ K[j]                  (K = clave fija de 4 bytes por fichero)

Recuperamos K asumiendo que el payload empieza por "HTB{".
"""
import re, struct, sys

EXE = open('CorpSyncAudit.exe', 'rb').read()
def foff(vma):
    for fo, base, size in [(0x1ac00, 0x14001c000, 0x310), (0x1b000, 0x14001d000, 0x1590)]:
        if base <= vma < base + size:
            return fo + (vma - base)
o = foff(0x14001d680)
TABLE = {struct.unpack('<Q', EXE[o + i*8:o + i*8 + 8])[0]: i for i in range(32)}
M = 0xffffffffffffffff
WD = {w: i+1 for i, w in enumerate(
    ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'])}

def ror(v, r): r &= 63; return ((v >> r) | (v << (64 - r))) & M
def H(s):
    h = 0xcbf29ce484222325
    for c in s.encode():
        if 0x61 <= c <= 0x7a: c -= 0x20
        h ^= c; h = (h * 0x100000001b3) & M; h = ror(h, 13)
    h ^= h >> 33; h = (h * 0xff51afd7ed558ccd) & M
    h ^= h >> 33; h = (h * 0xc4ceb9fe1a85ec53) & M
    h ^= h >> 33
    return h

LINE = re.compile(
    r'^(\w+), (\d+)/(\d+)/(\d+) (\d+):(\d+):(\d+) (\w+) (\w+) \| Region=(\S+)')

def decode_record(m):
    wd, D, Mo, Y, h, mi, s, ampm, tz, region = m.groups()
    D, Mo, Y, h, mi, s = map(int, (D, Mo, Y, h, mi, s))
    hh = H(region)
    if hh not in TABLE:
        return None
    idx = TABLE[hh]
    bits = [(idx >> (4 - k)) & 1 for k in range(5)]  # bits[0]=MSB .. bits[4]=LSB
    xkey = WD.get(wd, 1)
    if tz == 'GMT':
        mid = (h + mi - s) >> 1     # aritmetico (floor) — valores >=0 aqui
        h, mi, s = h - mid, mid, mi - mid
    r_hour  = h  ^ 12 if bits[0] else h
    r_min   = mi ^ 30 if bits[1] else mi
    r_sec   = s  ^ 30 if bits[2] else s
    r_day   = D  ^ 16 if bits[3] else D
    r_month = Mo ^ 6  if bits[4] else Mo
    val = ((r_hour << 27) | (r_min << 21) | (r_sec << 15) |
           (r_day << 10) | (r_month << 6) | ((Y - 1990) & 0x3f)) & 0xffffffff
    be = [(val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff]
    return bytes(b ^ xkey for b in be)

def decode_log(path):
    out = bytearray()
    for line in open(path):
        m = LINE.match(line.strip())
        if m:
            r = decode_record(m)
            if r is not None:
                out += r
    return bytes(out)

path = sys.argv[1] if len(sys.argv) > 1 else 'logs/sync_20260412_192364.log'
raw = decode_log(path)
# raw = payload ^ K (K repetido de 4 bytes). Recuperar K con prefijo "HTB{".
K = bytes(raw[i] ^ b'HTB{'[i] for i in range(4))
flag = bytes(raw[i] ^ K[i & 3] for i in range(len(raw)))
print("registros:", len(raw)//4, " clave K:", K.hex())
print("payload:", flag)

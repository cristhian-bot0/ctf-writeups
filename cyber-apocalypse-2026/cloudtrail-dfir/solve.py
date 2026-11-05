#!/usr/bin/env python3
"""Wrong Stamp - HTB Cyber Apocalypse 2026 (cloud / DFIR, AWS on LocalStack).

Investigacion graded: reconstruir la actividad de CloudTrail y responder 8 preguntas.
Acceso investigador read-only -> cloudtrail:LookupEvents.

Uso: .venv/bin/python solve.py
"""
import json, urllib.request, boto3

BRIEFING = "http://154.57.164.68:31732"
AWS_EP = "http://154.57.164.68:31595"
INTERNAL_IP = "10.30.41.118"   # workstation legitima de stonepass-warden

def fetch_live():
    creds = json.load(open("creds.json")) if __import__("os").path.exists("creds.json") \
        else json.load(urllib.request.urlopen(BRIEFING + "/player-creds.json"))
    ct = boto3.client("cloudtrail", region_name=creds["region"], endpoint_url=AWS_EP,
                      aws_access_key_id=creds["access_key_id"],
                      aws_secret_access_key=creds["secret_access_key"])
    evs = []
    for page in ct.get_paginator("lookup_events").paginate():
        evs.extend(page["Events"])
    rows = [json.loads(e["CloudTrailEvent"]) for e in evs]
    json.dump([{"evt": d, "eventTime": d["eventTime"]} for d in rows],
              open("events.json", "w"), indent=1)
    return rows

try:                                   # reproducible desde events.json (guardado); si no, live
    rows = [e["evt"] for e in json.load(open("events.json"))]
except Exception:
    rows = fetch_live()
rows.sort(key=lambda d: d["eventTime"])

def ip_of(d):   return d.get("sourceIPAddress")
def user_of(d): return d.get("userIdentity", {}).get("userName") \
                    or d.get("userIdentity", {}).get("arn", "")

# la sesion del atacante = unica IP externa que usa las creds de warden
attacker = [d for d in rows if ip_of(d) == "192.0.2.55"]
t0 = attacker[0]["eventTime"]
internal_before = [d for d in rows if ip_of(d) == INTERNAL_IP and d["eventTime"] < t0]

def denied(d): return d.get("errorCode") in ("AccessDenied", "AccessDeniedException")

ans = {
 1: internal_before[-1]["eventName"],
 2: attacker[0]["eventName"],
 3: next(d["eventName"] for d in attacker if denied(d)),
 4: next(d["requestParameters"]["bucketName"] for d in attacker
        if d["eventName"] in ("ListBucket", "ListObjectsV2")),
 5: next(d["requestParameters"]["name"] for d in attacker if d["eventName"] == "StopLogging"),
 6: next(user_of(d) for d in attacker if d["eventName"] == "StopLogging"),
 7: next(ip_of(d) for d in attacker if d["eventName"] == "StopLogging"),
 8: next(d["eventName"] for d in attacker if d["eventName"] == "StopLogging"),
}
Q = ["last action from internal IP before attacker session",
     "first action from attacker IP",
     "denied action before trail stopped",
     "S3 bucket enumerated before stopping trail",
     "trail name stopped", "IAM user of trail disable",
     "IP of trail disable", "action used to disable trail"]
for i in range(1, 9):
    print(f"Q{i}: {Q[i-1]}\n    -> {ans[i]}")

print("\n=== attacker timeline (192.0.2.55) ===")
for d in attacker:
    print(d["eventTime"], d["eventName"], "err=" + str(d.get("errorCode", "")),
          json.dumps(d.get("requestParameters")))

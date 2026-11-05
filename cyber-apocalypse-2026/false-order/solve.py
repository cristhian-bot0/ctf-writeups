#!/usr/bin/env python3
"""False Order — CA2026 Cloud/DFIR. Reconstruye la sesion del atacante desde CloudTrail
y responde las 12 preguntas. Usa events.json guardado; si no existe, lo baja en vivo."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVENTS = os.path.join(HERE, "events.json")
INTERNAL_IP = "10.41.53.22"
ATTACKER_IP = "198.18.44.91"


def load_events():
    if os.path.exists(EVENTS):
        return json.load(open(EVENTS))
    # fallback en vivo
    import boto3
    from botocore.config import Config
    c = json.load(open(os.path.join(HERE, "creds.json")))
    ct = boto3.client("cloudtrail", endpoint_url=c["endpoint"], region_name=c["region"],
                      aws_access_key_id=c["access_key_id"], aws_secret_access_key=c["secret_access_key"],
                      config=Config(retries={"max_attempts": 2}, connect_timeout=10, read_timeout=30))
    ev = [json.loads(e["CloudTrailEvent"])
          for page in ct.get_paginator("lookup_events").paginate() for e in page["Events"]]
    ev.sort(key=lambda d: d["eventTime"])
    json.dump(ev, open(EVENTS, "w"), indent=2, default=str)
    return ev


def rp(d):
    return d.get("requestParameters") or {}


def main():
    E = load_events()
    E.sort(key=lambda d: d["eventTime"])
    att = [d for d in E if d.get("sourceIPAddress") == ATTACKER_IP]
    first_att_t = att[0]["eventTime"]

    q = {}
    # 1: ultima accion interna antes de la sesion atacante
    internal_before = [d for d in E if d.get("sourceIPAddress") == INTERNAL_IP and d["eventTime"] < first_att_t]
    q[1] = internal_before[-1]["eventName"]
    # 2: primera accion desde IP atacante
    q[2] = att[0]["eventName"]
    # 3: accion S3 denegada antes de asumir rol
    assume_ok_t = next(d["eventTime"] for d in att if d["eventName"] == "AssumeRole" and not d.get("errorCode"))
    q[3] = next(d["eventName"] for d in att
                if d["eventName"] in ("GetObject", "HeadObject") and d.get("errorCode") and d["eventTime"] < assume_ok_t)
    # 4: objeto manipulado
    dele = next(d for d in E if d["eventName"] == "DeleteObject")
    q[4] = f"s3://{rp(dele)['bucketName']}/{rp(dele)['key']}"
    # 5: rol asumido (ARN)
    assume_ok = next(d for d in att if d["eventName"] == "AssumeRole" and not d.get("errorCode"))
    q[5] = rp(assume_ok)["roleArn"]
    # 6: STS principal en DeleteObject
    q[6] = dele["userIdentity"]["arn"]
    # 7: IP de assume + S3 destructivo
    q[7] = dele["sourceIPAddress"]
    # 8: usuario IAM dueño de las creds long-lived del AssumeRole
    q[8] = assume_ok["userIdentity"]["userName"]
    # 9: rol que fallo asumir antes del exito (solo nombre)
    fail = next(d for d in att if d["eventName"] == "AssumeRole" and d.get("errorCode") and d["eventTime"] < assume_ok_t)
    q[9] = rp(fail)["roleArn"].rsplit("/", 1)[-1]
    # 10: roleSessionName del assume exitoso
    q[10] = rp(assume_ok)["roleSessionName"]
    # 11: errorCode del GetObject denegado antes del assume
    q[11] = next(d["errorCode"] for d in att
                 if d["eventName"] == "GetObject" and d.get("errorCode") and d["eventTime"] < assume_ok_t
                 and d["eventTime"] > "2026-07-25T15:00")
    # 12: accion S3 del ledger forjado tras DeleteObject
    q[12] = next(d["eventName"] for d in E if d["eventName"] == "PutObject" and d["eventTime"] > dele["eventTime"])

    labels = {
        1: "Last internal-IP action before attacker session",
        2: "First action from attacker IP",
        3: "S3 action explicitly denied before AssumeRole",
        4: "Tampered object (s3://)",
        5: "Role assumed for destructive session (ARN)",
        6: "STS principal ARN on DeleteObject",
        7: "IP of AssumeRole + destructive S3",
        8: "IAM user owning long-lived creds for AssumeRole",
        9: "Role name failed to assume first",
        10: "roleSessionName on successful AssumeRole",
        11: "errorCode on denied GetObject probe",
        12: "S3 action of the forged-ledger upload",
    }
    print(f"[+] {len(E)} events | attacker={ATTACKER_IP} | internal={INTERNAL_IP}\n")
    for i in range(1, 13):
        print(f"Q{i:2}. {labels[i]:52} -> {q[i]}")


if __name__ == "__main__":
    sys.exit(main())

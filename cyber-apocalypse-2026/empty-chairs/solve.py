#!/usr/bin/env python3
"""Empty Chairs — CA2026 Cloud/DFIR. Reconstruye el ataque de desvio de scouts desde CloudTrail
(+ un S3 access log) y responde las 18 preguntas. Usa events.json guardado; fallback en vivo."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVENTS = os.path.join(HERE, "events.json")
LIVE_IP = "203.0.113.88"          # IP del ataque en vivo (incluye PurgeQueue)


def internal(ip):
    return ip.startswith("10.") or ip == "127.0.0.1"


def load_events():
    if os.path.exists(EVENTS):
        return json.load(open(EVENTS))
    import boto3
    from botocore.config import Config
    c = json.load(open(os.path.join(HERE, "creds.json")))
    ct = boto3.client("cloudtrail", endpoint_url=c["endpoint"], region_name=c["region"],
                      aws_access_key_id=c["access_key_id"], aws_secret_access_key=c["secret_access_key"],
                      config=Config(retries={"max_attempts": 2}, connect_timeout=10, read_timeout=40))
    ev = [json.loads(e["CloudTrailEvent"])
          for page in ct.get_paginator("lookup_events").paginate() for e in page["Events"]]
    ev.sort(key=lambda d: d["eventTime"])
    json.dump(ev, open(EVENTS, "w"), indent=2, default=str)
    return ev


def rp(d):
    return d.get("requestParameters") or {}


def qname(d):
    return (rp(d).get("queueUrl") or "").split("/")[-1]


def main():
    E = sorted(load_events(), key=lambda d: d["eventTime"])
    live = [d for d in E if d.get("sourceIPAddress") == LIVE_IP]

    def first(name, **kw):
        for d in E:
            if d.get("eventName") != name:
                continue
            if all(d.get(k) == v for k, v in kw.items()):
                return d
        return None

    ans = {}

    # Q1: source IP del ultimo ReceiveMessage antes de que un IP externo haga ReceiveMessage en esa cola
    rms = [d for d in E if d.get("eventName") == "ReceiveMessage"]
    ext_rm = next(d for d in rms if not internal(d.get("sourceIPAddress")))
    prior = [x for x in rms if qname(x) == qname(ext_rm) and x["eventTime"] < ext_rm["eventTime"]]
    ans[1] = prior[-1]["sourceIPAddress"]

    # Q2: IP externo del ataque completo (incluye PurgeQueue)
    ans[2] = next(d for d in E if d.get("eventName") == "PurgeQueue")["sourceIPAddress"]

    # pivot (AssumeRole exitoso) time
    assume_ok = next(d for d in live if d.get("eventName") == "AssumeRole" and not d.get("errorCode"))
    tpivot = assume_ok["eventTime"]

    # Q3: primer GetSecretValue denegado en el IP en vivo
    ans[3] = next(rp(d)["secretId"] for d in live
                  if d.get("eventName") == "GetSecretValue" and d.get("errorCode"))
    # Q4: secret leido con exito antes del pivot
    ans[4] = next(rp(d)["secretId"] for d in live
                  if d.get("eventName") == "GetSecretValue" and not d.get("errorCode") and d["eventTime"] < tpivot)
    # Q5: rol que fallo asumir antes del pivot (solo nombre)
    fail = next(d for d in live
                if d.get("eventName") == "AssumeRole" and d.get("errorCode") and d["eventTime"] < tpivot)
    ans[5] = rp(fail)["roleArn"].rsplit("/", 1)[-1]
    # Q6: ARN del rol asumido con exito
    ans[6] = rp(assume_ok)["roleArn"]
    # Q7: roleSessionName del assume exitoso
    ans[7] = rp(assume_ok)["roleSessionName"]
    # Q8: identity type tras el pivot
    ans[8] = next(d for d in E if d.get("eventName") == "PurgeQueue")["userIdentity"]["type"]
    # Q9: cola SQS del recall fraudulento
    send = next(d for d in live if d.get("eventName") == "SendMessage")
    ans[9] = qname(send)
    # Q10/Q11: cuerpo del SendMessage fraudulento
    body = json.loads(rp(send)["messageBody"])
    ans[10] = body["order_id"]
    ans[11] = body["route_override"]
    # Q12: KMS keyId del Decrypt (posterior al SendMessage)
    dec = next(d for d in live if d.get("eventName") == "Decrypt")
    ans[12] = rp(dec)["keyId"]
    # Q13: topic SNS del Publish
    pub = next(d for d in live if d.get("eventName") == "Publish")
    ans[13] = rp(pub)["topicArn"].rsplit(":", 1)[-1]
    # Q14: tabla DynamoDB del PutItem
    put = next(d for d in live if d.get("eventName") == "PutItem")
    ans[14] = rp(put)["tableName"]
    # Q15: campo operation del S3 access log (leido aparte -> hardcode verificado)
    ans[15] = "REST.GET.OBJECT"
    # Q16: trail verificado antes de purgar
    ans[16] = rp(next(d for d in live if d.get("eventName") == "GetTrailStatus"))["name"]
    # Q17: accion que destruyo la evidencia de la cola
    ans[17] = "PurgeQueue"
    # Q18: usuario IAM dueño de la key long-lived que inicio la cadena
    ans[18] = assume_ok["userIdentity"]["userName"]

    labels = {
        1: "Last ReceiveMessage source IP before external ReceiveMessage",
        2: "External IP of full diversion attack (incl. PurgeQueue)",
        3: "First denied GetSecretValue secret name",
        4: "Secret read successfully before role assumption",
        5: "Role name failed to assume before pivot",
        6: "Role ARN successfully assumed",
        7: "roleSessionName on successful AssumeRole",
        8: "IAM identity type after role pivot",
        9: "SQS queue targeted for fraudulent recall",
        10: "order_id injected",
        11: "route_override destination",
        12: "KMS keyId used to decrypt routing envelope",
        13: "SNS topic of diversion alert Publish",
        14: "DynamoDB table of forged ledger PutItem",
        15: "S3 access log operation field (GetObject bundle)",
        16: "CloudTrail trail verified before purge",
        17: "API action that destroyed queue evidence",
        18: "IAM user owning long-lived key that started chain",
    }
    print(f"[+] {len(E)} events | live-attack IP = {LIVE_IP}\n")
    for i in range(1, 19):
        print(f"Q{i:2}. {labels[i]:52} -> {ans[i]}")


if __name__ == "__main__":
    sys.exit(main())

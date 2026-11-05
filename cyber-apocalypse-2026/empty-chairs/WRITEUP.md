# Empty Chairs

**Cyber Apocalypse CTF 2026 — Cloud / DFIR (AWS CloudTrail + S3 access logs)**

> A road-watch post falls silent: warm fire pit, spears by the door, scouts gone. Elowen must follow the
> tracks and learn where the "Quiet Helpers" are taking the missing scouts.

A graded investigation: eighteen questions, no `HTB{}` flag. The digital story is a **scout-diversion
attack** — a contractor pivots into a dispatch role, injects a fraudulent "scout recall" order rerouting
the scouts to an enemy depot, forges the ledger, then purges the queue to hide the trail.

## Access

The briefing (`:31880`) serves read-only investigator creds at `/player-creds.json`
(`eastreach-investigator`). Point `AWS_ENDPOINT_URL` at the API port `:31003`. Primary evidence is
**`cloudtrail:LookupEvents`**; one answer needs an **S3 server access log** object.

```python
ct = boto3.client("cloudtrail", endpoint_url="http://154.57.164.75:31003", ...)
events = [json.loads(e["CloudTrailEvent"])
          for page in ct.get_paginator("lookup_events").paginate() for e in page["Events"]]
```

**3302 events.** Legitimate internal traffic (`eastreach-dispatcher`, `-relay-watch`, `-dispatch-lead`,
`-supply-clerk`) floods from `10.23.x.x`. The attacker is IAM user **`eastreach-contractor`** operating
from RFC5737 documentation IPs (`203.0.113.x` / `198.51.100.x`). For days they hammer
`AssumeRole eastreach-archive-reader` and get `AccessDenied`. The live attack lands from **`203.0.113.88`**.

## Attack chain (203.0.113.88 — user `eastreach-contractor`)

```
16:25:55  GetSecretValue eastreach/dispatch-signing-draft  AccessDenied   <- first denied probe
16:25:57  GetSecretValue eastreach/dispatch-signing        OK             <- signing secret obtained
16:25:57  AssumeRole     eastreach-archive-reader          AccessDenied   <- failed pivot (decoy role)
16:25:58  AssumeRole     eastreach-dispatch-role  sess=dispatch-runner  OK  <- PIVOT
--- calls below are recorded as userIdentity.type = AssumedRole ---
16:26:01  SendMessage    eastreach-scout-recall-pending
          body = {order_id: ER-DIV-9941, route_override: quietmarch-depot-11/bypass-C,
                  authorized_by: dispatch-runner, priority: URGENT}
16:26:02  Decrypt        alias/eastreach/watchpost-routing-key
16:26:02  Publish        sns:eastreach-diversion-alerts
16:26:02  PutItem        dynamodb:eastreach-watchpost-ledger    (forged ledger entry)
16:26:04  GetObject      s3://eastreach-watchpost-manifests/signed-routing-bundle.json
16:26:06  GetTrailStatus eastreach-watchpost-trail              (checks auditing is on)
16:26:07  PurgeQueue     eastreach-scout-recall-pending         (destroys queue evidence)
```

The contractor grabs the `eastreach-dispatch-signing` secret, fails the decoy `archive-reader` role, then
succeeds into `eastreach-dispatch-role` as session **`dispatch-runner`**. Under that role they drop a fake
recall order (`ER-DIV-9941`) rerouting scouts to `quietmarch-depot-11/bypass-C`, decrypt the routing
envelope, fire an SNS alert, write a forged ledger row, read the signed bundle, confirm the trail, and
`PurgeQueue` to wipe the SQS evidence.

**SQS handoff (Q1):** the last `ReceiveMessage` on `eastreach-scout-recall-pending` before the external
poller (`203.0.113.88`) read it came from internal IP `10.23.87.41`.

**S3 access log (Q15):** `ListBuckets` is denied, but the log objects in `eastreach-manifest-access-logs`
are directly readable. The entry for the bundle read shows the S3 `operation` field:

```
203.0.113.88 arn:aws:sts::719384620571:assumed-role/eastreach-dispatch-role/dispatch-runner
E1D3FA745BFE46AF REST.GET.OBJECT signed-routing-bundle.json "GET /.../signed-routing-bundle.json" 200 ...
```

## Answers

| #  | Question | Answer |
|----|----------|--------|
| 1  | Source IP of last ReceiveMessage before an external IP polls the same queue | `10.23.87.41` |
| 2  | External IP of the full diversion attack (incl. PurgeQueue) | `203.0.113.88` |
| 3  | Secret name on the first denied GetSecretValue | `eastreach/dispatch-signing-draft` |
| 4  | Secret read successfully before role assumption | `eastreach/dispatch-signing` |
| 5  | Role name failed to assume before the pivot | `eastreach-archive-reader` |
| 6  | Role ARN successfully assumed to control routing | `arn:aws:iam::719384620571:role/eastreach-dispatch-role` |
| 7  | roleSessionName on the successful AssumeRole | `dispatch-runner` |
| 8  | IAM identity type recorded after the pivot | `AssumedRole` |
| 9  | SQS queue targeted for the fraudulent recall | `eastreach-scout-recall-pending` |
| 10 | Injected `order_id` | `ER-DIV-9941` |
| 11 | `route_override` destination | `quietmarch-depot-11/bypass-C` |
| 12 | KMS keyId used to decrypt the routing envelope | `arn:aws:kms:us-east-1:719384620571:alias/eastreach/watchpost-routing-key` |
| 13 | SNS topic that received the diversion alert Publish | `eastreach-diversion-alerts` |
| 14 | DynamoDB table of the forged ledger PutItem | `eastreach-watchpost-ledger` |
| 15 | S3 access log `operation` field for the bundle GetObject | `REST.GET.OBJECT` |
| 16 | CloudTrail trail verified before purging | `eastreach-watchpost-trail` |
| 17 | API action that destroyed the queue evidence | `PurgeQueue` |
| 18 | IAM user owning the long-lived key that started the chain | `eastreach-contractor` |

Reproduce with `.venv/bin/python solve.py` (Q15 read from the `eastreach-manifest-access-logs` bucket).

# False Order

**Cyber Apocalypse CTF 2026 — Cloud / DFIR (AWS CloudTrail)**

> Caldrin knows Garran's orders carry small marks that copyists miss. He has to inspect the order, show
> the officer that it is false, and stop the unit from leaving before Vaultrune's soldiers reach the gate.

A graded investigation: twelve questions, no `HTB{}` flag. The "false order" is a **forged custody
ledger**: an attacker deleted the genuine east-gate order object and replaced it with a fake — and tried
to pin it on the internal clerk via a spoofed role-session name.

## Access

The briefing (`:30865`) serves read-only investigator creds at `/player-creds.json` (`gate-investigator`).
Point `AWS_ENDPOINT_URL` at the API port `:31608`. With read-only access, the tool that matters is
**`cloudtrail:LookupEvents`**.

```python
ct = boto3.client("cloudtrail", endpoint_url="http://154.57.164.75:31608", ...)
events = [json.loads(e["CloudTrailEvent"])
          for page in ct.get_paginator("lookup_events").paginate() for e in page["Events"]]
events.sort(key=lambda d: d["eventTime"])
```

**597 events.** Grouping by `sourceIPAddress` and `userIdentity` splits the noise from the signal:

- **`10.41.53.22`** — internal gatehouse IP, 548 events, legitimate `coalition-gate-clerk` activity. Goes
  quiet at `12:19:55`.
- **`198.18.44.91`** — external (TEST-NET) attacker IP, 21 events, IAM user `seal-copyist-contractor`.
- `127.0.0.1` — scenario setup (`root`). `38.226.149.3` — later `root` noise (all `AccessDenied`).

Account: `638291047582`.

## Attacker timeline (198.18.44.91 — user `seal-copyist-contractor`)

Hours of recon (12:20 → 15:19), then a sub-second destructive burst:

```
12:20:55.411  GetCallerIdentity                                              <- first attacker action
13:00:57.556  GetObject     AccessDenied  custody/east-gate-order.json       (first denied read probe)
13:56:29.656  AssumeRole    AccessDenied  role/ashguard-order-auditor  sess=seal-copyist-session
        ...   (ListBuckets / ListObjectsV2 recon across ashguard-* buckets)
15:19:58.930  GetObject     AccessDenied  custody/east-gate-order.json       (probe right before assume)
15:19:58.968  AssumeRole    AccessDenied  role/ashguard-order-auditor  sess=coalition-gate-clerk   <- failed
15:19:58.981  AssumeRole    OK            role/ashguard-order-scanner  sess=coalition-gate-clerk   <- success
15:19:59.563  DeleteObject                custody/east-gate-order.json       (removes the genuine order)
15:19:59.590  PutObject                   custody/east-gate-order.json       (uploads the forged ledger)
```

The attacker holds `seal-copyist-contractor`'s long-lived keys (`[REDACTED]`). Direct reads are
denied, and so is `ashguard-order-auditor`. They pivot to **`ashguard-order-scanner`**, which they *can*
assume, and — this is the "small mark a copyist misses" — pass `roleSessionName=coalition-gate-clerk` to
**frame the internal clerk**. Under that assumed role they `DeleteObject` the real order and `PutObject` a
forged replacement at the same key. The STS principal on the destructive calls is
`arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk`.

The tell that clears the clerk: every destructive call originates from the external IP `198.18.44.91` and
resolves to long-lived credentials owned by `seal-copyist-contractor`, **not** the clerk — the session
name is cosmetic and forgeable.

## Answers

| #  | Question | Answer |
|----|----------|--------|
| 1  | Last action from the internal gatehouse IP before the attacker session | `ListObjectsV2` |
| 2  | First action from the attacker IP | `GetCallerIdentity` |
| 3  | S3 action explicitly **denied** before assuming a role | `GetObject` |
| 4  | Full S3 path of the tampered object | `s3://ashguard-order-custody/custody/east-gate-order.json` |
| 5  | IAM role assumed for the destructive session (ARN) | `arn:aws:iam::638291047582:role/ashguard-order-scanner` |
| 6  | Full STS principal ARN on the `DeleteObject` call | `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk` |
| 7  | IP of the AssumeRole + destructive S3 calls | `198.18.44.91` |
| 8  | IAM username owning the long-lived creds used for AssumeRole | `seal-copyist-contractor` |
| 9  | Role name the attacker failed to assume first (name only) | `ashguard-order-auditor` |
| 10 | roleSessionName on the successful AssumeRole into the scanner role | `coalition-gate-clerk` |
| 11 | errorCode on the denied GetObject probe before role assumption | `AccessDenied` |
| 12 | S3 action marking the forged ledger upload after DeleteObject | `PutObject` |

Reproduce with `.venv/bin/python solve.py`.

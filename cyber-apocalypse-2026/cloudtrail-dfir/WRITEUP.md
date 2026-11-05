# Wrong Stamp

**Cyber Apocalypse CTF 2026 — Cloud / DFIR (AWS CloudTrail)**

> Stonepass's surviving CloudTrail history is the only record of activity surrounding the copied stamp.
> You hold read-only investigator access. Reconstruct the final recorded actions and determine which
> identity stopped the trail from logging.

A graded investigation: eight questions, no `HTB{}` flag.

## Access

The briefing (`:31732`) serves read-only investigator creds at `/player-creds.json`
(`stonepass-investigator`). Point `AWS_ENDPOINT_URL` at the API port `:31595`. With only read access, the
one tool that matters is **`cloudtrail:LookupEvents`**.

```python
ct = boto3.client("cloudtrail", endpoint_url="http://154.57.164.74:31595", ...)
events = [e for page in ct.get_paginator("lookup_events").paginate() for e in page["Events"]]
```

267 events, sorted by `eventTime`. Two days of legitimate `stonepass-warden` activity come from the
internal IP **10.30.41.118**. A short `root`@`127.0.0.1` burst is scenario setup. The **attacker session**
stands out: the same `stonepass-warden` credentials driven from an external IP, **192.0.2.55**.

## Attacker timeline (192.0.2.55)

```
06:01:00.726  GetTrailStatus   name=stonepass-audit-trail
06:01:03.159  DeleteTrail      name=stonepass-audit-trail        -> AccessDeniedException
06:01:05.135  ListBucket       bucket=stonepass-audit-trail-logs
06:01:07.154  ListObjectsV2    bucket=stonepass-audit-trail-logs
06:01:08.974  GetObject        key=AWSLogs/.../2026/06/24/audit.log.gz -> NoSuchKey
06:01:10.609  StopLogging      name=stonepass-audit-trail
```

The attacker probes the trail, tries to **delete** it (denied by policy), pokes at the log bucket, and —
unable to delete — falls back to **`StopLogging`** to blind the audit trail. The last legitimate action
from the internal IP just before this was `ListAccessKeys` (06:00:39).

## Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | Last action by the compromised user from the internal IP before the attacker session | `ListAccessKeys` |
| 2 | First action from the attacker IP | `GetTrailStatus` |
| 3 | Action attempted that was explicitly **denied** before the trail was stopped | `DeleteTrail` |
| 4 | S3 bucket the attacker enumerated before stopping the trail | `stonepass-audit-trail-logs` |
| 5 | Name of the CloudTrail trail that was stopped | `stonepass-audit-trail` |
| 6 | IAM username whose credentials disabled the trail | `stonepass-warden` |
| 7 | IP from which the trail was disabled | `192.0.2.55` |
| 8 | API action used to disable the audit trail | `StopLogging` |

Reproduce with `.venv/bin/python solve.py`.

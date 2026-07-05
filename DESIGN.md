# DESIGN.md — "ShopStack" CTF Challenge

> **Platform:** GZ::CTF (Dynamic Container, per-team instance)
> **Category:** Web → Pwn (chained)
> **Status:** Design blueprint. A separate build agent implements from this file. **No application code lives here.**
> **Source of truth:** This document. If any instruction here is ambiguous or physically impossible, the build agent must STOP and report rather than improvise.
>
> **Build phasing:** **Phase 1 (priority) = a working LOCAL Docker build the author can run and solve on their own machine.** **Phase 2 (later) = publish to a Harbor registry and wire into GZ::CTF** (config only, no code changes). The GZCTF-shaped constraints (no `EXPOSE`, `GZCTF_FLAG` env var with a local fallback, port 80 internal, non-root `web` + SUID) are baked in from Phase 1 **on purpose** — they cost nothing locally and mean Phase 2 is a config/push step, not a rebuild. Build and verify Phase 1 fully before touching Phase 2.

---

## 1. Overview & Theme

**ShopStack** is a deliberately vulnerable, lightweight fake e-commerce website ("your one-stop shop for artisanal keyboards"). It presents a public storefront and a hidden administrative panel. The challenge is a three-stage chain that takes the solver from an anonymous web visitor to reading a root-owned flag on the host.

The three stages are pedagogically distinct so the challenge teaches a recognizable, real-world kill chain rather than a single trick:

1. **Filtered SQL injection** authentication bypass — a naive blacklist filter blocks generic payloads, so the solver must craft a bypass tailored to *this* application (web foothold → admin).
2. **Server-Side Template Injection (SSTI)** in Jinja2 (admin → remote code execution → reverse shell as an unprivileged user `web`).
3. **Custom SUID binary abuse** — a root-owned SUID binary performs an arbitrary root file read (`functionbin -x /root/root.txt`), no full root shell required (unprivileged user → flag).

The design is deliberately constrained to a **single intended path** with all plausible shortcuts closed. This matters because the challenge is public-facing on GZCTF and the author intends to assist solvers; ambiguity or unintended solves would undermine both goals. Per-team instancing (GZCTF Dynamic Container) means each solver gets a throwaway box, so state-poisoning between solvers is not a concern.

---

## 2. Difficulty Rating & Target Solve Time

- **Overall difficulty:** Medium (HTB "Easy"–"Medium" box equivalent). Raised from the baseline because Stage 1 is a filtered/crafted injection rather than a copy-paste `' OR 1=1-- `.
- **Per-stage difficulty:**
  - Stage 1 (filtered SQLi bypass): Medium. Generic payloads fail; the solver must fingerprint the blacklist and build a challenge-specific payload.
  - Stage 2 (SSTI → RCE): Medium. Recognize `{{7*7}}=49`, then build a Jinja2 sandbox-escape RCE payload.
  - Stage 3 (SUID read): Easy–Medium. Local enumeration (`find / -perm -4000`) + reading the binary's `-x` usage; the `su -l` breadcrumb lowers difficulty.
- **Target solve time:** 60–120 minutes for a solver comfortable with web exploitation. This is a "learn the chain" challenge, not a rabbit-hole marathon.

---

## 3. Full Attack Chain — Stage by Stage

### Stage 1 — Filtered SQL Injection → Admin Panel

- **What the solver sees:** A storefront with a `/login` page (username + password). An `/admin` route redirects unauthenticated users back to login. Submitting an obvious injection like `' OR 1=1-- ` returns a generic "invalid input" / "login failed" — the payload is silently blocked by a filter. This is the key signal that the field is injectable but guarded.
- **What the solver does:** Fingerprints the blacklist by testing which tokens are rejected (spaces, `=`, `OR`, `--`). Realizing generic payloads are filtered, they craft a bypass using tokens the filter misses — SQLite inline comments `/**/` instead of spaces, an unterminated `/*` instead of `--`, `UNION SELECT` to pull the admin row, and `>` instead of `=`. A working payload logs them in as admin.
- **What the solver gets:** A valid authenticated admin session (session cookie) and access to `/admin`.

### Stage 2 — Jinja2 SSTI → Reverse Shell (`web`)

- **What the solver sees:** Inside `/admin`, a "Store Announcement" (banner/email template) feature that renders a live preview of what the admin types.
- **What the solver does:** Enters `{{7*7}}` and observes `49` in the preview — confirming server-side Jinja2 evaluation via `render_template_string()`. They then submit a Jinja2 sandbox-escape payload reaching an OS command primitive (e.g. `cycler.__init__.__globals__` → `os.popen`) and launch a reverse shell to their listener.
- **What the solver gets:** An interactive reverse shell as the unprivileged user **`web`** (confirmed via `id`), **not** root.

### Stage 3 — SUID Binary → Root File Read → Flag

- **What the solver sees:** As `web`, `cat /root/root.txt` is denied. `find / -perm -4000 -type f 2>/dev/null` reveals a non-standard root-owned SUID binary at `/usr/local/bin/functionbin`. Running `su -l` surfaces a stderr error that **names the binary** (intended breadcrumb from a broken wrapper in `web`'s shell profile).
- **What the solver does:** Inspects usage (`functionbin` with no args prints `usage: functionbin -x <path>`), learns it reads an arbitrary file as root, and runs:
  ```
  functionbin -x /root/root.txt
  ```
- **What the solver gets:** The contents of `/root/root.txt` — the flag. **No full root shell is required**; the arbitrary-read primitive alone suffices.

---

## 4. Vulnerability Details Per Stage (pseudocode level)

> The build agent implements real, working versions. Each vulnerable line must carry a comment: `# INTENTIONALLY VULNERABLE: <reason>`.

### Stage 1 — Filtered SQLi (blacklist + unsafe query construction)

```
# INTENTIONALLY VULNERABLE: naive blacklist filter + string-concatenated SQL
BLACKLIST = [" ", "=", "--", "or"]   # case-insensitive substring match

def filtered(s):
    low = s.lower()
    return any(tok in low for tok in BLACKLIST)

username = request.form["username"]
password = request.form["password"]

if filtered(username):
    return render("login.html", error="invalid input")   # blocks generic payloads

# INTENTIONALLY VULNERABLE: input concatenated directly into SQL after a weak filter
query = "SELECT id, username, is_admin FROM users " \
        "WHERE username = '" + username + "' AND password = '" + password + "'"
row = db.execute(query).fetchone()   # db opened READ-ONLY (see §9)
if row:
    session["user_id"] = row["id"]
    session["is_admin"] = row["is_admin"]
```

- **The flaw is the concatenation; the filter is only a speed bump.** The blacklist blocks spaces, `=`, the `OR` keyword, and `--` comments — which kills copy-paste payloads — but misses SQLite inline comments (`/**/`), unterminated block comments (`/*` runs to EOF in SQLite), `UNION`, and `>`.
- **Representative intended payload (username field):**
  ```
  '/**/UNION/**/SELECT/**/id,username,is_admin/**/FROM/**/users/**/WHERE/**/is_admin>0/*
  ```
  This makes the query:
  ```
  SELECT id, username, is_admin FROM users WHERE username = ''/**/UNION/**/SELECT/**/id,username,is_admin/**/FROM/**/users/**/WHERE/**/is_admin>0/*' AND password = '...'
  ```
  The first SELECT matches nothing (`username=''`); the UNION returns the admin row; the trailing `/*` comments the rest to end-of-input. Session is set to admin.
- **Build agent must verify:** generic payloads (`' OR 1=1-- `, `admin'-- `) are rejected by the filter, AND a crafted payload of the above class succeeds. The exact blacklist tokens may be tuned, but the property must hold: generic fails, a challenge-specific craft works, and it is solvable.
- The DB connection is opened **read-only** (`file:...?mode=ro`, `PRAGMA query_only=1`), so injection can `SELECT`/`UNION` but cannot `UPDATE`/`INSERT`/`DROP`.
- *(Optional variant, not required: a "second-order" version where a payload stored at registration is later used unsanitized in an admin-side query. Filtered login injection is the default because it is simpler to build and test deterministically.)*

### Stage 2 — SSTI (template rendered from user input)

```
# INTENTIONALLY VULNERABLE: attacker-controlled string passed to render_template_string
@app.route("/admin/announcement", methods=["POST"])
@admin_required
def announcement_preview():
    tpl = request.form["announcement"]           # attacker-controlled
    rendered = render_template_string(tpl)        # Jinja2 evaluates it server-side
    return render_template("admin.html", preview=rendered)
```

- `render_template_string` on raw user input is the flaw. `{{7*7}}` → `49` confirms.
- Guarded by `@admin_required`, so reachable **only after Stage 1**. This ordering is deliberate — SSTI must not be reachable pre-auth.

### Stage 3 — SUID arbitrary-read binary (C)

```
/* INTENTIONALLY VULNERABLE: SUID-root binary performs arbitrary file read with EUID 0 */
int main(int argc, char **argv) {
    /* usage: functionbin -x <path>  -> print <path> to stdout as root */
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
        /* does NOT drop privileges; opens argv[2] while EUID == 0 */
        FILE *f = fopen(argv[2], "r");
        if (!f) { perror("functionbin"); return 1; }
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
        fclose(f);
        return 0;
    }
    fprintf(stderr, "usage: functionbin -x <path>\n");
    return 2;
}
```

- Binary is `chown root:root` + `chmod u+s` (mode `4755`). It never drops privileges before `fopen`, so the read happens as root.
- Intended use is the read primitive only; any other invocation errors with the usage line (the author's "one function that works, rest fail" concept).

### Stage 3 breadcrumb — broken `su -l` wrapper

```
# In /home/web/.profile (or .bashrc):
# INTENTIONALLY a breadcrumb: emit a stderr hint naming functionbin on login / su -l
[ -x /usr/local/bin/functionbin ] && echo "notice: functionbin present; run 'functionbin' for usage" 1>&2
```

- Observable behavior is fixed: `su -l` (or logging in as `web`) must surface a stderr message naming `functionbin`, nudging toward the SUID binary **without** revealing the `-x /root/root.txt` answer.
- Must NOT be wired into PAM (a bad PAM edit can lock the container). Shell profile / MOTD / login banner only.

---

## 5. File / Repo Layout

```
shopstack/
├── DESIGN.md                 # This blueprint (already present).
├── app/
│   ├── app.py                # Flask app: filtered SQLi login, admin panel, SSTI announcement sink.
│   ├── db.py                 # Read-only SQLite connection helper (mode=ro, query_only=1).
│   ├── seed.sql              # Schema + admin user row. No guessable extra creds.
│   ├── requirements.txt      # Flask, gunicorn — pinned. Nothing else unless justified.
│   ├── templates/
│   │   ├── base.html         # Shared layout / storefront chrome.
│   │   ├── index.html        # Public storefront (product listing, flavor only).
│   │   ├── login.html        # Login form (filtered SQLi sink behind it).
│   │   └── admin.html        # Admin panel with the "Store Announcement" SSTI field + preview.
│   └── static/
│       └── style.css         # Minimal CSS. No build step, no JS framework.
├── privesc/
│   ├── functionbin.c         # SUID arbitrary-read binary source (-x <path>).
│   └── Makefile              # Builds functionbin.
├── entrypoint.sh             # Runtime: plant flags, fix perms/SUID, drop to web, start gunicorn.
├── Dockerfile                # python:3-slim build. NON-root web user. Builds functionbin. NO EXPOSE.
├── docker-compose.yml        # LOCAL testing only (not used by GZ::CTF). Injects a test GZCTF_FLAG.
└── SOLVE.md                  # (Produced later by the solve/QA agent, not the build agent.)
```

- No SPA, no bundler, no Node. Server-rendered Jinja2 + one CSS file only.
- `docker-compose.yml` exists **solely** for local build/test; production runs via GZ::CTF orchestration pulling the image from the registry (see §8).

---

## 6. Flag Handling

- **Root flag:** GZ::CTF injects a per-team flag as the environment variable **`GZCTF_FLAG`** at container start. `entrypoint.sh` reads it and writes it to **`/root/root.txt`**:
  - Owner `root:root`, mode `0400`. Written **before** privileges are dropped to `web`.
  - If `GZCTF_FLAG` is unset (local testing), fall back to `flag{local_test_placeholder}` so the box still builds and runs.
- **User flag (`user.txt`):** `/home/web/user.txt`, owner `web:web`, mode `0644`, readable once the reverse shell lands. A static, non-secret foothold marker (e.g. `SHOPSTACK{web_foothold_reached}`). **Not** the scored flag by default and must **never** contain the real `GZCTF_FLAG`.
- **Never** hardcode the real flag in the image, source, or seed data. Only path: `GZCTF_FLAG` → `/root/root.txt` at runtime.

---

## 7. Permissions & Users Table

| Path / Object                     | Owner        | Mode   | SUID | Notes                                                                 |
|-----------------------------------|--------------|--------|------|----------------------------------------------------------------------|
| App process (gunicorn)            | `web`        | —      | No   | Serves Flask; never runs as root.                                    |
| `/usr/local/bin/functionbin`      | `root:root`  | `4755` | **Yes** | The intended privesc primitive (arbitrary root read).            |
| `/root/root.txt`                  | `root:root`  | `0400` | No   | Scored flag; unreadable by `web` except via `functionbin -x`.       |
| `/home/web/user.txt`              | `web:web`    | `0644` | No   | Foothold marker; static, non-secret.                                |
| `/home/web/.profile` (breadcrumb) | `web:web`    | `0644` | No   | Emits stderr hint naming `functionbin`. Not PAM.                    |
| App source under `/app`           | `root:root`  | `0644` | No   | Owned by root, readable by `web`; `web` cannot modify app code.      |
| SQLite DB file                    | `root:root`  | `0644` | No   | Opened read-only by the app; `web` cannot write it.                 |
| Everything else                   | as base image| —      | No   | Only ONE non-standard SUID binary must exist beyond system defaults.|

**Invariant:** `find / -perm -4000 -type f 2>/dev/null` yields exactly one non-standard entry: `functionbin`.

---

## 8. Deployment — Phase 1 (local Docker) then Phase 2 (Harbor + GZ::CTF)

> Build and fully verify **Phase 1** before doing anything in Phase 2. Phase 2 requires **no code changes** — only a registry push and panel config.

### 8.1 PHASE 1 — Local build & test (the immediate goal, no registry needed)

This is what "done" means for the first pass: the image builds and the full three-stage chain is solvable on the author's own machine.

```
# from the shopstack/ directory
docker build -t shopstack:local .

# run locally with a fake flag to test the full chain end-to-end
docker run --rm -p 8080:80 -e GZCTF_FLAG='flag{local_test}' shopstack:local
# then browse http://localhost:8080 and solve it yourself:
#   Stage 1: craft the filtered-SQLi payload -> reach /admin
#   Stage 2: {{7*7}} -> 49 -> SSTI reverse shell as web
#   Stage 3: functionbin -x /root/root.txt -> see flag{local_test}
```

Optional convenience for local testing only (NOT used by GZ::CTF):
```
# docker-compose.yml sets GZCTF_FLAG and the port map for repeatable local runs
docker compose up --build
```

Phase 1 is complete when every item in §11 (Acceptance Criteria) passes locally.

### 8.2 PHASE 2 — Harbor registry (do later, config only)

Harbor is a private Docker registry (a self-hosted Docker Hub) that GZ::CTF pulls images from. Once Phase 1 works, the same image is pushed as-is — no rebuild of logic.

**Builder / devops** (whoever has Harbor access — may be the author later, or someone else):
```
docker build -t <harbor-host>/<project>/shopstack:latest .
docker login <harbor-host>            # Harbor username/password or robot account
docker push <harbor-host>/<project>/shopstack:latest
```
Hand the image path `<harbor-host>/<project>/shopstack:latest` to the GZCTF admin.

**One-time prerequisite (platform setup, not per-challenge):** GZ::CTF needs credentials to pull from Harbor — typically a Harbor **robot account** set as a registry/pull secret in the GZ::CTF deployment. If image pulls fail with an auth error, check this. Platform-admin task, outside the challenge repo.

### 8.3 PHASE 2 — GZ::CTF challenge config (enter in the admin panel — type: **Dynamic Container**)

| Field                | Value                                  | Rationale                                                              |
|----------------------|----------------------------------------|-----------------------------------------------------------------------|
| Challenge type       | Dynamic Container                      | Per-team isolated instance; kills cross-solver griefing & flag sharing.|
| Container image      | `<harbor-host>/<project>/shopstack:latest` | Image path from 8.2. This is what the admin pastes in.            |
| `ExposePort`         | `80`                                   | App listens on 80 inside the container. **Do NOT `EXPOSE` in Dockerfile** — GZ::CTF maps it to a random host port. |
| `MemoryLimit`        | `128` (MB)                             | Lightweight app.                                                      |
| `CPUCount`           | `1`                                    | No heavy compute.                                                    |
| `StorageLimit`       | `256` (MB)                             | Slim image + SQLite.                                                 |
| Network mode         | **Isolated**                           | Challenge hands out a shell; prevent egress / pivots.                |
| Flag template        | `flag{[TEAM_HASH]}`                    | Per-team unique flag via GZ::CTF `[TEAM_HASH]`; injected as `GZCTF_FLAG`.|

- **Do not** set `no-new-privileges` — it would neutralize the SUID privesc and break the intended path.
- Because the image already reads `GZCTF_FLAG` (with a local fallback) and listens on port 80 with no `EXPOSE`, moving from Phase 1 to Phase 2 requires **no image change** — just push and configure.

---

## 9. Hardening / Anti-Unintended-Solve Checklist

**Global**
- [ ] `DEBUG=False`, served via **gunicorn**, never the Flask dev server. → Closes the Werkzeug debugger-console RCE (classic Stage-2 shortcut).
- [ ] **No default / guessable credentials.** Admin password is random and never needed; only the SQLi gets in. → Prevents skipping Stage 1.
- [ ] App runs as **non-root `web`**; app source owned by root, not writable by `web`. → Prevents app tampering to shortcut later stages.
- [ ] **Only one** non-standard SUID binary (`functionbin`). → Prevents an alternate GTFOBins privesc.
- [ ] **Isolated network mode.** → Prevents using the shell to reach the internet or other infra.
- [ ] Pin dependency versions; only `Flask` + `gunicorn`. → Reduces incidental vulnerable surface.

**Stage 1 (filtered SQLi)**
- [ ] Blacklist blocks generic payloads (spaces, `=`, `OR`, `--`) → forces a challenge-specific craft, not copy-paste. → Delivers the "payload crafted for this challenge only" requirement.
- [ ] SQLite opened **read-only** (`mode=ro`, `PRAGMA query_only=1`), DB file not writable by `web`. → Injection cannot `UPDATE`/`DROP`; defense-in-depth on top of per-team instancing.
- [ ] Admin panel strictly gated by session set only via a successful login query. → No unauthenticated `/admin`.
- [ ] Filter is a speed bump, NOT real protection — a crafted payload must remain reliably solvable. → Prevents Stage 1 becoming an unsolvable guessing game.

**Stage 2 (SSTI)**
- [ ] SSTI sink **behind `@admin_required`**. → Not reachable pre-auth; enforces Stage 1 → 2 ordering.
- [ ] No file-upload, `pickle`, `eval`, or command-injection sink elsewhere. → SSTI is the single intended RCE.
- [ ] Reverse shell lands as `web`, never root. → Forces Stage 3.

**Stage 3 (SUID)**
- [ ] `functionbin` reads as EUID 0 and never drops privileges before `fopen`. → The intended primitive works.
- [ ] `/root/root.txt` mode `0400 root:root`. → Not directly readable by `web`.
- [ ] Breadcrumb via shell profile / MOTD only, **never PAM**. → Won't lock the box; names the binary without giving the exact answer.
- [ ] No `sudo` misconfig, no writable cron, no writable `PATH` dirs, no other SUID. → `functionbin -x` is the single intended privesc.

---

## 10. Hints (author-published, escalating — one per stage)

**Stage 1**
1. "The staff entrance trusts what you type a little too literally — but it's learned to slam the door on the usual tricks. The obvious key won't turn; you'll have to file down a new one that this particular lock doesn't recognize as a threat."

**Stage 2**
2. "Admins can preview announcements before they go out. The preview renders everything you write. Try a little math: does `{{7*7}}` become `49`?"

**Stage 3**
3. "You're in, but not all the way. Look for something that runs with more power than you have (`find / -perm -4000 -type f 2>/dev/null`) and read its usage carefully — you may not need a full shell, just a good read. Stuck? Try logging in properly and read the error."

> Publish hints progressively (locked / point-costed as the platform allows). Each hint points at the technique/location, never the exact payload.

---

## 11. Acceptance Criteria (build is verified against these)

The implementation is correct **only if all pass** on a freshly built container:

1. **Builds clean:** `docker build` completes with no errors; python:3-slim base; lightweight.
2. **No EXPOSE:** the Dockerfile contains no `EXPOSE`; app listens on port 80 internally.
3. **Stage 1 filter works:** generic payloads (`' OR 1=1-- `, `admin'-- `) are rejected as invalid input.
4. **Stage 1 crafted bypass works:** a challenge-specific payload of the documented class (e.g. the `/**/`+`UNION`+`/*` example) authenticates as admin and reaches `/admin`.
5. **Stage 1 negative:** a normal wrong username/password is rejected; no default creds work.
6. **Stage 2 confirm:** submitting `{{7*7}}` to the announcement field renders `49`.
7. **Stage 2 RCE:** an SSTI payload executes an OS command; a reverse-shell payload yields an interactive shell.
8. **Foothold identity:** the reverse shell reports `uid=…(web)` — **not** root. `/home/web/user.txt` is readable.
9. **Stage 3 blocked-then-unlocked:** as `web`, `cat /root/root.txt` → permission denied; `functionbin -x /root/root.txt` → prints the flag.
10. **Breadcrumb:** `su -l` (or a `web` login) surfaces a stderr message naming `functionbin`.
11. **SUID inventory:** `find / -perm -4000 -type f 2>/dev/null` lists exactly one non-standard binary, `functionbin` (`root:root`, `4755`).
12. **Flag plumbing:** `GZCTF_FLAG=flag{unit_test_value}` at container start results in that exact value in `/root/root.txt` (`root:root`, `0400`), retrievable via `functionbin -x`.
13. **No debug console:** the Werkzeug debugger is not reachable (DEBUG=False, gunicorn).
14. **Read-only DB:** an injected write attempt does not alter the database (connection is read-only).
15. **No unintended RCE:** no file upload, `eval`, `pickle`, or command-injection sink besides the intended SSTI.
16. **Single path holds:** the build report confirms each unintended path in §9 is closed, with the command/output used to verify.
17. **Local run smoke test:** `docker run -e GZCTF_FLAG=... -p 8080:80` serves the storefront and the full chain is solvable end-to-end locally.

> On completion, the build agent outputs a report mapping every criterion above to the command run and its observed result. Any deviation from this DESIGN.md must be flagged, not silently resolved.

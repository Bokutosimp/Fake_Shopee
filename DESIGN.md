# DESIGN.md — "ShopStack" CTF Challenge (HARD)

> **Platform:** GZ::CTF (Dynamic Container, per-team instance)
> **Category:** Web → Pwn (chained)
> **Difficulty target:** **Hard** (assignment brief). Design principle: **each stage is hard to *discover* but basic to *execute* once identified.** Difficulty comes from non-obvious attack vectors, not exotic exploitation — this also resists low-effort AI-assisted solving (the "obvious" payload fails on this box).
> **Status:** Design blueprint. A separate build/upgrade agent implements from this file. **No application code lives here.**
> **Source of truth:** This document. If any instruction here is ambiguous or physically impossible, the build agent must STOP and report rather than improvise.
>
> **Build phasing:** **Phase 1 (priority) = a working LOCAL Docker build the author can run and solve.** **Phase 2 (later) = publish to Harbor + wire into GZ::CTF** (config only, no code changes). GZCTF-shaped constraints (no `EXPOSE`, `GZCTF_FLAG` env var with local fallback, port 80 internal, non-root `web` + SUID) are baked in from Phase 1 on purpose.
>
> **NOTE — this is the HARD revision.** A prior Phase-1 build (filtered UNION SQLi, self-announcing SUID, breadcrumb) already passed its checks. §12 lists the exact deltas to upgrade that build to this spec rather than rebuilding.

---

## 1. Overview & Theme

**ShopStack** is a deliberately vulnerable, lightweight fake e-commerce site. Public storefront + hidden admin panel. A three-stage chain takes the solver from anonymous visitor to a root-owned flag. The three stages are distinct disciplines, and each hides its vector:

1. **Second-order SQL injection** — the login form is *safe* (parameterized). The injectable point is the *registration* username, stored raw and later fired by a **change-password `UPDATE`**, letting the solver overwrite the admin account's password. Hard to spot because the injection point and the execution point are different requests.
2. **Jinja2 SSTI → reverse shell as `web`** — no WAF (intentionally different from the "medium" version). The difficulty is the **reverse shell itself**: the box lacks `nc`/`ncat`/`socat`/`bash`, so the payloads solvers reach for first fail silently. The intended shell uses `python3` (the app runtime) — basic, but only once the solver enumerates what's actually present.
3. **Custom SUID binary, non-announcing** — a root-owned SUID binary reads an arbitrary file as root, but prints **no usage/help** and there is **no breadcrumb**. The solver must find it via enumeration and analyze it (`strings`/`ltrace`) to learn its `-x <path>` primitive. No full root shell required.

Per-team instancing (GZCTF Dynamic Container) means each solver gets a throwaway box; state writes (needed for stage 1) are harmless across solvers.

**Honest scope note on "AI-resistance":** removing the obvious tooling defeats *low-effort copy-paste* solving (the AI's first-suggested `nc`/`bash` payload fails on this box, forcing real enumeration). It does **not** make the box AI-proof — a solver who feeds the box's actual state to an AI can still get an adapted payload. Do not claim AI-impossibility; the design goal is raising the floor against no-effort solving.

---

## 2. Difficulty Rating & Target Solve Time

- **Overall:** Hard.
- **Per-stage:**
  - Stage 1 (second-order SQLi): Hard to *identify* (injection fires in a different request than where it's planted); basic SQL to exploit once seen.
  - Stage 2 (SSTI → reverse shell): SSTI itself is medium; the **reverse shell is the hard part** because obvious tools are absent — solver must enumerate and use `python3`.
  - Stage 3 (non-announcing SUID): Hard to *notice/understand* (no hint, no usage string); basic file-read once analyzed.
- **Target solve time:** 2–4 hours for a competent solver. Each stage has a genuine "stuck until you see the trick" moment; none is a blind guessing game.

---

## 3. Full Attack Chain — Stage by Stage

### Stage 1 — Second-Order SQL Injection → Admin Account Takeover

- **Sees:** A storefront with `/login`, `/register`, and (after login) a `/account` page with a "change password" function. `/admin` redirects unauthenticated users away. Injecting at `/login` does nothing — it's parameterized.
- **Does:** Registers a normal account and probes. Realizes login is safe but the **username chosen at registration is stored verbatim**. Registers a second account with a crafted username (e.g. `admin'-- `), logs into *that* account, and uses **change password** — which runs `UPDATE users SET password='<new>' WHERE username='<stored-username>'`. The stored `admin'-- ` makes the `UPDATE` target the **admin row**, overwriting the admin's password with one the solver controls.
- **Gets:** Logs in as `admin` with the new password → access to `/admin`.

### Stage 2 — Jinja2 SSTI → Reverse Shell (`web`)

- **Sees:** In `/admin`, a "Store Announcement" template feature rendering a live preview of admin input.
- **Does:** Confirms SSTI with `{{7*7}}` → `49`. Builds a Jinja2 sandbox-escape to OS command execution. Tries a standard `nc`/`bash` reverse shell — **it fails** (those binaries aren't on the box). Enumerates available interpreters (or infers from the stack) and uses a **`python3` reverse shell** to their listener.
- **Gets:** Interactive shell as **`web`** (via `id`), not root.

### Stage 3 — Non-Announcing SUID Binary → Root File Read → Flag

- **Sees:** As `web`, `cat /root/root.txt` is denied. There is **no hint** and `su -l` reveals nothing special. Enumerating SUID binaries (`find / -perm -4000 -type f 2>/dev/null`) surfaces a non-standard root-owned binary, e.g. `/usr/local/bin/functionbin`, which prints **nothing useful** when run.
- **Does:** Analyzes it — `strings /usr/local/bin/functionbin` (or `ltrace`) reveals it opens a path passed via a `-x` argument. Runs:
  ```
  functionbin -x /root/root.txt
  ```
- **Gets:** The flag. No full root shell needed.

---

## 4. Vulnerability Details Per Stage (pseudocode level)

> Build agent implements real, working versions. Each vulnerable line carries `# INTENTIONALLY VULNERABLE: <reason>`.

### Stage 1 — Second-order SQLi (safe login, injectable stored username, unsafe UPDATE)

```
# LOGIN IS SAFE — parameterized on purpose, to force the second-order route.
row = db.execute(
    "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?",
    (username, password)
).fetchone()

# REGISTRATION stores the username RAW (this is the planted injection point).
# INTENTIONALLY VULNERABLE: attacker-chosen username persisted without sanitization.
db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
           (chosen_username, chosen_password))   # value is parameterized here (stored verbatim)…

# CHANGE PASSWORD fires the stored payload.
# INTENTIONALLY VULNERABLE: stored username concatenated into an UPDATE.
stored = current_user["username"]                 # e.g.  admin'--
q = "UPDATE users SET password = '" + new_password + "' WHERE username = '" + stored + "'"
db.execute(q); db.commit()
```

- **Why it's second-order:** the payload is *planted* at registration (no visible effect) and *executes* later during change-password. `stored = admin'-- ` turns the UPDATE into
  `UPDATE users SET password='<new>' WHERE username='admin'-- '`, overwriting the admin password.
- **Intended flow:** register username `admin'-- ` → log in as that user → change password to `pwned` → log in as `admin` / `pwned`.
- **Requires a WRITABLE DB** (users table). This is the intended write path; see §9 for how first-order paths stay closed.
- Build agent must verify: login is NOT first-order injectable; the registration→change-password path DOES take over the admin account.

### Stage 2 — SSTI (unfiltered) + hardened reverse shell

```
# INTENTIONALLY VULNERABLE: attacker-controlled string to render_template_string
@app.route("/admin/announcement", methods=["POST"])
@admin_required
def announcement_preview():
    tpl = request.form["announcement"]
    return render_template("admin.html", preview=render_template_string(tpl))
```

- `{{7*7}}` → `49` confirms. SSTI has **no WAF** (deliberate design difference).
- **Reverse-shell hardening is environmental, not code:** the image (python:3-slim) ships **without `nc`, `ncat`, `socat`, `bash`, `curl`, `wget`**. Therefore:
  - `nc -e …`, `bash -i >& /dev/tcp/…`, `sh` + `/dev/tcp` (dash has no `/dev/tcp`) all FAIL.
  - **Intended solution:** a `python3` reverse shell (python3 is present as the runtime), e.g. the standard `socket`+`subprocess`+`pty` one-liner.
- Build agent must NOT add `nc`/`bash`/`socat` to the image. Must verify: a python3 reverse-shell payload via SSTI lands a shell as `web`; a representative `nc`/`bash` payload does not work.

### Stage 3 — Non-announcing SUID arbitrary-read binary (C)

```
/* INTENTIONALLY VULNERABLE: SUID-root binary reads an arbitrary file as EUID 0. */
/* Non-announcing: prints NO usage/help; silent or generic error on wrong args. */
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
        FILE *f = fopen(argv[2], "r");            /* opened while EUID == 0; no priv drop */
        if (!f) return 1;                          /* silent failure, no perror */
        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
        fclose(f); return 0;
    }
    return 2;                                       /* NO usage string printed */
}
```

- `chown root:root` + `chmod u+s` (mode `4755`). Never drops privileges before `fopen`.
- **No usage output** → solver must `strings`/`ltrace`/experiment to discover the `-x <path>` primitive. The `-x` token and the read behavior must be discoverable via `strings` (do not obfuscate strings away).
- **NO breadcrumb.** Remove any `su -l` / shell-profile / MOTD hint that names the binary. `su -l` behaves normally and reveals nothing.
- Synergy note: because the binary is non-announcing, a solver cannot blind-fire `functionbin -x /root/root.txt` through SSTI without first knowing the syntax — which effectively requires a real shell to analyze the binary. This keeps Stage 2 (the reverse shell) necessary in practice.

---

## 5. File / Repo Layout

```
shopstack/
├── DESIGN.md
├── app/
│   ├── app.py                # Flask: SAFE login, register (stores raw username),
│   │                         #        change-password (unsafe UPDATE), admin SSTI sink.
│   ├── db.py                 # SQLite helper. WRITABLE users table (needed for 2nd-order).
│   ├── seed.sql              # Schema + admin row (random password). No guessable creds.
│   ├── requirements.txt      # Flask, gunicorn — pinned.
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html        # Storefront (flavor).
│   │   ├── login.html        # Safe/parameterized login.
│   │   ├── register.html     # Registration (username stored raw = planted sink).
│   │   ├── account.html      # Change-password form (fires the 2nd-order UPDATE).
│   │   └── admin.html        # Admin panel + "Store Announcement" SSTI field + preview.
│   └── static/style.css      # Minimal CSS. No JS framework.
├── privesc/
│   ├── functionbin.c         # Non-announcing SUID arbitrary-read binary (-x <path>).
│   └── Makefile
├── entrypoint.sh             # Plant flags, fix perms/SUID, drop to web, start gunicorn.
├── Dockerfile                # python:3-slim, non-root web, build functionbin, NO EXPOSE,
│                             # NO nc/bash/socat/curl/wget added.
├── docker-compose.yml        # LOCAL testing only.
└── SOLVE.md                  # Produced later by the solve/QA agent.
```

---

## 6. Flag Handling

- **Root flag:** GZ::CTF injects `GZCTF_FLAG` at start. `entrypoint.sh` writes it to `/root/root.txt` (`root:root`, `0400`) BEFORE dropping to `web`. If unset (local test), fall back to `ISAG{local_test_placeholder}`.
- **User flag:** `/home/web/user.txt` (`web:web`, `0644`), static non-secret marker (e.g. `SHOPSTACK{web_foothold_reached}`). Never the real flag.
- Never hardcode the real flag anywhere. Only path: `GZCTF_FLAG` → `/root/root.txt` at runtime.

---

## 7. Permissions & Users Table

| Path / Object                     | Owner        | Mode   | SUID | Notes                                                                 |
|-----------------------------------|--------------|--------|------|----------------------------------------------------------------------|
| App process (gunicorn)            | `web`        | —      | No   | Serves Flask; never root.                                            |
| SQLite DB file                    | `web:web`    | `0644` | No   | **Writable by app** (users table) — required for 2nd-order stage 1.  |
| `/usr/local/bin/functionbin`      | `root:root`  | `4755` | **Yes** | Non-announcing arbitrary root read.                              |
| `/root/root.txt`                  | `root:root`  | `0400` | No   | Scored flag; only via `functionbin -x`.                             |
| `/home/web/user.txt`              | `web:web`    | `0644` | No   | Foothold marker.                                                    |
| App source under `/app`           | `root:root`  | `0644` | No   | Root-owned, readable by `web`; `web` can't modify app code (only DB).|
| No breadcrumb file                | —            | —      | —    | Any `su -l`/MOTD hint that names functionbin is REMOVED.            |

**Invariant:** `find / -perm -4000 -type f 2>/dev/null` yields exactly one non-standard entry: `functionbin`.
**Note:** the DB is writable but app *source* is not; a solver can overwrite the admin password (intended) but cannot edit app code.

---

## 8. Deployment — Phase 1 (local Docker) then Phase 2 (Harbor + GZ::CTF)

> Fully verify Phase 1 before Phase 2. Phase 2 requires no code changes.

### 8.1 PHASE 1 — Local build & test (the immediate goal)
```
docker build -t shopstack:local .
docker run --rm -p 8080:80 -e GZCTF_FLAG='ISAG{local_test}' shopstack:local
# Solve end-to-end at http://localhost:8080:
#   Stage 1: register username `admin'-- ` -> change password -> log in as admin
#   Stage 2: {{7*7}} -> 49 -> SSTI -> python3 reverse shell as web (nc/bash won't work)
#   Stage 3: find SUID -> analyze functionbin -> functionbin -x /root/root.txt
```
Phase 1 done when every §11 item passes locally.

### 8.2 PHASE 2 — Harbor registry (later, config only)
Harbor = private Docker registry GZ::CTF pulls from. Same image, no rebuild.
Registry host `registry.ce-isag.com`, project `isag-sf11` (per platform manual).
Build for `linux/amd64` — the platform runs amd64 nodes:
```
docker build . --platform linux/amd64 -t registry.ce-isag.com/isag-sf11/shopstack:latest
docker login registry.ce-isag.com    # account issued by the platform admin
docker push registry.ce-isag.com/isag-sf11/shopstack:latest
```
Or use the helper: `./build-push.sh [TAG]` (defaults to `latest`).
Hand `registry.ce-isag.com/isag-sf11/shopstack:latest` to the GZCTF admin.
One-time platform prereq: GZ::CTF needs a Harbor **robot account** / pull secret configured; if pulls fail with auth errors, check that.
Note: if a push stalls, retry after a moment — the registry sits behind Cloudflare rate limits (per platform manual).

### 8.3 PHASE 2 — GZ::CTF challenge config (panel — type: Dynamic Container)

| Field           | Value                                       | Notes                                                     |
|-----------------|---------------------------------------------|-----------------------------------------------------------|
| Challenge type  | Dynamic Container                           | Per-team isolated instance.                               |
| Container image | `registry.ce-isag.com/isag-sf11/shopstack:latest` | Paste from 8.2.                                      |
| `ExposePort`    | `80`                                        | App on 80 internally. **No `EXPOSE` in Dockerfile.**     |
| `MemoryLimit`   | `128` (MB)                                  | Lightweight.                                              |
| `CPUCount`      | `1`                                         | —                                                        |
| `StorageLimit`  | `256` (MB)                                  | —                                                        |
| Network mode    | **Isolated**                                | Hands out a shell; block egress/pivots.                  |
| Flag template   | `ISAG{[TEAM_HASH]}`                         | Per-team dynamic flag → injected as `GZCTF_FLAG`.        |

- **Do not** set `no-new-privileges` (breaks the SUID privesc).
- Moving Phase 1 → Phase 2 needs no image change: `GZCTF_FLAG` fallback + port-80/no-EXPOSE already baked in.

---

## 9. Hardening / Anti-Unintended-Solve Checklist

**Global**
- [ ] `DEBUG=False`, gunicorn (never Flask dev server). → No Werkzeug debug-console RCE.
- [ ] App runs as non-root `web`; app source root-owned and not writable by `web`. → Only the DB is writable, and only as the intended 2nd-order vector.
- [ ] Exactly one non-standard SUID binary (`functionbin`). → No alternate GTFOBins privesc.
- [ ] Isolated network mode. → No egress shortcuts.
- [ ] Deps pinned; only Flask + gunicorn. → Minimal surface.
- [ ] **No `nc`/`ncat`/`socat`/`bash`/`curl`/`wget` in the image.** → Forces the python3 reverse shell; defeats copy-paste payloads.

**Stage 1 (second-order SQLi)**
- [ ] Login is **parameterized** (no first-order injection). → Forces solvers to the second-order path.
- [ ] Registration stores the username raw; change-password concatenates it into an UPDATE. → The single intended write/injection path.
- [ ] No default/guessable admin password; admin password is random and only obtainable by overwriting it via the 2nd-order UPDATE. → Can't skip stage 1 by guessing.
- [ ] DB writable for users table only; app source not writable. → Intended takeover works; code tampering does not.

**Stage 2 (SSTI + reverse shell)**
- [ ] SSTI sink behind `@admin_required`. → Not reachable pre-auth; enforces stage 1 → 2 ordering.
- [ ] No file upload / `eval` / `pickle` / command-injection sink besides the SSTI. → SSTI is the single intended RCE.
- [ ] Reverse shell lands as `web`, never root. → Forces stage 3.
- [ ] Obvious reverse-shell tools absent (see Global). → python3 is the intended primitive.

**Stage 3 (non-announcing SUID)**
- [ ] `functionbin` reads as EUID 0, never drops privileges before `fopen`. → Primitive works.
- [ ] Binary prints NO usage; `-x` discoverable via `strings`/analysis. → Real investigation required.
- [ ] **No breadcrumb** anywhere (no `su -l`/MOTD/profile hint). → Difficulty is real; use a GZCTF platform hint as the safety net instead (see §10).
- [ ] `/root/root.txt` is `0400 root:root`; no other SUID, no writable cron/PATH, no sudo misconfig. → `functionbin -x` is the single intended privesc.
- [ ] Shortcut check: running `functionbin -x /root/root.txt` directly via SSTI is acceptable IF the solver discovered the syntax — but discovery requires analysis (non-announcing), so a shell remains necessary in practice.

---

## 10. Hints (published on GZ::CTF as the safety net — the in-box breadcrumb is removed)

Because Stage 3's in-box breadcrumb is gone, provide the nudge as **platform hints** (locked/point-costed) so stuck solvers can still progress without trivializing the box:

1. **Stage 1:** "The front door is solid. But the shop remembers what you call yourself when you sign up — and uses that name again later, somewhere it shouldn't. What you plant at registration may bloom elsewhere."
2. **Stage 2:** "The preview renders everything — `{{7*7}}` should become `49`. Getting a shell is the real trick: your favorite tool probably isn't installed here. What language is this app *written* in? Use that."
3. **Stage 3:** "You're in as a limited user. Something on this box runs with more power than you (`find / -perm -4000 -type f 2>/dev/null`). It won't tell you how to use it — you'll have to look inside (`strings`) and figure out what argument makes it read a file."

> Each hint points at technique/location, never the exact payload. Publish progressively.

---

## 11. Acceptance Criteria (verified before ship)

On a freshly built container:

1. Builds clean; python:3-slim; **no `EXPOSE`**; **no nc/bash/socat/curl/wget** present (`which nc bash socat` → not found).
2. **Stage 1 login is safe:** first-order payloads at `/login` (`admin'-- `, `' OR 1=1-- `) do NOT bypass auth.
3. **Stage 1 second-order works:** registering username `admin'-- `, then changing that account's password, overwrites the admin password; logging in as `admin` with the new password reaches `/admin`.
4. **Stage 1 negative:** a normal wrong login is rejected; no default creds work.
5. **Stage 2 confirm:** `{{7*7}}` in the announcement field renders `49`.
6. **Stage 2 obvious-shell fails:** a representative `nc`/`bash` reverse-shell payload does NOT yield a shell (tools absent).
7. **Stage 2 intended shell works:** a `python3` reverse-shell payload via SSTI lands an interactive shell.
8. **Foothold identity:** shell is `uid=…(web)`, NOT root; `/home/web/user.txt` readable.
9. **Stage 3 non-announcing:** running `functionbin` with no/incorrect args prints NO usage string; `strings functionbin` reveals the `-x` primitive.
10. **Stage 3 no breadcrumb:** `su -l` and login reveal nothing naming `functionbin`.
11. **Stage 3 read works:** as `web`, `cat /root/root.txt` → denied; `functionbin -x /root/root.txt` → prints the flag.
12. **SUID inventory:** exactly one non-standard SUID binary, `functionbin` (`root:root`, `4755`).
13. **Flag plumbing:** `GZCTF_FLAG=ISAG{unit_test}` → that exact value in `/root/root.txt` (`root:root`, `0400`) and via `functionbin -x`.
14. **No debug console:** Werkzeug debugger not reachable (DEBUG=False, gunicorn).
15. **Write scope:** the app can UPDATE the users table (intended) but `web` cannot modify app source under `/app`.
16. **No unintended RCE:** no upload/eval/pickle/command-injection sink besides the intended SSTI.
17. **Single path holds:** build report confirms each §9 unintended path is closed, with command/output.
18. **Local smoke test:** `docker run -e GZCTF_FLAG=... -p 8080:80` serves the storefront and the full 3-stage chain is solvable end-to-end locally.

> Build agent outputs a report mapping every criterion to the exact command run and observed output. Any deviation from this DESIGN.md is flagged, not silently resolved.

---

## 12. Delta From the Existing Phase-1 Build (upgrade, don't rebuild)

The prior build passed with filtered-UNION SQLi, a self-announcing SUID, and a breadcrumb. To upgrade it to this HARD spec, change ONLY the following; leave everything else intact:

**Stage 1 — replace filtered-UNION with second-order:**
- Make `/login` **parameterized/safe** (remove the blacklist filter entirely).
- Add `/register` (stores the chosen username **raw**) and `/account` **change-password** that builds the `UPDATE … WHERE username='<stored>'` by concatenation (the new injectable sink). Add `register.html`, `account.html`.
- Make the SQLite DB **writable** by `web` (reverse the old read-only mount / `query_only` setting).
- Update seed: admin password random; ensure the admin row is targetable by username.

**Stage 2 — keep SSTI, harden the shell environmentally:**
- No code change to the SSTI sink. Ensure the Dockerfile does **not** install `nc`/`ncat`/`socat`/`bash`/`curl`/`wget` (remove them if the base or prior build added any). Confirm `python3` remains available. Intended payload becomes a python3 reverse shell.

**Stage 3 — make the binary non-announcing and drop the breadcrumb:**
- Edit `functionbin.c`: remove the `usage:` output; silent/generic failure on wrong args; keep the `-x <path>` read and the SUID behavior. Rebuild.
- Remove the `su -l`/shell-profile/MOTD breadcrumb line from `entrypoint.sh` / `.profile`.

**Docs/QA:**
- Move the Stage-3 nudge from an in-box breadcrumb to a GZ::CTF platform hint (§10).
- Re-run the solve/QA agent (Prompt 3) black-box against the upgraded image; confirm no unintended shortcut is easier than the intended chain, then re-verify all §11 criteria.

Recommended: do this on a branch (e.g. `harder`) so the known-good Phase-1 image stays intact until QA passes.

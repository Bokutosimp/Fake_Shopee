# ShopStack

A deliberately vulnerable Flask storefront, packaged as a self-contained Docker CTF
challenge. Solvers start as an anonymous visitor and finish by reading a root-owned
flag, through a three-stage chain.

---

## ⚠️ This image is intentionally exploitable

Everything in here is broken on purpose. The container ships working SQL injection
and template-injection flaws and installs a **SUID-root binary that reads any file
as root**. Treat it accordingly:

- Run it **in Docker**, on a machine you don't mind losing.
- Never expose it to an untrusted network or the public internet.
- Never install any part of it — especially `privesc/functionbin.c` — on a real system.

It exists to be attacked in a controlled setting: CTFs, training labs, and
classrooms. Nothing more.

## Disclaimer

**ShopStack is fictional.** The storefront, its products, and its branding were
invented for this challenge. This project is not affiliated with, endorsed by, or
derived from Shopee or any other real retailer, and it does not imitate any real
company's site or systems.

---

## The challenge

A three-stage chain, each stage a different discipline. The design principle is that
every stage is **hard to discover but basic to execute once identified** — the
difficulty is in noticing the vector, not in exotic exploitation.

| Stage | Class | Gets you |
|-------|-------|----------|
| 1 | Second-order SQL injection | The admin panel |
| 2 | Jinja2 server-side template injection → RCE | A shell as the unprivileged `web` user |
| 3 | Linux SUID privilege escalation (arbitrary root read) | The flag |

**Difficulty:** Hard. **Target solve time:** 2–4 hours for a competent solver.

Stage 1 is hard to *identify* — the login form is safe, and the injection fires in a
different request from the one that plants it. Stage 2's SSTI is straightforward to
spot; getting a shell is the real work, because the obvious tooling isn't on the box.
Stage 3 is hard to *notice* — the binary announces nothing and there is no hint in
the box pointing at it.

> **A note on difficulty:** stripping the obvious tooling raises the floor against
> no-effort, copy-paste solving — the first payload most people (or their AI
> assistant) reach for fails here. It does not make the box AI-proof, and this repo
> doesn't claim otherwise. A solver who feeds the box's actual state to a model will
> still get a working adapted payload.

---

## Run it

```sh
docker compose up --build
```

Then open <http://localhost:8080>.

Or without compose:

```sh
docker build -t shopstack:local .
docker run --rm -p 8080:80 -e GZCTF_FLAG='flag{your_flag_here}' shopstack:local
```

The app listens on port **80 inside the container**. There is deliberately no
`EXPOSE` in the Dockerfile — the host, or your CTF platform, decides the outside port.

## How the flag works

The flag is injected at container start via the **`GZCTF_FLAG`** environment
variable. `entrypoint.sh` runs as root and, before dropping privileges:

1. Writes the flag to `/root/root.txt`, owned `root:root`, mode `0400` — so the
   unprivileged `web` user cannot read it directly.
2. **Unsets `GZCTF_FLAG`.** This matters: privileges are dropped with `setpriv`,
   which preserves the environment, so a flag left in the environment would be
   readable by the app process via `env` or `/proc/self/environ` — letting stage 2
   leak the flag and skip stage 3 entirely.
3. Plants a static, non-secret foothold marker at `/home/web/user.txt`.

If `GZCTF_FLAG` is unset, it falls back to `flag{local_test_placeholder}` so the box
still builds and runs locally.

**No real flag is ever committed to this repository.** Account passwords are not
committed either — `entrypoint.sh` generates them from `/dev/urandom` at every
container start, and they are never needed to solve the challenge.

---

## Layout

```
.
├── app/
│   ├── app.py            # Flask routes. Both intentional sinks live here,
│   │                     # each marked `# INTENTIONALLY VULNERABLE`.
│   ├── db.py             # SQLite connection helper.
│   ├── seed.sql          # Schema + seed rows; passwords filled in at runtime.
│   ├── requirements.txt  # Flask + gunicorn, pinned.
│   ├── static/style.css  # One stylesheet. No build step, no JS framework.
│   └── templates/        # base, index, login, register, account, admin
├── privesc/
│   ├── functionbin.c     # The SUID helper installed to /usr/local/bin.
│   └── Makefile          # Builds it statically.
├── Dockerfile            # Multi-stage: compile the binary, then a slim runtime.
├── docker-compose.yml    # Local testing only.
├── entrypoint.sh         # Runs as root: plant flag, seed DB, set SUID, drop to `web`.
└── CHALLENGE.md          # Player-facing brief (EN + TH).
```

Roughly 200 lines of Python and 25 lines of C. It is meant to be read.

## How it's put together

A few choices look odd until you know why:

- **Served by gunicorn with `DEBUG=False`.** The Flask dev server's Werkzeug
  debugger is a console-shaped shortcut straight past stage 2, so it never runs.
- **App source is root-owned and not writable by `web`.** A solver who lands a shell
  can't patch the app to skip ahead. The SQLite database *is* writable — that's
  required by stage 1 — but it lives in `/home/web`, outside the root-owned `/app`.
- **Multi-stage build.** `functionbin` is compiled statically in a throwaway stage,
  so the ~180MB gcc toolchain never reaches the final image and there is no compiler
  on the challenge box.
- **Common reverse-shell tooling is removed.** `bash`, `nc`, `ncat`, `netcat`,
  `socat`, `curl`, `wget`, and `telnet` are deleted from the runtime image, and
  `web`'s shell is `/bin/sh` (dash). `python3` remains — it's the app runtime.
- **Exactly one non-standard SUID binary.** `find / -perm -4000 -type f` should turn
  up `functionbin` and nothing else unusual, so there's no alternate GTFOBins route.
- **No default or guessable credentials**, and no second privesc path — the chain has
  a single intended solution.

---

## Hosting it on a CTF platform

Built for GZ::CTF as a **Dynamic Container** challenge (one throwaway instance per
team), but nothing here is GZ::CTF-specific beyond the `GZCTF_FLAG` variable name.

Push the image to whatever registry your platform pulls from:

```sh
docker build . --platform linux/amd64 -t <your-registry>/<your-project>/shopstack:latest
docker login <your-registry>
docker push <your-registry>/<your-project>/shopstack:latest
```

Suggested challenge settings:

| Field | Value |
|-------|-------|
| Challenge type | Dynamic Container (per-team instance) |
| Exposed port | `80` |
| Memory limit | 128 MB |
| CPU count | 1 |
| Storage limit | 256 MB |
| Network mode | Isolated |

Two things to get right:

- **Do not set `no-new-privileges`.** It neutralises the SUID binary and makes stage 3
  unsolvable.
- **Use isolated networking.** The challenge hands out a shell; don't let it reach
  the rest of your infrastructure.

Stage 1 writes to the database, so give each team its own instance rather than
sharing one box.

---

## Hints

These are the escalating hints to publish alongside the challenge — one per stage,
progressively unlocked. Each points at a technique or a location; none gives a
payload or an answer.

<details>
<summary>Show hints</summary>

1. **Stage 1** — "The front door is solid. But the shop remembers what you call
   yourself when you sign up — and uses that name again later, somewhere it
   shouldn't. What you plant at registration may bloom elsewhere."

2. **Stage 2** — "The preview renders everything — `{{7*7}}` should become `49`.
   Getting a shell is the real trick: your favorite tool probably isn't installed
   here. What language is this app *written* in? Use that."

3. **Stage 3** — "You're in as a limited user. Something on this box runs with more
   power than you (`find / -perm -4000 -type f 2>/dev/null`). It won't tell you how
   to use it — you'll have to look inside (`strings`) and figure out what argument
   makes it read a file."

</details>

No solution walkthrough is published here. The source is in the repository, so
reading it will spoil the challenge — if you intend to solve it, run the container
and start from the storefront instead.

---

## License

MIT — see [LICENSE](LICENSE).

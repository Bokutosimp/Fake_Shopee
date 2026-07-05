# ShopStack — deliberately vulnerable CTF challenge image (HARD revision).
# NOTE: no EXPOSE on purpose. GZ::CTF maps the internal port 80 to a random host
# port; declaring EXPOSE is unnecessary and deviates from the platform contract.
#
# Multi-stage: the SUID binary is compiled in a throwaway `build` stage, so the
# ~180MB toolchain (gcc/libc6-dev/make) never lands in the final image. This
# keeps every runtime layer under Cloudflare's ~100MB per-blob push limit AND
# removes compilers from the challenge box (extra hardening). functionbin is
# built -static (see privesc/Makefile), so it needs no libs at runtime.

# --- Build stage: compile the static SUID binary ----------------------------
FROM python:3-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        make \
    && rm -rf /var/lib/apt/lists/*
COPY privesc/ /tmp/privesc/
RUN make -C /tmp/privesc

# --- Runtime stage ----------------------------------------------------------
FROM python:3-slim

# Runtime-only tooling: sqlite3 CLI (seed DB), util-linux (setpriv), passwd (su).
RUN apt-get update && apt-get install -y --no-install-recommends \
        sqlite3 \
        util-linux \
        passwd \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged runtime user. The app and reverse shell run as `web`, never root.
# Shell is /bin/sh (dash) — bash is removed below, so the intended reverse shell
# must be built with python3, not bash/nc.
RUN useradd --create-home --shell /bin/sh web

# --- Python app --------------------------------------------------------------
WORKDIR /app
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/
# App source owned by root, readable but not writable by web.
RUN chown -R root:root /app && chmod -R 0644 /app \
    && find /app -type d -exec chmod 0755 {} \;

# --- Install the SUID privesc binary (compiled in the build stage) ----------
COPY --from=build /tmp/privesc/functionbin /usr/local/bin/functionbin
RUN chown root:root /usr/local/bin/functionbin \
    && chmod 4755 /usr/local/bin/functionbin

# --- Environmental hardening (Stage 2) --------------------------------------
# Remove common reverse-shell / download tools so the obvious payloads fail and
# the intended solution is a python3 reverse shell. python3 stays (it IS the base).
RUN for t in bash nc ncat netcat socat curl wget telnet; do \
        for d in /bin /usr/bin /usr/local/bin; do rm -f "$d/$t"; done; \
    done

# --- Entrypoint --------------------------------------------------------------
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# Starts as root (to plant flags + set SUID), then drops to web for gunicorn.
ENTRYPOINT ["/entrypoint.sh"]

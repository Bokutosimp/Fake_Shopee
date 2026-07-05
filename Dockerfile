# ShopStack — deliberately vulnerable CTF challenge image (HARD revision).
# NOTE: no EXPOSE on purpose. GZ::CTF maps the internal port 80 to a random host
# port; declaring EXPOSE is unnecessary and deviates from the platform contract.
FROM python:3-slim

# Build tooling for the SUID binary + sqlite3 CLI + util-linux (setpriv) and su.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        make \
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

# --- Build the SUID privesc binary ------------------------------------------
COPY privesc/ /tmp/privesc/
RUN make -C /tmp/privesc \
    && cp /tmp/privesc/functionbin /usr/local/bin/functionbin \
    && chown root:root /usr/local/bin/functionbin \
    && chmod 4755 /usr/local/bin/functionbin \
    && rm -rf /tmp/privesc

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

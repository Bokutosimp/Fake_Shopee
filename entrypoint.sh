#!/bin/sh
# ShopStack container entrypoint.
# Runs as root: plants flags, seeds the DB with a random admin password, fixes
# permissions + SUID, then drops to the unprivileged `web` user to run gunicorn.
set -eu

# DB lives in web's home so `web` can write it (registration + change-password).
# App source under /app stays root-owned and NOT writable by web.
DB_PATH="/home/web/shopstack.db"
export SHOPSTACK_DB="$DB_PATH"

# --- Root flag ---------------------------------------------------------------
# GZ::CTF injects the per-team flag as $GZCTF_FLAG. Fall back to a placeholder for
# local testing. Written BEFORE privileges are dropped.
# NOTE: an explicit if-check, not ${VAR:-default}, because the flag contains '{'
# and '}' and POSIX ${...} expansion ends at the first '}', which would corrupt it.
if [ -n "${GZCTF_FLAG:-}" ]; then
    FLAG="$GZCTF_FLAG"
else
    FLAG="ISAG{local_test_placeholder}"
fi
printf '%s\n' "$FLAG" > /root/root.txt
chown root:root /root/root.txt
chmod 0400 /root/root.txt

# Scrub the flag from the environment. setpriv (below) preserves the env, so if
# GZCTF_FLAG stayed set it would be inherited by gunicorn and readable as `web`
# via `env` / /proc/self/environ — letting an SSTI RCE read the flag directly and
# skip the Stage-3 SUID read entirely. Unset it now that /root/root.txt is written.
unset GZCTF_FLAG

# --- User (foothold) flag ----------------------------------------------------
# Static, non-secret marker. Never contains the real flag.
printf '%s\n' "SHOPSTACK{web_foothold_reached}" > /home/web/user.txt
chown web:web /home/web/user.txt
chmod 0644 /home/web/user.txt

# --- Seed the database with random, never-needed passwords -------------------
# Passwords are long random hex; the challenge is solved via SQLi, never login.
ADMIN_PW="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CUSTOMER_PW="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

rm -f "$DB_PATH"
sed -e "s/__ADMIN_PASSWORD__/${ADMIN_PW}/" \
    -e "s/__CUSTOMER_PASSWORD__/${CUSTOMER_PW}/" \
    /app/seed.sql | sqlite3 "$DB_PATH"

# DB owned by web so the app (running as web) can INSERT/UPDATE. The containing
# directory /home/web is web-owned too, so SQLite can create its journal/WAL files.
chown web:web "$DB_PATH"
chmod 0644 "$DB_PATH"

# Shared Flask session secret for all gunicorn workers (fresh per container).
SHOPSTACK_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export SHOPSTACK_SECRET

# --- SUID privesc binary -----------------------------------------------------
chown root:root /usr/local/bin/functionbin
chmod 4755 /usr/local/bin/functionbin

# --- Drop privileges and start the app ---------------------------------------
# gunicorn binds port 80 (internal only; GZ::CTF maps it). DEBUG stays off.
cd /app
exec setpriv --reuid web --regid web --init-groups \
    gunicorn --bind 0.0.0.0:80 --workers 2 --chdir /app app:app

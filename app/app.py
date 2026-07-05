"""ShopStack — deliberately vulnerable CTF web app.

Stage 1: filtered SQL injection auth bypass on /login.
Stage 2: Jinja2 SSTI via render_template_string on /admin/announcement.

Both flaws are intentional and marked with `# INTENTIONALLY VULNERABLE`.
Served in production by gunicorn with DEBUG disabled.
"""

import os
from functools import wraps

from flask import (
    Flask,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)

from db import get_db

app = Flask(__name__)
# Session signing key. Sourced from the environment so every gunicorn worker in a
# container shares the same key (a per-process os.urandom() would make sessions
# break across workers). entrypoint.sh sets SHOPSTACK_SECRET to a fresh random
# value per container start; the fallback keeps local `python app.py` working.
app.secret_key = os.environ.get("SHOPSTACK_SECRET", os.urandom(32).hex())

# INTENTIONALLY VULNERABLE: naive blacklist filter. Blocks the tokens used by
# copy-paste payloads (spaces, '=', the OR keyword, '--' comments) but misses
# SQLite inline comments (/**/), unterminated block comments (/*), UNION and '>'.
BLACKLIST = [" ", "=", "--", "or"]

PRODUCTS = [
    {"name": "Artisan Alpha", "desc": "Hand-lubed linear switches, walnut case.", "price": "189.00"},
    {"name": "Tactile Tourmaline", "desc": "Brass plate, PBT keycaps, 65% layout.", "price": "159.00"},
    {"name": "Clicky Cobalt", "desc": "Box jade switches for the brave.", "price": "142.50"},
    {"name": "Silent Slate", "desc": "Silent tactiles, gasket mount.", "price": "205.00"},
    {"name": "Retro Ruby", "desc": "Dye-sub SA profile, dedicated numpad.", "price": "171.00"},
    {"name": "Mecha Mint", "desc": "Low-profile, hot-swap, RGB underglow.", "price": "133.00"},
]


def filtered(s):
    """Case-insensitive substring blacklist check."""
    low = s.lower()
    return any(tok in low for tok in BLACKLIST)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    return render_template("index.html", products=PRODUCTS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Filter is applied to the username field — the injection sink for this stage.
    if filtered(username):
        return render_template("login.html", error="invalid input")

    # INTENTIONALLY VULNERABLE: user input concatenated directly into SQL after a
    # weak blacklist. The concatenation is the real flaw; the filter is a speed bump.
    query = (
        "SELECT id, username, is_admin FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )

    try:
        db = get_db()
        row = db.execute(query).fetchone()
    except Exception:
        return render_template("login.html", error="login failed")
    finally:
        try:
            db.close()
        except Exception:
            pass

    if row:
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_admin"] = row["is_admin"]
        if row["is_admin"]:
            return redirect(url_for("admin"))
        return redirect(url_for("index"))

    return render_template("login.html", error="login failed")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html", preview=None)


@app.route("/admin/announcement", methods=["POST"])
@admin_required
def announcement_preview():
    tpl = request.form.get("announcement", "")
    # INTENTIONALLY VULNERABLE: attacker-controlled string passed to
    # render_template_string, so Jinja2 evaluates it server-side (SSTI -> RCE).
    # Reachable only after Stage 1 thanks to @admin_required.
    rendered = render_template_string(tpl)
    return render_template("admin.html", preview=rendered)


if __name__ == "__main__":
    # Local dev only. Production uses gunicorn with DEBUG=False (see entrypoint.sh).
    app.run(host="0.0.0.0", port=80, debug=False)

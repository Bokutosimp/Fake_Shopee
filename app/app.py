"""ShopStack — deliberately vulnerable CTF web app (HARD revision).

Stage 1: SECOND-ORDER SQL injection. /login is parameterized and safe. /register
         stores the chosen username RAW. /account change-password concatenates that
         stored username into an UPDATE, so a username registered as `admin'-- `
         rewrites the admin account's password.
Stage 2: Jinja2 SSTI via render_template_string on /admin/announcement.

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
# Shared session secret across gunicorn workers (set per container in entrypoint.sh).
app.secret_key = os.environ.get("SHOPSTACK_SECRET", os.urandom(32).hex())

PRODUCTS = [
    {"name": "Artisan Alpha", "desc": "Hand-lubed linear switches, walnut case.", "price": "189.00"},
    {"name": "Tactile Tourmaline", "desc": "Brass plate, PBT keycaps, 65% layout.", "price": "159.00"},
    {"name": "Clicky Cobalt", "desc": "Box jade switches for the brave.", "price": "142.50"},
    {"name": "Silent Slate", "desc": "Silent tactiles, gasket mount.", "price": "205.00"},
    {"name": "Retro Ruby", "desc": "Dye-sub SA profile, dedicated numpad.", "price": "171.00"},
    {"name": "Mecha Mint", "desc": "Low-profile, hot-swap, RGB underglow.", "price": "133.00"},
]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


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

    # SAFE: parameterized query — first-order injection at /login does not work.
    db = get_db()
    try:
        row = db.execute(
            "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
    finally:
        db.close()

    if row:
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_admin"] = row["is_admin"]
        if row["is_admin"]:
            return redirect(url_for("admin"))
        return redirect(url_for("account"))

    return render_template("login.html", error="login failed")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        return render_template("register.html", error="username and password required")

    db = get_db()
    try:
        # INTENTIONALLY VULNERABLE: the username is stored RAW (no sanitization). The
        # INSERT itself is parameterized, so the exact bytes — including quotes and
        # `--` — are persisted verbatim, planting the second-order injection payload
        # that /account later concatenates into an UPDATE.
        db.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (username, password),
        )
        db.commit()
    except Exception:
        return render_template("register.html", error="username already taken")
    finally:
        db.close()

    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "GET":
        return render_template("account.html", username=session.get("username"))

    new_password = request.form.get("new_password", "")
    stored_username = session.get("username", "")

    # INTENTIONALLY VULNERABLE: the raw-stored username is concatenated directly into
    # an UPDATE (second-order SQLi). A user registered as `admin'-- ` makes this:
    #   UPDATE users SET password='<new>' WHERE username='admin'-- '
    # which rewrites the admin row's password instead of the attacker's own.
    query = (
        "UPDATE users SET password = '" + new_password + "' "
        "WHERE username = '" + stored_username + "'"
    )
    db = get_db()
    try:
        db.execute(query)
        db.commit()
    except Exception:
        return render_template("account.html", username=stored_username, error="update failed")
    finally:
        db.close()

    return render_template("account.html", username=stored_username, message="password updated")


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
    app.run(host="0.0.0.0", port=80, debug=False)

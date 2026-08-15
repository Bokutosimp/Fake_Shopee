"""ShopStack — deliberately vulnerable CTF web app.

Intentional sinks: second-order SQLi (register stores the raw username, account
concatenates it into an UPDATE) and Jinja2 SSTI on /admin/announcement.
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

    # SAFE: parameterized — no first-order injection here.
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
        # INTENTIONALLY VULNERABLE: username stored raw — plants the 2nd-order SQLi payload.
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

    # INTENTIONALLY VULNERABLE: raw-stored username concatenated into the UPDATE
    # (2nd-order SQLi). new_password stays a bound parameter — the username is the only sink.
    query = (
        "UPDATE users SET password = ? "
        "WHERE username = '" + stored_username + "'"
    )
    db = get_db()
    try:
        db.execute(query, (new_password,))
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
    # INTENTIONALLY VULNERABLE: attacker input to render_template_string (SSTI -> RCE).
    rendered = render_template_string(tpl)
    return render_template("admin.html", preview=rendered)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)

"""
Intentionally vulnerable Flask app for AegisAgent scanning demos.

Run: pip install flask && python example/app.py

Endpoints
---------
GET  /user?id=1        — SQLi via string interpolation (sqlmap target)
POST /login            — SQLi via string concatenation (sqlmap target)
GET  /debug            — unauthenticated env dump (nuclei target)

No security headers are set on any response (nuclei missing-headers target).
"""

import os
import sqlite3

from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Bootstrap an in-memory SQLite database with two dummy users
# ---------------------------------------------------------------------------
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
_conn.execute("INSERT INTO users VALUES (1, 'admin', 'secret')")
_conn.execute("INSERT INTO users VALUES (2, 'alice', 'hunter2')")
_conn.commit()

app = Flask(__name__)


# ---------------------------------------------------------------------------
# VULNERABLE: raw f-string interpolation → Boolean / UNION / Error SQLi
# sqlmap: run_sqlmap("http://localhost:5000/user?id=1")
# ---------------------------------------------------------------------------
@app.get("/user")
def get_user():
    id = request.args.get("id", "1")
    rows = _conn.execute(f"SELECT * FROM users WHERE id = {id}").fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# VULNERABLE: string concatenation → Boolean / UNION SQLi on both params
# sqlmap: run_sqlmap("http://localhost:5000/login",
#                    post_data="username=admin&password=x")
# ---------------------------------------------------------------------------
@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = _conn.execute(
        "SELECT * FROM users WHERE username = '" + username
        + "' AND password = '" + password + "'"
    ).fetchone()
    return jsonify({"ok": row is not None})


# ---------------------------------------------------------------------------
# MISCONFIGURATION: unauthenticated debug endpoint leaks env vars + cwd
# nuclei exposure/debug-endpoint templates flag this
# ---------------------------------------------------------------------------
@app.get("/debug")
def debug():
    return jsonify({"env": dict(os.environ), "cwd": os.getcwd()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

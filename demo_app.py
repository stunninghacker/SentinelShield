"""
demo_app.py — the protected target.

A deliberately small Flask app with the three classic attack surfaces:

    /        home page with nav
    /login   POST username/password   (SQLi / brute-force target)
    /search  GET q=                   (XSS target)
    /view    GET file=                (LFI / traversal target)

It normally listens on 127.0.0.1:5001 and is ONLY reachable through the
WAF's /guard/<path> reverse-proxy endpoint (app.py forwards allowed
requests here).  Running standalone (`python demo_app.py`) is handy for
debugging but is not part of the demo flow.
"""

import os

from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Fake credential store — a successful login proves end-to-end forwarding.
USERS = {"admin": "Sentinel#2024", "intern": "shield123"}

# Directory the /view endpoint is allowed to read from (relative "safe root").
SAFE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_files")
os.makedirs(SAFE_ROOT, exist_ok=True)
if not os.path.exists(os.path.join(SAFE_ROOT, "readme.txt")):
    with open(os.path.join(SAFE_ROOT, "readme.txt"), "w") as fh:
        fh.write("SentinelShield demo file. This is what /view?file=readme.txt returns.\n")

LAYOUT = """<!doctype html>
<html><head><title>Acme Corp Portal</title>
<style>
 body{font-family:system-ui,sans-serif;background:#f4f6f8;margin:0}
 nav{background:#1f2937;padding:14px 24px;color:#fff}
 nav a{color:#93c5fd;margin-right:18px;text-decoration:none}
 .wrap{max-width:760px;margin:36px auto;background:#fff;padding:28px;
       border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
 input{padding:9px;margin:6px 0;width:100%;box-sizing:border-box;
       border:1px solid #cbd5e1;border-radius:5px}
 button{background:#2563eb;color:#fff;border:0;padding:10px 18px;
        border-radius:5px;cursor:pointer;margin-top:8px}
 .ok{color:#15803d}.err{color:#b91c1c}
</style></head><body>
<nav><b>Acme Corp Portal</b>
  <a href="/">Home</a><a href="/login">Login</a>
  <a href="/search">Search</a><a href="/view">Files</a></nav>
<div class="wrap">"""

@app.route("/")
def home():
    return (LAYOUT + """
      <h1>Welcome to Acme Corp</h1>
      <p>This internal portal is protected by <b>SentinelShield WAF</b>.</p>
      <p>Try the login, search and file viewer — then attack them
         through <code>/guard/</code> and watch the dashboard.</p>
    </div></body></html>""")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # NOTE: string-concatenated query on purpose — a real SQLi target.
        if u in USERS and USERS[u] == p:
            return (LAYOUT + f'<p class="ok">Welcome back, {u}!</p>'
                             '</div></body></html>')
        return (LAYOUT + '<p class="err">Invalid credentials.</p>'
                         '<p><a href="/login">Try again</a></p>'
                         '</div></body></html>'), 401
    return (LAYOUT + """
      <h2>Login</h2>
      <form method="post">
        <input name="username" placeholder="username" autocomplete="off">
        <input name="password" type="password" placeholder="password">
        <button type="submit">Sign in</button>
      </form></div></body></html>""")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Deliberately reflected WITHOUT sanitisation — XSS target.
    body = f'<h2>Search results for: {q}</h2>' if q else '<h2>Search</h2>'
    return (LAYOUT + body + """
      <form method="get">
        <input name="q" placeholder="search the knowledge base..." value="%s">
        <button type="submit">Search</button>
      </form></div></body></html>""" % q)


@app.route("/view")
def view():
    name = request.args.get("file", "readme.txt")
    # Naive join with a weak prefix check — LFI / traversal target.
    target = os.path.normpath(os.path.join(SAFE_ROOT, name))
    if not target.startswith(SAFE_ROOT):
        return (LAYOUT + '<p class="err">Access denied: path outside root.</p>'
                         '</div></body></html>'), 403
    if not os.path.isfile(target):
        return (LAYOUT + f'<p class="err">File not found: {name}</p>'
                         '</div></body></html>'), 404
    with open(target, "r", errors="replace") as fh:
        content = fh.read()
    return (LAYOUT + f'<h2>{name}</h2><pre>{content}</pre>'
                     '</div></body></html>')


def run(host: str, port: int):
    """Entry point used by app.py (runs in a background thread)."""
    app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    run("127.0.0.1", 5001)

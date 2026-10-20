"""
app.py — SentinelShield entry point.  Run:  python app.py

Starts three things in one process:

  1. the demo_app Flask server on :5001 (background thread — the
     "origin server" behind the proxy),
  2. the WAF + dashboard + API Flask server on :5000,
  3. the shared logger / rules / rate-limiter singletons.

Endpoints
    /                     live dashboard (dashboard/index.html)
    /api/stats            JSON stats polled every ~2s by the dashboard
    /guard/<path>         THE WAF — inspect -> decide -> log -> forward/block
    /health               tiny liveness probe
"""

import json
import os
import threading

import requests
from flask import Flask, request, jsonify, send_from_directory, make_response

import config
import demo_app
from waf.engine import WAFEngine
from waf.logger import EventLogger
from waf.ratelimit import RateLimiter
from waf.rules import RuleSet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- #
# Singletons — built once at import time
# --------------------------------------------------------------------------- #
logger = EventLogger(os.path.join(BASE_DIR, config.DATABASE))
ruleset = RuleSet.from_yaml(os.path.join(BASE_DIR, config.RULES_FILE))
ratelimit = RateLimiter(
    max_requests=config.RATE_LIMIT_MAX_REQUESTS,
    window_sec=config.RATE_LIMIT_WINDOW_SEC,
    cooldown_sec=config.RATE_LIMIT_COOLDOWN_SEC,
)
engine = WAFEngine(ruleset, ratelimit)

waf = Flask(__name__, static_folder=None)

DEMO_ORIGIN = f"http://{config.DEMO_HOST}:{config.DEMO_PORT}"

# Headers we never forward verbatim to the origin
_STRIP_HEADERS = {"host", "content-length", "connection", "x-forwarded-for"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def client_ip() -> str:
    """Real client IP — honours X-Forwarded-For (used by the simulator)."""
    xff = request.headers.get(config.PROXY_IP_HEADER, "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def persist(verdict, sim_id: str):
    """Log decision to SQLite; flag the IP for any non-ALLOWED verdict."""
    logger.log(
        ip=verdict.ip, method=verdict.method, path=verdict.path,
        query=verdict.query, category=verdict.category,
        severity=verdict.severity, verdict=verdict.verdict,
        rule_id=verdict.rule_id, detail=verdict.detail, sim_id=sim_id,
    )
    if verdict.verdict in ("BLOCKED", "FLAGGED"):
        logger.flag_ip(verdict.ip)


def block_response(verdict, sim_id: str):
    """Render the block page (HTML for browsers, JSON for APIs)."""
    payload = {
        "error": "Blocked by SentinelShield WAF",
        "verdict": verdict.verdict,
        "category": verdict.category,
        "severity": verdict.severity,
        "rule": verdict.rule_id,
        "detail": verdict.detail,
        "ip": verdict.ip,
    }
    resp = jsonify(payload)
    resp.status_code = 403
    resp.headers["X-WAF-Verdict"] = verdict.verdict
    resp.headers["X-WAF-Rule"] = verdict.rule_id
    if sim_id:
        resp.headers["X-Sim-Id"] = sim_id
    return resp


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@waf.route("/")
def dashboard():
    return send_from_directory(os.path.join(BASE_DIR, "dashboard"), "index.html")


@waf.route("/<path:asset>")
def dashboard_assets(asset):
    """Serve dashboard static files (chart.umd.min.js, favicon, ...).

    More specific routes (/guard/..., /api/...) win over this catch-all,
    so it only ever matches asset requests.
    """
    return send_from_directory(os.path.join(BASE_DIR, "dashboard"), asset)


@waf.route("/health")
def health():
    return jsonify({"status": "ok", "service": "sentinelshield"})


@waf.route("/api/stats")
def api_stats():
    """JSON feed consumed by the dashboard every ~2 seconds."""
    return jsonify({
        "counts": logger.counts(),
        "categories": logger.by_category(),
        "timeline": logger.over_time(bucket_sec=10, last_n_buckets=30),
        "flagged_ips": logger.top_flagged_ips(limit=10),
        "flagged_total": len(logger.flagged_ip_list()),
        "recent": logger.recent_events(limit=20),
        "config": {
            "rate_max": config.RATE_LIMIT_MAX_REQUESTS,
            "rate_window": config.RATE_LIMIT_WINDOW_SEC,
            "rate_cooldown": config.RATE_LIMIT_COOLDOWN_SEC,
            "rules": len(ruleset.rules),
        },
    })


# Methods the WAF accepts and proxies (login form is POST, REST-ish verbs too)
_WAF_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


@waf.route("/guard/", defaults={"path": ""}, methods=_WAF_METHODS)
@waf.route("/guard/<path:path>", methods=_WAF_METHODS)
def guard(path):
    """
    Reverse-proxy-style WAF endpoint.

    1. extract attacker-controlled input (URL, query, headers, body)
    2. engine.inspect()  -> verdict (rules first, then rate limit)
    3. persist()         -> SQLite row (+ flag IP when malicious/abusive)
    4. ALLOWED           -> forward to demo_app and stream the response back
       BLOCKED/FLAGGED   -> stop here, return 403 / alert payload
    """
    sim_id = request.headers.get("X-Sim-Id", "")
    body = request.get_data(as_text=True) or ""

    inspection = {
        "ip": client_ip(),
        "method": request.method,
        "path": "/" + path,
        "query": request.query_string.decode("utf-8", "replace"),
        "headers": dict(request.headers),
        "body": body,
    }

    verdict = engine.inspect(inspection)
    persist(verdict, sim_id)

    if verdict.verdict != "ALLOWED":
        return block_response(verdict, sim_id)

    # ---- clean: forward to the origin (demo_app) ------------------------
    url = f"{DEMO_ORIGIN}/{path}"
    if inspection["query"]:
        url += "?" + inspection["query"]

    fwd_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _STRIP_HEADERS
    }

    try:
        upstream = requests.request(
            request.method, url,
            data=request.get_data() if request.method in ("POST", "PUT", "PATCH") else None,
            headers=fwd_headers,
            timeout=5,
            allow_redirects=False,
        )
    except requests.RequestException as exc:  # origin down — surface clearly
        resp = jsonify({"error": "origin unreachable", "detail": str(exc)})
        resp.status_code = 502
        resp.headers["X-WAF-Verdict"] = "ALLOWED"
        return resp

    # Copy origin headers, minus hop-by-hop ones Flask manages itself.
    resp = make_response(upstream.content, upstream.status_code)
    for key, value in upstream.headers.items():
        if key.lower() in ("content-length", "transfer-encoding", "connection",
                           "content-encoding"):
            continue
        resp.headers[key] = value
    resp.headers["X-WAF-Verdict"] = "ALLOWED"
    if sim_id:
        resp.headers["X-Sim-Id"] = sim_id
    return resp


# --------------------------------------------------------------------------- #
# Boot
# --------------------------------------------------------------------------- #
def start_demo_app():
    """Run the protected origin on :5001 in a daemon thread."""
    t = threading.Thread(
        target=demo_app.run,
        args=(config.DEMO_HOST, config.DEMO_PORT),
        daemon=True,
        name="demo-app",
    )
    t.start()
    return t


def main():
    print(r"""
   ____              _ _                _ _ _____
  / ___|___  _ __ __| | |__   __ _  __| | |_   _|
 | |   / _ \| '__/ _` | '_ \ / _` |/ _` | | | |
 | |__| (_) | | | (_| | |_) | (_| | (_| | | | |
  \____\___/|_|  \__,_|_.__/ \__,_|\__,_| |_| |
  Intrusion Detection & Web Protection System
    """  )
    start_demo_app()
    print(f"  [+] Demo app (protected origin)  http://{config.DEMO_HOST}:{config.DEMO_PORT}")
    print(f"  [+] WAF + proxy endpoint          http://{config.WAF_HOST}:{config.WAF_PORT}/guard/<path>")
    print(f"  [+] Live dashboard                http://{config.WAF_HOST}:{config.WAF_PORT}/")
    print(f"  [+] Stats API                     http://{config.WAF_HOST}:{config.WAF_PORT}/api/stats")
    print(f"  [+] Loaded {len(ruleset.rules)} detection rules from {config.RULES_FILE}")
    print(f"  [+] Rate limit: {config.RATE_LIMIT_MAX_REQUESTS} req / "
          f"{config.RATE_LIMIT_WINDOW_SEC}s window, "
          f"{config.RATE_LIMIT_COOLDOWN_SEC}s cooldown\n")
    waf.run(host=config.WAF_HOST, port=config.WAF_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()

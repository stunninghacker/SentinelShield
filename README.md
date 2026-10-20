# SentinelShield — Intrusion Detection & Web Application Firewall (Demo)

A self-contained Flask + SQLite WAF/IDS built for an internship practical.
It inspects every HTTP request in a reverse-proxy stance, matches it against
a YAML signature set, enforces per-IP rate limiting, logs everything to
SQLite, and presents a live dashboard, an attack simulator, and a
one-command report generator.

No external services. No API keys. No Docker. Five commands from clone to report.

---

## 1. Architecture

```
                       (simulator / browser / curl)
                                   |
                                   | HTTP
                                   v
                 +--------------------------------------+
                 |  SentinelShield WAF   :5000          |
                 |                                      |
                 |  /guard/<path>  <-- inspection hook  |
                 |      |                               |
                 |      v                               |
                 |  engine.decide()                     |
                 |    1. build_inspection_text          |
                 |       (raw + 3-pass decoded views)   |
                 |    2. rules.match(raw, decoded)      |
                 |       rules.yaml  (15 signatures)    |
                 |    3. rate_limiter.check(ip)         |
                 |       20 req / 10s, 30s cooldown     |
                 |    4. verdict:                       |
                 |       BLOCKED  -> 403 JSON (no fwd)  |
                 |       FLAGGED  -> 200 + log (no fwd) |
                 |       ALLOWED  -> forward to origin  |
                 |      |                               |
                 |      v                               |
                 |  logger (SQLite logs.db)             |
                 |    events + flagged_ips tables       |
                 |      |                               |
                 |  /            dashboard (Chart.js)   |
                 |  /api/stats   JSON for the dashboard |
                 +------------------+------------------+
                                    | forward allowed
                                    | requests
                                    v
                 +--------------------------------------+
                 |  Demo origin app        :5001        |
                 |  /login  /search  /view              |
                 +--------------------------------------+

  simulator.py --(burst & probe traffic)--> WAF   report.py <-- logs.db
  (writes simulator_run.json for FP/FN correlation)   |
                                                      v
                                                report.md + report.pdf
```

**Key design decisions**

- **Proxy stance, not middleware.** The WAF is a real front (`/guard/<path>`)
  that forwards to the origin, so blocking actually stops traffic instead of
  just decorating an internal request.
- **Two inspection views.** Raw bytes (for ENC-* rules) and a 3-pass decoded
  text (`%xx`, `+`→space, NUL/CR/LF/tab→space) that every other rule sees.
  This is what lets `UNION%20SELECT` and `%253Cscript` be caught while
  `"quarterly report"` passes.
- **Rules first, then rate limit.** A signature hit also flag-IPs the source
  for 30s, so an attacker who gets one probe through still trips the window.
- **First breach = FLAGGED, cooldown = BLOCKED.** Same window as legitimate
  burst traffic, so a single fast page-refresh sequence is visible but not
  fatal.

---

## 2. Quick start (5 steps)

```bash
# 1. install dependencies
pip install -r requirements.txt

# 2. start the WAF + demo origin (foreground; or pythonw app.py)
python app.py

# 3. in a second terminal — run the attack simulator
python simulator.py

# 4. generate the report (report.md + report.pdf)
python report.py

# 5. open the live dashboard
#    http://127.0.0.1:5000/
```

Stop the server with `Ctrl+C` (or `taskkill /PID <pid> /F` on Windows;
the PID is written to `app.pid`).

---

## 3. Signature rules (`rules.yaml`)

15 rules, evaluated in file order, first hit wins.

| ID | Category | Severity | Matches |
|---|---|---|---|
| SQLI-001 | SQL Injection | high | `UNION ... SELECT` / `SELECT ... FROM` probes |
| SQLI-002 | SQL Injection | high | Classic tautologies (`' OR 1=1 --`) |
| SQLI-003 | SQL Injection | medium | Comment/terminator tails, `sleep()`/`benchmark()` style functions |
| SQLI-004 | SQL Injection | medium | Destructive DML/DDL (`DROP TABLE`, `DELETE FROM`, ...) |
| XSS-001 | XSS | high | Inline `<script>` tags |
| XSS-002 | XSS | high | Event handlers (`onerror=`), `javascript:` / `data:` URIs |
| XSS-003 | XSS | medium | JS sinks (`alert(`, `document.cookie`), `<svg>` vectors |
| CMDI-001 | Command Injection | high | Shell metacharacters + recon binary, `$( )` / backticks |
| CMDI-002 | Command Injection | high | `cat /etc/passwd`, `nc <ip> -e /bin/sh` |
| CMDI-003 | Command Injection | medium | Chaining (`&&`, `\|\|`), interpreter invocation |
| LFI-001 | LFI / Traversal | high | `../` traversal, plain or `%2f`-encoded |
| LFI-002 | LFI / Traversal | high | `/etc/passwd`, `/etc/shadow`, ... targeted by name |
| LFI-003 | LFI / Traversal | high | `php://filter`, stream wrappers |
| ENC-001 | Suspicious Encoding | low | Dense `%xx%xx%xx...` run (smuggling past naive filters) |
| ENC-002 | Suspicious Encoding | medium | Double-encoded metacharacters (`%253C`) |

ENC-* match the **raw** request text; everything else matches the **decoded**
text. Editing `rules.yaml` requires no code change — it is re-read at startup.

---

## 4. How one request flows (worked example)

```bash
# Allowed: forwarded to the origin app
curl -i "http://127.0.0.1:5000/guard/search?q=quarterly+report"
#   200 OK, X-WAF-Verdict: ALLOWED, body = origin's page

# Blocked: signature hit, never reaches the origin
curl -i "http://127.0.0.1:5000/guard/search?q=%27%20OR%201%3D1--"
#   403 Forbidden, X-WAF-Verdict: BLOCKED
#   {"category":"SQL Injection","detail":"matched ...","rule":"SQLI-002"}

# Rate limited: 20 requests / 10 s per IP
for i in $(seq 1 25); do curl -s -o /dev/null http://127.0.0.1:5000/guard/login; done
#   first breach -> FLAGGED (200, logged), later ones -> BLOCKED (403, 30 s)
```

Client IP is taken from `X-Forwarded-For` (configurable in `config.py`),
so spoofed source IPs are supported for testing.

---

## 5. Attack simulator (`simulator.py`)

Sends four phases of traffic and prints a per-tag verdict table:

| Phase | Tag | Expected | Purpose |
|---|---|---|---|
| Benign browsing | `normal` | ALLOWED | proves low false-positive rate |
| SQLi / XSS / LFI / CMDI / encoding probes | `sqli` `xss` `lfi` `cmdi` `encoding` | BLOCKED or FLAGGED | proves signature coverage |
| 35-request login burst | `bruteforce` | FLAGGED then BLOCKED | proves rate limiting |
| Edge cases | `edge_fp` / `edge_fn` | BLOCKED / ALLOWED | measures FP & FN honestly |

Every request carries an `X-Sim-Id` header; the WAF logs it, and
`report.py` joins against the manifest (`simulator_run.json`) to compute
real false-positive / false-negative counts instead of guessing.

---

## 6. Report (`report.py`)

Reads `logs.db` (+ `simulator_run.json` if present) and writes:

- **`report.md`** — executive summary, category breakdown table, top flagged
  IPs, sample request/response pairs, timeline, FP/FN analysis.
- **`report.pdf`** — same content, typeset with ReportLab.

---

## 7. Project layout

```
Sentinal_Shield/
├── app.py              # WAF entry: proxy, dashboard, /api/stats
├── demo_app.py         # protected origin app (port 5001)
├── config.py           # all ports/thresholds in one file
├── rules.yaml          # 15 detection signatures
├── waf/
│   ├── engine.py       # inspection text + decision flow
│   ├── rules.py        # YAML loader, 3-pass payload decoder, matcher
│   ├── ratelimit.py    # sliding-window per-IP limiter (SQLite-backed)
│   └── logger.py       # SQLite schema, stats queries
├── dashboard/
│   ├── index.html      # live charts + event feed (polls /api/stats)
│   └── chart.umd.min.js
├── simulator.py        # attack traffic generator
├── report.py           # report.md + report.pdf generator
├── requirements.txt
├── Makefile
└── README.md
```

---

## 8. Makefile targets

| Target | Does |
|---|---|
| `make install` | `pip install -r requirements.txt` |
| `make run` | start WAF + demo origin |
| `make sim` | run the attack simulator |
| `make report` | generate `report.md` / `report.pdf` |
| `make demo` | full pipeline: reset DB, run, simulate, report |
| `make stop` | kill the server via `app.pid` |
| `make clean` | remove generated artifacts (`logs.db`, reports, logs) |

---

## 9. Limitations (honest section for the write-up)

- **Signature-based only.** No anomaly/ML scoring; novel or heavily
  obfuscated payloads can evade (the simulator's `edge_fn` seed demonstrates
  this on purpose).
- **Development server.** `app.py` uses Flask's built-in server; a real
  deployment would front it with gunicorn/nginx.
- **Known false positives.** Keyword rules can catch innocent text
  (`edge_fp` in the simulator); signatures are ordered/damped but not
  semantic.
- **Single process.** Rate-limit state lives in the WAF process + SQLite;
  multi-worker deployments would need a shared store.

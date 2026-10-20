"""
report.py — generates report.md and report.pdf from logs.db.

Run:  python report.py     (after app.py + simulator.py)

Contents
  1. executive summary / headline numbers
  2. detection summary table (per attack category)
  3. repeatedly flagged IPs
  4. detected attacks with the triggering signature
  5. false positives / false negatives (cross-references the simulator
     manifest simulator_run.json against actual logged verdicts)
  6. security recommendations derived from observed patterns

PDF is produced with reportlab (pure Python, no external services).
"""

import datetime
import json
import os
from collections import Counter, defaultdict

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

import config
from waf.logger import EventLogger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MD_PATH = os.path.join(BASE_DIR, "report.md")
PDF_PATH = os.path.join(BASE_DIR, "report.pdf")
MANIFEST = os.path.join(BASE_DIR, "simulator_run.json")

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


# --------------------------------------------------------------------------- #
# data gathering
# --------------------------------------------------------------------------- #
def collect():
    logger = EventLogger(os.path.join(BASE_DIR, config.DATABASE))
    events = logger.all_events()
    counts = logger.counts()
    by_cat = logger.by_category()
    flagged = logger.flagged_ip_list()
    top_ips = logger.top_flagged_ips(limit=10)
    logger.close()

    manifest = []
    if os.path.exists(MANIFEST):
        with open(MANIFEST, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)

    # index logged events by sim_id for exact expectation matching
    by_sim = {e["sim_id"]: e for e in events if e.get("sim_id")}

    fp, fn, detected = [], [], []
    for probe in manifest:
        logged = by_sim.get(probe["sim_id"])
        actual = (logged or {}).get("verdict", probe.get("verdict", "?"))
        expected_bad = probe["expected_malicious"]
        surf = actual in ("BLOCKED", "FLAGGED")
        entry = {**probe, "logged_verdict": actual,
                 "logged_rule": (logged or {}).get("rule_id", probe.get("rule", "")),
                 "logged_category": (logged or {}).get("category", probe.get("category", ""))}
        # Rate-limit probes are *designed* to pass until the window fills,
        # so per-request expectations don't apply — they are evaluated as a
        # burst instead (see burst_ok below).
        if probe["tag"] == "bruteforce":
            if surf:
                detected.append(entry)
            continue
        if expected_bad and surf:
            detected.append(entry)
        elif expected_bad and not surf:
            fn.append(entry)          # should have been caught -> wasn't
        elif not expected_bad and surf:
            fp.append(entry)          # innocent -> wrongly blocked
    # did the burst as a whole get stopped?
    burst = [p for p in manifest if p["tag"] == "bruteforce"]
    burst_ok = bool(burst) and any(
        (by_sim.get(p["sim_id"]) or {}).get("verdict") in ("FLAGGED", "BLOCKED")
        for p in burst
    )
    return dict(counts=counts, by_cat=by_cat, flagged=flagged,
                top_ips=top_ips, events=events, manifest=manifest,
                detected=detected, fp=fp, fn=fn, burst_ok=burst_ok,
                burst_total=len(burst))


def fmt_ts(epoch=None):
    epoch = epoch or __import__("time").time()
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def build_markdown(d):
    c = d["counts"]
    total = c["total"] or 1
    attacks = c["blocked"] + c["flagged"]
    lines = []
    A = lines.append

    A("# SentinelShield — Intrusion Detection & Web Protection Report")
    A("")
    A(f"*Generated: {fmt_ts()}  ·  source: `{config.DATABASE}`*")
    A("")
    A("---")
    A("")
    A("## 1. Executive Summary")
    A("")
    A(f"- **Total requests inspected:** {c['total']}")
    A(f"- **Malicious / abusive requests blocked or flagged:** {attacks} "
      f"({attacks * 100 // total}% of traffic)")
    A(f"  - BLOCKED: **{c['blocked']}** · FLAGGED: **{c['flagged']}**")
    A(f"- **Legitimate requests allowed through:** {c['allowed']}")
    A(f"- **Distinct IPs flagged:** {len(d['flagged'])}")
    A(f"- **Detection rules loaded:** see rules.yaml "
      f"({len(d['by_cat'])} categories fired)")
    A("")

    # ---- summary table ----------------------------------------------------
    A("## 2. Detection Summary by Attack Category")
    A("")
    A("| Attack Category | Detected | Share of Attacks |")
    A("|---|---:|---:|")
    for row in d["by_cat"]:
        share = (row["count"] * 100 / attacks) if attacks else 0
        A(f"| {row['category']} | {row['count']} | {share:.1f}% |")
    A(f"| **TOTAL** | **{attacks}** | **100%** |")
    A("")

    # ---- flagged IPs -------------------------------------------------------
    A("## 3. Repeatedly Flagged IP Addresses")
    A("")
    if d["top_ips"]:
        A("| IP Address | Events | Blocked | Category Mix |")
        A("|---|---:|---:|---|")
        mix = defaultdict(Counter)
        for e in d["events"]:
            if e["verdict"] in ("BLOCKED", "FLAGGED"):
                mix[e["ip"]][e["category"]] += 1
        for ip_row in d["top_ips"]:
            cats = ", ".join(f"{k} ({v})" for k, v in mix[ip_row["ip"]].most_common(3))
            A(f"| `{ip_row['ip']}` | {ip_row['count']} | {ip_row['blocked']} | {cats} |")
    else:
        A("_No IPs flagged._")
    A("")

    # ---- detected attacks + signature --------------------------------------
    A("## 4. Detected Attacks & Triggering Signature")
    A("")
    sig_hits = Counter()
    for e in d["events"]:
        if e["verdict"] in ("BLOCKED", "FLAGGED") and e["rule_id"]:
            sig_hits[e["rule_id"]] += 1
    if sig_hits:
        A("| Rule ID | Category | Times Fired |")
        A("|---|---|---:|")
        rule_cat = {e["rule_id"]: e["category"] for e in d["events"] if e["rule_id"]}
        for rule_id, n in sig_hits.most_common():
            A(f"| `{rule_id}` | {rule_cat.get(rule_id, '?')} | {n} |")
        A("")
    A("<details><summary>Full chronological list of blocked/flagged requests</summary>")
    A("")
    A("| Time | IP | Method | Path | Category | Verdict | Rule |")
    A("|---|---|---|---|---|---|---|")
    for e in d["events"]:
        if e["verdict"] in ("BLOCKED", "FLAGGED"):
            t = datetime.datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
            path = e["path"] + (("?" + e["query"]) if e["query"] else "")
            path = path.replace("|", "%7C")[:70]
            A(f"| {t} | `{e['ip']}` | {e['method']} | `{path}` | "
              f"{e['category']} | **{e['verdict']}** | `{e['rule_id']}` |")
    A("")
    A("</details>")
    A("")

    # ---- FP / FN -----------------------------------------------------------
    A("## 5. False Positives / False Negative Analysis")
    A("")
    A("Edge cases are seeded deliberately by `simulator.py` and matched to "
      "logged verdicts via the `X-Sim-Id` correlation header.")
    A("")
    A(f"- **Seeded probes evaluated:** {len(d['manifest'])}")
    A(f"- **Correctly detected (true positives):** {len(d['detected'])}")
    A(f"- **False positives (blocked but benign):** {len(d['fp'])}")
    A(f"- **False negatives (malicious but allowed):** {len(d['fn'])}")
    if d.get("burst_total"):
        status = "stopped mid-burst ✓" if d["burst_ok"] else "NOT stopped ✗"
        A(f"- **Brute-force burst ({d['burst_total']} requests):** {status} "
          "(early requests are allowed by design until the sliding window fills)")
    A("")
    if d["fp"]:
        A("### False Positives")
        A("")
        A("| Payload | Expected | Actual | Why it happened |")
        A("|---|---|---|---|")
        for e in d["fp"]:
            A(f"| `{e['target']}` | ALLOWED | **{e['logged_verdict']}** | "
              f"{e.get('note','')} — matched `{e['logged_rule']}` |")
        A("")
        A("*Cause:* signature `SQLI-*` matches raw keyword patterns, so a "
          "legit phrase like “drop table” in natural language trips it. "
          "**Mitigation:** add a keyword-count / context threshold, or "
          "whitelist search fields with a word-boundary + quoting check.")
        A("")
    if d["fn"]:
        A("### False Negatives")
        A("")
        A("| Payload | Expected | Actual | Evasion technique |")
        A("|---|---|---|---|")
        for e in d["fn"]:
            A(f"| `{e['target']}` | BLOCKED | **{e['logged_verdict']}** | "
              f"{e.get('note','')} |")
        A("")
        A("*Cause:* SQLI-002 requires literal whitespace after `OR`/`AND` "
          "and SQLI-003 requires a comment/terminator tail — removing both "
          "(no space, no `--`) evades every current regex while MySQL still "
          "executes the tautology. **Mitigation:** normalise before matching "
          "(expand keyword-boundary rules to `OR(`, strip `/**/`, collapse "
          "whitespace variants), or add a lightweight anomaly score "
          "alongside signatures.")
        A("")
    if not d["fp"] and not d["fn"]:
        A("_No false positives or negatives observed in this run._")
        A("")

    # ---- recommendations ---------------------------------------------------
    A("## 6. Security Recommendations")
    A("")
    recs = []
    cats = {row["category"] for row in d["by_cat"]}
    if any("SQL" in x for x in cats):
        recs.append("**Parameterised queries** — the demo login concatenates "
                    "SQL; use prepared statements/ORM everywhere (CWE-89).")
    if any("XSS" in x for x in cats):
        recs.append("**Contextual output encoding** on the search reflection "
                    "path plus a CSP header with `script-src 'self'` (CWE-79).")
    if any("LFI" in x for x in cats):
        recs.append("**Canonicalise paths and allow-list filenames** for "
                    "`/view`; reject `..` after `realpath()` (CWE-22).")
    if any("Command" in x for x in cats):
        recs.append("**Never pass user input to a shell** — use `execve`-style "
                    "argv arrays or disable shell features (CWE-78).")
    if d["flagged"]:
        recs.append(f"**Rate limiting is active** ({config.RATE_LIMIT_MAX_REQUESTS}/"
                    f"{config.RATE_LIMIT_WINDOW_SEC}s, "
                    f"{config.RATE_LIMIT_COOLDOWN_SEC}s cooldown). Consider "
                    "jail+exponential backoff for repeated offenders, and "
                    "persisting flagged IPs across restarts.")
    if d["fp"] or d["fn"]:
        recs.append("**Tune signatures** using the FP/FN section above: add "
                    "normalisation before matching to close the FN gap, and "
                    "context checks to reduce FP noise.")
    recs.append("**Layer defences**: WAF signatures are a first line — pair "
                "with HSTS, strict CSP, `X-Content-Type-Options`, and regular "
                "patch cycles.")
    for i, r in enumerate(recs, 1):
        A(f"{i}. {r}")
    A("")
    A("---")
    A("*Report generated by SentinelShield `report.py`.*")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# pdf
# --------------------------------------------------------------------------- #
def build_pdf(markdown_text, d):
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#0f2a44"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13,
                        textColor=colors.HexColor("#12406b"), spaceBefore=14)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=body, fontSize=8.5, leading=11)
    mono = ParagraphStyle("Mono", parent=small, fontName="Courier")

    def table(data, col_widths=None, header_bg="#0f2a44"):
        t = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_bg)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9aa8bb")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#eef3f9")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    c = d["counts"]
    total = c["total"] or 1
    attacks = c["blocked"] + c["flagged"]
    story = []
    story.append(Paragraph("SentinelShield — Intrusion Detection &amp; "
                           "Web Protection Report", h1))
    story.append(Paragraph(
        f"Generated {fmt_ts()} &nbsp;|&nbsp; source <font face='Courier'>{config.DATABASE}</font>",
        small))
    story.append(Spacer(1, 8))

    # headline cards as a 2x3 table
    headline = [
        ["Total Requests", "Blocked", "Flagged", "Allowed", "Flagged IPs"],
        [str(c["total"]), str(c["blocked"]), str(c["flagged"]),
         str(c["allowed"]), str(len(d["flagged"]))],
    ]
    story.append(table(headline,
                       col_widths=[3.2 * cm] * 5, header_bg="#12406b"))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<b>{attacks}</b> of <b>{total}</b> requests "
        f"({attacks * 100 // total}%) were malicious or abusive and were "
        f"blocked or flagged by the WAF before reaching the origin.",
        body))
    story.append(Spacer(1, 4))

    # category table
    story.append(Paragraph("1. Detection Summary by Attack Category", h2))
    rows = [["Attack Category", "Detected", "Share"]]
    for r in d["by_cat"]:
        share = (r["count"] * 100 / attacks) if attacks else 0
        rows.append([r["category"], str(r["count"]), f"{share:.1f}%"])
    rows.append(["TOTAL", str(attacks), "100%"])
    story.append(table(rows, col_widths=[9.5 * cm, 3 * cm, 3 * cm]))

    # flagged IPs
    story.append(Paragraph("2. Repeatedly Flagged IPs", h2))
    if d["top_ips"]:
        rows = [["IP Address", "Events", "Blocked"]]
        for r in d["top_ips"]:
            rows.append([r["ip"], str(r["count"]), str(r["blocked"])])
        story.append(table(rows, col_widths=[7 * cm, 3 * cm, 3 * cm]))
    else:
        story.append(Paragraph("No IPs flagged.", body))

    # signatures
    story.append(Paragraph("3. Detected Attacks &amp; Triggering Signature", h2))
    sig = Counter()
    rule_cat = {}
    for e in d["events"]:
        if e["verdict"] in ("BLOCKED", "FLAGGED") and e["rule_id"]:
            sig[e["rule_id"]] += 1
            rule_cat[e["rule_id"]] = e["category"]
    if sig:
        rows = [["Rule ID", "Category", "Times Fired"]]
        for rid, n in sig.most_common():
            rows.append([rid, rule_cat.get(rid, "?"), str(n)])
        story.append(table(rows, col_widths=[3.5 * cm, 8 * cm, 3.5 * cm]))
    story.append(Spacer(1, 4))
    # sample of blocked requests
    blocked = [e for e in d["events"] if e["verdict"] in ("BLOCKED", "FLAGGED")]
    rows = [["Time", "IP", "Path", "Category", "Verdict"]]
    for e in blocked[:14]:
        t = datetime.datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
        p = (e["path"] + (("?" + e["query"]) if e["query"] else ""))[:44]
        rows.append([t, e["ip"], p, e["category"], e["verdict"]])
    if len(rows) > 1:
        story.append(table(rows, col_widths=[2.0 * cm, 3.4 * cm, 6.2 * cm,
                                             3.6 * cm, 2.3 * cm]))
    if len(blocked) > 14:
        story.append(Paragraph(f"… and {len(blocked) - 14} more (see report.md "
                               "for the full chronological list).", small))

    # FP / FN
    story.append(Paragraph("4. False Positives / False Negatives", h2))
    rows = [["Metric", "Count"]]
    rows += [["Seeded probes evaluated", str(len(d["manifest"]))],
             ["True positives (correctly detected)", str(len(d["detected"]))],
             ["False positives (benign but blocked)", str(len(d["fp"]))],
             ["False negatives (malicious but allowed)", str(len(d["fn"]))]]
    if d.get("burst_total"):
        rows.append(["Brute-force burst stopped?",
                     "YES" if d["burst_ok"] else f"NO ({d['burst_total']} req)"])
    story.append(table(rows, col_widths=[10 * cm, 3 * cm]))
    story.append(Spacer(1, 5))
    if d["fp"]:
        story.append(Paragraph("<b>False positives</b>", body))
        rows = [["Payload", "Actual", "Cause"]]
        for e in d["fp"]:
            rows.append([Paragraph(f"<font face='Courier' size='7'>{e['target']}</font>", mono),
                         e["logged_verdict"],
                         Paragraph(e.get("note", ""), small)])
        story.append(table(rows, col_widths=[7.5 * cm, 2.5 * cm, 6.5 * cm],
                           header_bg="#7f1d1d"))
        story.append(Spacer(1, 5))
    if d["fn"]:
        story.append(Paragraph("<b>False negatives</b>", body))
        rows = [["Payload", "Actual", "Evasion technique"]]
        for e in d["fn"]:
            rows.append([Paragraph(f"<font face='Courier' size='7'>{e['target']}</font>", mono),
                         e["logged_verdict"],
                         Paragraph(e.get("note", ""), small)])
        story.append(table(rows, col_widths=[7.5 * cm, 2.5 * cm, 6.5 * cm],
                           header_bg="#7f1d1d"))
        story.append(Spacer(1, 5))
    if not d["fp"] and not d["fn"]:
        story.append(Paragraph("No false positives or negatives observed.", body))

    # recommendations
    story.append(Paragraph("5. Security Recommendations", h2))
    cats = {row["category"] for row in d["by_cat"]}
    recs = []
    if any("SQL" in x for x in cats):
        recs.append("Use parameterised queries / ORM for all DB access "
                    "(the demo login concatenates SQL — CWE-89).")
    if any("XSS" in x for x in cats):
        recs.append("Apply contextual output encoding on reflected input and "
                    "deploy a strict CSP (CWE-79).")
    if any("LFI" in x for x in cats):
        recs.append("Canonicalise and allow-list file paths; reject traversal "
                    "after realpath() (CWE-22).")
    if any("Command" in x for x in cats):
        recs.append("Never build shell commands from user input — use argv "
                    "arrays (CWE-78).")
    if d["flagged"]:
        recs.append(f"Keep rate limiting ({config.RATE_LIMIT_MAX_REQUESTS}/"
                    f"{config.RATE_LIMIT_WINDOW_SEC}s, "
                    f"{config.RATE_LIMIT_COOLDOWN_SEC}s cooldown); add "
                    "exponential backoff and persistent IP blocklists.")
    if d["fp"] or d["fn"]:
        recs.append("Normalise input (comments, whitespace, double-encoding) "
                    "before matching to reduce both FP and FN rates.")
    recs.append("Layer WAF controls with HSTS, strict CSP and patch cycles.")
    for i, r in enumerate(recs, 1):
        story.append(Paragraph(f"{i}. {r}", body))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<i>Report generated by SentinelShield report.py</i>", small))

    doc = SimpleDocTemplate(PDF_PATH, pagesize=A4,
                            leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm,
                            title="SentinelShield Report",
                            author="SentinelShield")
    doc.build(story)


# --------------------------------------------------------------------------- #
def main():
    print("[*] Reading logs.db …")
    data = collect()
    if data["counts"]["total"] == 0:
        print("[!] logs.db is empty — run `python app.py` then "
              "`python simulator.py` first.")
        return

    md = build_markdown(data)
    with open(MD_PATH, "w", encoding="utf-8") as fh:
        fh.write(md)
    print(f"[+] Wrote {MD_PATH} ({len(md)} bytes)")

    build_pdf(md, data)
    print(f"[+] Wrote {PDF_PATH} ({os.path.getsize(PDF_PATH)} bytes)")

    c = data["counts"]
    print(f"\n    requests={c['total']}  blocked={c['blocked']}  "
          f"flagged={c['flagged']}  allowed={c['allowed']}")
    print(f"    FP={len(data['fp'])}  FN={len(data['fn'])}  "
          f"true positives={len(data['detected'])}\n")


if __name__ == "__main__":
    main()

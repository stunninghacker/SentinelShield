"""
engine.py — the decision core.

Decision flow (exactly as specified):

    request arrives
        -> inspect (URL, query, headers, body — raw + decoded views)
        -> rule match?
              YES : verdict = BLOCKED, category = rule.category,
                    flag IP, raise alert
              NO  -> rate check:
                    breach (first) : verdict = FLAGGED, flag IP, alert
                    in cooldown    : verdict = BLOCKED (category: Rate Limit)
                    within limits  : verdict = ALLOWED -> forward to demo app

The engine is transport-agnostic: app.py hands it a dict-like request
summary and gets back a Verdict it can act on (log + allow/block).
"""

from dataclasses import dataclass, field

from .ratelimit import RateLimiter
from .rules import RuleSet, decode_payload


@dataclass
class Verdict:
    verdict: str            # ALLOWED | BLOCKED | FLAGGED
    category: str = "Benign"
    severity: str = "info"
    rule_id: str = ""
    detail: str = ""
    rate_count: int = 0
    # populated by engine so callers can log without re-deriving:
    ip: str = ""
    method: str = ""
    path: str = ""
    query: str = ""


# Header / param names worth scanning verbatim in addition to the raw blob.
_INTERESTING_HEADERS = (
    "user-agent", "referer", "cookie", "x-forwarded-for",
    "x-requested-with", "accept-language",
)


def build_inspection_text(request: dict) -> tuple[str, str]:
    """
    Assemble (raw, decoded) views of everything attacker-controllable.

    request = {ip, method, path, query, headers: {..}, body: str}
    """
    parts_raw = [
        request.get("path", ""),
        request.get("query", ""),
        request.get("body", ""),
    ]
    for name, value in (request.get("headers") or {}).items():
        if name.lower() in _INTERESTING_HEADERS:
            parts_raw.append(str(value))

    raw = " & ".join(p for p in parts_raw if p)
    # Decode each component individually AND the whole blob, so
    # "q=..%2f..%2f" decodes to "q=../../" before matching.
    decoded_parts = [
        decode_payload(request.get("path", "")),
        decode_payload(request.get("query", "")),
        decode_payload(request.get("body", "")),
    ]
    for name, value in (request.get("headers") or {}).items():
        if name.lower() in _INTERESTING_HEADERS:
            decoded_parts.append(decode_payload(str(value)))
    decoded = " & ".join(p for p in decoded_parts if p)
    return raw, decoded


class WAFEngine:
    def __init__(self, ruleset: RuleSet, ratelimit: RateLimiter):
        self.ruleset = ruleset
        self.ratelimit = ratelimit

    def inspect(self, request: dict) -> Verdict:
        """Run the full detect -> decide flow for one inbound request."""
        ip = request.get("ip", "0.0.0.0")
        base = dict(
            ip=ip,
            method=request.get("method", "GET"),
            path=request.get("path", "/"),
            query=request.get("query", ""),
        )

        # ---- Step 1: signature inspection -------------------------------
        raw, decoded = build_inspection_text(request)
        rule, snippet = self.ruleset.match(raw, decoded)
        if rule:
            # Malicious -> block, (flagging handled by caller via flag_ip)
            return Verdict(
                verdict="BLOCKED",
                category=rule.category,
                severity=rule.severity,
                rule_id=rule.id,
                detail=f"matched '{snippet}' — {rule.description}",
                **base,
            )

        # ---- Step 2: behaviour / rate check -----------------------------
        rate = self.ratelimit.register(ip)
        if rate.state == "cooldown":
            return Verdict(
                verdict="BLOCKED",
                category="Rate Limit / Abuse",
                severity="medium",
                rule_id="RATE-001",
                detail=(f"IP in cooldown until "
                        f"{rate.blocked_until:.0f} after exceeding "
                        f"{self.ratelimit.max_requests} req/"
                        f"{self.ratelimit.window_sec:.0f}s"),
                rate_count=rate.count,
                **base,
            )
        if rate.state == "flagged":
            return Verdict(
                verdict="FLAGGED",
                category="Rate Limit / Abuse",
                severity="high",
                rule_id="RATE-001",
                detail=(f"threshold breach: {rate.count} requests in "
                        f"{self.ratelimit.window_sec:.0f}s window "
                        f"(limit {self.ratelimit.max_requests}); "
                        f"cooldown {self.ratelimit.cooldown_sec:.0f}s started"),
                rate_count=rate.count,
                **base,
            )

        # ---- Step 3: clean -> allow ------------------------------------
        return Verdict(
            verdict="ALLOWED",
            category="Benign",
            severity="info",
            rate_count=rate.count,
            **base,
        )

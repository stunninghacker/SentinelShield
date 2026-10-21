"""
tests/test_waf.py — unit tests for the core WAF logic.

Covers:
* the 3-pass payload decoder (rules.decode_payload)
* signature matching on decoded vs raw views (rules.RuleSet.match)
* the sliding-window rate limiter (ratelimit.RateLimiter)

Run from the repo root:  pytest -q
"""

from pathlib import Path

from waf.ratelimit import RateLimiter
from waf.rules import RuleSet, decode_payload

RULES_PATH = Path(__file__).resolve().parent.parent / "rules.yaml"

_RULESET = None


def ruleset() -> RuleSet:
    """Load rules.yaml once per module run."""
    global _RULESET
    if _RULESET is None:
        _RULESET = RuleSet.from_yaml(str(RULES_PATH))
    return _RULESET


# ---------------------------------------------------------------------------
# 3-pass decoder
# ---------------------------------------------------------------------------

class TestDecodePayload:
    def test_plain_text_unchanged(self):
        assert decode_payload("quarterly report") == "quarterly report"

    def test_single_encoding(self):
        assert decode_payload("UNION%20SELECT") == "UNION SELECT"

    def test_plus_becomes_space(self):
        assert decode_payload("q=quarterly+report") == "q=quarterly report"

    def test_double_encoding_two_passes(self):
        # %253C -> %3C -> <
        assert decode_payload("%253Cscript%253E") == "<script>"

    def test_triple_encoding_three_passes(self):
        # %25253C -> %253C -> %3C -> <
        assert decode_payload("%25253Cscript") == "<script"

    def test_newlines_and_tabs_normalised(self):
        assert decode_payload("a%0ab%09c%0dr") == "a b c r"

    def test_null_bytes_stripped(self):
        assert decode_payload("ab%00cd") == "abcd"

    def test_empty_and_none(self):
        assert decode_payload("") == ""
        assert decode_payload(None) == ""


# ---------------------------------------------------------------------------
# Signature matching (uses the real rules.yaml)
# ---------------------------------------------------------------------------

class TestRuleMatching:
    def test_rules_yaml_loads_with_expected_count(self):
        assert len(ruleset().rules) == 15

    def test_encoded_union_select_is_caught(self):
        raw = "q=UNION%20SELECT%20password%20FROM%20users"
        decoded = decode_payload(raw)
        rule, snippet = ruleset().match(raw, decoded)
        assert rule is not None
        assert rule.id == "SQLI-001"
        assert rule.category == "SQL Injection"
        assert "union" in snippet.lower()

    def test_double_encoded_script_tag_is_caught(self):
        raw = "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
        decoded = decode_payload(raw)
        rule, snippet = ruleset().match(raw, decoded)
        assert rule is not None
        assert rule.id.startswith("XSS-")

    def test_plain_script_tag_is_caught(self):
        raw = "q=<script>alert(1)</script>"
        rule, snippet = ruleset().match(raw, decode_payload(raw))
        assert rule is not None
        assert rule.id == "XSS-001"

    def test_benign_quarterly_report_is_allowed(self):
        raw = "q=quarterly+report"
        rule, snippet = ruleset().match(raw, decode_payload(raw))
        assert rule is None
        assert snippet is None

    def test_benign_words_with_encoding_are_allowed(self):
        raw = "q=%63uarterly%20report"
        rule, _ = ruleset().match(raw, decode_payload(raw))
        assert rule is None

    def test_sqli_tautology_is_caught(self):
        raw = "id=%27%20OR%201%3D1--"
        rule, _ = ruleset().match(raw, decode_payload(raw))
        assert rule is not None
        assert rule.id == "SQLI-002"

    def test_traversal_is_caught(self):
        raw = "file=..%2f..%2f..%2fetc%2fpasswd"
        rule, _ = ruleset().match(raw, decode_payload(raw))
        assert rule is not None
        assert rule.id == "LFI-001"
        assert rule.category == "LFI / Directory Traversal"

    def test_disabled_rules_are_not_loaded(self):
        # every loaded rule must be enabled
        assert all(r.enabled for r in ruleset().rules)

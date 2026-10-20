"""
rules.py — signature ruleset loader and matcher.

* Parses rules.yaml (one dict per rule: id/category/severity/regex/...).
* Matching runs against a DECODED view of the request so payloads hidden
  behind %xx encoding are still caught, while ENC-* rules match the RAW
  view to detect the encoding itself.
"""

import re
from dataclasses import dataclass
from urllib.parse import unquote

import yaml


@dataclass
class Rule:
    id: str
    category: str
    severity: str          # low | medium | high
    regex: str
    description: str
    enabled: bool = True
    _pattern: re.Pattern = None  # compiled lazily

    def compile(self) -> "Rule":
        """Compile the regex once (case-insensitive)."""
        self._pattern = re.compile(self.regex, re.IGNORECASE)
        return self

    def match(self, text: str):
        """Return the matched snippet, or None."""
        if not self._pattern:
            self.compile()
        m = self._pattern.search(text or "")
        return m.group(0) if m else None


def decode_payload(raw: str, passes: int = 3) -> str:
    """
    Repeatedly URL-decode a string.

    Three passes defeat layered encoding tricks:
        %25253C -> %253C -> %3C -> <
    `+` is treated as space (form/query encoding) so space-separated
    signatures like `union select` still match, and embedded NULs /
    newlines / tabs are normalised so %0a-style smuggling reaches the
    regexes as plain whitespace.
    """
    s = raw or ""
    for _ in range(passes):
        decoded = unquote(s.replace("+", " "))
        if decoded == s:            # no further change -> stop early
            break
        s = decoded
    return (s.replace("\x00", "")
             .replace("\r", " ")
             .replace("\n", " ")
             .replace("\t", " "))


class RuleSet:
    """Holds compiled rules and exposes match()."""

    def __init__(self, rules):
        self.rules = [r.compile() for r in rules if r.enabled]

    @classmethod
    def from_yaml(cls, path: str) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        rules = []
        for entry in data.get("rules", []):
            rules.append(
                Rule(
                    id=entry["id"],
                    category=entry["category"],
                    severity=entry["severity"],
                    regex=entry["regex"],
                    description=entry.get("description", ""),
                    enabled=entry.get("enabled", True),
                )
            )
        return cls(rules)

    def match(self, raw_text: str, decoded_text: str):
        """
        Run every rule, in rules.yaml order; first hit wins.

        * ENC-* rules are evaluated against the RAW text (they look for
          encoded sequences themselves).
        * All other rules run against the DECODED text.

        Returns the first hit as (Rule, matched_snippet) or (None, None).
        """
        for rule in self.rules:
            target = raw_text if rule.id.startswith("ENC-") else decoded_text
            snippet = rule.match(target)
            if snippet:
                return rule, snippet
        return None, None

"""
ratelimit.py — per-IP sliding-window request counter.

Design
------
* Every arrival timestamp for an IP lives in a deque.
* On each request we drop timestamps older than `window_sec`,
  then count what remains (true sliding window, no bucket edges).
* Crossing `max_requests` marks the IP abusive:
      - the *breaching* request gets verdict FLAGGED
      - every subsequent request during `cooldown_sec` gets BLOCKED
* After the cooldown expires the IP starts clean again.

Thresholds come from config.py so they are config-driven.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass
class RateDecision:
    state: str          # "ok" | "flagged" | "cooldown"
    count: int          # requests inside the current window
    blocked_until: float = 0.0


class RateLimiter:
    def __init__(self, max_requests: int, window_sec: float, cooldown_sec: float):
        self.max_requests = max_requests
        self.window_sec = window_sec
        self.cooldown_sec = cooldown_sec
        self._hits = defaultdict(deque)     # ip -> deque[timestamp]
        self._blocked_until = {}            # ip -> epoch when cooldown ends
        self._flagged = {}                  # ip -> epoch of first flag
        self._lock = Lock()

    # ------------------------------------------------------------------ API --
    def register(self, ip: str, now: float = None) -> RateDecision:
        """Record one request from `ip` and decide its rate verdict."""
        now = time.time() if now is None else now
        with self._lock:
            # 1) still in cooldown? -> BLOCKED
            until = self._blocked_until.get(ip, 0.0)
            if now < until:
                return RateDecision("cooldown", self.max_requests, until)

            # 2) slide the window
            hits = self._hits[ip]
            while hits and now - hits[0] > self.window_sec:
                hits.popleft()
            hits.append(now)
            count = len(hits)

            # 3) threshold breached -> flag + start cooldown
            if count > self.max_requests:
                self._blocked_until[ip] = now + self.cooldown_sec
                self._flagged.setdefault(ip, now)
                return RateDecision("flagged", count, self._blocked_until[ip])

            return RateDecision("ok", count)

    def is_blocked(self, ip: str, now: float = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            return now < self._blocked_until.get(ip, 0.0)

    def flagged_ips(self):
        """Return {ip: first_flag_epoch} for every IP ever flagged this run."""
        with self._lock:
            return dict(self._flagged)

    def reset(self):
        with self._lock:
            self._hits.clear()
            self._blocked_until.clear()
            self._flagged.clear()

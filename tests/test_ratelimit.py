"""
tests/test_ratelimit.py — sliding-window rate-limiter tests.

Uses explicit timestamps (no sleeps) so the window logic is deterministic.
"""

from waf.ratelimit import RateLimiter


def make_limiter(max_requests=3, window_sec=10.0, cooldown_sec=30.0):
    return RateLimiter(max_requests, window_sec, cooldown_sec)


class TestRateLimiterWindow:
    def test_requests_under_limit_are_ok(self):
        rl = make_limiter()
        for i in range(3):
            d = rl.register("10.0.0.1", now=1000.0 + i)
            assert d.state == "ok"
            assert d.count == i + 1

    def test_breaching_request_is_flagged_not_blocked(self):
        rl = make_limiter()
        for i in range(3):
            rl.register("10.0.0.1", now=1000.0 + i)
        d = rl.register("10.0.0.1", now=1000.5)
        assert d.state == "flagged"
        assert d.count == 4
        assert d.blocked_until == 1000.5 + 30.0

    def test_subsequent_request_in_cooldown_is_blocked(self):
        rl = make_limiter()
        for i in range(4):
            rl.register("10.0.0.1", now=1000.0 + i * 0.1)
        d = rl.register("10.0.0.1", now=1001.0)
        assert d.state == "cooldown"
        assert rl.is_blocked("10.0.0.1", now=1001.0)

    def test_window_slides_old_hits_out(self):
        rl = make_limiter()
        # 3 hits, then wait > window so they all expire -> fresh start
        for i in range(3):
            rl.register("10.0.0.1", now=1000.0 + i)
        d = rl.register("10.0.0.1", now=1020.0)   # 20s later, window = 10s
        assert d.state == "ok"
        assert d.count == 1

    def test_cooldown_expires_and_ip_starts_clean(self):
        rl = make_limiter()
        for i in range(4):
            rl.register("10.0.0.1", now=1000.0 + i * 0.1)
        # in cooldown at t=1005
        assert rl.register("10.0.0.1", now=1005.0).state == "cooldown"
        # cooldown was 30s -> clear by t=1035, window empty -> ok
        d = rl.register("10.0.0.1", now=1000.5 + 30.0)
        assert d.state == "ok"
        assert not rl.is_blocked("10.0.0.1", now=1031.0)

    def test_ips_are_tracked_independently(self):
        rl = make_limiter()
        for i in range(4):
            rl.register("10.0.0.1", now=1000.0 + i * 0.1)
        assert rl.register("10.0.0.2", now=1000.4).state == "ok"

    def test_flagged_ips_are_recorded(self):
        rl = make_limiter()
        for i in range(4):
            rl.register("10.0.0.1", now=1000.0 + i * 0.1)
        assert "10.0.0.1" in rl.flagged_ips()

    def test_reset_clears_state(self):
        rl = make_limiter()
        for i in range(4):
            rl.register("10.0.0.1", now=1000.0 + i * 0.1)
        rl.reset()
        assert rl.flagged_ips() == {}
        assert not rl.is_blocked("10.0.0.1", now=1001.0)
        assert rl.register("10.0.0.1", now=1001.0).state == "ok"

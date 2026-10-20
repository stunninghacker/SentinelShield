"""
SentinelShield WAF package.

    engine.py    – orchestrates inspection of one request
    rules.py     – signature loading + regex matching (with decoding)
    ratelimit.py – per-IP sliding-window counter + cooldown blocking
    logger.py    – SQLite persistence for every WAF decision
"""

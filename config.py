"""
SentinelShield — central configuration.

Every tunable threshold lives here so judges can see (and change) the
WAF's behaviour without touching engine code.
"""

# ---------------------------------------------------------------------------
# Network / topology
# ---------------------------------------------------------------------------
WAF_HOST = "127.0.0.1"
WAF_PORT = 5000          # public-facing WAF + dashboard + API

DEMO_HOST = "127.0.0.1"
DEMO_PORT = 5001         # protected demo app (only reachable through the WAF)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
DATABASE = "logs.db"     # SQLite file, auto-created on first run
RULES_FILE = "rules.yaml"

# ---------------------------------------------------------------------------
# Rate limiting / behaviour monitoring  (sliding window)
# ---------------------------------------------------------------------------
RATE_LIMIT_MAX_REQUESTS = 20   # requests allowed per window, per IP
RATE_LIMIT_WINDOW_SEC = 10     # sliding window length in seconds
RATE_LIMIT_COOLDOWN_SEC = 30   # how long an abusive IP stays blocked

# ---------------------------------------------------------------------------
# Client IP resolution
# ---------------------------------------------------------------------------
# When the WAF sits behind a reverse proxy / the simulator, the real client
# IP arrives in this header. First hop in the list wins.
PROXY_IP_HEADER = "X-Forwarded-For"

# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------
SIMULATOR_TARGET = f"http://{WAF_HOST}:{WAF_PORT}"

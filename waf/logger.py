"""
logger.py — every WAF decision lands in SQLite (logs.db).

Schema
------
events(
  id, ts, ip, method, path, query, category, severity,
  verdict,        -- ALLOWED | BLOCKED | FLAGGED
  rule_id, detail, sim_id
)

flagged_ips(
  ip, first_seen, last_seen, total_flagged
)

`sim_id` is an optional correlation id injected by the simulator
(header X-Sim-Id) so report.py can line up expected vs. actual verdicts
and compute false positives / false negatives.
"""

import sqlite3
import time
from threading import Lock

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL    NOT NULL,
    ip       TEXT    NOT NULL,
    method   TEXT    NOT NULL,
    path     TEXT    NOT NULL,
    query    TEXT    DEFAULT '',
    category TEXT    NOT NULL,
    severity TEXT    DEFAULT 'info',
    verdict  TEXT    NOT NULL,
    rule_id  TEXT    DEFAULT '',
    detail   TEXT    DEFAULT '',
    sim_id   TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ver ON events(verdict);

CREATE TABLE IF NOT EXISTS flagged_ips (
    ip            TEXT PRIMARY KEY,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    total_flagged INTEGER NOT NULL DEFAULT 1
);
"""


class EventLogger:
    """Thread-safe thin wrapper over one SQLite connection."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------- writing --
    def log(self, *, ip, method, path, query="", category, severity="info",
            verdict, rule_id="", detail="", sim_id="") -> int:
        """Persist one decision; returns the new row id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, ip, method, path, query, category,"
                " severity, verdict, rule_id, detail, sim_id)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), ip, method, path, query, category, severity,
                 verdict, rule_id, detail, sim_id),
            )
            self._conn.commit()
            return cur.lastrowid

    def flag_ip(self, ip: str):
        """Upsert an IP into flagged_ips (used whenever verdict != ALLOWED)."""
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO flagged_ips (ip, first_seen, last_seen, total_flagged)"
                " VALUES (?,?,?,1)"
                " ON CONFLICT(ip) DO UPDATE SET last_seen=?, total_flagged=total_flagged+1",
                (ip, now, now, now),
            )
            self._conn.commit()

    # ------------------------------------------------------------- reading --
    def _q(self, sql, args=()):
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def counts(self):
        row = self._q(
            "SELECT COUNT(*) total,"
            " SUM(verdict='BLOCKED') blocked,"
            " SUM(verdict='FLAGGED')  flagged,"
            " SUM(verdict='ALLOWED')  allowed"
            " FROM events"
        )[0]
        return {
            "total": row["total"] or 0,
            "blocked": row["blocked"] or 0,
            "flagged": row["flagged"] or 0,
            "allowed": row["allowed"] or 0,
        }

    def by_category(self):
        rows = self._q(
            "SELECT category, COUNT(*) n FROM events"
            " WHERE verdict IN ('BLOCKED','FLAGGED') GROUP BY category ORDER BY n DESC"
        )
        return [{"category": r["category"], "count": r["n"]} for r in rows]

    def over_time(self, bucket_sec=10, last_n_buckets=30):
        """Attack counts bucketed over time for the line chart."""
        now = time.time()
        start = now - bucket_sec * last_n_buckets
        rows = self._q(
            "SELECT ts, category FROM events"
            " WHERE verdict IN ('BLOCKED','FLAGGED') AND ts >= ?",
            (start,),
        )
        buckets = {}
        for i in range(last_n_buckets):
            t0 = start + i * bucket_sec
            buckets[int(t0 // bucket_sec)] = 0
        for r in rows:
            key = int(r["ts"] // bucket_sec)
            if key in buckets:
                buckets[key] += 1
        labels, values = [], []
        for key in sorted(buckets):
            import datetime
            labels.append(datetime.datetime.fromtimestamp(key * bucket_sec)
                           .strftime("%H:%M:%S"))
            values.append(buckets[key])
        return {"labels": labels, "values": values}

    def top_flagged_ips(self, limit=10):
        rows = self._q(
            "SELECT ip, COUNT(*) n, SUM(verdict='BLOCKED') blocked"
            " FROM events WHERE verdict IN ('BLOCKED','FLAGGED')"
            " GROUP BY ip ORDER BY n DESC LIMIT ?", (limit,)
        )
        return [{"ip": r["ip"], "count": r["n"], "blocked": r["blocked"] or 0}
                for r in rows]

    def recent_events(self, limit=20):
        rows = self._q(
            "SELECT ts, ip, method, path, category, severity, verdict, rule_id"
            " FROM events ORDER BY id DESC LIMIT ?", (limit,)
        )
        import datetime
        return [{
            "time": datetime.datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S"),
            "ip": r["ip"], "method": r["method"], "path": r["path"],
            "category": r["category"], "severity": r["severity"],
            "verdict": r["verdict"], "rule_id": r["rule_id"],
        } for r in rows]

    def flagged_ip_list(self):
        rows = self._q(
            "SELECT ip, total_flagged, first_seen FROM flagged_ips"
            " ORDER BY total_flagged DESC LIMIT 10"
        )
        return [{"ip": r["ip"], "count": r["total_flagged"],
                 "first_seen": r["first_seen"]} for r in rows]

    def all_events(self):
        """Full history — used by report.py."""
        rows = self._q("SELECT * FROM events ORDER BY id ASC")
        return [dict(r) for r in rows]

    def close(self):
        with self._lock:
            self._conn.close()

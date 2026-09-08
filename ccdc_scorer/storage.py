from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence

from .models import ServiceResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    service_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    learned_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rounds (
    number INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS results (
    round_number INTEGER NOT NULL REFERENCES rounds(number) ON DELETE CASCADE,
    service_id TEXT NOT NULL,
    team TEXT NOT NULL,
    service_type TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    accurate INTEGER,
    baseline_state TEXT NOT NULL,
    points INTEGER NOT NULL,
    message TEXT NOT NULL,
    latency_ms INTEGER,
    fingerprint TEXT,
    timestamp TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (round_number, service_id)
);

CREATE INDEX IF NOT EXISTS results_team_round_idx ON results(team, round_number);
CREATE INDEX IF NOT EXISTS results_service_round_idx ON results(service_id, round_number);
"""


class ScoreStore:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Own a SQLite connection and always release its Windows file handle."""
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(SCHEMA)
            row = connection.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
            if row is None:
                connection.execute("INSERT INTO schema_info(version) VALUES (1)")
            elif int(row["version"]) != 1:
                raise RuntimeError("Unsupported scoring database schema version: %s" % row["version"])

    def next_round_number(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COALESCE(MAX(number), 0) + 1 AS number FROM rounds").fetchone()
            return int(row["number"])

    def load_baselines(self) -> Dict[str, str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT service_id, fingerprint FROM baselines").fetchall()
        return {str(row["service_id"]): str(row["fingerprint"]) for row in rows}

    def save_baseline(self, service_id: str, fingerprint: str, learned_at: str) -> None:
        with self._write_lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO baselines(service_id, fingerprint, learned_at) VALUES (?, ?, ?) "
                "ON CONFLICT(service_id) DO UPDATE SET fingerprint=excluded.fingerprint, learned_at=excluded.learned_at",
                (service_id, fingerprint, learned_at),
            )

    def clear_baselines(self) -> int:
        with self._write_lock, self._connection() as connection:
            count = int(connection.execute("SELECT COUNT(*) AS count FROM baselines").fetchone()["count"])
            connection.execute("DELETE FROM baselines")
        return count

    def record_round(
        self,
        number: int,
        started_at: str,
        finished_at: str,
        results: Sequence[ServiceResult],
    ) -> None:
        with self._write_lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO rounds(number, started_at, finished_at) VALUES (?, ?, ?)",
                (number, started_at, finished_at),
            )
            connection.executemany(
                """
                INSERT INTO results(
                    round_number, service_id, team, service_type, host, port,
                    passed, accurate, baseline_state, points, message, latency_ms,
                    fingerprint, timestamp, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        number,
                        result.id,
                        result.team,
                        result.type,
                        result.host,
                        result.port,
                        int(result.passed),
                        None if result.accurate is None else int(result.accurate),
                        result.baseline_state,
                        result.points,
                        result.message,
                        result.latency_ms,
                        result.fingerprint,
                        result.timestamp,
                        json.dumps(result.details, sort_keys=True, default=str),
                    )
                    for result in results
                ],
            )

    def totals(self) -> Dict[str, int]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT team, COALESCE(SUM(points), 0) AS points FROM results GROUP BY team ORDER BY points DESC, team"
            ).fetchall()
        return {str(row["team"]): int(row["points"]) for row in rows}

    def last_round_number(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COALESCE(MAX(number), 0) AS number FROM rounds").fetchone()
        return int(row["number"])

    def latest_results(self) -> List[Dict[str, Any]]:
        with self._connection() as connection:
            row = connection.execute("SELECT MAX(number) AS number FROM rounds").fetchone()
            if row is None or row["number"] is None:
                return []
            rows = connection.execute(
                "SELECT * FROM results WHERE round_number = ? ORDER BY team, service_id",
                (int(row["number"]),),
            ).fetchall()
        return [self._result_row(row) for row in rows]

    def recent_rounds(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        with self._connection() as connection:
            rounds = connection.execute(
                "SELECT number, started_at, finished_at FROM rounds ORDER BY number DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
            payload = []
            for round_row in reversed(rounds):
                teams = connection.execute(
                    """
                    SELECT team, SUM(points) AS points, SUM(passed) AS services_up, COUNT(*) AS services_total,
                           AVG(latency_ms) AS avg_latency_ms
                    FROM results WHERE round_number = ? GROUP BY team ORDER BY team
                    """,
                    (int(round_row["number"]),),
                ).fetchall()
                payload.append({
                    "round": int(round_row["number"]),
                    "started_at": round_row["started_at"],
                    "finished_at": round_row["finished_at"],
                    "teams": [
                        {
                            "team": team["team"],
                            "points": int(team["points"] or 0),
                            "services_up": int(team["services_up"] or 0),
                            "services_total": int(team["services_total"] or 0),
                            "avg_latency_ms": None if team["avg_latency_ms"] is None else round(float(team["avg_latency_ms"]), 1),
                        }
                        for team in teams
                    ],
                })
        return payload

    def uptime_stats(self, round_limit: int = 0) -> Dict[str, Any]:
        """Aggregate availability by service over all or the latest N rounds."""
        safe_limit = max(0, min(int(round_limit), 10000))
        with self._connection() as connection:
            if safe_limit:
                selected = connection.execute(
                    "SELECT number FROM rounds ORDER BY number DESC LIMIT ?",
                    (safe_limit,),
                ).fetchall()
                round_numbers = [int(row["number"]) for row in selected]
                where_clause = "WHERE round_number IN (SELECT number FROM rounds ORDER BY number DESC LIMIT ?)"
                parameters = (safe_limit,)
            else:
                selected = connection.execute("SELECT number FROM rounds ORDER BY number DESC").fetchall()
                round_numbers = [int(row["number"]) for row in selected]
                where_clause = ""
                parameters = ()
            if not round_numbers:
                return {"round_count": 0, "first_round": None, "last_round": None, "results": []}
            rows = connection.execute(
                """
                SELECT service_id, team, COUNT(*) AS checks, SUM(passed) AS passed_checks,
                       AVG(latency_ms) AS avg_latency_ms
                FROM results
                %s
                GROUP BY service_id, team
                ORDER BY team, service_id
                """ % where_clause,
                parameters,
            ).fetchall()
        return {
            "round_count": len(round_numbers),
            "first_round": min(round_numbers),
            "last_round": max(round_numbers),
            "results": [
                {
                    "id": str(row["service_id"]),
                    "team": str(row["team"]),
                    "checks": int(row["checks"]),
                    "passed_checks": int(row["passed_checks"] or 0),
                    "uptime_percent": round(100.0 * int(row["passed_checks"] or 0) / int(row["checks"]), 1),
                    "avg_latency_ms": None if row["avg_latency_ms"] is None else round(float(row["avg_latency_ms"]), 1),
                }
                for row in rows
            ],
        }

    def _result_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        accurate = row["accurate"]
        return {
            "id": row["service_id"],
            "team": row["team"],
            "type": row["service_type"],
            "host": row["host"],
            "port": int(row["port"]),
            "passed": bool(row["passed"]),
            "accurate": None if accurate is None else bool(accurate),
            "baseline_state": row["baseline_state"],
            "points": int(row["points"]),
            "message": row["message"],
            "latency_ms": row["latency_ms"],
            "timestamp": row["timestamp"],
            "details": json.loads(row["details_json"] or "{}"),
        }

"""Decay monitor storage — SQLite database for probe result history."""
import sqlite3
from datetime import datetime
from pathlib import Path

import structlog

from aatmf.core.models import ProbeResult

logger = structlog.get_logger()

SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    probe_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    tactic_id TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL,
    compliance_score REAL NOT NULL,
    response_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    model TEXT NOT NULL,
    provider TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_probe_results_probe_id ON probe_results(probe_id);
CREATE INDEX IF NOT EXISTS idx_probe_results_timestamp ON probe_results(timestamp);
"""


class DecayStorage:
    """SQLite storage for historical probe results."""

    def __init__(self, db_path: str | Path = "./aatmf-decay.db"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def store_result(
        self,
        run_id: str,
        result: ProbeResult,
        model: str,
        provider: str,
    ) -> None:
        """Store a single probe result."""
        self._conn.execute(
            """INSERT INTO probe_results
               (run_id, probe_id, technique_id, tactic_id, category,
                verdict, compliance_score, response_hash, timestamp, model, provider)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                result.probe_id,
                result.technique_id,
                result.tactic_id,
                result.category,
                result.verdict.value,
                result.compliance_score,
                result.response_hash,
                datetime.utcnow().isoformat() + "Z",
                model,
                provider,
            ),
        )
        self._conn.commit()

    def store_results(
        self,
        run_id: str,
        results: list[ProbeResult],
        model: str,
        provider: str,
    ) -> None:
        """Store multiple probe results in a single transaction."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        rows = [
            (
                run_id,
                r.probe_id,
                r.technique_id,
                r.tactic_id,
                r.category,
                r.verdict.value,
                r.compliance_score,
                r.response_hash,
                timestamp,
                model,
                provider,
            )
            for r in results
        ]
        self._conn.executemany(
            """INSERT INTO probe_results
               (run_id, probe_id, technique_id, tactic_id, category,
                verdict, compliance_score, response_hash, timestamp, model, provider)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()

    def get_baseline_results(
        self,
        probe_id: str,
        model: str,
        provider: str,
        limit: int = 100,
    ) -> list[dict]:
        """Get historical results for a probe to use as baseline."""
        cursor = self._conn.execute(
            """SELECT * FROM probe_results
               WHERE probe_id = ? AND model = ? AND provider = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (probe_id, model, provider, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_latest_timestamp(self, model: str, provider: str) -> str | None:
        """Get timestamp of most recent result for staleness check."""
        cursor = self._conn.execute(
            """SELECT MAX(timestamp) as latest FROM probe_results
               WHERE model = ? AND provider = ?""",
            (model, provider),
        )
        row = cursor.fetchone()
        return row["latest"] if row and row["latest"] else None

    def close(self) -> None:
        self._conn.close()

"""SQLite lightweight index for task metadata and report paths.

Status is derived from Event Ledger projection, NOT stored as source-of-truth here.
The cached `status` column exists for fast reads only — the ledger is authoritative.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator, Optional

from veriaudit.core.schema import AuditReport, INDEX_DB_PATH

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id     TEXT PRIMARY KEY,
    repo_url    TEXT NOT NULL,
    mode        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL,
    completed_at TEXT,
    report_paths TEXT
);

CREATE TABLE IF NOT EXISTS finding_index (
    task_id     TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    cwe         TEXT,
    file_path   TEXT NOT NULL,
    message     TEXT NOT NULL,
    PRIMARY KEY (task_id, finding_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_finding_task
    ON finding_index(task_id);
"""


def _now() -> str:
    """Return current UTC timestamp as ISO 8601 string."""
    return datetime.utcnow().isoformat()


@contextmanager
def _transaction(db_path: str) -> Iterator[sqlite3.Connection]:
    """Yield a connection with foreign keys enabled, commit on success, rollback on error."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class TaskIndex:
    """SQLite lightweight index for task metadata and finding summaries."""

    def __init__(self, db_path: str = INDEX_DB_PATH) -> None:
        self.db_path = db_path
        with _transaction(db_path) as conn:
            conn.executescript(_SCHEMA_SQL)

    # ── task CRUD ────────────────────────────────────────────

    def create_task(
        self, task_id: str, repo_url: str, mode: str, status: str = "pending"
    ) -> None:
        """Insert a new task row."""
        with _transaction(self.db_path) as conn:
            conn.execute(
                "INSERT INTO tasks (task_id, repo_url, mode, status, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (task_id, repo_url, mode, status, _now()),
            )

    def update_task_status(self, task_id: str, status: str) -> None:
        """Update the cached status for a task."""
        with _transaction(self.db_path) as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, completed_at = CASE"
                " WHEN ? IN ('completed', 'failed') THEN ?"
                " ELSE completed_at END"
                " WHERE task_id = ?",
                (status, status, _now(), task_id),
            )

    def save_report(self, task_id: str, report: AuditReport) -> None:
        """Persist a completed report and its findings.

        Atomically:
        1. Updates the tasks row with report_paths JSON, status='completed', completed_at
        2. Deletes old finding_index rows for this task
        3. Inserts current findings from the report
        """
        report_paths_json = json.dumps(report.report_paths, sort_keys=True)
        now = _now()

        with _transaction(self.db_path) as conn:
            conn.execute(
                "UPDATE tasks"
                " SET status = 'completed', completed_at = ?, report_paths = ?"
                " WHERE task_id = ?",
                (now, report_paths_json, task_id),
            )
            conn.execute(
                "DELETE FROM finding_index WHERE task_id = ?", (task_id,)
            )
            conn.executemany(
                "INSERT INTO finding_index"
                " (task_id, finding_id, status, severity, cwe, file_path, message)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        task_id,
                        finding.finding_id,
                        finding.status.value
                        if hasattr(finding.status, "value")
                        else str(finding.status),
                        finding.severity,
                        finding.cwe,
                        finding.file_path,
                        finding.message,
                    )
                    for finding in report.findings
                ],
            )

    # ── queries ──────────────────────────────────────────────

    def get_task(self, task_id: str) -> Optional[dict[str, Any]]:
        """Return a task dict or None.  Parses ``report_paths`` from JSON."""
        with _transaction(self.db_path) as conn:
            row = conn.execute(
                "SELECT task_id, repo_url, mode, status, created_at,"
                "       completed_at, report_paths"
                " FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()

        if row is None:
            return None

        return _task_row_to_dict(row)

    def list_tasks(
        self, limit: int = 20, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Return tasks ordered by created_at descending."""
        with _transaction(self.db_path) as conn:
            rows = conn.execute(
                "SELECT task_id, repo_url, mode, status, created_at,"
                "       completed_at, report_paths"
                " FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()

        return [_task_row_to_dict(r) for r in rows]

    def get_finding_summaries(
        self, task_id: str,
    ) -> list[dict[str, Any]]:
        """Return lightweight finding summaries for a task."""
        with _transaction(self.db_path) as conn:
            rows = conn.execute(
                "SELECT finding_id, status, severity, cwe, file_path, message"
                " FROM finding_index WHERE task_id = ?"
                " ORDER BY"
                " CASE severity"
                "   WHEN 'critical' THEN 1"
                "   WHEN 'high' THEN 2"
                "   WHEN 'medium' THEN 3"
                "   WHEN 'low' THEN 4"
                "   WHEN 'info' THEN 5"
                "   ELSE 6 END,"
                " file_path ASC",
                (task_id,),
            ).fetchall()

        return [
            {
                "finding_id": r[0],
                "status": r[1],
                "severity": r[2],
                "cwe": r[3],
                "file_path": r[4],
                "message": r[5],
            }
            for r in rows
        ]


# ── helpers ──────────────────────────────────────────────────


def _task_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a ``tasks`` row to a plain dict, parsing JSON columns."""
    return {
        "task_id": row[0],
        "repo_url": row[1],
        "mode": row[2],
        "status": row[3],
        "created_at": row[4],
        "completed_at": row[5],
        "report_paths": json.loads(row[6]) if row[6] else {},
    }

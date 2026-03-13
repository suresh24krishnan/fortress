from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List


def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: str) -> None:
    """Initialize the SQLite ledger (idempotent)."""
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA synchronous=NORMAL;")
        cur.execute("PRAGMA temp_store=MEMORY;")

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                created_at_utc TEXT,
                updated_at_utc TEXT,
                payload_json TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS baselines (
                baseline_id TEXT PRIMARY KEY,
                created_at_utc TEXT,
                updated_at_utc TEXT,
                payload_json TEXT
            );
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_jobs_updated ON jobs(updated_at_utc);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_baselines_updated ON baselines(updated_at_utc);")
        con.commit()
    finally:
        con.close()


def _connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


def upsert_job(db_path: str, job_id: str, payload: Dict[str, Any]) -> None:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        now = _utc_ts()
        created = payload.get("created_at_utc") or now
        payload.setdefault("created_at_utc", created)

        cur.execute(
            """
            INSERT INTO jobs(job_id, created_at_utc, updated_at_utc, payload_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
              updated_at_utc=excluded.updated_at_utc,
              payload_json=excluded.payload_json;
            """,
            (job_id, created, now, json.dumps(payload)),
        )
        con.commit()
    finally:
        con.close()


def get_job(db_path: str, job_id: str) -> Optional[Dict[str, Any]]:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("SELECT payload_json FROM jobs WHERE job_id = ?;", (job_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])
    finally:
        con.close()


def list_recent_job_ids(db_path: str, limit: int = 20) -> List[str]:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT job_id FROM jobs ORDER BY updated_at_utc DESC LIMIT ?;",
            (int(limit),),
        )
        return [r["job_id"] for r in cur.fetchall()]
    finally:
        con.close()


def upsert_baseline(db_path: str, baseline_id: str, payload: Dict[str, Any]) -> None:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        now = _utc_ts()
        created = payload.get("created_at_utc") or now
        payload.setdefault("created_at_utc", created)

        cur.execute(
            """
            INSERT INTO baselines(baseline_id, created_at_utc, updated_at_utc, payload_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(baseline_id) DO UPDATE SET
              updated_at_utc=excluded.updated_at_utc,
              payload_json=excluded.payload_json;
            """,
            (baseline_id, created, now, json.dumps(payload)),
        )
        con.commit()
    finally:
        con.close()


def get_baseline(db_path: str, baseline_id: str) -> Optional[Dict[str, Any]]:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("SELECT payload_json FROM baselines WHERE baseline_id = ?;", (baseline_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])
    finally:
        con.close()


def list_recent_baseline_ids(db_path: str, limit: int = 20) -> List[str]:
    con = _connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT baseline_id FROM baselines ORDER BY updated_at_utc DESC LIMIT ?;",
            (int(limit),),
        )
        return [r["baseline_id"] for r in cur.fetchall()]
    finally:
        con.close()


def clear_all(db_path: str) -> Dict[str, int]:
    """Delete all jobs and baselines from the ledger. Returns counts removed."""
    con = _connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(1) AS n FROM jobs;")
        jobs_cnt = int(cur.fetchone()["n"] or 0)
        cur.execute("SELECT COUNT(1) AS n FROM baselines;")
        baselines_cnt = int(cur.fetchone()["n"] or 0)

        cur.execute("DELETE FROM jobs;")
        cur.execute("DELETE FROM baselines;")
        con.commit()

        # Best-effort compaction
        try:
            cur.execute("VACUUM;")
            con.commit()
        except Exception:
            pass

        return {"jobs_deleted": jobs_cnt, "baselines_deleted": baselines_cnt}
    finally:
        con.close()
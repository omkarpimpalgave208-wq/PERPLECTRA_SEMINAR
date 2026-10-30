"""
SQLite persistence layer for PERPLECTRA.

Uses only the Python standard-library ``sqlite3`` module — no ORM.
All queries are parameterised.  WAL mode is enabled for safe concurrent
access from the recovery engine and the HTTP handlers.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

# ── Schema ─────────────────────────────────────────────────────────────────────
_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS agents (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    env         TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_agents_prefix
    ON agents (key_prefix, revoked);

CREATE TABLE IF NOT EXISTS executions (
    id                       TEXT PRIMARY KEY,
    agent_id                 TEXT NOT NULL,
    idempotency_key          TEXT,
    idempotency_payload_hash TEXT,
    action_name              TEXT NOT NULL,
    intent                   TEXT NOT NULL,
    env                      TEXT NOT NULL,
    policy                   TEXT NOT NULL,
    fail_injection           INTEGER NOT NULL DEFAULT 0,
    status                   TEXT NOT NULL DEFAULT 'RUNNING',
    baseline_hash            TEXT,
    result_hash              TEXT,
    verified_hash            TEXT,
    recovery_outcome         TEXT,
    verification_outcome     TEXT,
    fail_reason              TEXT,
    stages_json              TEXT NOT NULL DEFAULT '[]',
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_exec_idempotency
    ON executions (agent_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
"""


def get_conn(db_path: str, check_same_thread: bool = False) -> sqlite3.Connection:
    """Open a connection with row_factory and WAL + foreign keys enabled."""
    conn = sqlite3.connect(db_path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str) -> None:
    """Create tables and indexes if they do not already exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn(db_path)
    try:
        conn.executescript(_SCHEMA)
        # Backward-compatible column migration for verified_hash
        cols = [c[1] for c in conn.execute("PRAGMA table_info(executions)").fetchall()]
        if "verified_hash" not in cols:
            conn.execute("ALTER TABLE executions ADD COLUMN verified_hash TEXT")
        conn.commit()
    finally:
        conn.close()


# ── Agent helpers ───────────────────────────────────────────────────────────────
def insert_agent(
    conn: sqlite3.Connection,
    *,
    agent_id: str,
    name: str,
    agent_type: str,
    env: str,
    key_hash: str,
    key_prefix: str,
    created_at: str,
) -> None:
    conn.execute(
        """INSERT INTO agents (id, name, type, env, key_hash, key_prefix, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (agent_id, name, agent_type, env, key_hash, key_prefix, created_at),
    )
    conn.commit()


def find_agent_by_key_prefix(
    conn: sqlite3.Connection, key_prefix: str
) -> list[dict]:
    """Return all non-revoked agents whose key_prefix matches."""
    rows = conn.execute(
        "SELECT * FROM agents WHERE key_prefix = ? AND revoked = 0",
        (key_prefix,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_agent_by_id(conn: sqlite3.Connection, agent_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM agents WHERE id = ? AND revoked = 0", (agent_id,)
    ).fetchone()
    return dict(row) if row else None


# ── Execution helpers ───────────────────────────────────────────────────────────
def insert_execution(
    conn: sqlite3.Connection,
    *,
    exec_id: str,
    agent_id: str,
    idempotency_key: Optional[str],
    idempotency_payload_hash: Optional[str],
    action_name: str,
    intent: str,
    env: str,
    policy: str,
    fail_injection: bool,
    created_at: str,
) -> None:
    conn.execute(
        """INSERT INTO executions
           (id, agent_id, idempotency_key, idempotency_payload_hash,
            action_name, intent, env, policy, fail_injection,
            status, stages_json, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,'RUNNING','[]',?,?)""",
        (
            exec_id, agent_id, idempotency_key, idempotency_payload_hash,
            action_name, intent, env, policy, int(fail_injection),
            created_at, created_at,
        ),
    )
    conn.commit()


def update_execution(conn: sqlite3.Connection, exec_id: str, updated_at: str, **fields) -> None:
    """Update arbitrary columns on an execution row."""
    if not fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [updated_at, exec_id]
    conn.execute(
        f"UPDATE executions SET {set_clause}, updated_at = ? WHERE id = ?",
        values,
    )
    conn.commit()


def get_execution(conn: sqlite3.Connection, exec_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM executions WHERE id = ?", (exec_id,)
    ).fetchone()
    return dict(row) if row else None


def get_execution_for_agent(
    conn: sqlite3.Connection, exec_id: str, agent_id: str
) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM executions WHERE id = ? AND agent_id = ?",
        (exec_id, agent_id),
    ).fetchone()
    return dict(row) if row else None


def find_idempotent_execution(
    conn: sqlite3.Connection, agent_id: str, idempotency_key: str
) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM executions WHERE agent_id = ? AND idempotency_key = ?",
        (agent_id, idempotency_key),
    ).fetchone()
    return dict(row) if row else None


def list_all_executions(
    conn: sqlite3.Connection, limit: int = 50, offset: int = 0
) -> tuple[list[dict], int]:
    """Return all persisted executions (e.g. for receipts page display)."""
    total = conn.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
    rows = conn.execute(
        """SELECT * FROM executions
           ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        (limit, offset),
    ).fetchall()
    return [dict(r) for r in rows], total


def list_executions_for_agent(
    conn: sqlite3.Connection, agent_id: str, limit: int, offset: int
) -> tuple[list[dict], int]:
    total = conn.execute(
        "SELECT COUNT(*) FROM executions WHERE agent_id = ?", (agent_id,)
    ).fetchone()[0]
    rows = conn.execute(
        """SELECT * FROM executions WHERE agent_id = ?
           ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        (agent_id, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows], total


def execution_row_to_dict(row: dict) -> dict:
    """Deserialise stages_json and normalise types for API response."""
    out = dict(row)
    out["stages"] = json.loads(out.pop("stages_json", "[]") or "[]")
    out["fail_injection"] = bool(out.get("fail_injection", 0))
    # Drop internal columns not part of the public API
    out.pop("idempotency_payload_hash", None)
    return out

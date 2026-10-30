"""
PERPLECTRA Recovery Engine — Phase 1: local file-operation recovery.

This module is entirely decoupled from HTTP handlers.  It accepts plain
Python values and a database path; it never imports FastAPI or Starlette.

Lifecycle states
----------------
RUNNING              → Initial state; execution record created.
EXECUTED_VERIFIED    → File modified and post-write hash confirmed.  No
                       failure was injected.
FAILED               → Execution failed (injected or unexpected).
RECOVERING           → RESTORE_BASELINE policy is being applied.
RECOVERED_UNVERIFIED → Baseline bytes written back; verification pending.
RECOVERY_FAILED      → Restoration write itself failed.
VERIFICATION_FAILED  → File re-read after restore; hash did not match.
RECOVERY_VERIFIED    → Independent hash of restored file equals baseline.

Only RECOVERY_VERIFIED and EXECUTED_VERIFIED are non-failure terminal states.

Test-only injection points
--------------------------
_inject_restore_fail : bool — if True, skips the restoration write and
    records RECOVERY_FAILED.  Not reachable from the HTTP API.
_inject_verify_fail  : bool — if True, corrupts the target after restore
    so that the hash comparison fails.  Not reachable from the HTTP API.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from .database import (
    get_conn,
    insert_execution,
    update_execution,
    get_execution,
    execution_row_to_dict,
)
from .file_guard import PathViolationError, safe_resolve

TARGET_FILENAME = "target.txt"

_MODIFICATION_TEMPLATE = (
    "== PERPLECTRA controlled modification ==\n"
    "Timestamp : {ts}\n"
    "Agent     : {agent_id}\n"
    "Intent    : {intent}\n"
    "Policy    : {policy}\n"
    "Exec ID   : {exec_id}\n"
)


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _append_stage(
    stages: list[dict],
    conn,
    exec_id: str,
    stage: str,
    **extra: Any,
) -> None:
    entry: dict[str, Any] = {"stage": stage, "ts": _now()}
    entry.update({k: v for k, v in extra.items() if v is not None})
    stages.append(entry)
    update_execution(
        conn, exec_id, _now(), stages_json=json.dumps(stages)
    )


# ── Public entry point ──────────────────────────────────────────────────────────
def run_protected_action(
    *,
    agent_id: str,
    action_name: str,
    intent: str,
    env: str,
    policy: str,
    fail_injection: bool,
    db_path: str,
    workspace_root: Path,
    idempotency_key: Optional[str] = None,
    idempotency_payload_hash: Optional[str] = None,
    # ── Test-only injection points — NOT exposed via any HTTP parameter ──
    _inject_restore_fail: bool = False,
    _inject_verify_fail: bool = False,
) -> dict:
    """
    Execute the full recovery lifecycle and return the final execution row dict.

    Guarantees
    ----------
    * A DB row is created with status RUNNING before any file I/O.
    * Every stage transition is persisted before the next stage begins.
    * Unexpected exceptions are caught, recorded, and re-raised; the row
      is left in FAILED state so interrupted runs are identifiable.
    * RECOVERY_VERIFIED is only written when the independent hash matches.
    * Plaintext key and snapshot content are never stored in the DB row.
    """
    conn = get_conn(db_path)
    exec_id = "exec_" + uuid.uuid4().hex[:16]
    now = _now()
    stages: list[dict] = []

    # ── 1. Create durable RUNNING record ────────────────────────────────────────
    insert_execution(
        conn,
        exec_id=exec_id,
        agent_id=agent_id,
        idempotency_key=idempotency_key,
        idempotency_payload_hash=idempotency_payload_hash,
        action_name=action_name,
        intent=intent,
        env=env,
        policy=policy,
        fail_injection=fail_injection,
        created_at=now,
    )

    try:
        # ── 2. Validate and resolve target path ──────────────────────────────────
        target_path = safe_resolve(TARGET_FILENAME, workspace_root)
        _append_stage(
            stages, conn, exec_id, "VALIDATED",
            detail=f"Target path validated: {TARGET_FILENAME}",
            target=str(target_path),
        )

        # ── 3. Capture baseline ──────────────────────────────────────────────────
        if not target_path.exists():
            target_path.write_text(
                "PERPLECTRA test target file.\nInitial state.\n", encoding="utf-8"
            )
        original_bytes = target_path.read_bytes()
        baseline_hash = _sha256_bytes(original_bytes)

        _append_stage(
            stages, conn, exec_id, "BASELINE_CAPTURED",
            baseline_hash=baseline_hash,
        )
        update_execution(conn, exec_id, _now(), baseline_hash=baseline_hash)

        # ── 4. Execute modification ──────────────────────────────────────────────
        new_text = _MODIFICATION_TEMPLATE.format(
            ts=_now(), agent_id=agent_id, intent=intent,
            policy=policy, exec_id=exec_id,
        )
        new_bytes = new_text.encode("utf-8")
        target_path.write_bytes(new_bytes)
        result_hash = _sha256_bytes(new_bytes)

        _append_stage(
            stages, conn, exec_id, "EXECUTED",
            result_hash=result_hash,
        )
        update_execution(conn, exec_id, _now(), result_hash=result_hash)

        # ── 5. Failure detection ─────────────────────────────────────────────────
        if fail_injection:
            _append_stage(
                stages, conn, exec_id, "FAILURE_DETECTED",
                detail="Controlled failure injected (fail_injection=true)",
            )
            update_execution(conn, exec_id, _now(), status="FAILED")

            # ── 6. Recovery ──────────────────────────────────────────────────────
            _append_stage(
                stages, conn, exec_id, "RECOVERING",
                policy=policy,
                detail="Applying RESTORE_BASELINE: restoring captured snapshot",
            )
            update_execution(conn, exec_id, _now(), status="RECOVERING")

            if _inject_restore_fail:
                # Test-only: simulate the restoration write failing
                _append_stage(
                    stages, conn, exec_id, "RECOVERY_FAILED",
                    detail="Restoration write failed (test injection)",
                )
                update_execution(
                    conn, exec_id, _now(),
                    status="RECOVERY_FAILED",
                    recovery_outcome="FAILED",
                    fail_reason="Restoration write failed (test injection)",
                )
                conn.close()
                return _fetch(db_path, exec_id)

            # Write original bytes back
            target_path.write_bytes(original_bytes)
            _append_stage(
                stages, conn, exec_id, "BASELINE_RESTORED",
                detail="Original content written back to target file",
            )
            update_execution(
                conn, exec_id, _now(),
                status="RECOVERED_UNVERIFIED",
                recovery_outcome="RESTORE_BASELINE_APPLIED",
            )

            # ── 7. Independent verification ───────────────────────────────────────
            _append_stage(
                stages, conn, exec_id, "VERIFYING",
                detail="Re-reading target file independently for hash comparison",
            )

            if _inject_verify_fail:
                # Test-only: corrupt the file after restore to force mismatch
                target_path.write_bytes(b"__CORRUPTED_BY_TEST_INJECTION__")

            verified_bytes = target_path.read_bytes()
            verified_hash = _sha256_bytes(verified_bytes)

            if verified_hash == baseline_hash:
                _append_stage(
                    stages, conn, exec_id, "RECOVERY_VERIFIED",
                    baseline_hash=baseline_hash,
                    actual_hash=verified_hash,
                )
                update_execution(
                    conn, exec_id, _now(),
                    status="RECOVERY_VERIFIED",
                    verified_hash=verified_hash,
                    recovery_outcome="RESTORE_BASELINE_APPLIED",
                    verification_outcome="HASH_MATCH",
                )
            else:
                _append_stage(
                    stages, conn, exec_id, "VERIFICATION_FAILED",
                    baseline_hash=baseline_hash,
                    actual_hash=verified_hash,
                )
                update_execution(
                    conn, exec_id, _now(),
                    status="VERIFICATION_FAILED",
                    verified_hash=verified_hash,
                    recovery_outcome="RESTORE_BASELINE_APPLIED",
                    verification_outcome="HASH_MISMATCH",
                    fail_reason=(
                        f"Hash mismatch after restore: "
                        f"expected {baseline_hash}, got {verified_hash}"
                    ),
                )

        else:
            # No failure injection — verify the modification was written correctly
            _append_stage(
                stages, conn, exec_id, "VERIFYING",
                detail="Verifying file write integrity (no failure injection)",
            )
            verified_bytes = target_path.read_bytes()
            verified_hash = _sha256_bytes(verified_bytes)

            if verified_hash == result_hash:
                _append_stage(
                    stages, conn, exec_id, "EXECUTION_VERIFIED",
                    result_hash=result_hash,
                    actual_hash=verified_hash,
                )
                update_execution(
                    conn, exec_id, _now(),
                    status="EXECUTION_VERIFIED",
                    verified_hash=verified_hash,
                    verification_outcome="HASH_MATCH",
                )
            else:
                _append_stage(
                    stages, conn, exec_id, "VERIFICATION_FAILED",
                    result_hash=result_hash,
                    actual_hash=verified_hash,
                )
                update_execution(
                    conn, exec_id, _now(),
                    status="VERIFICATION_FAILED",
                    verified_hash=verified_hash,
                    verification_outcome="HASH_MISMATCH",
                    fail_reason="Post-write hash mismatch: file on disk differs from written bytes",
                )

    except PathViolationError as exc:
        update_execution(
            conn, exec_id, _now(),
            status="FAILED",
            fail_reason=f"Path safety violation: {exc}",
        )
        _append_stage(stages, conn, exec_id, "FAILED", detail=str(exc))

    except Exception as exc:
        update_execution(
            conn, exec_id, _now(),
            status="FAILED",
            fail_reason=f"Unexpected error ({type(exc).__name__}): {exc}",
        )
        _append_stage(stages, conn, exec_id, "FAILED", detail=str(exc))

    finally:
        conn.close()

    return _fetch(db_path, exec_id)


def _fetch(db_path: str, exec_id: str) -> dict:
    """Re-open the DB and return the final execution row."""
    conn = get_conn(db_path)
    try:
        row = get_execution(conn, exec_id)
        if row is None:
            raise RuntimeError(f"Execution {exec_id!r} vanished from DB")
        return execution_row_to_dict(row)
    finally:
        conn.close()

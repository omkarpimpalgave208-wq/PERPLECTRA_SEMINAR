"""
Tests for perplectra.recovery_engine — unit-level, no HTTP.
"""
from __future__ import annotations

import hashlib
import pytest
from pathlib import Path

from perplectra.database import init_db, get_conn, get_execution, execution_row_to_dict, insert_agent
from perplectra.recovery_engine import run_protected_action


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture()
def engine_env(tmp_path: Path):
    db_path = str(tmp_path / "engine_test.db")
    init_db(db_path)
    conn = get_conn(db_path)
    insert_agent(
        conn,
        agent_id="agt_test000001",
        name="test-agent",
        agent_type="Infrastructure",
        env="dev",
        key_hash="hash",
        key_prefix="prefix",
        created_at="2026-10-26T00:00:00Z",
    )
    conn.close()
    ws = tmp_path / "test_files"
    ws.mkdir()
    seed = ws / "target.txt"
    seed.write_text("Initial content.\n", encoding="utf-8")
    return db_path, ws, seed


def _run(db_path, ws, *, fail_injection=False,
         _inject_restore_fail=False, _inject_verify_fail=False):
    return run_protected_action(
        agent_id="agt_test000001",
        action_name="modify_test_file",
        intent="Unit test intent",
        env="dev",
        policy="RESTORE_BASELINE",
        fail_injection=fail_injection,
        db_path=db_path,
        workspace_root=ws,
        _inject_restore_fail=_inject_restore_fail,
        _inject_verify_fail=_inject_verify_fail,
    )


class TestSuccessfulModification:
    def test_status_is_execution_verified(self, engine_env):
        db_path, ws, seed = engine_env
        result = _run(db_path, ws)
        assert result["status"] == "EXECUTION_VERIFIED"

    def test_baseline_hash_recorded(self, engine_env):
        db_path, ws, seed = engine_env
        original = seed.read_bytes()
        result = _run(db_path, ws)
        assert result["baseline_hash"] == _sha256(original)

    def test_result_hash_recorded(self, engine_env):
        db_path, ws, seed = engine_env
        result = _run(db_path, ws)
        current = seed.read_bytes()
        assert result["result_hash"] == _sha256(current)

    def test_file_is_modified(self, engine_env):
        db_path, ws, seed = engine_env
        original = seed.read_text(encoding="utf-8")
        _run(db_path, ws)
        modified = seed.read_text(encoding="utf-8")
        assert modified != original

    def test_stages_contain_executed(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws)
        stages = [s["stage"] for s in result["stages"]]
        assert "EXECUTED" in stages
        assert "EXECUTION_VERIFIED" in stages

    def test_receipt_persisted_to_db(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws)
        conn = get_conn(db_path)
        row = get_execution(conn, result["id"])
        conn.close()
        assert row is not None
        assert row["status"] == "EXECUTION_VERIFIED"


class TestFailureAndRecovery:
    def test_status_is_recovery_verified(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True)
        assert result["status"] == "RECOVERY_VERIFIED"

    def test_file_restored_to_baseline(self, engine_env):
        db_path, ws, seed = engine_env
        original = seed.read_bytes()
        _run(db_path, ws, fail_injection=True)
        restored = seed.read_bytes()
        assert restored == original

    def test_verification_outcome_hash_match(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True)
        assert result["verification_outcome"] == "HASH_MATCH"

    def test_stages_include_all_recovery_steps(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True)
        stages = [s["stage"] for s in result["stages"]]
        for expected in [
            "VALIDATED", "BASELINE_CAPTURED", "EXECUTED",
            "FAILURE_DETECTED", "RECOVERING", "BASELINE_RESTORED",
            "VERIFYING", "RECOVERY_VERIFIED",
        ]:
            assert expected in stages, f"Missing stage: {expected}"

    def test_recovery_outcome_recorded(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True)
        assert result["recovery_outcome"] == "RESTORE_BASELINE_APPLIED"


class TestRestorationFailure:
    def test_status_is_recovery_failed(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True, _inject_restore_fail=True)
        assert result["status"] == "RECOVERY_FAILED"

    def test_fail_reason_recorded(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True, _inject_restore_fail=True)
        assert result["fail_reason"]

    def test_not_labelled_verified(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True, _inject_restore_fail=True)
        assert "VERIFIED" not in result["status"]


class TestVerificationFailure:
    def test_status_is_verification_failed(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(
            db_path, ws, fail_injection=True,
            _inject_verify_fail=True,
        )
        assert result["status"] == "VERIFICATION_FAILED"

    def test_hash_mismatch_recorded(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(
            db_path, ws, fail_injection=True,
            _inject_verify_fail=True,
        )
        assert result["verification_outcome"] == "HASH_MISMATCH"

    def test_fail_reason_contains_hash_info(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(
            db_path, ws, fail_injection=True,
            _inject_verify_fail=True,
        )
        assert "mismatch" in (result.get("fail_reason") or "").lower()

    def test_not_labelled_verified(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(
            db_path, ws, fail_injection=True,
            _inject_verify_fail=True,
        )
        assert result["status"] != "RECOVERY_VERIFIED"


class TestPersistenceAfterReopen:
    def test_receipt_survives_connection_close(self, engine_env):
        db_path, ws, _ = engine_env
        result = _run(db_path, ws, fail_injection=True)

        # Open a fresh connection — simulates app restart
        conn = get_conn(db_path)
        row = get_execution(conn, result["id"])
        conn.close()

        assert row is not None
        assert row["status"] == "RECOVERY_VERIFIED"
        assert row["baseline_hash"] is not None
        assert row["verification_outcome"] == "HASH_MATCH"


class TestInterruptedExecution:
    def test_running_status_not_labelled_verified(self, engine_env, monkeypatch):
        """A RUNNING record that was never completed must not be RECOVERY_VERIFIED."""
        db_path, ws, _ = engine_env
        from perplectra import recovery_engine as eng_mod

        original_insert = eng_mod.insert_execution

        def insert_then_raise(*args, **kwargs):
            original_insert(*args, **kwargs)
            raise RuntimeError("Simulated process crash")

        monkeypatch.setattr(eng_mod, "insert_execution", insert_then_raise)

        with pytest.raises(RuntimeError):
            _run(db_path, ws)

        # The row must be in RUNNING (never updated) — certainly not VERIFIED
        conn = get_conn(db_path)
        rows = conn.execute("SELECT * FROM executions").fetchall()
        conn.close()
        for row in rows:
            assert row["status"] not in ("RECOVERY_VERIFIED", "EXECUTION_VERIFIED")

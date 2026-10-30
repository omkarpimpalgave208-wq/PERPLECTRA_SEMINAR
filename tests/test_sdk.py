"""
Unit and integration tests for the Perplectra Python SDK.
"""
from __future__ import annotations

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import server
from perplectra import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PerplectraClient,
    ValidationError,
)


@pytest.fixture()
def sdk_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Provides a PerplectraClient connected via TestClient to the FastAPI app
    with an isolated temporary database and workspace.
    """
    db_path = str(tmp_path / "test_sdk.db")
    workspace = tmp_path / "test_sdk_files"
    workspace.mkdir(parents=True)
    (workspace / "target.txt").write_text("Initial test target content.\n", encoding="utf-8")

    from perplectra.database import init_db
    init_db(db_path)

    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "WORKSPACE_ROOT", workspace)

    with TestClient(server.app, base_url="http://testserver") as tc:
        client = PerplectraClient(
            base_url="http://testserver",
            http_client=tc,
        )
        yield client, db_path, workspace
        client.close()


class TestSDKClientInitialization:
    def test_init_with_explicit_key(self):
        client = PerplectraClient(api_key="pxk_live_test12345678", base_url="http://localhost:8000/")
        assert client.api_key == "pxk_live_test12345678"
        assert client.base_url == "http://localhost:8000"
        assert "test12345678" not in repr(client)
        assert "[REDACTED]" in repr(client)

    def test_init_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PERPLECTRA_API_KEY", "pxk_live_envkey87654321")
        client = PerplectraClient()
        assert client.api_key == "pxk_live_envkey87654321"
        assert "envkey87654321" not in repr(client)
        assert "[REDACTED]" in repr(client)

    def test_repr_without_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("PERPLECTRA_API_KEY", raising=False)
        client = PerplectraClient()
        assert client.api_key is None
        assert "<none>" in repr(client)


class TestSDKRegistrationAndActions:
    def test_register_agent(self, sdk_client):
        client, _, _ = sdk_client
        agent = client.register_agent(
            name="SDKTestAgent",
            agent_type="Infrastructure",
            env="dev",
        )
        assert agent["agent_id"].startswith("agt_")
        assert agent["api_key"].startswith("pxk_live_")
        assert client.api_key == agent["api_key"]

    def test_execute_action_clean(self, sdk_client):
        client, _, _ = sdk_client
        client.register_agent(name="CleanAgent", agent_type="Infrastructure", env="dev")

        receipt = client.execute_action(
            action_name="modify_test_file",
            intent="Execute clean verified modification",
            env="dev",
            policy="RESTORE_BASELINE",
            fail_injection=False,
        )
        assert receipt["status"] == "EXECUTION_VERIFIED"
        assert receipt["baseline_hash"] is not None
        assert receipt["result_hash"] is not None
        assert receipt["baseline_hash"] != receipt["result_hash"]

        # Fetch receipt by ID
        fetched = client.get_execution(receipt["execution_id"])
        assert fetched["execution_id"] == receipt["execution_id"]
        assert fetched["status"] == "EXECUTION_VERIFIED"

    def test_execute_action_with_failure_injection(self, sdk_client):
        client, _, workspace = sdk_client
        client.register_agent(name="FailureTestAgent", agent_type="Infrastructure", env="dev")

        target_file = workspace / "target.txt"
        orig_content = target_file.read_text(encoding="utf-8")

        receipt = client.execute_action(
            action_name="modify_test_file",
            intent="Execute test with deterministic failure injection",
            env="dev",
            policy="RESTORE_BASELINE",
            fail_injection=True,
        )

        assert receipt["status"] == "RECOVERY_VERIFIED"
        assert receipt["recovery_outcome"] == "RESTORE_BASELINE_APPLIED"
        assert receipt["verification_outcome"] == "HASH_MATCH"
        assert receipt["baseline_hash"] is not None
        assert receipt["verified_hash"] == receipt["baseline_hash"]
        assert receipt["result_hash"] != receipt["baseline_hash"]

        # Confirm target file on disk was genuinely restored to original bytes
        assert target_file.read_text(encoding="utf-8") == orig_content

    def test_list_executions(self, sdk_client):
        client, _, _ = sdk_client
        client.register_agent(name="ListAgent", agent_type="Infrastructure", env="dev")

        for i in range(2):
            client.execute_action(
                action_name="modify_test_file",
                intent=f"Execution index {i} for listing",
                env="dev",
                policy="RESTORE_BASELINE",
                fail_injection=False,
            )

        resp = client.list_executions(page=1, per_page=10)
        assert resp["total"] >= 2
        assert len(resp["executions"]) >= 2


class TestSDKErrorsAndSecurity:
    def test_execute_without_key_raises_auth_error(self, sdk_client, monkeypatch):
        monkeypatch.delenv("PERPLECTRA_API_KEY", raising=False)
        client, _, _ = sdk_client
        with pytest.raises(AuthenticationError) as exc_info:
            client.execute_action(action_name="modify_test_file", intent="Will fail with no key")
        assert "API key is required" in str(exc_info.value)

    def test_invalid_key_raises_auth_error(self, sdk_client):
        client, _, _ = sdk_client
        client.api_key = "pxk_live_invalidkey000000000000"
        with pytest.raises(AuthenticationError) as exc_info:
            client.execute_action(action_name="modify_test_file", intent="Will fail auth")
        assert exc_info.value.status_code == 401

    def test_invalid_action_raises_validation_error(self, sdk_client):
        client, _, _ = sdk_client
        client.register_agent(name="ValAgent", agent_type="Infrastructure", env="dev")
        with pytest.raises(ValidationError) as exc_info:
            client.execute_action(action_name="rm_rf_everything", intent="Illegal action")
        assert exc_info.value.status_code == 422

    def test_nonexistent_execution_raises_not_found(self, sdk_client):
        client, _, _ = sdk_client
        client.register_agent(name="NotFoundAgent", agent_type="Infrastructure", env="dev")
        with pytest.raises(NotFoundError) as exc_info:
            client.get_execution("exec_nonexistent12345")
        assert exc_info.value.status_code == 404

    def test_idempotency_conflict_raises_conflict_error(self, sdk_client):
        client, _, _ = sdk_client
        client.register_agent(name="IdemAgent", agent_type="Infrastructure", env="dev")
        idem_key = "idem_key_unique_123"

        # First call succeeds
        client.execute_action(
            action_name="modify_test_file",
            intent="First execution with key",
            idempotency_key=idem_key,
        )

        # Same key with different payload raises 409 Conflict
        with pytest.raises(ConflictError) as exc_info:
            client.execute_action(
                action_name="modify_test_file",
                intent="Different intent with same key",
                idempotency_key=idem_key,
            )
        assert exc_info.value.status_code == 409

    def test_persistence_across_client_reinstantiation(self, sdk_client):
        client1, _, _ = sdk_client
        agent = client1.register_agent(name="PersistAgent", agent_type="Infrastructure", env="dev")
        rec = client1.execute_action(
            action_name="modify_test_file",
            intent="Persist across separate instances",
            fail_injection=True,
        )

        # Separate client instance with same key
        client2 = PerplectraClient(
            api_key=agent["api_key"],
            base_url="http://testserver",
            http_client=client1.http_client,
        )
        fetched = client2.get_execution(rec["execution_id"])
        assert fetched["execution_id"] == rec["execution_id"]
        assert fetched["status"] == "RECOVERY_VERIFIED"
        assert fetched["verified_hash"] == rec["verified_hash"]

    def test_remote_unauthenticated_public_access_forbidden(self, client):
        c, _, _ = client
        # In TestClient, default host is 'testclient', which is allowed.
        # Calling with an external client host header/override or remote client IP should be 403:
        resp = c.get("/api/public/executions", headers={"X-Forwarded-For": "203.0.113.195"})
        # When request.client.host is mocked as remote:
        from unittest.mock import MagicMock
        from server import _verify_public_access
        from fastapi import HTTPException

        fake_request = MagicMock()
        fake_request.client.host = "198.51.100.24"
        with pytest.raises(HTTPException) as exc_info:
            _verify_public_access(fake_request, opt_agent=None)
        assert exc_info.value.status_code == 403

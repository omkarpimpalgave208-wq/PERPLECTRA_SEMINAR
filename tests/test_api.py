"""
Integration tests for the PERPLECTRA HTTP API.

Uses FastAPI's TestClient (synchronous) backed by temporary DB + workspace.
All fixtures are defined in conftest.py.
"""
from __future__ import annotations

import pytest

_EXEC_PAYLOAD = {
    "action_name": "modify_test_file",
    "intent": "Integration test controlled modification",
    "env": "dev",
    "policy": "RESTORE_BASELINE",
    "fail_injection": False,
}


# ── Agent registration ─────────────────────────────────────────────────────────
class TestAgentRegistration:
    def test_create_agent_success(self, client):
        c, *_ = client
        resp = c.post(
            "/api/agents",
            json={"name": "my-agent", "type": "Infrastructure", "env": "dev"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["agent_id"].startswith("agt_")
        assert data["api_key"].startswith("pxk_live_")
        assert "name" in data

    def test_api_key_unique_per_registration(self, client):
        c, *_ = client
        keys = set()
        for i in range(3):
            r = c.post(
                "/api/agents",
                json={"name": f"agent-{i}", "type": "Infrastructure", "env": "dev"},
            )
            assert r.status_code == 201
            keys.add(r.json()["api_key"])
        assert len(keys) == 3

    def test_invalid_name_rejected(self, client):
        c, *_ = client
        resp = c.post(
            "/api/agents",
            json={"name": "bad name!", "type": "Infrastructure", "env": "dev"},
        )
        assert resp.status_code == 422

    def test_invalid_env_rejected(self, client):
        c, *_ = client
        resp = c.post(
            "/api/agents",
            json={"name": "ok-name", "type": "Infrastructure", "env": "cloud"},
        )
        assert resp.status_code == 422

    def test_invalid_type_rejected(self, client):
        c, *_ = client
        resp = c.post(
            "/api/agents",
            json={"name": "ok-name", "type": "RandomType", "env": "dev"},
        )
        assert resp.status_code == 422

    def test_api_key_not_in_subsequent_response(self, registered_with_headers):
        c, agent_data, headers, *_ = registered_with_headers
        resp = c.get("/api/executions", headers=headers)
        assert resp.status_code == 200
        # api_key must never appear in a list response
        assert "api_key" not in resp.text or "pxk_live_" not in resp.text


# ── Authentication ─────────────────────────────────────────────────────────────
class TestAuthentication:
    def test_no_auth_header_returns_401(self, client):
        c, *_ = client
        assert c.get("/api/executions").status_code == 401

    def test_malformed_bearer_returns_401(self, client):
        c, *_ = client
        assert c.get(
            "/api/executions", headers={"Authorization": "Token abc"}
        ).status_code == 401

    def test_wrong_key_returns_401(self, registered_with_headers):
        c, _, _, *_ = registered_with_headers
        assert c.get(
            "/api/executions",
            headers={"Authorization": "Bearer pxk_live_" + "a" * 64},
        ).status_code == 401

    def test_valid_key_returns_200(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        assert c.get("/api/executions", headers=headers).status_code == 200


# ── Execution — happy path ─────────────────────────────────────────────────────
class TestExecutionHappyPath:
    def test_successful_modification_status(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["status"] == "EXECUTION_VERIFIED"

    def test_response_has_execution_id(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        assert resp.json()["execution_id"].startswith("exec_")

    def test_baseline_hash_present(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        assert resp.json()["baseline_hash"].startswith("sha256:")

    def test_stages_present(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        stages = [s["stage"] for s in resp.json()["stages"]]
        assert "EXECUTED" in stages
        assert "EXECUTION_VERIFIED" in stages

    def test_no_recovery_without_injection(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        assert resp.json().get("recovery_outcome") is None


# ── Execution — failure injection ──────────────────────────────────────────────
class TestFailureInjection:
    def test_recovery_verified_on_injection(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "fail_injection": True}
        resp = c.post("/api/executions", json=payload, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["status"] == "RECOVERY_VERIFIED"

    def test_recovery_outcome_set(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "fail_injection": True}
        resp = c.post("/api/executions", json=payload, headers=headers)
        assert resp.json()["recovery_outcome"] == "RESTORE_BASELINE_APPLIED"

    def test_verification_outcome_hash_match(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "fail_injection": True}
        resp = c.post("/api/executions", json=payload, headers=headers)
        assert resp.json()["verification_outcome"] == "HASH_MATCH"


# ── Execution — validation errors ──────────────────────────────────────────────
class TestExecutionValidation:
    def test_invalid_action_rejected(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "action_name": "drop_table"}
        assert c.post("/api/executions", json=payload, headers=headers).status_code == 422

    def test_invalid_policy_rejected(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "policy": "AUTO_ROLLBACK"}
        assert c.post("/api/executions", json=payload, headers=headers).status_code == 422

    def test_invalid_env_rejected(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "env": "prod-us-east-1"}
        assert c.post("/api/executions", json=payload, headers=headers).status_code == 422

    def test_short_intent_rejected(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "intent": "x"}
        assert c.post("/api/executions", json=payload, headers=headers).status_code == 422


# ── Receipt retrieval ──────────────────────────────────────────────────────────
class TestReceiptRetrieval:
    def test_get_single_receipt(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        exec_id = c.post(
            "/api/executions", json=_EXEC_PAYLOAD, headers=headers
        ).json()["execution_id"]
        resp = c.get(f"/api/executions/{exec_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["execution_id"] == exec_id

    def test_list_executions(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        for _ in range(3):
            c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        resp = c.get("/api/executions", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["executions"]) == 3

    def test_pagination(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        for _ in range(5):
            c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        resp = c.get("/api/executions?page=1&per_page=2", headers=headers)
        data = resp.json()
        assert len(data["executions"]) == 2
        assert data["total"] == 5

    def test_nonexistent_receipt_returns_404(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        resp = c.get("/api/executions/exec_doesnotexist", headers=headers)
        assert resp.status_code == 404


# ── Agent ownership enforcement ────────────────────────────────────────────────
class TestAgentOwnership:
    def test_agent_cannot_read_other_agents_receipt(self, client):
        c, db_path, ws = client
        # Register two agents
        r1 = c.post(
            "/api/agents",
            json={"name": "agent-alpha", "type": "Infrastructure", "env": "dev"},
        )
        r2 = c.post(
            "/api/agents",
            json={"name": "agent-beta", "type": "Infrastructure", "env": "dev"},
        )
        h1 = {"Authorization": f"Bearer {r1.json()['api_key']}"}
        h2 = {"Authorization": f"Bearer {r2.json()['api_key']}"}

        # Agent 1 creates an execution
        exec_id = c.post(
            "/api/executions", json=_EXEC_PAYLOAD, headers=h1
        ).json()["execution_id"]

        # Agent 2 must NOT be able to read agent 1's receipt
        resp = c.get(f"/api/executions/{exec_id}", headers=h2)
        assert resp.status_code == 404

    def test_agent_cannot_see_other_agents_list(self, client):
        c, *_ = client
        r1 = c.post(
            "/api/agents",
            json={"name": "agent-alpha", "type": "Infrastructure", "env": "dev"},
        )
        r2 = c.post(
            "/api/agents",
            json={"name": "agent-beta", "type": "Infrastructure", "env": "dev"},
        )
        h1 = {"Authorization": f"Bearer {r1.json()['api_key']}"}
        h2 = {"Authorization": f"Bearer {r2.json()['api_key']}"}

        c.post("/api/executions", json=_EXEC_PAYLOAD, headers=h1)
        data = c.get("/api/executions", headers=h2).json()
        assert data["total"] == 0


# ── Idempotency ────────────────────────────────────────────────────────────────
class TestIdempotency:
    def test_same_key_same_payload_returns_cached(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "idempotency_key": "test-idem-01"}
        r1 = c.post("/api/executions", json=payload, headers=headers)
        r2 = c.post("/api/executions", json=payload, headers=headers)
        assert r1.json()["execution_id"] == r2.json()["execution_id"]

    def test_file_not_modified_twice(self, registered_with_headers):
        """Second identical request must not execute again."""
        c, _, headers, db_path, ws = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "idempotency_key": "test-idem-02"}
        c.post("/api/executions", json=payload, headers=headers)
        c.post("/api/executions", json=payload, headers=headers)
        # Only 1 execution record must exist for this agent with this key
        from perplectra.database import get_conn
        conn = get_conn(db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM executions WHERE idempotency_key=?", ("test-idem-02",)
        ).fetchone()[0]
        conn.close()
        assert count == 1

    def test_same_key_different_payload_returns_409(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        p1 = {**_EXEC_PAYLOAD, "idempotency_key": "test-idem-03", "intent": "First intent here"}
        p2 = {**_EXEC_PAYLOAD, "idempotency_key": "test-idem-03", "intent": "Second different intent"}
        c.post("/api/executions", json=p1, headers=headers)
        r2 = c.post("/api/executions", json=p2, headers=headers)
        assert r2.status_code == 409


# ── Log/response safety ────────────────────────────────────────────────────────
class TestResponseSafety:
    def test_plaintext_key_not_in_execution_list(self, registered_with_headers):
        c, agent_data, headers, *_ = registered_with_headers
        c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        resp = c.get("/api/executions", headers=headers)
        # The raw API key must not appear anywhere in the list response
        assert agent_data["api_key"] not in resp.text

    def test_plaintext_key_not_in_execution_detail(self, registered_with_headers):
        c, agent_data, headers, *_ = registered_with_headers
        exec_id = c.post(
            "/api/executions", json=_EXEC_PAYLOAD, headers=headers
        ).json()["execution_id"]
        resp = c.get(f"/api/executions/{exec_id}", headers=headers)
        assert agent_data["api_key"] not in resp.text


# ── Public Receipt Endpoints & Demo/Live Separation ────────────────────────────
class TestPublicReceiptsAndSeparation:
    def test_public_list_executions(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        # Create a real execution
        c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        resp = c.get("/api/public/executions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert len(data["executions"]) >= 1
        assert "execution_id" in data["executions"][0]
        assert "baseline_hash" in data["executions"][0]

    def test_public_get_execution_by_id(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        exec_id = c.post(
            "/api/executions", json=_EXEC_PAYLOAD, headers=headers
        ).json()["execution_id"]
        resp = c.get(f"/api/public/executions/{exec_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["execution_id"] == exec_id
        assert data["action_name"] == "modify_test_file"
        assert data["status"] == "EXECUTION_VERIFIED"
        assert data["baseline_hash"].startswith("sha256:")
        assert data["result_hash"].startswith("sha256:")

    def test_public_get_execution_evidence_and_stages(self, registered_with_headers):
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "fail_injection": True}
        exec_id = c.post("/api/executions", json=payload, headers=headers).json()["execution_id"]
        resp = c.get(f"/api/public/executions/{exec_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "RECOVERY_VERIFIED"
        assert data["recovery_outcome"] == "RESTORE_BASELINE_APPLIED"
        assert data["verification_outcome"] == "HASH_MATCH"
        assert len(data["stages"]) >= 6

    def test_public_get_nonexistent_execution_returns_404(self, client):
        c, *_ = client
        resp = c.get("/api/public/executions/exec_nonexistent123")
        assert resp.status_code == 404

    def test_authenticated_agent_filtered_in_public_list(self, client):
        """When an agent sends Authorization to /api/public/executions, only their executions appear."""
        c, *_ = client
        # Create two agents
        r1 = c.post("/api/agents", json={"name": "agent-one", "type": "Infrastructure", "env": "dev"}).json()
        r2 = c.post("/api/agents", json={"name": "agent-two", "type": "Infrastructure", "env": "dev"}).json()
        h1 = {"Authorization": f"Bearer {r1['api_key']}"}
        h2 = {"Authorization": f"Bearer {r2['api_key']}"}

        # Agent 1 creates execution
        c.post("/api/executions", json=_EXEC_PAYLOAD, headers=h1)

        # Agent 2 queries public executions with their token -> total must be 0 for Agent 2
        res2 = c.get("/api/public/executions", headers=h2)
        assert res2.status_code == 200
        assert res2.json()["total"] == 0

        # Unauthenticated query sees the executions
        res_unauth = c.get("/api/public/executions")
        assert res_unauth.status_code == 200
        assert res_unauth.json()["total"] == 1

    def test_authenticated_agent_cannot_access_other_agent_public_execution(self, client):
        """When an agent tries to query another agent's execution by ID, returns 404."""
        c, *_ = client
        r1 = c.post("/api/agents", json={"name": "agent-one-a", "type": "Infrastructure", "env": "dev"}).json()
        r2 = c.post("/api/agents", json={"name": "agent-two-b", "type": "Infrastructure", "env": "dev"}).json()
        h1 = {"Authorization": f"Bearer {r1['api_key']}"}
        h2 = {"Authorization": f"Bearer {r2['api_key']}"}

        exec_id = c.post("/api/executions", json=_EXEC_PAYLOAD, headers=h1).json()["execution_id"]

        # Agent 2 requests Agent 1's execution -> 404
        assert c.get(f"/api/public/executions/{exec_id}", headers=h2).status_code == 404
        # Agent 1 requests Agent 1's execution -> 200
        assert c.get(f"/api/public/executions/{exec_id}", headers=h1).status_code == 200

    def test_verified_hash_field_present_and_distinguished(self, registered_with_headers):
        """Verify verified_hash is in the response and distinct from result_hash upon recovery."""
        c, _, headers, *_ = registered_with_headers
        payload = {**_EXEC_PAYLOAD, "fail_injection": True}
        exec_id = c.post("/api/executions", json=payload, headers=headers).json()["execution_id"]
        resp = c.get(f"/api/public/executions/{exec_id}")
        data = resp.json()
        assert data["status"] == "RECOVERY_VERIFIED"
        assert "verified_hash" in data
        assert data["verified_hash"] == data["baseline_hash"]
        assert data["verified_hash"] != data["result_hash"]

    def test_no_sensitive_secrets_leaked_in_any_response(self, registered_with_headers):
        c, agent_data, headers, *_ = registered_with_headers
        c.post("/api/executions", json=_EXEC_PAYLOAD, headers=headers)
        resp = c.get("/api/public/executions")
        text = resp.text
        # Neither plaintext API key nor salt/key_hash must ever be exposed
        assert "key_hash" not in text
        assert "pbkdf2" not in text
        assert "salt" not in text
        assert agent_data["api_key"] not in text


# ── Vercel & Serverless Compatibility ─────────────────────────────────────────
class TestVercelCompatibility:
    def test_vercel_entrypoint_imports_app(self):
        """Ensure api.index exports the FastAPI application instance for Vercel."""
        import api.index
        assert hasattr(api.index, "app")
        from fastapi import FastAPI
        assert isinstance(api.index.app, FastAPI)

    def test_serverless_public_access_allowed_on_vercel(self, monkeypatch):
        """Ensure public receipts console is accessible to remote visitors when hosted on Vercel."""
        from unittest.mock import MagicMock
        from server import _verify_public_access

        fake_request = MagicMock()
        fake_request.client.host = "198.51.100.24"

        monkeypatch.setenv("VERCEL", "1")
        # Should not raise HTTPException when VERCEL=1
        _verify_public_access(fake_request, opt_agent=None)

    def test_serverless_public_access_blocked_locally(self, monkeypatch):
        """Ensure public receipts endpoint still blocks non-local IP when VERCEL is not set."""
        from unittest.mock import MagicMock
        from fastapi import HTTPException
        from server import _verify_public_access

        fake_request = MagicMock()
        fake_request.client.host = "198.51.100.24"

        monkeypatch.delenv("VERCEL", raising=False)
        monkeypatch.delenv("PERPLECTRA_ALLOW_PUBLIC_CONSOLE", raising=False)
        with pytest.raises(HTTPException) as exc_info:
            _verify_public_access(fake_request, opt_agent=None)
        assert exc_info.value.status_code == 403

    def test_serverless_temp_paths(self, monkeypatch):
        """Ensure serverless mode defaults to writable temp directory paths."""
        import tempfile
        import server
        monkeypatch.setenv("VERCEL", "1")
        # Test calculation
        tmp_dir = tempfile.gettempdir()
        assert tmp_dir in str(server._TMP_DIR)



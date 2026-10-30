"""
Shared pytest fixtures for PERPLECTRA tests.

Every fixture uses a temporary directory so tests are fully isolated —
no production DB or workspace files are touched.
"""
from __future__ import annotations

import pytest
from pathlib import Path
from fastapi.testclient import TestClient


# ── Low-level fixtures ─────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path: Path) -> str:
    db_path = str(tmp_path / "test.db")
    from perplectra.database import init_db
    init_db(db_path)
    return db_path


@pytest.fixture()
def tmp_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "test_files"
    ws.mkdir(parents=True)
    (ws / "target.txt").write_text("Initial content for tests.\n", encoding="utf-8")
    return ws


# ── API client fixture ─────────────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Return a (TestClient, db_path, workspace_root) tuple backed by a
    fresh temporary database and workspace.

    monkeypatch overrides server.DB_PATH and server.WORKSPACE_ROOT so
    the startup handler and all route handlers use the test paths.
    """
    import server  # import here so monkeypatch can reach the module

    db_path = str(tmp_path / "test.db")
    workspace = tmp_path / "test_files"
    workspace.mkdir(parents=True)
    (workspace / "target.txt").write_text(
        "Initial content for tests.\n", encoding="utf-8"
    )

    monkeypatch.setattr(server, "DB_PATH", db_path)
    monkeypatch.setattr(server, "WORKSPACE_ROOT", workspace)

    with TestClient(server.app, raise_server_exceptions=True) as c:
        yield c, db_path, workspace


@pytest.fixture()
def registered(client):
    """Return (TestClient, agent_data, db_path, workspace) after registration."""
    c, db_path, ws = client
    resp = c.post(
        "/api/agents",
        json={"name": "test-agent-01", "type": "Infrastructure", "env": "dev"},
    )
    assert resp.status_code == 201, resp.text
    return c, resp.json(), db_path, ws


@pytest.fixture()
def auth_headers(registered):
    _, agent_data, _, _ = registered
    return {"Authorization": f"Bearer {agent_data['api_key']}"}


@pytest.fixture()
def registered_with_headers(registered):
    c, agent_data, db_path, ws = registered
    headers = {"Authorization": f"Bearer {agent_data['api_key']}"}
    return c, agent_data, headers, db_path, ws

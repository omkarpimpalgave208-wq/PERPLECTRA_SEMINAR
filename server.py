"""
PERPLECTRA — FastAPI server.

Serves index.html at / and provides the REST API at /api/*.
The UI and API share the same origin — no CORS configuration needed.

Configuration
-------------
DB_PATH and WORKSPACE_ROOT are module-level variables.  Tests override
them with ``monkeypatch`` before constructing a TestClient so the
startup handler picks up the patched values.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse

from perplectra.auth import (
    KEY_PREFIX,
    generate_api_key,
    hash_api_key,
    key_prefix_index,
    verify_api_key,
)
from perplectra.database import (
    execution_row_to_dict,
    find_agent_by_key_prefix,
    find_idempotent_execution,
    get_conn,
    get_execution as db_get_execution,
    get_execution_for_agent,
    init_db,
    insert_agent,
    list_all_executions,
    list_executions_for_agent,
)
from perplectra.models import (
    AgentCreate,
    AgentOut,
    ExecutionCreate,
    ExecutionListOut,
    ExecutionOut,
)
from perplectra.recovery_engine import run_protected_action

# ── Configuration (overridden by tests via monkeypatch) ────────────────────────
_BASE = Path(__file__).parent.resolve()
DB_PATH: str = os.environ.get(
    "PERPLECTRA_DB_PATH", str(_BASE / "db" / "perplectra.db")
)
WORKSPACE_ROOT: Path = Path(
    os.environ.get("PERPLECTRA_WORKSPACE", str(_BASE / "workspace" / "test_files"))
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(DB_PATH)
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    seed = WORKSPACE_ROOT / "target.txt"
    if not seed.exists():
        seed.write_text(
            "PERPLECTRA test target file.\nInitial state.\n", encoding="utf-8"
        )
    yield


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PERPLECTRA",
    version="0.1.0",
    description="Autonomous System Recovery Infrastructure — Phase 1",
    lifespan=lifespan,
)


# ── Database dependency ────────────────────────────────────────────────────────
def _get_db():
    conn = get_conn(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


_Conn = Annotated[object, Depends(_get_db)]


# ── Auth dependency ────────────────────────────────────────────────────────────
def _get_current_agent(
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
    conn: _Conn = None,
) -> dict:
    """
    Validate a ``Bearer <key>`` header and return the matching agent row.

    Raises HTTP 401 on any invalid, missing, or revoked credential.
    The plaintext key is never logged or stored.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header. "
            "Include 'Authorization: Bearer <your-api-key>'.",
        )
    key = authorization.removeprefix("Bearer ").strip()
    if not key.startswith(KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Invalid API key format.")

    prefix = key_prefix_index(key)
    candidates = find_agent_by_key_prefix(conn, prefix)
    for agent in candidates:
        if verify_api_key(key, agent["key_hash"]):
            return agent

    raise HTTPException(status_code=401, detail="Invalid or revoked API key.")


_Agent = Annotated[dict, Depends(_get_current_agent)]


def _get_optional_agent(
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
    conn: _Conn = None,
) -> Optional[dict]:
    """
    Optional auth dependency: validates Bearer token if provided.
    Returns the agent dict if valid, or None if no Authorization header is sent.
    Raises HTTP 401 only if an invalid/malformed token is explicitly supplied.
    """
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Malformed Authorization header. Format: 'Bearer <your-api-key>'.",
        )
    key = authorization.removeprefix("Bearer ").strip()
    if not key.startswith(KEY_PREFIX):
        raise HTTPException(status_code=401, detail="Invalid API key format.")

    prefix = key_prefix_index(key)
    candidates = find_agent_by_key_prefix(conn, prefix)
    for agent in candidates:
        if verify_api_key(key, agent["key_hash"]):
            return agent

    raise HTTPException(status_code=401, detail="Invalid or revoked API key.")


_OptAgent = Annotated[Optional[dict], Depends(_get_optional_agent)]


# ── Static UI ──────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_ui() -> FileResponse:
    return FileResponse(str(_BASE / "index.html"))


# ── POST /api/agents ───────────────────────────────────────────────────────────
@app.post("/api/agents", response_model=AgentOut, status_code=201)
async def create_agent(body: AgentCreate, conn: _Conn) -> AgentOut:
    """
    Register a new agent.  Returns the plaintext API key exactly once.
    The server stores only a PBKDF2-HMAC-SHA256 hash.
    """
    key = generate_api_key()
    stored_hash = hash_api_key(key)
    prefix = key_prefix_index(key)
    agent_id = "agt_" + uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()

    insert_agent(
        conn,
        agent_id=agent_id,
        name=body.name,
        agent_type=body.type,
        env=body.env,
        key_hash=stored_hash,
        key_prefix=prefix,
        created_at=now,
    )
    return AgentOut(
        agent_id=agent_id,
        name=body.name,
        type=body.type,
        env=body.env,
        created_at=now,
        api_key=key,  # plaintext returned once; not persisted
    )


# ── POST /api/executions ───────────────────────────────────────────────────────
@app.post("/api/executions", response_model=ExecutionOut, status_code=201)
async def create_execution(
    body: ExecutionCreate, agent: _Agent, conn: _Conn
) -> ExecutionOut:
    """
    Submit a protected action for the authenticated agent.

    Idempotency
    -----------
    If ``idempotency_key`` is provided and an execution with that key already
    exists for this agent, returns the cached result without re-executing.
    Reusing the same key with a different payload returns HTTP 409.
    """
    # ── Idempotency check ──────────────────────────────────────────────────────
    if body.idempotency_key:
        payload_hash = hashlib.sha256(
            json.dumps(body.model_dump(exclude={"idempotency_key"}), sort_keys=True).encode()
        ).hexdigest()
        existing = find_idempotent_execution(conn, agent["id"], body.idempotency_key)
        if existing:
            if existing.get("idempotency_payload_hash") != payload_hash:
                raise HTTPException(
                    status_code=409,
                    detail="Idempotency key has been reused with a different payload.",
                )
            return _to_out(execution_row_to_dict(existing))
    else:
        payload_hash = None

    # ── Run the engine ─────────────────────────────────────────────────────────
    row = run_protected_action(
        agent_id=agent["id"],
        action_name=body.action_name,
        intent=body.intent,
        env=body.env,
        policy=body.policy,
        fail_injection=body.fail_injection,
        db_path=DB_PATH,
        workspace_root=WORKSPACE_ROOT,
        idempotency_key=body.idempotency_key,
        idempotency_payload_hash=payload_hash,
    )
    return _to_out(row)


# ── Public Receipt Endpoints (for console & auditor viewing) ─────────────────
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def _verify_public_access(request: Request, opt_agent: Optional[dict]) -> None:
    """
    Ensure public audit endpoints are either:
    1. Authenticated by an agent (filtered to that agent's records), or
    2. Accessed from the local console / loopback interface.
    """
    if opt_agent is None:
        client_host = request.client.host if request.client else None
        if client_host and client_host not in _LOCAL_HOSTS:
            raise HTTPException(
                status_code=403,
                detail="Unauthenticated access to audit receipts is restricted to local console sessions.",
            )


@app.get("/api/public/executions", response_model=ExecutionListOut)
async def list_public_executions(
    request: Request,
    conn: _Conn,
    opt_agent: _OptAgent = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> ExecutionListOut:
    """
    List execution receipts for console audit viewing.
    If authenticated as an agent, filters to that agent's records to prevent cross-agent data exposure.
    If unauthenticated (local console view), returns public execution history without exposing credentials.
    """
    _verify_public_access(request, opt_agent)
    offset = (page - 1) * per_page
    if opt_agent:
        rows, total = list_executions_for_agent(conn, opt_agent["id"], per_page, offset)
    else:
        rows, total = list_all_executions(conn, per_page, offset)
    return ExecutionListOut(
        executions=[_to_out(execution_row_to_dict(r)) for r in rows],
        total=total,
        page=page,
        per_page=per_page,
    )


@app.get("/api/public/executions/{execution_id}", response_model=ExecutionOut)
async def get_public_execution(
    request: Request,
    execution_id: str,
    conn: _Conn,
    opt_agent: _OptAgent = None,
) -> ExecutionOut:
    """
    Retrieve a single execution receipt for console audit viewing.
    If authenticated as an agent, verifies the requested execution belongs to that agent.
    """
    _verify_public_access(request, opt_agent)
    if opt_agent:
        row = get_execution_for_agent(conn, execution_id, opt_agent["id"])
    else:
        row = db_get_execution(conn, execution_id)

    if row is None:
        raise HTTPException(status_code=404, detail="Execution not found.")
    return _to_out(execution_row_to_dict(row))


# ── GET /api/executions ────────────────────────────────────────────────────────
@app.get("/api/executions", response_model=ExecutionListOut)
async def list_executions(
    agent: _Agent,
    conn: _Conn,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> ExecutionListOut:
    """List execution receipts for the authenticated agent, newest first."""
    offset = (page - 1) * per_page
    rows, total = list_executions_for_agent(conn, agent["id"], per_page, offset)
    return ExecutionListOut(
        executions=[_to_out(execution_row_to_dict(r)) for r in rows],
        total=total,
        page=page,
        per_page=per_page,
    )


# ── GET /api/executions/{execution_id} ────────────────────────────────────────
@app.get("/api/executions/{execution_id}", response_model=ExecutionOut)
async def get_execution(
    execution_id: str, agent: _Agent, conn: _Conn
) -> ExecutionOut:
    """Retrieve a single execution receipt.  Agents can only read their own."""
    row = get_execution_for_agent(conn, execution_id, agent["id"])
    if row is None:
        raise HTTPException(status_code=404, detail="Execution not found.")
    return _to_out(execution_row_to_dict(row))


# ── Converter ──────────────────────────────────────────────────────────────────
def _to_out(row: dict) -> ExecutionOut:
    return ExecutionOut(
        execution_id=row["id"],
        agent_id=row["agent_id"],
        action_name=row["action_name"],
        intent=row["intent"],
        env=row["env"],
        policy=row["policy"],
        fail_injection=row.get("fail_injection", False),
        status=row["status"],
        baseline_hash=row.get("baseline_hash"),
        result_hash=row.get("result_hash"),
        verified_hash=row.get("verified_hash"),
        recovery_outcome=row.get("recovery_outcome"),
        verification_outcome=row.get("verification_outcome"),
        fail_reason=row.get("fail_reason"),
        stages=row.get("stages", []),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ── Dev entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)

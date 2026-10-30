"""
Pydantic request/response models for PERPLECTRA.
"""
from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel, Field, field_validator

# ── Allowed values ─────────────────────────────────────────────────────────────
ALLOWED_ENVS: set[str] = {"dev", "staging", "production", "sandbox"}
ALLOWED_AGENT_TYPES: set[str] = {
    "Infrastructure", "Data Pipeline", "Deployment",
    "Database", "API Orchestration", "Custom",
}
ALLOWED_ACTIONS: set[str] = {"modify_test_file"}
ALLOWED_POLICIES: set[str] = {"RESTORE_BASELINE"}

# Map frontend shorthand codes to canonical backend values
_TYPE_ALIASES: dict[str, str] = {
    "infra": "Infrastructure",
    "data": "Data Pipeline",
    "deploy": "Deployment",
    "db": "Database",
    "api": "API Orchestration",
    "custom": "Custom",
}
_ENV_ALIASES: dict[str, str] = {
    "prod": "production",
}

_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$")


# ── Agent models ───────────────────────────────────────────────────────────────
class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    type: str
    env: str

    @field_validator("name")
    @classmethod
    def name_safe(cls, v: str) -> str:
        if not _NAME_RE.match(v):
            raise ValueError(
                "name must start with alphanumeric, contain only letters, "
                "digits, hyphens or underscores, and be 1–64 chars"
            )
        return v

    @field_validator("type", mode="before")
    @classmethod
    def type_valid(cls, v: str) -> str:
        if isinstance(v, str):
            v = _TYPE_ALIASES.get(v.strip().lower(), v.strip())
        if v not in ALLOWED_AGENT_TYPES:
            raise ValueError(f"type must be one of {sorted(ALLOWED_AGENT_TYPES)}")
        return v

    @field_validator("env", mode="before")
    @classmethod
    def env_valid(cls, v: str) -> str:
        if isinstance(v, str):
            v = _ENV_ALIASES.get(v.strip().lower(), v.strip())
        if v not in ALLOWED_ENVS:
            raise ValueError(f"env must be one of {sorted(ALLOWED_ENVS)}")
        return v


class AgentOut(BaseModel):
    agent_id: str
    name: str
    type: str
    env: str
    created_at: str
    # Returned only on creation; absent on all subsequent reads.
    api_key: Optional[str] = None


# ── Execution models ───────────────────────────────────────────────────────────
class ExecutionCreate(BaseModel):
    action_name: str
    intent: str = Field(..., min_length=5, max_length=500)
    env: str
    policy: str
    fail_injection: bool = False
    idempotency_key: Optional[str] = Field(None, max_length=128)

    @field_validator("action_name")
    @classmethod
    def action_supported(cls, v: str) -> str:
        if v not in ALLOWED_ACTIONS:
            raise ValueError(
                f"action_name must be one of {sorted(ALLOWED_ACTIONS)}. "
                "Only 'modify_test_file' is supported in Phase 1."
            )
        return v

    @field_validator("env")
    @classmethod
    def env_valid(cls, v: str) -> str:
        if v not in ALLOWED_ENVS:
            raise ValueError(f"env must be one of {sorted(ALLOWED_ENVS)}")
        return v

    @field_validator("policy")
    @classmethod
    def policy_supported(cls, v: str) -> str:
        if v not in ALLOWED_POLICIES:
            raise ValueError(
                f"policy must be one of {sorted(ALLOWED_POLICIES)}. "
                "RESTORE_BASELINE restores a captured file snapshot; it is "
                "not a general-purpose rollback mechanism."
            )
        return v


class ExecutionOut(BaseModel):
    execution_id: str
    agent_id: str
    action_name: str
    intent: str
    env: str
    policy: str
    fail_injection: bool
    status: str
    baseline_hash: Optional[str] = None
    result_hash: Optional[str] = None
    verified_hash: Optional[str] = None
    recovery_outcome: Optional[str] = None
    verification_outcome: Optional[str] = None
    fail_reason: Optional[str] = None
    stages: list[dict] = []
    created_at: str
    updated_at: str


class ExecutionListOut(BaseModel):
    executions: list[ExecutionOut]
    total: int
    page: int
    per_page: int

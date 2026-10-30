"""
PERPLECTRA Python SDK Client.

Provides PerplectraClient for communicating with the Perplectra backend API.
Supports agent authentication, protected action execution, deterministic failure
injection, and cryptographic execution receipt verification.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from perplectra.exceptions import (
    AuthenticationError,
    ConflictError,
    ConnectionError,
    ExecutionError,
    NotFoundError,
    ValidationError,
)


class PerplectraClient:
    """
    Client for interacting with the Perplectra Autonomous System Recovery API.

    Parameters
    ----------
    api_key : str, optional
        Perplectra agent API key (starts with 'pxk_live_'). If omitted,
        the client attempts to read the PERPLECTRA_API_KEY environment variable.
    base_url : str, default "http://127.0.0.1:8000"
        Root URL of the running Perplectra backend service.
    timeout : float, default 30.0
        Network request timeout in seconds.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float = 30.0,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self.api_key: Optional[str] = api_key or os.environ.get("PERPLECTRA_API_KEY")
        self.base_url: str = base_url.rstrip("/")
        self.timeout: float = float(timeout)
        self._http_client: Optional[httpx.Client] = http_client
        self._owns_http_client: bool = http_client is None

    @property
    def http_client(self) -> httpx.Client:
        """Internal lazily initialized HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
            )
            self._owns_http_client = True
        return self._http_client

    def __enter__(self) -> PerplectraClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client session."""
        if self._http_client is not None and not self._http_client.is_closed and self._owns_http_client:
            self._http_client.close()

    def __repr__(self) -> str:
        """Safe string representation that never exposes plaintext API keys."""
        masked_key = (
            f"{self.api_key[:8]}...[REDACTED]"
            if self.api_key and len(self.api_key) > 8
            else ("<present>" if self.api_key else "<none>")
        )
        return f"<PerplectraClient base_url={self.base_url!r} api_key={masked_key}>"

    def _parse_error_detail(self, resp: httpx.Response) -> tuple[str, Any]:
        """Extract user-readable error message and raw details from response body."""
        try:
            body = resp.json()
            detail = body.get("detail", body.get("message", resp.text))
            if isinstance(detail, list):
                messages = []
                for item in detail:
                    if isinstance(item, dict):
                        loc = " -> ".join(str(p) for p in item.get("loc", []) if p != "body")
                        msg = item.get("msg", "")
                        messages.append(f"{loc}: {msg}" if loc else msg)
                    else:
                        messages.append(str(item))
                return "; ".join(messages), detail
            elif isinstance(detail, dict):
                return detail.get("msg", str(detail)), detail
            return str(detail), detail
        except Exception:
            return resp.text or f"HTTP {resp.status_code}", None

    def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
        require_auth: bool = False,
    ) -> dict[str, Any]:
        """Send HTTP request and handle network and API errors."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        elif require_auth:
            raise AuthenticationError(
                "An API key is required for this operation. "
                "Provide api_key to PerplectraClient or set the PERPLECTRA_API_KEY environment variable."
            )

        try:
            resp = self.http_client.request(
                method=method,
                url=path,
                headers=headers,
                json=json_data,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise ConnectionError(
                f"Request to {self.base_url}{path} timed out after {self.timeout}s: {exc}"
            ) from exc
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            raise ConnectionError(
                f"Failed to connect to Perplectra server at {self.base_url}: {exc}"
            ) from exc
        except Exception as exc:
            raise ConnectionError(f"Unexpected connection error: {exc}") from exc

        if resp.status_code in (200, 201):
            try:
                return resp.json()
            except Exception as exc:
                raise ExecutionError(f"Server returned non-JSON response: {resp.text}") from exc

        msg, details = self._parse_error_detail(resp)

        if resp.status_code == 401:
            raise AuthenticationError(msg, status_code=401, details=details)
        if resp.status_code == 404:
            raise NotFoundError(msg, status_code=404, details=details)
        if resp.status_code == 409:
            raise ConflictError(msg, status_code=409, details=details)
        if resp.status_code == 422:
            raise ValidationError(msg, status_code=422, details=details)

        raise ExecutionError(msg, status_code=resp.status_code, details=details)

    def register_agent(
        self,
        name: str,
        agent_type: str = "Infrastructure",
        env: str = "dev",
    ) -> dict[str, Any]:
        """
        Register a new agent with the Perplectra backend.

        If the client does not already have an API key, it is automatically
        assigned the newly generated API key returned by the server.

        Returns
        -------
        dict
            Agent record including 'agent_id', 'name', 'type', 'env', and 'api_key'.
        """
        payload = {"name": name, "type": agent_type, "env": env}
        data = self._request("POST", "/api/agents", json_data=payload, require_auth=False)
        if not self.api_key and "api_key" in data:
            self.api_key = data["api_key"]
        return data

    def execute_action(
        self,
        action_name: str = "modify_test_file",
        intent: str = "Execute protected sandboxed file modification",
        env: str = "dev",
        policy: str = "RESTORE_BASELINE",
        fail_injection: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Submit a protected file action for recovery enforcement.

        Parameters
        ----------
        action_name : str, default "modify_test_file"
            The authorized sandbox action to execute.
        intent : str
            Description of the operation (minimum 10 characters).
        env : str, default "dev"
            Execution environment ('dev', 'staging', 'prod').
        policy : str, default "RESTORE_BASELINE"
            Recovery policy to apply on failure ('RESTORE_BASELINE', 'FAIL_STOP', 'ISOLATE').
        fail_injection : bool, default False
            When True, triggers deterministic failure injection to exercise recovery.
        idempotency_key : str, optional
            Unique client-generated key to prevent duplicate execution.

        Returns
        -------
        dict
            Full execution receipt containing execution_id, status, baseline_hash,
            result_hash, verified_hash, recovery_outcome, verification_outcome,
            and audit stages.
        """
        payload: dict[str, Any] = {
            "action_name": action_name,
            "intent": intent,
            "env": env,
            "policy": policy,
            "fail_injection": fail_injection,
        }
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key

        return self._request("POST", "/api/executions", json_data=payload, require_auth=True)

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        """
        Retrieve an execution receipt by ID.

        If authenticated, fetches the agent's private execution receipt.
        If unauthenticated, fetches from the public audit endpoint.

        Returns
        -------
        dict
            The persisted execution receipt and verification details.
        """
        path = (
            f"/api/executions/{execution_id}"
            if self.api_key
            else f"/api/public/executions/{execution_id}"
        )
        return self._request("GET", path, require_auth=False)

    def list_executions(self, page: int = 1, per_page: int = 20) -> dict[str, Any]:
        """
        List execution receipts.

        If authenticated, returns executions for this agent.
        If unauthenticated, returns the public console audit list.

        Returns
        -------
        dict
            Dict with 'executions' list, 'total', 'page', and 'per_page'.
        """
        path = "/api/executions" if self.api_key else "/api/public/executions"
        params = {"page": page, "per_page": per_page}
        return self._request("GET", path, params=params, require_auth=False)

"""
PERPLECTRA SDK Exceptions.

Hierarchy of structured exceptions for client-side API error handling.
"""
from __future__ import annotations


class PerplectraError(Exception):
    """Base exception for all Perplectra SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, details: dict | list | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details

    def __str__(self) -> str:
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(PerplectraError):
    """Raised when authentication fails (HTTP 401) or credentials are invalid/missing."""
    pass


class ValidationError(PerplectraError):
    """Raised when request payload fails validation (HTTP 422)."""
    pass


class NotFoundError(PerplectraError):
    """Raised when a requested resource is not found (HTTP 404)."""
    pass


class ConflictError(PerplectraError):
    """Raised on idempotency conflicts (HTTP 409)."""
    pass


class ExecutionError(PerplectraError):
    """Raised when an execution fails or returns an unhandled server error."""
    pass


class ConnectionError(PerplectraError):
    """Raised when network connection fails or requests time out."""
    pass

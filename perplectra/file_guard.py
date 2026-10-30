"""
Filesystem safety for the PERPLECTRA recovery engine.

The engine is permitted to read and write ONLY inside *workspace_root*.
Every path presented by a caller is validated here before any I/O.

Protections implemented
-----------------------
* ``..`` / absolute-path components rejected.
* Resolved path must be strictly under ``workspace_root``.
* Symlinks whose real target escapes ``workspace_root`` are rejected.
* Only the single fixed filename ``target.txt`` is accepted in Phase 1.
* ``PathViolationError`` is raised on any violation — the engine fails closed.
"""
from __future__ import annotations

from pathlib import Path

ALLOWED_FILENAMES: frozenset[str] = frozenset({"target.txt"})


class PathViolationError(ValueError):
    """Raised when a requested path fails the safety check."""


def safe_resolve(filename: str, workspace_root: Path) -> Path:
    """
    Validate *filename* and return its absolute ``Path`` inside *workspace_root*.

    Parameters
    ----------
    filename:
        A bare filename (no directory components).  Must be in
        ``ALLOWED_FILENAMES``.
    workspace_root:
        Trusted absolute directory.  Must already exist and be a directory.

    Returns
    -------
    Path
        Resolved absolute path, guaranteed to be under *workspace_root*.

    Raises
    ------
    PathViolationError
        On any safety violation.  Never raises any other exception for
        invalid input.
    """
    # 1. Reject anything that is not a plain filename.
    if not filename or filename != Path(filename).name:
        raise PathViolationError(
            f"filename must be a plain name with no path components; got {filename!r}"
        )

    # 2. Whitelist: only known filenames are accepted.
    if filename not in ALLOWED_FILENAMES:
        raise PathViolationError(
            f"{filename!r} is not an allowed target filename. "
            f"Allowed: {sorted(ALLOWED_FILENAMES)}"
        )

    # 3. Resolve workspace_root to an absolute, canonical path.
    try:
        base = workspace_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathViolationError(f"workspace_root cannot be resolved: {exc}") from exc

    if not base.is_dir():
        raise PathViolationError(f"workspace_root is not a directory: {base}")

    # 4. Build candidate path without following symlinks yet.
    candidate = base / filename

    # 5. Reject if candidate itself is a symlink.
    if candidate.is_symlink():
        raise PathViolationError(
            f"Target {filename!r} is a symbolic link; symlinks are not permitted."
        )

    # 6. Resolve the candidate (creates the file's canonical path).
    #    We use strict=False so we can validate even if the file doesn't exist yet.
    resolved = candidate.resolve(strict=False)

    # 7. Strict containment: resolved path must be *under* base.
    try:
        resolved.relative_to(base)
    except ValueError:
        raise PathViolationError(
            f"Resolved path {resolved} escapes workspace root {base}."
        )

    return resolved

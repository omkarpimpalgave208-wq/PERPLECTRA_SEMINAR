# PERPLECTRA — Autonomous System Recovery Infrastructure

PERPLECTRA wraps AI agent operations with failure detection, deterministic state recovery, and independent cryptographic verification.

---

## Architecture & Directory Structure

```text
Seminar_Perplectra/
├── index.html                       # NVIDIA-inspired dark console UI (5 approved views)
├── server.py                        # FastAPI application mounting UI & REST API
├── perplectra/
│   ├── __init__.py                  # Package descriptor
│   ├── auth.py                      # PBKDF2-HMAC-SHA256 (260,000 iterations), constant-time verification
│   ├── database.py                  # SQLite WAL layer with foreign keys & parameterised queries
│   ├── file_guard.py                # Strict path safety: traversal, symlink, and sandbox boundaries
│   ├── models.py                    # Strict Pydantic validation schemas
│   └── recovery_engine.py           # 8-stage recovery lifecycle with cryptographic verification
├── workspace/
│   └── test_files/
│       └── target.txt               # Designated reversible test file
├── db/
│   └── perplectra.db                # SQLite database (auto-created on startup)
├── tests/
│   ├── conftest.py                  # Pytest fixtures: temp db, isolated sandbox, TestClient
│   ├── test_auth.py                 # Key generation, hashing, timing safety, rejection tests
│   ├── test_file_guard.py           # Path traversal, symlink escape, and safety tests
│   ├── test_recovery_engine.py      # Lifecycle, rollback, verification failure, persistence tests
│   └── test_api.py                  # API endpoints, auth, agent ownership, idempotency tests
├── requirements.txt                 # Dependencies: fastapi, uvicorn, httpx, pytest
└── README.md
```

---

## Safety Guarantees

1. **Strictly Sandboxed Execution**: All reversible file actions operate exclusively within `workspace/test_files/`. Any attempt to traverse (`..`), use symlinks, or access absolute paths is rejected with `PathViolationError`.
2. **Cryptographic Integrity**:
   - Agent API keys are generated with 32 bytes of secure entropy (`pxk_live_<64 hex chars>`).
   - Keys are stored using salted PBKDF2-HMAC-SHA256 (260,000 iterations).
   - The plaintext API key is returned exactly once at registration and is never logged or persisted.
3. **Independent Verification**:
   - A recovery is never marked verified until SHA-256 cryptographic hashes are computed and confirmed against the baseline.
   - If recovery or verification fails, the engine transitions to `RECOVERY_FAILED` or `VERIFICATION_FAILED` and halts safely.
4. **Idempotency Protection**: Execution requests support `idempotency_key`. Repeating a key with the same payload returns the cached receipt; conflicting payloads trigger HTTP 409 Conflict.

---

## API Endpoints

- `GET /`: Serves the 5-page recovery console (`index.html`).
- `POST /api/agents`: Registers a new AI agent; returns single-use plaintext API key.
- `POST /api/executions`: Authenticated (`Bearer <api-key>`) action executor with failure injection support.
- `GET /api/executions`: Lists execution receipts for the authenticated agent (pagination supported).
- `GET /api/executions/{execution_id}`: Fetches a single signed receipt with complete stage evidence.

---

## Quickstart & Local Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
```bash
python -m pytest -v
```
*(All 77 test cases pass: 44 unit tests covering auth, file guard, and recovery engine + 33 API integration tests).*

### 3. Start the Server
```bash
python server.py
# or
uvicorn server:app --reload --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your browser.

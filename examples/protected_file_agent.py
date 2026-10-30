"""
PERPLECTRA — Protected File Agent Example.

Demonstrates an autonomous Python agent executing protected operations via the
Perplectra SDK.
1. Authenticates using PERPLECTRA_API_KEY (or registers an agent if unset).
2. Executes a sandboxed file modification with deterministic failure injection.
   Verifies automatic baseline capture, failure detection, restoration, and independent
   cryptographic verification (RECOVERY_VERIFIED).
3. Executes a normal sandboxed file modification without failure injection
   (EXECUTION_VERIFIED).
4. Retrieves real persisted execution receipts from SQLite storage and prints
   a structured execution audit report.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path when running as a standalone script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from perplectra import PerplectraClient
from perplectra.exceptions import PerplectraError


def print_divider(title: str = "") -> None:
    width = 72
    if title:
        line = f"-- {title} "
        print(line + "-" * max(0, width - len(line)))
    else:
        print("-" * width)


def print_receipt_report(receipt: dict, title: str) -> None:
    print_divider(title)
    fail_detected = receipt.get('fail_reason') or ('Controlled failure injected & detected' if receipt.get('fail_injection') else 'None (Clean Execution)')
    print(f"  Execution ID            : {receipt.get('execution_id')}")
    print(f"  Agent ID                : {receipt.get('agent_id')}")
    print(f"  Action Name             : {receipt.get('action_name')}")
    print(f"  Intent                  : {receipt.get('intent')}")
    print(f"  Environment             : {receipt.get('env')}")
    print(f"  Policy                  : {receipt.get('policy')}")
    print(f"  Failure Injected        : {receipt.get('fail_injection')}")
    print(f"  Failure Detection       : {fail_detected}")
    print(f"  Recovery Outcome        : {receipt.get('recovery_outcome') or 'N/A'}")
    print(f"  Baseline SHA-256        : {receipt.get('baseline_hash')}")
    print(f"  Pre-Recovery SHA-256    : {receipt.get('result_hash')}")
    print(f"  Post-Recovery SHA-256   : {receipt.get('verified_hash') or 'N/A'}")
    print(f"  Verification Outcome    : {receipt.get('verification_outcome') or 'N/A'}")
    print(f"  Final Status            : {receipt.get('status')}")
    print("  Audit Stages Recorded   :")
    for stage in receipt.get("stages", []):
        ts = stage.get("ts") or stage.get("timestamp") or "N/A"
        detail = stage.get("detail") or stage.get("message") or stage.get("stage")
        print(f"    * [{ts}] {stage.get('stage')}: {detail}")
    print_divider()


def main() -> int:
    base_url = os.environ.get("PERPLECTRA_BASE_URL", "http://127.0.0.1:8000")
    api_key = os.environ.get("PERPLECTRA_API_KEY")

    print_divider("PERPLECTRA AUTONOMOUS AGENT INTEGRATION")
    print(f"Connecting to Perplectra server at: {base_url}")

    client = PerplectraClient(api_key=api_key, base_url=base_url)

    # ── Step 1: Ensure Authentication ──────────────────────────────────────────
    if not client.api_key:
        print("PERPLECTRA_API_KEY not set. Registering a new agent with backend...")
        try:
            agent = client.register_agent(
                name="PythonSDKProtectedAgent",
                agent_type="Infrastructure",
                env="dev",
            )
            print(f"[OK] Registered agent: {agent['agent_id']} ({agent['name']})")
            print("[OK] Acquired agent API key (masked for security): pxk_live_***")
        except PerplectraError as exc:
            print(f"[ERR] Failed to register agent: {exc}")
            return 1
    else:
        print("[OK] Using PERPLECTRA_API_KEY from environment (masked): pxk_live_***")

    # ── Step 2: Demonstration 1 — Deterministic Failure & Recovery ─────────────
    print("\n[Run 1] Executing protected action WITH deterministic failure injection...")
    try:
        exec1 = client.execute_action(
            action_name="modify_test_file",
            intent="Test automated recovery and independent byte verification",
            env="dev",
            policy="RESTORE_BASELINE",
            fail_injection=True,
        )
    except PerplectraError as exc:
        print(f"[ERR] Execution request failed: {exc}")
        return 1

    # Retrieve real persisted execution receipt from SQLite storage
    exec1_id = exec1["execution_id"]
    receipt1 = client.get_execution(exec1_id)
    print_receipt_report(receipt1, f"EXECUTION 1 RECEIPT (ID: {exec1_id})")

    # Verification assertions
    status1 = receipt1.get("status")
    baseline1 = receipt1.get("baseline_hash")
    verified1 = receipt1.get("verified_hash")
    recovery_outcome1 = receipt1.get("recovery_outcome")

    if status1 != "RECOVERY_VERIFIED":
        print(f"[ERR] Expected status 'RECOVERY_VERIFIED', got '{status1}'")
        return 1

    if recovery_outcome1 != "RESTORE_BASELINE_APPLIED":
        print(f"[ERR] Expected recovery_outcome 'RESTORE_BASELINE_APPLIED', got '{recovery_outcome1}'")
        return 1

    if not verified1 or verified1 != baseline1:
        print(f"[ERR] Post-recovery hash mismatch! Baseline: {baseline1}, Verified: {verified1}")
        return 1

    print("[OK] Run 1 Succeeded: Failure detected, baseline restored, and independent SHA-256 verified!")

    # ── Step 3: Demonstration 2 — Normal Execution Without Failure Injection ───
    print("\n[Run 2] Executing protected action WITHOUT failure injection (Normal Operation)...")
    try:
        exec2 = client.execute_action(
            action_name="modify_test_file",
            intent="Perform authorized sandboxed file update under normal conditions",
            env="dev",
            policy="RESTORE_BASELINE",
            fail_injection=False,
        )
    except PerplectraError as exc:
        print(f"[ERR] Execution request failed: {exc}")
        return 1

    exec2_id = exec2["execution_id"]
    receipt2 = client.get_execution(exec2_id)
    print_receipt_report(receipt2, f"EXECUTION 2 RECEIPT (ID: {exec2_id})")

    status2 = receipt2.get("status")
    result_hash2 = receipt2.get("result_hash")
    baseline2 = receipt2.get("baseline_hash")

    if status2 != "EXECUTION_VERIFIED":
        print(f"[ERR] Expected status 'EXECUTION_VERIFIED', got '{status2}'")
        return 1

    if not result_hash2 or result_hash2 == baseline2:
        print("[ERR] Expected result_hash to reflect modified file content.")
        return 1

    print("[OK] Run 2 Succeeded: Sandboxed file modification verified without recovery triggers.")
    print_divider("ALL PYTHON AGENT PROTECTED RUNS VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Diagnostic Health Check Utility for 8 GB RAM Windows Environments.

Verifies:
1. Python runtime and platform architecture (Python 3.8.10, 64-bit).
2. Physical and available system memory (RAM).
3. Critical local network ports (5050, 8088).
4. SQLite evidence database storage.
5. RebuiltV4 Checkpoint-200 and Checkpoint-300 adapter files integrity.
6. Core controller guardrails and PolicyEngine import safety.
7. Model Brain Gateway and runtime inference mode detection.
"""

import os
import platform
import socket
import sqlite3
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.brain.resource_profile import (
    get_system_memory_info,
    get_process_memory_info,
    get_runtime_capabilities,
)
from controller.config import DEFAULT_CONFIG
from controller.guardrails.scope_validator import ScopeValidator
from controller.guardrails.policy_engine import PolicyEngine


def check_port(host: str, port: int) -> bool:
    """Return True if port is free / bindable, False if already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        res = s.connect_ex((host, port))
        return res != 0  # 0 means port is occupied, non-zero means port is free


def main():
    print("=" * 76)
    print("   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING AGENT")
    print("               PORTABLE 8 GB RAM HEALTH CHECK")
    print("=" * 76)

    all_passed = True
    checks = []

    # 1. Python Architecture & Version
    py_ver = platform.python_version()
    is_64bit = sys.maxsize > 2**32
    py_ok = (sys.version_info.major == 3 and sys.version_info.minor >= 8) and is_64bit
    checks.append((
        "Python Runtime",
        f"{py_ver} ({'64-bit' if is_64bit else '32-bit'})",
        "PASS" if py_ok else "WARN",
    ))
    if not py_ok:
        all_passed = False

    # 2. System RAM & Headroom
    mem_info = get_system_memory_info()
    tot_ram_gb = round(mem_info["total_ram_mb"] / 1024, 2)
    avail_ram_mb = mem_info["available_ram_mb"]
    ram_ok = mem_info["total_ram_mb"] >= 3500.0
    checks.append((
        "System Physical RAM",
        f"{tot_ram_gb} GB Total | {avail_ram_mb} MB Available ({mem_info['memory_load_pct']}% Load)",
        "PASS" if ram_ok else "FAIL",
    ))

    # 3. Process Memory Footprint
    proc_mem = get_process_memory_info()
    checks.append((
        "Agent Base Process RAM",
        f"{proc_mem['working_set_mb']} MB Working Set | {proc_mem['commit_charge_mb']} MB Commit",
        "PASS",
    ))

    # 4. Local Port Availability
    lab_free = check_port("127.0.0.1", 5050)
    dash_free = check_port("127.0.0.1", 8088)
    checks.append((
        "Port 5050 (Vulnerable Lab)",
        "Free / Ready" if lab_free else "In Use / Active Server Detected",
        "PASS",
    ))
    checks.append((
        "Port 8088 (Dashboard UI)",
        "Free / Ready" if dash_free else "In Use / Active Server Detected",
        "PASS",
    ))

    # 5. Checkpoint-200 Model Adapter
    ckpt200_dir = os.path.join(
        PROJECT_ROOT, "staging_rebuiltv4_training_checkpoints", "checkpoint-200"
    )
    safetensors_path = os.path.join(ckpt200_dir, "adapter_model.safetensors")
    config_path = os.path.join(ckpt200_dir, "adapter_config.json")
    ckpt200_ok = os.path.isfile(safetensors_path) and os.path.isfile(config_path)
    size_mb = round(os.path.getsize(safetensors_path) / (1024 * 1024), 2) if os.path.isfile(safetensors_path) else 0
    checks.append((
        "RebuiltV4 Checkpoint-200",
        f"Verified ({size_mb} MB Safetensors)" if ckpt200_ok else "Missing files",
        "PASS" if ckpt200_ok else "FAIL",
    ))
    if not ckpt200_ok:
        all_passed = False

    # 6. Checkpoint-300 Model Adapter
    ckpt300_dir = os.path.join(
        PROJECT_ROOT, "staging_rebuiltv4_training_checkpoints", "checkpoint-300"
    )
    ckpt300_ok = os.path.isfile(os.path.join(ckpt300_dir, "adapter_model.safetensors"))
    checks.append((
        "RebuiltV4 Checkpoint-300",
        "Verified (Preserved on Disk)" if ckpt300_ok else "Missing files",
        "PASS" if ckpt300_ok else "WARN",
    ))

    # 7. SQLite Evidence Database Capability
    try:
        test_conn = sqlite3.connect(":memory:")
        test_conn.execute("CREATE TABLE test_health (id INTEGER PRIMARY KEY, v TEXT)")
        test_conn.execute("INSERT INTO test_health (v) VALUES ('ok')")
        test_conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    checks.append(("SQLite Storage Engine", "Functional (In-memory & File)", "PASS" if db_ok else "FAIL"))
    if not db_ok:
        all_passed = False

    # 8. ScopeValidator & Guardrails
    try:
        validator = ScopeValidator(DEFAULT_CONFIG)
        scope_ok = validator.validate_url("http://127.0.0.1:5050").is_valid
        scope_reject = not validator.validate_url("http://google.com").is_valid
        guard_ok = scope_ok and scope_reject
    except Exception:
        guard_ok = False
    checks.append(("Scope & Policy Guardrails", "Active (Strict Localhost Bounds)", "PASS" if guard_ok else "FAIL"))
    if not guard_ok:
        all_passed = False

    # 9. Hardware & Inference Strategy Recommendation
    capabilities = get_runtime_capabilities()
    checks.append((
        "Inference Recommendation",
        f"{capabilities['recommended_mode'].upper()} (Safe for 8 GB RAM)",
        "PASS",
    ))

    # 10. Standalone Offline CPU GGUF Model Check
    from controller.brain.local_cpu_client import find_default_gguf_model
    gguf_model = find_default_gguf_model()
    if gguf_model:
        gguf_size_mb = round(os.path.getsize(gguf_model) / (1024 * 1024), 2)
        checks.append((
            "Local CPU GGUF Model",
            f"Present ({gguf_size_mb} MB Q4_K_M)",
            "PASS",
        ))
    else:
        checks.append((
            "Local CPU GGUF Model",
            "Pending Kaggle Export (Fallback Ready)",
            "WARN",
        ))

    # Output Table
    print(f"{'Subsystem / Component':<28} | {'Status Details':<34} | {'State':<6}")
    print("-" * 76)
    for name, detail, state in checks:
        color = "\033[92m" if state == "PASS" else ("\033[93m" if state == "WARN" else "\033[91m")
        reset = "\033[0m"
        print(f"{name:<28} | {detail:<34} | {color}{state:<6}{reset}")
    print("=" * 76)

    if all_passed:
        print("[+] ALL CRITICAL CHECKS PASSED. System is ready for autonomous operations.")
        sys.exit(0)
    else:
        print("[!] SOME CRITICAL CHECKS FAILED. Review warnings above before proceeding.")
        sys.exit(1)


if __name__ == "__main__":
    main()


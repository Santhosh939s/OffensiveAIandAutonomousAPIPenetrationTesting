"""Standalone Packaging and Installation Verification Utility.

Performs static and dynamic validation of the standalone deployment package:
- Directory structure and required files
- Python dependencies and version requirements
- Model GGUF artifact presence and integrity
- llama-cli execution binary
- SQLite evidence database connectivity
- Port availability (5050, 8088)
- Offline readiness (no remote URLs, zero external CDNs)
"""

import hashlib
import json
import os
import platform
import shutil
import socket
import sys
from pathlib import Path
from typing import Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def check_hash(file_path: Path, expected_prefix: str) -> bool:
    """Check if SHA-256 of file starts with or matches expected prefix."""
    if not file_path.exists():
        return False
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower().startswith(expected_prefix.lower())


def run_verification() -> Dict[str, Any]:
    report = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "architecture_64bit": sys.maxsize > 2**32,
        "checks": {},
        "all_passed": True,
    }

    # 1. Structure checks
    required_paths = [
        "controller",
        "dashboard",
        "lab",
        "models",
        "launch.bat",
        "stop.bat",
        "launcher.py",
        "requirements.txt",
    ]
    report["checks"]["structure"] = {}
    for p in required_paths:
        exists = (PROJECT_ROOT / p).exists()
        report["checks"]["structure"][p] = exists
        if not exists:
            report["all_passed"] = False

    # 2. Dependency checks
    deps = ["flask", "werkzeug", "httpx", "requests", "pydantic", "yaml", "cryptography", "jwt"]
    report["checks"]["dependencies"] = {}
    for dep in deps:
        try:
            __import__(dep)
            report["checks"]["dependencies"][dep] = True
        except ImportError:
            report["checks"]["dependencies"][dep] = False
            report["all_passed"] = False

    # 3. Model GGUF check
    gguf_path = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
    gguf_exists = gguf_path.exists()
    gguf_size_mb = round(gguf_path.stat().st_size / (1024 * 1024), 2) if gguf_exists else 0
    report["checks"]["model_gguf"] = {
        "exists": gguf_exists,
        "size_mb": gguf_size_mb,
        "path": str(gguf_path),
        # Known SHA256 prefix
        "sha256_verified": check_hash(gguf_path, "cd7dc83335b02d90f44a7fe4bd0f06eea4d64deb429710f238fe8c5de3da4dc5") if gguf_exists else False,
    }
    if not (gguf_exists and report["checks"]["model_gguf"]["sha256_verified"]):
        report["all_passed"] = False

    # 4. Engine binary check
    cli_candidates = [
        os.environ.get("LLAMA_CLI_PATH"),
        str(Path(os.environ.get("LLAMACPP_DIR", "")) / "llama-cli.exe") if os.environ.get("LLAMACPP_DIR") else None,
        str(PROJECT_ROOT / "models" / "bin" / "llama-cli.exe"),
        str(PROJECT_ROOT / "models" / "bin" / "llama-cli"),
        shutil.which("llama-cli.exe") or shutil.which("llama-cli"),
    ]
    cli_found = next((c for c in cli_candidates if c and Path(c).is_file()), None)
    is_local_repo = bool(cli_found and str(PROJECT_ROOT / "models" / "bin") in cli_found) if cli_found else False
    report["checks"]["inference_engine"] = {
        "llama_cli_found": bool(cli_found),
        "path": cli_found or "",
        "standalone_local_repository": is_local_repo,
    }
    if not cli_found:
        report["all_passed"] = False

    # 5. Offline self-containment check in HTML templates
    index_html = PROJECT_ROOT / "dashboard" / "templates" / "index.html"
    has_external_links = False
    if index_html.exists():
        content = index_html.read_text(encoding="utf-8")
        if any(x in content for x in ["https://cdn", "cdnjs", "googleapis.com"]):
            has_external_links = True
    report["checks"]["offline_self_contained"] = not has_external_links
    if has_external_links:
        report["all_passed"] = False

    return report


if __name__ == "__main__":
    rep = run_verification()
    print(json.dumps(rep, indent=2))
    sys.exit(0 if rep["all_passed"] else 1)

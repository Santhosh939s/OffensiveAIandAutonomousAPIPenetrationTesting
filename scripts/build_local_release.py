"""Script to build and assemble the local standalone release candidate in dist/local_release/.

Produces:
1. Clean directory structure with all runtime assets.
2. SHA256SUMS.txt manifest covering all release files and model artifacts.
3. Standalone user documentation and deployment guide.
"""

import hashlib
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist" / "local_release"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_release():
    print("=" * 78)
    print("   PHASE 9.0: LOCAL RELEASE CANDIDATE ASSEMBLY")
    print("=" * 78)

    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[*] Target Release Directory: {DIST_DIR}")

    # Copy core modules
    dirs_to_copy = ["controller", "dashboard", "lab"]
    for d in dirs_to_copy:
        src = PROJECT_ROOT / d
        dst = DIST_DIR / d
        print(f"    - Copying {d}...")
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.pyd"))

    # Copy binaries (llama-cli and DLLs)
    models_bin_src = PROJECT_ROOT / "models" / "bin"
    models_bin_dst = DIST_DIR / "models" / "bin"
    if models_bin_src.exists():
        print(f"    - Copying models/bin runtime binaries...")
        shutil.copytree(models_bin_src, models_bin_dst)

    # Copy root launcher scripts
    files_to_copy = ["launcher.py", "launch.bat", "stop.bat", "requirements.txt"]
    for f in files_to_copy:
        src = PROJECT_ROOT / f
        dst = DIST_DIR / f
        if src.exists():
            print(f"    - Copying {f}...")
            shutil.copy2(src, dst)

    # Create logs directory
    (DIST_DIR / "logs").mkdir(exist_ok=True)

    # Generate Manifest & SHA-256 sums
    print("\n[*] Generating SHA256SUMS.txt Manifest...")
    manifest_entries = []
    
    # Include project root model files in manifest
    gguf_path = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
    if gguf_path.exists():
        gguf_hash = compute_sha256(gguf_path)
        manifest_entries.append(f"{gguf_hash}  models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf")

    adapter_path = PROJECT_ROOT / "models" / "training_artifacts" / "final_adapter" / "adapter_model.safetensors"
    if adapter_path.exists():
        adapter_hash = compute_sha256(adapter_path)
        manifest_entries.append(f"{adapter_hash}  models/training_artifacts/final_adapter/adapter_model.safetensors")

    for root, _, files in os.walk(DIST_DIR):
        for fname in sorted(files):
            fpath = Path(root) / fname
            rel_path = fpath.relative_to(DIST_DIR).as_posix()
            digest = compute_sha256(fpath)
            manifest_entries.append(f"{digest}  {rel_path}")

    manifest_file = DIST_DIR / "SHA256SUMS.txt"
    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write("\n".join(manifest_entries) + "\n")
    print(f"    [+] {len(manifest_entries)} files cataloged in SHA256SUMS.txt")

    # Generate Release README
    readme_file = DIST_DIR / "README.md"
    with open(readme_file, "w", encoding="utf-8") as f:
        f.write("""# Autonomous Offensive AI & API Penetration Testing — Local Release

**Version:** 1.0.0-Production (Release Candidate)  
**Hardware Specification:** 8 GB RAM, 4-Thread CPU (Intel i3 / Ryzen 3), Windows 10/11 x64  
**Runtime:** 100% Offline Local CPU GGUF Inference (`llama.cpp`)  
**License:** Academic / Ethical Security Research  

---

## Quick Start (Windows)

1. **Install Prerequisites:**
   - 64-bit Python 3.8+ (Ensure `python` is added to system PATH).
   - Microsoft Visual C++ 2015–2022 Redistributable (x64).
   - Ensure the GGUF model file `qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` is located in `models/`.

2. **Install Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Launch the System:**
   Double-click `launch.bat` or run:
   ```powershell
   python launcher.py
   ```
   - Automatically initializes security engine, database, and default policies.
   - Starts the Target Vulnerable API Lab on `http://127.0.0.1:5050`.
   - Starts the Autonomous Testing Dashboard on `http://127.0.0.1:8088`.
   - Opens your browser directly to the dashboard.

4. **Clean Shutdown:**
   Double-click `stop.bat` or press `Ctrl + C` in the launcher console.

---

## Directory Architecture

- `controller/`: Autonomous controller, policy engine, tools, storage, and reporting.
- `dashboard/`: Flask web application, REST APIs, static assets, and templates.
- `lab/`: Self-contained target API lab for safe local vulnerability verification.
- `models/bin/`: Standalone pre-compiled `llama-cli.exe` runtime binaries.
- `launch.bat` / `stop.bat`: One-click Windows startup and shutdown utilities.
- `SHA256SUMS.txt`: Cryptographic integrity manifest for all distribution files.
""")

    # Generate Deployment Guide
    deploy_file = DIST_DIR / "DEPLOYMENT_GUIDE.md"
    with open(deploy_file, "w", encoding="utf-8") as f:
        f.write("""# Standalone Deployment & Operational Guide

## 1. System Requirements

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Windows 10 64-bit (Build 19041+) | Windows 11 64-bit |
| **Processor** | Intel Core i3 (4 Threads) / AMD Ryzen 3 | Intel Core i5 / Ryzen 5 (6+ Threads) |
| **System Memory** | 8 GB RAM | 16 GB RAM |
| **Disk Space** | 2 GB Free Storage | 5 GB Free Storage (SSD) |
| **GPU Requirement** | None (100% Offline CPU Inference) | Optional |

---

## 2. Administrator Credential Management

Upon first execution, the system dynamically bootstraps an initial administrator account with a cryptographically random, high-entropy password.

- The temporary password is displayed **only once** on the launcher terminal console.
- The web console enforces a mandatory password change on initial login.
- Emergency administrator password reset is available via CLI:
  ```powershell
  python launcher.py --recover-admin admin --new-password "YourNewSecurePassword123!@#"
  ```

---

## 3. Scope and Policy Guardrails

- By default, all tools operate under strict localhost boundaries (`127.0.0.1`, `localhost`).
- Cloud metadata endpoints (`169.254.169.254`), broadcast addresses, and arbitrary external targets are rejected at Layer 1 socket handshakes.
- To add authorized targets, access the **Policy Management** view on the dashboard and define explicit target authorization rules.
""")

    print(f"\n[*] Release Candidate Assembly Finished successfully in: {DIST_DIR}\n")
    print("=" * 78)


if __name__ == "__main__":
    build_release()


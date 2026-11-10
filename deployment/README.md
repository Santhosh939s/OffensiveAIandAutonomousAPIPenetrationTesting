# Standalone Packaging and Offline Deployment Guide

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Platform:** Windows 10/11 (64-bit), 8 GB RAM Minimum  
**Target Environment:** 100% Offline Localhost Deployment  

---

## 1. Package Contents Overview

The standalone distribution includes:
- **`launch.bat`**: One-click Windows startup script.
- **`stop.bat`**: Graceful service shutdown script.
- **`launcher.py`**: Multi-component orchestrator and diagnostic pre-flight engine.
- **`controller/`**: Autonomous decision loop, tools registry, and Layer 1 policy guardrails.
- **`dashboard/`**: Local Flask administration console, interactive analytics, and Policy Management UI.
- **`lab/`**: Local in-process Vulnerable API Lab with seeded OWASP API Top 10 vulnerabilities.
- **`models/`**: Preserved fine-tuned Qwen2.5-1.5B GGUF model (`qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`).
- **`packaging/`**: Verification tooling and deployment manifests.

---

## 2. System Requirements & Prerequisites

### Hardware Requirements
- **CPU:** Intel Core i3/i5/i7 (x64) or AMD Ryzen (4+ CPU cores recommended).
- **RAM:** Minimum 8 GB physical memory (system uses < 1.5 GB RSS at runtime).
- **Storage:** ~3 GB free space (including 940 MB GGUF model and evidence logs).

### Software Requirements
- **OS:** Windows 10 or Windows 11 (64-bit).
- **Python Runtime:** Python 3.8 through 3.11 (64-bit). Baseline development environment is Python 3.8.10 (64-bit). *Note: Upstream Python 3.8 reached EOL in October 2024; deploying on Python 3.10 or 3.11 64-bit avoids future cryptography package deprecation warnings.*
- **Native C++ Runtime:** Microsoft Visual C++ 2015–2022 Redistributable (x64) (`vcruntime140.dll`, `msvcp140.dll`). Required for native CPU execution of `llama-cli.exe`. Available from [Microsoft Official VC_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe).
- **Inference Binary:** Compatible `llama.cpp` Windows x86_64 binary (`llama-cli.exe` build >= b3000 / v0.3.0+) located in `models/bin/` or on system PATH.

---

## 3. First-Time Setup & Installation

If deploying to a fresh Windows workstation with Python installed:

1. **Clone or Copy Repository:**
   Extract the repository to a local directory (e.g., `C:\PenTestAI\` or `S:\UROP\...`).

2. **Install Minimal Dependencies:**
   Open Windows Command Prompt (`cmd.exe`) in the project directory:
   ```cmd
   pip install -r requirements.txt
   ```
   *Note: All dependencies are pure Python and standard C extensions. No CUDA, Torch, or heavy deep-learning frameworks are required.*

3. **Inference Engine Provisioning (llama.cpp):**
   The application requires a compatible `llama.cpp` CPU inference binary (build >= b3000 / v0.3.0+ for Windows x86_64) located in `models/bin/` or on system PATH.
   To provision the local runtime:
   - **Method A (Auto-copy existing system installation):**
     ```cmd
     python deployment\provision_engine.py --auto-copy-discovered
     ```
   - **Method B (Copy from official release zip or directory):**
     Download the official Windows release zip (`llama-b<version>-bin-win-x64.zip`) from [llama.cpp releases](https://github.com/ggerganov/llama.cpp/releases) and run:
     ```cmd
     python deployment\provision_engine.py --source-dir <unzipped_folder>
     ```
   *(Note: The platform never downloads inference binaries silently in the background at startup.)*

4. **Verify Installation:**
   Run the packaging verification script:
   ```cmd
   python deployment\verify_installation.py
   ```
   Ensure `"all_passed": true` is returned.

---

## 4. Launching the Application

### Method A: One-Click Windows Launcher (Recommended)
Double-click `launch.bat` in Windows File Explorer or execute in Command Prompt:
```cmd
launch.bat
```
The launcher will:
1. Run pre-flight checks (Python, dependencies, GGUF model, engine binary).
2. Validate and initialize `offensive_ai_evidence.db`.
3. Check administrator account status:
   - On a fresh installation, generates a cryptographically secure 24-character one-time random password.
   - Displays the one-time credential to the console window only (passwords are **never** written to application logs).
   - Enforces a mandatory password change on first login before administrative actions can be performed.
4. Start the local Vulnerable API Lab on `http://127.0.0.1:5050`.
5. Start the Monitoring Dashboard on `http://127.0.0.1:8088`.
6. Launch your default browser directly to the dashboard.

### Method B: Advanced CLI Options
```cmd
python launcher.py --help

Options:
  --host HOST                Host binding address (default: 127.0.0.1)
  --port PORT                Dashboard port (default: 8088)
  --lab-port LAB_PORT        Vulnerable lab port (default: 5050)
  --no-lab                   Do not start the built-in vulnerable lab
  --no-browser               Do not auto-open default web browser
  --check-only               Run pre-flight diagnostics and exit
  --model-path PATH          Specify custom GGUF model path
  --recover-admin USERNAME   Reset password for an existing administrator
  --new-password PASSWORD    Specify new password during admin recovery
```

---

## 5. Clean Application Shutdown

To stop the running application:
- **Interactive Console:** Press `Ctrl + C` in the console window running `launch.bat`.
- **Background Termination:** Double-click or execute `stop.bat` to cleanly terminate any background services on ports 8088 and 5050.

---

## 6. Offline Verification Guarantees

- **Zero Cloud Calls:** The system makes zero outbound internet requests.
- **Air-Gapped Operation:** All CSS, JavaScript, and icons in the dashboard are 100% inline and locally hosted. No Google Fonts or public CDNs are requested.
- **Layer 1 Socket Guardrails:** `ScopeValidator` intercepts and denies any socket connection attempt to non-whitelisted or external hosts before TCP handshake.

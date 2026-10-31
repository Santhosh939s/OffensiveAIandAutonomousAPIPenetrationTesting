# Portable Setup & Deployment Guide: 8 GB RAM Windows Environments

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Target Hardware:** Windows 10/11, 8 GB RAM, Standard Multi-Core CPU, No Dedicated GPU  
**Runtime:** Python 3.8.10 (64-bit)  

---

## 1. System Requirements & Architecture

This guide details how to set up and run the complete autonomous API penetration testing agent and live monitoring console on an ordinary Windows laptop or desktop with **8 GB RAM and no dedicated graphics card**.

```
+-----------------------------------------------------------------------------+
|                          LOCAL WINDOWS WORKSTATION (8 GB RAM)               |
|                                                                             |
|   +------------------------------------+  +-----------------------------+   |
|   |         LIVE WEB DASHBOARD         |  |   VULNERABLE LOCAL API LAB  |   |
|   |  - HTML5/CSS3/Vanilla JS (No CDNs) |  |  - Intentionally vulnerable |   |
|   |  - Real-time SSE Telemetry Stream  |  |  - Runs on 127.0.0.1:5050   |   |
|   |  - Runs on 127.0.0.1:8088          |  |  - RAM: ~40 MB              |   |
|   |  - RAM: ~40 MB                     |  +-----------------------------+   |
|   +-----------------+------------------+                                    |
|                     |                                                       |
|                     v                                                       |
|   +---------------------------------------------------------------------+   |
|   |                     AUTONOMOUS CONTROLLER & TOOLS                   |   |
|   |  - PolicyEngine & Scope Whitelist (127.0.0.1 only)                  |   |
|   |  - ToolRegistry (HTTPX, OpenAPI Parser, ZAP Client, JWT, Fuzzer)    |   |
|   |  - SQLite Evidence Storage (evidence/evidence.db)                   |   |
|   |  - Total Local RAM Footprint: ~50 MB                                |   |
|   +-----------------+---------------------------------------------------+   |
+---------------------│-------------------------------------------------------+
                      │
                      │ Authenticated HTTP POST (Zero Local GPU Overhead)
                      v
+-----------------------------------------------------------------------------+
|                    REMOTE GPU INFERENCE WORKER (Optional/Cloud)             |
|   Kaggle Tesla T4 / Google Colab (16 GB VRAM)                               |
|   - Base Model : Qwen/Qwen2.5-1.5B-Instruct                                 |
|   - Adapter    : RebuiltV4 Checkpoint-200 (4-bit NF4 Quantization)          |
|   - VRAM Peak  : 1,692.4 MB (Sub-second latency: 368 ms/sample)             |
+-----------------------------------------------------------------------------+
```

---

## 2. Quick-Start (Automated Setup)

Open **PowerShell** in the project directory:

```powershell
cd "S:\UROP\offensive AI and autonomous APi penetration testing"
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\scripts\setup_windows_8gb.ps1
```

The setup script automatically:
1. Detects Python 3.8.10 64-bit.
2. Checks available physical RAM.
3. Installs lightweight requirements without downloading heavy CUDA binaries.
4. Verifies the local presence of `staging_rebuiltv4_training_checkpoints/checkpoint-200`.
5. Runs the pre-flight system health check.

---

## 3. Manual Installation (Alternative)

If you prefer installing dependencies manually:

### Step 1: Verify Python 3.8.10 (64-bit)
```powershell
python --version
# Output must be Python 3.8.x
python -c "import sys; print('64-bit' if sys.maxsize > 2**32 else '32-bit')"
# Output must be 64-bit
```

### Step 2: Install Lightweight Requirements
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> **Important:** Do **NOT** install `torch`, `torchvision`, or `transformers` locally on an 8 GB laptop without a CUDA GPU. Those packages consume $\sim 4$ GB of disk and require 4 to 6 GB of RAM to run unquantized on CPU.

### Step 3: Verify Checkpoint Files
Ensure the fine-tuned RebuiltV4 Checkpoint-200 files exist locally:
```powershell
Get-Item staging_rebuiltv4_training_checkpoints\checkpoint-200\adapter_model.safetensors
```

---

## 4. Pre-Flight Health Check

Execute the zero-dependency diagnostic utility:

```powershell
python scripts\health_check.py
```

Expected Output:
```
============================================================================
   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING AGENT
               PORTABLE 8 GB RAM HEALTH CHECK
============================================================================
Subsystem / Component        | Status Details                     | State 
----------------------------------------------------------------------------
Python Runtime               | 3.8.10 (64-bit)                    | PASS  
System Physical RAM          | 7.65 GB Total | 1307 MB Available  | PASS  
Agent Base Process RAM       | 16.66 MB Working Set               | PASS  
Port 5050 (Vulnerable Lab)   | Free / Ready                       | PASS  
Port 8088 (Dashboard UI)     | Free / Ready                       | PASS  
RebuiltV4 Checkpoint-200     | Verified (70.49 MB Safetensors)    | PASS  
RebuiltV4 Checkpoint-300     | Verified (Preserved on Disk)       | PASS  
SQLite Storage Engine        | Functional (In-memory & File)      | PASS  
Scope & Policy Guardrails    | Active (Strict Localhost Bounds)   | PASS  
Inference Recommendation     | REMOTE (Safe for 8 GB RAM)         | PASS  
============================================================================
[+] ALL CRITICAL CHECKS PASSED. System is ready for autonomous operations.
```

---

## 5. Starting the Live Monitoring Dashboard

### Option A: One-Click PowerShell Launcher
```powershell
.\scripts\run_optimized_dashboard.ps1
```

### Option B: Direct Python Command
```powershell
python run_dashboard.py --with-lab --open-browser
```

This command:
- Starts the intentionally vulnerable API laboratory on **`http://127.0.0.1:5050`**.
- Starts the Flask Live Dashboard on **`http://127.0.0.1:8088`**.
- Automatically launches your default web browser to the dashboard console.

---

## 6. Inference Mode Selection

On the dashboard under **New Assessment**, select the decision engine mode suited to your setup:

### Mode 1: Deterministic Mock Brain (Offline / Zero Setup)
- **Best for:** Local testing, automated test runs, laboratory exploration without internet.
- **RAM Impact:** $\sim 25$ MB.
- **Requires:** No GPU, no remote server, zero internet connection.
- **Behavior:** Deterministic, rule-driven ReAct decisions reproducing ground-truth vulnerability verification.

### Mode 2: Remote GPU Qwen Brain (Production Research Mode)
- **Best for:** Evaluating actual Qwen2.5-1.5B RebuiltV4 neural reasoning on an 8 GB laptop.
- **RAM Impact:** $\sim 15$ MB local RAM.
- **Requires:** A free Kaggle or Google Colab notebook running the lightweight FastAPI server.
- **Setup in 3 Steps:**
  1. Open a Kaggle notebook with GPU enabled (Tesla T4).
  2. Run [`kaggle_kernel/qwen_inference_server.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/kaggle_kernel/qwen_inference_server.py).
  3. Start a public tunnel using `ngrok` or `localtunnel` (e.g. `https://xxxx-your-tunnel.ngrok-free.app`).
  4. Paste this URL into the **Remote Brain Endpoint URL** field in the dashboard New Assessment form.

### Mode 3: Local Qwen Brain (CUDA Workstations Only)
- **Best for:** Workstations equipped with a dedicated Nvidia GPU ($\ge 3$ GB VRAM).
- **RAM Impact:** $\sim 1.7$ GB VRAM on GPU.
- **Status on 8 GB Laptop:** Labeled as *Requires CUDA GPU* to protect system memory.

---

## 7. Running an Autonomous Assessment

1. Navigate to the **New Assessment** tab on `http://127.0.0.1:8088`.
2. Configure targets:
   - **Target Base API URL:** `http://127.0.0.1:5050` (or your authorized target)
   - **Permitted Scope Hosts:** `127.0.0.1, localhost`
   - **OpenAPI Specification Source:** `lab/openapi_spec.json`
   - **Decision Engine:** `Deterministic Mock Brain` or `Remote Qwen2.5-1.5B Brain`
   - **Testing Budgets:** `Max Turns: 8`, `Max Requests: 25`
3. Click **Start Autonomous Assessment**.
4. Switch to **Live Activity** to monitor the real-time ReAct loop and telemetry stream.
5. In **Traffic Inspector**, click any request to inspect masked headers, credentials, and payloads.
6. In **Security Findings**, view verified vulnerabilities (`CONFIRMED` / `SUSPECTED`).
7. In **Reports**, preview the audit report and click **Download Report (.md)**.

---

## 8. Troubleshooting & FAQ

### Q1: "Port 5050 or 8088 is already in use"
A previous background server may still be bound to the port. Terminate orphan python processes:
```powershell
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
```

### Q2: "Can I run Qwen locally on CPU without a GPU?"
Loading Qwen2.5-1.5B in unquantized FP16 requires over $3.2$ GB of RAM, and BitsAndBytes 4-bit NF4 quantization requires CUDA. On an 8 GB laptop with $\sim 1.25$ GB available, loading the model locally on CPU risks freezing Windows. Use **Remote GPU mode** (via Kaggle/Colab) or **Deterministic Mock mode** for local testing.

### Q3: "Does the PolicyEngine block external websites?"
Yes. By default, the `ScopeValidator` strictly blocks any outbound HTTP request to domains outside the permitted host whitelist (`127.0.0.1, localhost`), preventing accidental scanning of unauthorized internet systems.

---

## 9. Clean Shutdown Procedure

To cleanly stop all background services:
1. In the PowerShell window running the dashboard, press **`Ctrl + C`**.
2. The runner will gracefully terminate the Flask server and background lab threads.
3. Temporary SQLite test databases in `evaluation/phase8_results/` can be deleted safely at any time. All core checkpoints and datasets remain untouched.


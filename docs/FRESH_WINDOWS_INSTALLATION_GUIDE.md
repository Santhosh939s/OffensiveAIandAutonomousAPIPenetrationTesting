# Standalone Windows Installation & User Operations Guide

**Project:** Autonomous Offensive AI & API Penetration Testing Platform  
**Target Environment:** Any Clean 64-bit Windows 10 or Windows 11 Computer  
**Prerequisites:** Python 64-bit (3.8 to 3.11) and Visual C++ 2015–2022 Redistributable (x64)  
**Operation Mode:** 100% Offline Local Execution (No Internet, Cloud APIs, or GPU required)  

---

## 1. System Requirements & Hardware Checklist

Before transferring the software, ensure the destination Windows computer meets these minimum specifications:

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Windows 10 (64-bit) Build 19041+ | Windows 11 (64-bit) |
| **Processor (CPU)** | Intel Core i3 (4 Cores / Threads) or AMD Ryzen 3 | Intel Core i5/i7 or AMD Ryzen 5/7 |
| **System Memory (RAM)** | **8 GB Physical RAM** | 16 GB RAM |
| **Free Storage Space** | **3.0 GB Free Space** | 5.0 GB Free Space (SSD) |
| **Graphics Card (GPU)** | **None Required** (Runs 100% on CPU) | Optional |
| **Network Connection** | **None Required** for operation (Fully offline) | Internet only for initial Python download |

---

## 2. Step-by-Step Installation of Prerequisites

If the destination computer does **not** have Python or C++ libraries installed, complete these two quick steps:

### Step 2.1: Install 64-bit Python
1. Download official **Python 3.10 (64-bit)** or **Python 3.11 (64-bit)** from [python.org](https://www.python.org/downloads/).
2. Run the downloaded installer (`python-3.10.x-amd64.exe`).
3. > [!IMPORTANT]
   > On the very first installer screen, **CHECK the box labeled:**  
   > `☑ Add Python to PATH`  
   > Then click **Install Now**.
4. To verify installation, open Windows Command Prompt (`cmd.exe`) and type:
   ```cmd
   python --version
   ```
   It should display `Python 3.10.x` or `Python 3.11.x`.

### Step 2.2: Install Visual C++ 2015–2022 Runtime
The bundled AI engine (`llama-cli.exe`) requires Microsoft's standard C++ runtime libraries:
1. Download the official installer: [Microsoft VC_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe).
2. Run `VC_redist.x64.exe`, agree to license terms, and click **Install**.
3. Restart the computer if prompted.

---

## 3. How to Transfer the Software to the Destination Machine

1. On the source workstation, locate the transfer folder:
   `dist\fresh_machine_transfer\`
2. Copy this entire folder onto a USB flash drive, external SSD, or local network share.
3. On the destination computer, copy the folder to your preferred directory, for example:
   `C:\OffensiveAIPenTest\`
4. Open the folder. You will see:
   - `launcher.py` (Main system startup orchestrator)
   - `launch.bat` (Double-click Windows launcher)
   - `stop.bat` (Double-click Windows shutdown utility)
   - `requirements.txt` (List of required Python libraries)
   - `models\` (Contains the AI model and engine binaries)
   - `controller\`, `dashboard\`, `lab\` (Application modules)

---

## 4. Install Application Dependencies

Open Command Prompt inside the application folder:
1. Hold `Shift` and right-click inside the folder window, then select **Open PowerShell window here** (or **Open in Terminal**).
2. Run the following command:
   ```powershell
   pip install -r requirements.txt
   ```
   *Note: This downloads only standard lightweight Python networking and web libraries (Flask, requests, httpx, cryptography). It does NOT install PyTorch, CUDA, or heavy AI frameworks.*

---

## 5. Verify File Hashes (Security & Integrity Check)

To confirm that no files were corrupted during the file transfer:
1. In PowerShell, run:
   ```powershell
   Get-FileHash models\qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf -Algorithm SHA256
   ```
2. Verify that the output hash exactly matches the official project hash:
   `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5`

---

## 6. How to Start the Application

You have two convenient ways to start the system:

- **Method A (Easiest):** Simply double-click `launch.bat`.
- **Method B (PowerShell / Command Prompt):**
  ```powershell
  python launcher.py
  ```

### What Happens on Startup:
1. The launcher runs an automated pre-flight diagnostic:
   - Validates 64-bit Python.
   - Detects the offline AI model (`qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`).
   - Detects the local AI engine (`models\bin\llama-cli.exe`).
   - Initializes the local SQLite evidence database (`offensive_ai_evidence.db`).
2. Starts the **Vulnerable Target API Lab** on port `5050` (`http://127.0.0.1:5050`).
3. Starts the **Security Management Dashboard** on port `8088` (`http://127.0.0.1:8088`).
4. Automatically opens your default web browser to the login screen.

---

## 7. Obtaining Initial Administrator Credentials

When you run the application for the very first time on a fresh computer, the launcher dynamically creates a secure initial administrator account:

1. Watch the terminal console during the first startup. You will see a prominent banner:
   ```
   ##############################################################################
    [!] FIRST-RUN ADMINISTRATOR SETUP COMPLETED (ONE-TIME CREDENTIALS)
    [!] Username: admin
    [!] One-Time Temporary Password: <YOUR_TEMPORARY_RANDOM_PASSWORD>
    [!] SECURITY NOTE: This password is NOT written to application logs.
    [!] MANDATORY ACTION: Password change is required before normal dashboard operations.
   ##############################################################################
   ```
2. **Copy or write down** this temporary password. (It is never stored in plaintext and cannot be recovered from ordinary logs).

---

## 8. Changing the Password & Logging In

1. Your web browser will display the login page at `http://127.0.0.1:8088/login`.
2. Enter:
   - **Username:** `admin`
   - **Password:** The one-time temporary password from the terminal.
3. Click **Sign In**.
4. The application will immediately display a mandatory **Change Password** screen.
5. Enter:
   - Current temporary password.
   - New secure password (at least 12 characters, including uppercase, lowercase, numbers, and symbols; cannot contain the word "admin").
   - Confirm new password.
6. Click **Update Password**. You will be logged into the main security console.

---

## 9. Authorizing the Target API Lab

By default, the platform strictly enforces defense-in-depth policy guardrails. It will **refuse** to test any API endpoint that has not been explicitly authorized by an administrator:

1. In the dashboard top navigation bar, click the **Policies** tab.
2. You will see the default policy: **Default Localhost Penetration Testing Policy**.
3. Click **View Targets** (or **Add Target Authorization**).
4. Verify that the local lab is authorized:
   - **Host Pattern:** `127.0.0.1`
   - **Port Range:** `5050`
   - **Path Prefix:** `/`
   - **Allowed Schemes:** `http`
5. If not already present, fill in these values and click **Authorize Target**.

---

## 10. Running an Autonomous Penetration Test

1. Click on the **Dashboard** tab.
2. In the **New Assessment** card on the left:
   - **Target Base URL:** `http://127.0.0.1:5050`
   - **Assessment Depth:** Select `Standard` or `Deep Recon`.
   - **Session Notes:** Enter a descriptive note (e.g., `Fresh Machine Compatibility Audit`).
3. Click **Launch Autonomous Assessment**.
4. Watch the live execution:
   - **Turn Counter:** Shows current decision turn (e.g., Turn 1/8).
   - **Request Budget:** Shows requests remaining (out of 30 allowed requests).
   - **Live Telemetry Log:** Streams real-time thoughts from the offline Qwen model, tool execution receipts, and HTTP request/response traces.

---

## 11. Inspecting Findings & Evidence

As vulnerabilities are discovered and verified, they appear dynamically:
1. Click the **Findings** tab:
   - Displays all vulnerabilities discovered (BOLA, Broken Authentication, BFLA, SQL Injection, GraphQL Introspection, etc.).
   - Distinguishes **CONFIRMED** vulnerabilities (backed by cryptographic proof) from **SUSPECTED** issues.
   - Shows CVSS v3.1 scores, severity badges (CRITICAL, HIGH, MEDIUM), and CWE identifiers.
2. Click any finding to expand:
   - **Technical Impact:** Detailed explanation of what an attacker could achieve.
   - **Safe Reproduction Steps:** Step-by-step instructions to reproduce the issue safely.
   - **Remediation Guidance:** Concrete code fixes for developers.
   - **Cryptographic Evidence Hash:** SHA-256 fingerprint of the exact raw traffic packet that verified the flaw.

---

## 12. Exporting Audit Reports

1. In the dashboard, click the **Reports** tab.
2. Locate your completed assessment session.
3. Choose your preferred export format:
   - **Download Markdown (`.md`):** Formatted for GitHub issues or developer tickets.
   - **Download JSON (`.json`):** Full structured data for automated CI/CD security pipelines.
   - **Download HTML (`.html`):** Standalone styled executive report suitable for PDF printing or stakeholder presentation.

---

## 13. How to Cleanly Shut Down the Application

When finished testing:
- **Method A:** In the terminal console running the application, press `Ctrl + C`. The system will cleanly terminate all background threads, flush the database, and exit.
- **Method B:** Double-click `stop.bat`. It will locate and terminate any remaining service processes on ports 5050 and 8088.

---

## 14. Troubleshooting Common Errors

### Q1: "Python was not found in your system PATH"
- **Cause:** Python was installed without checking `Add Python to PATH`.
- **Fix:** Re-run the Python installer, choose **Modify**, and ensure **Add to PATH** is checked. Or add `C:\Users\<YourUser>\AppData\Local\Programs\Python\Python310` to your system Environment Variables.

### Q2: "VCRUNTIME140.dll was not found" or "llama-cli.exe failed to start"
- **Cause:** The destination computer lacks the Microsoft Visual C++ Runtime.
- **Fix:** Download and install [VC_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe) as described in Step 2.2.

### Q3: "Port 5050 or 8088 is already in use"
- **Cause:** A previous instance of the application or another web server is occupying the port.
- **Fix:** Double-click `stop.bat` to sweep active listeners, or run `python launcher.py --port 8090 --lab-port 5052` to use alternative ports.

### Q4: "I lost my administrator password"
- **Cause:** Temporary password was cleared from the terminal or forgotten.
- **Fix:** Run the built-in emergency recovery command in PowerShell:
  ```powershell
  python launcher.py --recover-admin admin --new-password "MyEmergencyPassword2026!#"
  ```
  This immediately updates the administrator credentials without modifying historical assessment evidence.


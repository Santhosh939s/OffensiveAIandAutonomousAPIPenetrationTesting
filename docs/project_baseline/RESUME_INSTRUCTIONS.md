# Instructions for Resuming the Project

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Status:** Pre-Deployment Checkpoint (Preserved Baseline)  
**Date:** November 4, 2026

When returning from your break to resume work, follow this exact sequence:

---

## Step 1: Verify Working-Tree & Artifact Integrity

Before making any changes or launching new workflows, confirm that the repository and model artifacts remain bit-for-bit identical to this baseline:

```powershell
# 1. Confirm working tree has not been modified
git status --short

# 2. Verify GGUF Model SHA-256 Checksum
(Get-FileHash models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf).Hash
# Expected: CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5

# 3. Verify Final LoRA Adapter SHA-256 Checksum
(Get-FileHash models/training_artifacts/final_adapter/adapter_model.safetensors).Hash
# Expected: 39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327
```

---

## Step 2: Run Fast Baseline Smoke Test

Run the 219 fast automated regression tests to verify environment health:

```powershell
python -m pytest tests/ --ignore=tests/test_qa_phase1_real_gguf.py -v
```
- **Expected Result:** `219 passed` in ~2.8 minutes with 0 failures.

---

## Step 3: Launch Local Services (Development & Testing)

If you wish to test the live web dashboard against the authentic local API lab:

### Terminal 1: Start Vulnerable Local API Lab
```powershell
python lab/app.py
```
- Listens on `http://127.0.0.1:5050`
- Provides vulnerable OWASP endpoints and OpenAPI documentation at `http://127.0.0.1:5050/openapi.json`.

### Terminal 2: Start Operational Web Dashboard
```powershell
python dashboard/app.py
```
- Listens on `http://127.0.0.1:5000`
- Access via your browser to view telemetry, launch assessments, inspect traffic, and download reports.

---

## Step 4: Next Phase Instructions (When Authorized)

When the user gives the directive to proceed to the **Deployment & Packaging Phase**:

1. **Standalone Windows Packaging:**
   - Package the Flask dashboard and controller into a standalone executable or portable bundle (PyInstaller / Inno Setup).
   - Ensure `llama-cli.exe` and `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` are bundled in a relative `models/` directory.
2. **One-Click Windows Launcher:**
   - Create `run_offensive_ai.bat` to launch the dashboard and API lab in background processes and automatically open `http://127.0.0.1:5000` in the default browser.
3. **Physical Laptop Verification:**
   - Transfer the bundle to an ordinary laptop (Intel Core i3, 8 GB RAM, no GPU) and verify:
     - Peak RAM working set stays below 1.5 GB.
     - Offline execution functions with network adapter disabled.
     - Autonomous penetration testing completes successfully on CPU.


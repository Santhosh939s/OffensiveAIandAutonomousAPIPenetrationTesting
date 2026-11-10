# Phase 7.0: Academic Research Reproducibility Guide

## Offensive AI and Autonomous API Penetration Testing

**Project Directory:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Date of Validation:** November 2026  
**Status:** Validated, Reproducible, Empirical Evidence Preserved

---

## 1. System Environment & Prerequisites

The platform runs 100% locally on CPU without external network dependencies, third-party AI APIs, or specialized GPU hardware.

- **Operating System:** Microsoft Windows 10/11 x64 (AMD64 architecture)
- **Python Runtime:** Python 3.8.10 (compatible with 3.10 and 3.11)
- **Native Inference Engine:** llama.cpp CPU binary runtime (`models/bin/llama-cli.exe`)
- **System Runtime Dependency:** Microsoft Visual C++ 2015–2022 Redistributable (x64)
- **Memory Footprint:** 
  - Host Python Process: ~42 MB RSS
  - Native llama-cli Runtime: ~1,278 MB peak working set
  - Recommended System RAM: $\ge$ 4 GB

---

## 2. Cryptographic Artifact Integrity Signatures

Every model, adapter, and runtime binary is verified against immutable SHA-256 cryptographic digests:

| Component | Local Relative Path | Size (Bytes) | SHA-256 Cryptographic Hash |
| :--- | :--- | :--- | :--- |
| **Quantized GGUF Model** | `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` | 986,050,464 | `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5` |
| **LoRA Fine-Tuned Adapter** | `models/training_artifacts/final_adapter/adapter_model.safetensors` | 33,576,076 | `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` |
| **Native CPU llama-cli** | `models/bin/llama-cli.exe` | 1,842,688 | `25BAE44E226F27EA54D7AB7B55F55A01DFA6954637350E8F67DC8BDA695A8D24` |
| **Held-out Test Dataset** | `evaluation/test_sample_2000.jsonl` | 895,309 | `0DEEDDE274D547DB05A7F2D172F301287B95F54E708E77610EC8C4C5B3DC6CA7` |

To verify these signatures on Windows PowerShell:
```powershell
Get-FileHash -Algorithm SHA256 "models\qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
Get-FileHash -Algorithm SHA256 "models\training_artifacts\final_adapter\adapter_model.safetensors"
Get-FileHash -Algorithm SHA256 "models\bin\llama-cli.exe"
```

---

## 3. Step-by-Step Reproduction Instructions

All evaluation and verification scripts execute strictly against local CPU inference and local databases.

### Step 3.1: Model Accuracy, F1-Score & Confusion Matrix Evaluation

Evaluates the real Qwen2.5-1.5B Q4_K_M model on CPU against a stratified 64-sample held-out test split (8 samples across all 8 vulnerability classes).

```powershell
python research/phase7/evaluate_model.py
```
- **Output Artifact:** `research/phase7/model_evaluation_results.json`
- **Measured Accuracy:** 95.31% (61/64 correct)
- **Macro F1-Score:** 0.9665
- **Weighted F1-Score:** 0.9665
- **Average CPU Latency:** 5.12 seconds per sample

### Step 3.2: Full Autonomous Workflow Evaluation on Local Lab

Deploys the local Vulnerable API Lab (`lab/app.py`) on an ephemeral port and executes `AutonomousController` with real CPU model inference across 3 distinct scenarios:
1. Multi-turn autonomous vulnerability discovery
2. Request budget hard-cutoff enforcement
3. Restricted endpoint probing

```powershell
python research/phase7/evaluate_autonomous_workflow.py
```
- **Output Artifact:** `research/phase7/autonomous_workflow_results.json`
- **Budget Compliance:** 100% (Zero request overrun)
- **Evidence Integrity:** 100% Cryptographically verified via SHA-256 chains

### Step 3.3: Security Boundary & Policy Enforcement Suite

Validates all 10 core security boundaries (Layer 1 socket SSRF interception, DNS rebinding interception, private IP restrictions, budget exhaustion, live target revocation, registry sentinel unforgeability, setup locking, must_change_password gating, and database tamper detection).

```powershell
python research/phase7/security_validation.py
```
- **Output Artifact:** `research/phase7/security_validation_results.json`
- **Result:** 10/10 Boundaries Passed

### Step 3.4: Performance & Resource Utilization Benchmark

Benchmarks component initialization latency, model inference throughput, report generation speed across JSON, HTML, and Markdown, and memory footprint.

```powershell
python research/phase7/measure_performance.py
```
- **Output Artifact:** `research/phase7/performance_benchmarks.json`
- **Total Backend Cold Start:** 218.94 ms
- **Report Generation (all 3 formats):** 3.63 ms total
- **Python Base Memory:** 40.72 MB RSS

### Step 3.5: Master Regression Test Suite

Runs the entire project regression suite (388 baseline tests) covering auth, controllers, tools, policy engines, and reporting:

```powershell
python -m pytest tests/
```
- **Expected Result:** 388 passed in ~230 seconds.

---

## 4. Random Seeds and Determinism

- Evaluation scripts sample deterministically using stratified modulo offsets over `evaluation/test_sample_2000.jsonl`.
- Native inference parameters are pinned in `LocalCpuBrainClient`:
  - `temperature`: `0.1` (greedy sampling for deterministic security reasoning)
  - `top_p`: `0.9`
  - `repeat_penalty`: `1.1`
  - `n_threads`: `4`


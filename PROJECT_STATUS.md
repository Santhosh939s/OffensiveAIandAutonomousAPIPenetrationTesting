# Project Status: API Security Classification & Automation Pipeline

**Document Version:** 4.2.0  
**Audit Timestamp:** 2026-10-26T19:00:00+05:30  
**Auditor:** Senior ML & Automation Engineer  
**Workspace:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**GitHub Repository:** `https://github.com/Santhosh939s/OffensiveAIandAutonomousAPIPenetrationTesting` (Branch: `main`, Commit: `41613a9`)  
**Kaggle Kernel:** `santhosh939s/urop-offensive-ai` (Version 18 - Restore-Only Verification PASS)  
**Kaggle Master Recovery Dataset:** `santhosh939s/recovery` (Read-Only / Untouched)  
**Kaggle Adapters Dataset:** `santhosh939s/rebuiltv4-adapters` (Active / 148 MB / Inference Only)  
**Kaggle Training Checkpoints Dataset:** `santhosh939s/rebuiltv4-training-checkpoints` (Version 1 - Verified & Restored / 445 MB)  
**Kaggle Output Runs Dataset:** `santhosh939s/offensive-ai-runs` (Version 1 - Published & Verified)  

---

## 1. Inventory & Resource Comparison Matrix

| Resource / File | Local Laptop (`S:\...`) | GitHub (`main`) | Kaggle Cloud Resource | Status & Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Master Recovery Archive** (`API_Security_Recovery_...zip`) | **Present** (761.8 MB) | *Excluded* (.gitignore) | `santhosh939s/recovery` | Untouched, read-only baseline |
| **Step-4500 Adapter** | **Present** | *Excluded* | `santhosh939s/recovery` | Verified in Kernel V14 |
| **RebuiltV4 Checkpoints 200 & 300 (Inference)** | **Present** | *Excluded* | `santhosh939s/rebuiltv4-adapters` | Staged & verified in Kernel V15 |
| **RebuiltV4 Checkpoints 200 & 300 (Full Resumption)** | **Present** (inside local archive) | *Excluded* | `santhosh939s/rebuiltv4-training-checkpoints` | **Version 1 Restored & Verified (Kernel V18 PASS)** |
| **Test Set (2,000 samples)** | **Present** (2.96 MB) | **Tracked** | All datasets | SHA256 verified identical |
| **Local Offline Run Archives** | **Preserved** in `runs/` | *Excluded* (.gitignore) | N/A | Persistent local offline backup |
| **Dedicated Runs Dataset** | `staging_offensive_ai_runs/` | *Excluded* | `santhosh939s/offensive-ai-runs` | **Version 1 Published & Verified** |
| **Automation Suite** | `automation/*.py` | **Tracked** | N/A | 9/9 unit tests passing |

---

## 2. Kernel Execution History (`santhosh939s/urop-offensive-ai`)

- **Version 13 (Smoke Test):** Tesla T4, 10 samples, latency 0.081s/sample, verified 4-bit NF4 greedy inference.
- **Version 14 (Step-4500 Baseline Evaluation):** Tesla T4, 2,000 samples, completed in ~13.5 min. Accuracy: **98.65%**, Macro F1: **0.9731**, 20 false positives on Benign, 7 invalid Cookie outputs.
- **Version 15 (RebuiltV4 Dual Checkpoint Evaluation):** Tesla T4, 2,000 samples each on Checkpoint-200 and Checkpoint-300, completed in ~26 min.
  - **Checkpoint-200 (Top Performer):** Accuracy: **99.65%** (1,993/2,000), Macro F1: **0.9924**, **0 false positives on Benign**, 100% precision on Benign and SQL Injection.
  - **Checkpoint-300 (Final Step):** Accuracy: **99.60%** (1,992/2,000), Macro F1: **0.9911**, **0 false positives on Benign**.
  - **Cookie Injection Analysis:** The 7 unresolved cases (`[24, 867, 1614, 1671, 1790, 1874, 1983]`) are raw HTTP header echoing hallucinations; Checkpoint-200 eliminated false positive SQL alarms on these cases.
- **Version 18 (Restore-Only Verification - PASS):** Kaggle CPU (0 GPU quota consumed), executed in fresh session.
  - Restored Version 1 files into `/tmp/restore_verification_fresh`.
  - Cryptographically matched all 28 SHA256 checksums.
  - Confirmed all 13 components present in `checkpoint-200` and `checkpoint-300`.
  - Resolved `Qwen/Qwen2.5-1.5B-Instruct` base model registry and tokenizer without downloading weights.
  - Deserialized PyTorch 32-bit AdamW optimizer states (392 tensors, 2 param groups), learning rate schedulers, GradScaler, RNG states, and training arguments.
  - Verified intended resume steps: Step 200 (momentum LR: `6.8e-05`) and Step 300 (momentum LR: `1.33e-06`).
  - Zero optimizer steps executed. Report saved to `runs/restore_verification_v18/restore_verification_report.json`.

---

## 3. Remote Dataset Publications

### A. Training Resumption Dataset (`santhosh939s/rebuiltv4-training-checkpoints`)
- **Dataset URL:** `https://www.kaggle.com/datasets/santhosh939s/rebuiltv4-training-checkpoints`
- **Current Version:** `1` (Initial Release, Private)
- **Status:** `ready` / `is_frozen: True` / **Verified Restorable**
- **Total Files:** 30 remote files (466,872,615 bytes / 445.24 MB)
- **Included Artifacts:** Complete weights, 32-bit AdamW optimizer states (`optimizer.pt`), LR schedulers (`scheduler.pt`), GradScaler (`scaler.pt`), Trainer states (`trainer_state.json`), training args, RNG states, tokenizer assets, and canonical training script `train_rebuilt_v4.py`.

### B. Benchmark Runs Dataset (`santhosh939s/offensive-ai-runs`)
- **Dataset URL:** `https://www.kaggle.com/datasets/santhosh939s/offensive-ai-runs`
- **Current Version:** `1` (Initial Release, Private)
- **Status:** `ready` / `is_frozen: True`
- **Included Artifacts (16 remote items, 2.31 MB):** Predictions JSONLs, metrics JSONs, comparative summaries, confusion matrix comparison plots, execution logs, audit ledger, and publication manifests.

---

## 4. Safety & Governance Status

1. **Master Recovery Dataset (`santhosh939s/recovery`):** Strictly unmodified and preserved.
2. **Local Backup:** Stored in `runs/run_20261026_rebuiltv4_dual_benchmark/`, `staging_rebuiltv4_training_checkpoints/`, `runs/restore_verification_v18/`, and `kaggle_output_full_eval_step4500/`.
3. **Resumption Assurance:** **PROVEN.** Deserialization and step recovery tested in live Kaggle session.
4. **Credentials:** No API tokens, keys, or credentials committed or stored in git.
5. **GPU Quota:** >24 hours of T4 GPU quota remain intact (Verification ran on CPU).

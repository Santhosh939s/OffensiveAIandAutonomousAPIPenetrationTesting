# Offensive AI and Autonomous API Penetration Testing

An automated machine learning and security evaluation framework for API vulnerability classification, multi-task offensive reasoning, and autonomous penetration testing, powered by fine-tuned **Qwen2.5-1.5B-Instruct** with parameter-efficient LoRA adapters.

---

## 📌 Quick Directory Index & Navigation (Where is Everything?)

Anyone exploring this repository can immediately locate all datasets, models, code, and execution notebooks below:

### 1. 📓 Master Notebook (All Executions & Manual Code)
| File | Description |
| :--- | :--- |
| **[`urop_offensive_ai_master_all_executions.ipynb`](./urop_offensive_ai_master_all_executions.ipynb)** | **The primary cumulative archive (284 cells).** Contains 100% of the manual code, exploratory data analysis, ATRDF ingestion, RebuiltV1–V4 pipeline (Cell 199 selection), Checkpoint Restore Verification run, and the 20-case Multi-Task Capability Evaluation run. |
| **[`capability_eval_kaggle.ipynb`](./capability_eval_kaggle.ipynb)** | Dedicated standalone notebook for the 20-case RebuiltV4 Checkpoint-200 capability evaluation. |
| **[`urop-offensive-ai.ipynb`](./urop-offensive-ai.ipynb)** | Dedicated standalone notebook for the 6-step Checkpoint Restoration & Health verification run. |

---

### 2. 📁 Datasets & Records Directory
| Dataset / Path | Records | Description |
| :--- | :---: | :--- |
| **[`finetuning/rebuilt_v5_pilot/`](./finetuning/rebuilt_v5_pilot/)** | **1,000** | **RebuiltV5 Multi-Task Pilot Dataset** spanning all 5 offensive capabilities (Anchor Classification, Evidence Reasoning, Safe Tool Selection, OWASP Test Planning, Grounded Reporting). |
| ├── [`train.jsonl`](./finetuning/rebuilt_v5_pilot/train.jsonl) | 800 | 80% training split (160 scenario families, 0 overlap with val/test). |
| ├── [`val.jsonl`](./finetuning/rebuilt_v5_pilot/val.jsonl) | 100 | 10% validation split for Trainer evaluation. |
| ├── [`test.jsonl`](./finetuning/rebuilt_v5_pilot/test.jsonl) | 100 | 10% held-out test split for post-training audit. |
| ├── [`pilot_1000_full.jsonl`](./finetuning/rebuilt_v5_pilot/pilot_1000_full.jsonl) | 1,000 | Complete combined pilot set with provenance and scenario IDs. |
| ├── [`DATASET_AUDIT_REPORT.md`](./finetuning/rebuilt_v5_pilot/DATASET_AUDIT_REPORT.md) | — | Verification report, per-category counts, and SHA256 checksums. |
| └── [`provenance_manifest.json`](./finetuning/rebuilt_v5_pilot/provenance_manifest.json) | — | Cryptographic manifest for RebuiltV5 pilot data. |
| **[`evaluation/test_sample_2000.jsonl`](./evaluation/test_sample_2000.jsonl)** | **2,000** | Standardized held-out 8-class HTTP evaluation benchmark. |
| **[`kaggle_output/.../ATRDF/extracted/`](./kaggle_output/api_pentest_research/ATRDF/extracted/)** | **459,049** | Raw source ATRDF datasets 1, 2, 3, 4 (`dataset_1_train.json` through `dataset_4_train.json`). |
| **[`evaluation/`](./evaluation/)** | — | Ground-truth metrics and evaluation reports (`original_sample2000.json`, `rebuiltv4_sample2000.json`). |

---

### 3. 🧠 Model Weights & Checkpoints
Because model weights exceed GitHub's 100MB file limit, they are tracked via private Kaggle Datasets and local staging:

* **Checkpoint-200 (Preferred Candidate):**  
  * Adapter Weights: `staging_rebuiltv4_training_checkpoints/checkpoint-200/adapter_model.safetensors` (73.9 MB)
  * Resumption State: `optimizer.pt` (148.0 MB), `scheduler.pt`, `scaler.pt`, `trainer_state.json`
* **Checkpoint-300 (Final 300-step run):**  
  * Adapter Weights: `staging_rebuiltv4_training_checkpoints/checkpoint-300/adapter_model.safetensors` (73.9 MB)
* **Kaggle Cloud Dataset:** `santhosh939s/rebuiltv4-training-checkpoints`
* **Local Master Recovery Archive:** `API_Security_Recovery_20261020_114027.zip`

---

### 4. ⚙️ Training & Fine-Tuning Scripts
| Script | Description |
| :--- | :--- |
| **[`finetuning/train_rebuilt_v4.py`](./finetuning/train_rebuilt_v4.py)** | Production DDP QLoRA fine-tuning script used for RebuiltV4 on dual Tesla T4 GPUs. |
| **[`finetuning/rebuilt_v5_pilot/train_rebuilt_v5_pilot.py`](./finetuning/rebuilt_v5_pilot/train_rebuilt_v5_pilot.py)** | Staged RebuiltV5 Pilot script with explicit prompt boundary loss masking (`MultiTaskCompletionCollator`) and singleton process lock (`.training.lock`). |

---

### 5. 📊 Evaluation & Run Ledger
* **[`RUN_LEDGER.jsonl`](./RUN_LEDGER.jsonl):** Complete append-only audit trail recording every benchmark run, timestamp, Git commit, Kaggle kernel version, and composite scores.
* **[`PROJECT_STATUS.md`](./PROJECT_STATUS.md):** Active project status, component health, and verification ledger.
* **[`PROJECT_RECOVERY_NOTES.md`](./PROJECT_RECOVERY_NOTES.md):** Historical disaster recovery audit and architecture specifications.

---

## Model Specifications

| Parameter | Specification |
| :--- | :--- |
| **Base Model** | `Qwen/Qwen2.5-1.5B-Instruct` |
| **Fine-Tuning Method** | QLoRA (NF4 4-bit Quantization, FP16 Compute, Double Quantization) |
| **LoRA Target Modules** | All linear projections: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `up_proj`, `down_proj`, `gate_proj` |
| **LoRA Hyperparameters** | Rank $r=16$, Alpha $\alpha=32$, Dropout $0.05$ |
| **RebuiltV4 Task** | 8-Class HTTP Security Classification (`Benign`, `Cookie Injection`, `Directory Traversal`, `LOG4J`, `Log Forging`, `RCE`, `SQL Injection`, `XSS`) |
| **RebuiltV5 Task** | 5 Offensive Capabilities: (1) Classification Anchor, (2) Evidence Reasoning, (3) Safe Tool Calling, (4) OWASP Test Planning, (5) Grounded Reporting & Abstention |

---

## Evaluation Benchmark Summary (2,000 Sample Slice)

| Metric | Original Model (Step 4500) | RebuiltV4 (Step 300) | RebuiltV4 (Step 200 - Preferred) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 99.20% | **99.65%** | **99.70%** |
| **Macro F1** | 0.9828 | **0.9924** | **0.9934** |
| **Weighted F1** | 0.9937 | **0.9981** | **0.9985** |
| **Invalid Predictions** | 7 (0.35%) | 7 (0.35%) | **6 (0.30%)** |

---

## Automation & Workflow Architecture

```
                                  [ Local Antigravity IDE ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [ Git Version Control ]                     [ Kaggle API CLI ]
         (GitHub: Santhosh939s/...)                   (Dual Tesla T4 Compute)
                       │                                           │
                       │                              ┌────────────┴────────────┐
                       ▼                              ▼                         ▼
         urop_offensive_ai_master_...       [ Headless GPU Run ]      [ Model Checkpoints ]
         (All Cumulative Executions)         (Batch Execution)        (Private Dataset)
```

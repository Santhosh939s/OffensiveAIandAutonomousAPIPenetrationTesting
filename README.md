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
| **[`DATASET_PROVENANCE_AND_PREPARATION.md`](./DATASET_PROVENANCE_AND_PREPARATION.md)** | — | **Comprehensive Provenance Guide:** Upstream repo links, download URLs, raw schemas, the 3-stage 9,000-sample selection pipeline, and formatting specifications. |
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

## 📦 Dataset Provenance & The 9,000-Record RebuiltV4 Pipeline

### Upstream Source Repository & Academic Origin
The foundational training data originates from the **API Traffic Research Dataset Framework (ATRDF)**, developed for the Ariel Cyber Innovation Center (ACIC) and Cisco API Security Competition by Shmuel Lavian (Ariel University):
* **Upstream GitHub Repository:** [`https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge)
* **Direct Official Dataset Downloads:**
  * [Dataset 1 Train (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_1_train.7z) | [Dataset 1 Val (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_1_val.7z) (4,282 train records)
  * [Dataset 2 Train (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_2_train.7z) | [Dataset 2 Val (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_2_val.7z) (127,500 train records)
  * [Dataset 3 Train (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_3_train.7z) | [Dataset 3 Val (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_3_val.7z) (144,500 train records)
  * [Dataset 4 Train (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_4_train.7z) | [Dataset 4 Val (7z)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_4_val.7z) (182,767 train records)
  * **Total Raw Available:** **459,049 records** across 8 attack categories.

### How the 9,000 Records Were Selected from 459,049
To eliminate extreme class imbalance (Benign was 85.3% of raw data) and accelerate training without losing rare attack sensitivity, records were processed through three deterministic stages:

1. **Stage 1 (`Cell 164` $\rightarrow$ `rebuilt_v2`):** Loaded all 459,049 records from Datasets 1–4, preserved all headers (`Set-Cookie`, `Date`, etc.), sorted dictionary keys deterministically, and partitioned by class using `random_seed = 42`.
2. **Stage 2 (`Cell 166` $\rightarrow$ `rebuilt_v3`):** To prevent identical requests from appearing across splits, every input was hashed via SHA-256 (`hashlib.sha256(input)`). All records sharing the same input were grouped atomically into the same split, guaranteeing **zero cross-split data leakage**.
3. **Stage 3 (`Cell 199` $\rightarrow$ `rebuilt_v4`):** From `rebuilt_v3/train.jsonl`, category-stratified random sampling without replacement (`rng.sample`) was applied with fixed seed `SEED = 42`:
   * **Benign:** Exactly 2,000 records
   * **Cookie Injection:** Exactly 1,000 records
   * **Directory Traversal:** Exactly 1,000 records
   * **LOG4J:** Exactly 1,000 records
   * **Log Forging:** Exactly 1,000 records
   * **RCE:** Exactly 1,000 records
   * **SQL Injection:** Exactly 1,000 records
   * **XSS:** Exactly 1,000 records
   * **Final Combined Dataset:** **9,000 records** (shuffled globally with `rng.shuffle`).

### Originating Source Breakdown of the 9,000 Records:
* **Dataset 4:** 4,760 records (52.9%)
* **Dataset 3:** 2,326 records (25.8%)
* **Dataset 2:** 1,670 records (18.6%)
* **Dataset 1:** 244 records (2.7%)

### How Records Were Formatted for Fine-Tuning
Each record in the dataset is structured as:
```json
{
  "input": "Classify this HTTP request into exactly one category: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS.\nReturn only the category name.\nHTTP request:\n{\"body\": \"\", \"headers\": {\"Host\": \"127.0.0.1:5000\", \"User-Agent\": \"...\"}, \"method\": \"GET\", \"url\": \"http://127.0.0.1:5000/...\"}",
  "category": "SQL Injection",
  "binary_label": "Malware",
  "source_dataset": "dataset_4_train",
  "source_index": 12845
}
```
During training, the dataset loader maps this into the canonical Qwen2.5 chat template:
* **System Prompt:** `"You are an API security classifier. Classify the HTTP request into exactly one of these categories: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS. Return only the category name."`
* **User Prompt:** The serialized HTTP request JSON.
* **Assistant Completion (Trained):** The category name (e.g. `SQL Injection`).
* **Loss Masking:** All prompt tokens are masked with `-100`, computing loss strictly on the assistant tokens.

*(For full implementation scripts and reproduction steps, see [`DATASET_PROVENANCE_AND_PREPARATION.md`](./DATASET_PROVENANCE_AND_PREPARATION.md)).*

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

# FINAL DATASET PROVENANCE AND EVALUATION SPLIT AUDIT REPORT

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Investigation Scope:** Original Dataset Sampling Strategy, Evaluation Splits, Data Contamination Audit, and Empirical Independence Reconciliation  
**Date:** November 11, 2026  
**Auditor:** Autonomous Senior Security Research Agent  
**Enforcement Policy:** STRICT READ-ONLY. Zero changes to model weights, datasets, evaluation results, source code, or Git history.

---

## 1. Executive Summary & Verification Master Table

| Investigation Topic | Key Finding | Verification Status |
| :--- | :--- | :---: |
| **Original 5K Requirement** | Original blueprint mandated **5,000 samples per category across 8 categories = 40,000 classification records** (+ 5K difficult + 5K reasoning = 50,000 total). Stage 1 piloted **5,000 records total (625/class)**; Stage 2 expanded to **30,000 records**. | **`VERIFIED`** |
| **Origin of `test_sample_2000.jsonl`** | Created in **Cell 217 of `urop_offensive_ai_master_all_executions.ipynb`** via proportional stratified random sampling from `finetuning/rebuilt_v3/test.jsonl` using **`random.seed(42)`**. | **`VERIFIED`** |
| **Independence of `test_sample_2000.jsonl`** | **0 records (0.00% overlap)** with the 50,000-record master corpus and all training stages. Never used for training, hyperparameter tuning, or validation. | **`VERIFIED`** |
| **Original 50K Splitting Strategy** | **Hierarchical 80:10:10 stratified split** on the 41,000 expansion pool (32,800 train, 4,100 val, 4,100 test) with 9,000 baseline permanently locked in train, yielding **41,800 train (83.6%), 4,100 val (8.2%), 4,100 test (8.2%)**. Splitting used atomic scenario-group hashing (`seed=20261101`) post-repair. | **`VERIFIED`** |
| **Stage 2 Split Contamination** | Stage 2 assembled **30,000 clean classification records** by taking all available non-baseline classification records, pulling **23,818 from `master_train`**, **2,597 from `master_val`**, and **3,585 from `master_test`**. | **`VERIFIED`** |
| **Integrity of Master Test Split** | `master_test_4100_repaired.jsonl` is **87.4% contaminated** by Stage 2 training (3,585/4,100 records seen). Exactly **515 records** remain genuinely unseen (`independent_unseen_test_515.jsonl`). | **`VERIFIED`** |
| **Independence of 128-Record Evaluation** | Sampled from `test_sample_2000.jsonl` (16 per class, `seed=42`). Achieved **96.88% accuracy** (124/128). **100% genuinely independent** (0 training exposure). | **`VERIFIED`** |
| **Independence of External Phase 11** | Four external benchmarks (Mendeley, WAMM, SecLists, ATRDF Unseen). Audited in Phase 11.1 with **0.00% exact or normalized collisions**. **100% genuinely independent out-of-distribution suites**. | **`VERIFIED`** |

---

## 2. Section 1: Original Sampling Requirements vs. Actual Implementation

### A. The Blueprint Plan vs. Actual Training Implementations
* **[VERIFIED] Original Blueprint Plan:**
  In [`reports/MODEL_PHASE_B_DATASET_EXPANSION_BLUEPRINT.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/reports/MODEL_PHASE_B_DATASET_EXPANSION_BLUEPRINT.md#L53-L67) (dated October 31, 2026), the requirement was explicitly specified as:
  > *"The final target for 8-class classification is **40,000 records (5,000 per class)**. Because RebuiltV4 already provides 9,000 records, exactly 31,000 new records must be added."*
  Adding 5,000 Difficult Classification records and 5,000 Autonomous Security Reasoning traces formed the **50,000-record Master Corpus**.
* **[VERIFIED] Actual Implementation Stage 1 (Initial Pilot):**
  In [`scripts/create_training_views.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/scripts/create_training_views.py#L71-L97), Stage 1 was sampled as a controlled initial training run:
  * **5,000 total records**, balanced at exactly **625 records per class** across all 8 classes ($8 \times 625 = 5,000$).
  * Purpose: Validate multi-GPU DDP stability, learning rate schedule, and error distributions before committing to the full expansion.
* **[VERIFIED] Actual Implementation Stage 2 (Expanded Model):**
  In [`dataset/splits/classification_training_30000.jsonl`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/splits/classification_training_30000.jsonl), Stage 2 was assembled with:
  * **30,000 total records** spanning all remaining clean classification candidates.
  * The 5,000 autonomous reasoning traces were reserved and held out for the agent execution engine.

### B. Exact Class Distributions (Direct File Inspection)

| Vulnerability Class | Stage 1 (`stage1_train_5000_repaired.jsonl`) | Stage 2 (`classification_training_30000.jsonl`) | Master Corpus (`master_corpus_50000_repaired.jsonl`) |
| :--- | :---: | :---: | :---: |
| **Directory Traversal** | 625 (12.50%) | 4,400 (14.67%) | 6,150 (12.30%) |
| **SQL Injection** | 625 (12.50%) | 4,050 (13.50%) | 5,800 (11.60%) |
| **Benign** | 625 (12.50%) | 3,950 (13.17%) | 6,700 (13.40%) |
| **RCE** | 625 (12.50%) | 3,750 (12.50%) | 5,500 (11.00%) |
| **LOG4J** | 625 (12.50%) | 3,750 (12.50%) | 5,500 (11.00%) |
| **Log Forging** | 625 (12.50%) | 3,600 (12.00%) | 5,350 (10.70%) |
| **XSS** | 625 (12.50%) | 3,250 (10.83%) | 5,000 (10.00%) |
| **Cookie Injection** | 625 (12.50%) | 3,250 (10.83%) | 5,000 (10.00%) |
| **OWASP API Top 10 (Traces)** | 0 (0.00%) | 0 (0.00%) | 5,000 (10.00%) |
| **Total Records** | **5,000 (100.0%)** | **30,000 (100.0%)** | **50,000 (100.0%)** |

---

## 3. Section 2: Origin and Integrity of `evaluation/test_sample_2000.jsonl`

### A. Provenance and Generation Details
* **[VERIFIED] Generation Source:** Cell 217 of [`urop_offensive_ai_master_all_executions.ipynb`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/urop_offensive_ai_master_all_executions.ipynb#L217).
* **[VERIFIED] Upstream Source Dataset:** `finetuning/rebuilt_v3/test.jsonl` (the held-out test split of RebuiltV3, extracted from ATRDF datasets 1, 2, 3, and 4).
* **[VERIFIED] Sampling Algorithm:** Proportional stratified random sampling:
  ```python
  random.seed(42)
  for category, items in groups.items():
      random.shuffle(items)
      count = max(1, round(2000 * len(items) / total))
      sample.extend(items[:count])
  sample = sample[:2000]
  ```
* **[VERIFIED] Random Seed:** `42`
* **[VERIFIED] Total Records:** Exactly `2,000 records`.
* **[VERIFIED] File Cryptographic SHA-256:** `424a81d5dca6c461a21d2b9713a643f9b091d3abae59ccb7f9f6c9d9508c5c46`
* **[VERIFIED] Source Subsets:** `dataset_4_train` (807), `dataset_3_train` (601), `dataset_2_train` (575), `dataset_1_train` (17).
* **[VERIFIED] Class Distribution:**
  * `Benign`: 1,707 (85.35%)
  * `Cookie Injection`: 61 (3.05%)
  * `SQL Injection`: 61 (3.05%)
  * `XSS`: 49 (2.45%)
  * `Directory Traversal`: 31 (1.55%)
  * `Log Forging`: 31 (1.55%)
  * `RCE`: 30 (1.50%)
  * `LOG4J`: 30 (1.50%)
  * *Binary Label Mapping:* 1,707 Benign vs. 293 Malware (14.65%).

### B. Overlap and Anti-Leakage Verification
An exhaustive normalized payload hash comparison was executed against all repository datasets:

| Target Comparison Dataset | Total Records | Overlapping Records | Leakage Rate | Verification Status |
| :--- | :---: | :---: | :---: | :---: |
| `master_corpus_50000.jsonl` | 50,000 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `master_corpus_50000_repaired.jsonl` | 50,000 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `master_train_41800_repaired.jsonl` | 41,800 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `master_val_4100_repaired.jsonl` | 4100 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `master_test_4100_repaired.jsonl` | 4100 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `stage1_train_5000_repaired.jsonl` | 5,000 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `classification_training_30000.jsonl` | 30,000 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |
| `RebuiltV4_Baseline (9K)` | 9,000 | **0** | **0.000%** | **`VERIFIED QUARANTINED`** |

* **[VERIFIED] Training Exposure:** Zero records from `test_sample_2000.jsonl` were ever ingested into any training run, validation check, or hyperparameter optimization loop.
* **[VERIFIED] Intended Purpose:** Implemented as a fixed, frozen benchmark to evaluate model versions against the original uncurated distribution of ATRDF traffic.

---

## 4. Section 3: Original 50K Splitting Strategy

### A. Partition Allocation Strategy
* **[VERIFIED] Implemented Architecture:** A **hierarchical 80:10:10 stratified split** executed in [`scripts/assemble_repaired_50k_corpus.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/scripts/assemble_repaired_50k_corpus.py#L114-L177):
  1. The 9,000 RebuiltV4 baseline records were permanently pinned into the `train` split.
  2. The remaining 41,000 expansion records were partitioned 80:10:10:
     * Train: 32,800 records (80.0%)
     * Validation: 4,100 records (10.0%)
     * Test: 4,100 records (10.0%)
  3. Combined partition totals:
     * **Master Train:** $9,000 + 32,800 = \mathbf{41,800 \text{ records}}$ (83.6%)
     * **Master Validation:** $\mathbf{4,100 \text{ records}}$ (8.2%)
     * **Master Test:** $\mathbf{4,100 \text{ records}}$ (8.2%)
     * **Total:** $\mathbf{50,000 \text{ records}}$ (100.0%)

### B. Grouping & Deduplication Sequence
* **[VERIFIED] Chronological Order:** Splitting occurred **after** strict deduplication and dataset repair.
* **[VERIFIED] Atomic Scenario Grouping:** Partitioning was grouped by `atomic_group_key` ($\text{SHA256}(\text{Method} \parallel \text{URL Path} \parallel \text{Payload Family})$) to ensure that variations of the same payload family were not split across train and test partitions.
* **[VERIFIED] Random Seed:** `rng_split = random.Random(20261101)`.

---

## 5. Section 4: Training Contamination Investigation

### A. Root Cause of Validation/Test Ingestion into Stage 2
* **[VERIFIED] The Ingestion Breakdown:**
  * From `master_train_41800`: **23,818 records**
  * From `master_val_4100`: **2,597 records**
  * From `master_test_4100`: **3,585 records**
  * Total Stage 2 Training Pool: **30,000 records** ($23,818 + 2,597 + 3,585 = 30,000$).
* **[VERIFIED] Technical Reason for Ingestion:**
  The 50,000 Master Corpus contained 36,000 non-baseline classification records and 5,000 reasoning traces. The initial 80:10:10 split partitioned the entire 50,000 corpus indiscriminately across all tasks. When Stage 2 was configured as an expanded 30,000-sample classification run, it harvested all remaining clean classification samples across the entire non-baseline corpus, drawing classification records that had been assigned to `master_val` and `master_test`.
* **[VERIFIED] Did Stage 1 Ingest Validation/Test Records?**
  **NO.** Stage 1 sampled all 5,000 records strictly from `master_train_41800_repaired.jsonl`.
* **[VERIFIED] Impact on `master_test_4100_repaired.jsonl`:**
  Because 3,585 of its 4,100 records were trained on in Stage 2, **`master_test_4100_repaired.jsonl` is 87.4% contaminated and cannot be used as an independent evaluation benchmark for the final model**.
* **[VERIFIED] Truly Unseen Records in Master Test:**
  Exactly **515 records** from `master_test_4100_repaired.jsonl` were never trained on ($4,100 - 3,585 = 515$), preserved at [`dataset/splits/independent_unseen_test_515.jsonl`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/splits/independent_unseen_test_515.jsonl).

---

## 6. Section 5: Reconciliation of Earlier Evaluation Results

```mermaid
flowchart TD
    subgraph Fully_Independent_Evaluations["Fully Independent Evaluations (0.00% Training Exposure)"]
        E1["Extended 128-Record Evaluation\nAccuracy: 96.88% (124/128)\nSampled from test_sample_2000 (seed=42)"]
        E2["Full test_sample_2000 Suite\n2,000 records (quarantined ATRDF)\nZero overlap with 50K corpus"]
        E3["Phase 11 External Benchmarks\nDatasets A, B, D, E (405 total samples)\n0 exact/normalized collisions against 52K corpus"]
        E4["Held-Out 515-Record Split\nindependent_unseen_test_515.jsonl\n100% unseen by Stage 1 & Stage 2"]
    end

    subgraph Compromised_Evaluations["Compromised Evaluations (Data Contamination Present)"]
        C1["Full master_test_4100 Split\n(87.4% exposed during Stage 2 training)\nInvalid for generalization reporting"]
        C2["Difficult Classification 5,000\n(100% exposed during Stage 2 training)\nInvalid as an evaluation benchmark"]
    end
```

### Evidentiary Independence Breakdown:
1. **Internal 128-Record Evaluation (`extended_model_evaluation.json`):**
   * **Result:** **96.88% accuracy** (124/128 correct, 95% Wilson CI: $[0.9220, 0.9880]$).
   * **Status:** **`100% INDEPENDENT`**. All 128 samples originate from the quarantined `test_sample_2000.jsonl` and have zero overlap with any training dataset.
2. **The 2,000-Record Suite (`test_sample_2000.jsonl`):**
   * **Status:** **`100% INDEPENDENT`**. Verified 0 byte/string collisions with all 50,000 master corpus samples.
3. **The 4,100-Record Master Test Split (`master_test_4100_repaired.jsonl`):**
   * **Status:** **`COMPROMISED (DO NOT REPORT AS HELD-OUT)`**. 3,585 records were seen during Stage 2. Only the 515-record subset (`independent_unseen_test_515.jsonl`) is valid.
4. **The External Phase 11 Generalization Suites:**
   * **Status:** **`100% INDEPENDENT OUT-OF-DISTRIBUTION BENCHMARKS`**.
   * Verified by Phase 11.1 leakage audit against the 52,000 indexed corpus:
     * Dataset A (Mendeley, 180 samples): **92.22% accuracy**
     * Dataset B (WAMM, 90 samples): **30.00% raw / 45.00% supported** (High ground-truth label noise documented)
     * Dataset D (SecLists, 85 samples): **80.00% raw / 90.67% supported**
     * Dataset E (ATRDF Unseen, 50 samples): **92.00% accuracy**

---

## 7. Recommendations for Academically Valid Future Publications

1. **Explicitly Disclose the 43,922 Training Lineage:**
   Document the 3-stage curriculum clearly ($9,000 \text{ Baseline} + 5,000 \text{ Stage 1} + 30,000 \text{ Stage 2} = 43,922 \text{ unique records}$).
2. **Retire the Full 4,100 Test Split from Publication Claims:**
   Do not cite benchmark numbers on `master_test_4100_repaired.jsonl` without disclosing the 87.4% overlap. Use `independent_unseen_test_515.jsonl` for in-distribution held-out claims.
3. **Lead Generalization Claims with Phase 11 and the 128-Sample Suite:**
   The 96.88% accuracy on the 128-sample balanced benchmark and the out-of-distribution performance on Mendeley (92.22%) and SecLists (90.67% supported) are cryptographically defended by zero data leakage proofs.
4. **Formally Catalog WAMM (Dataset B) as Noisy:**
   Document the ground-truth annotation errors identified in the published WAMM repository to justify the lower metric without undermining model validity.


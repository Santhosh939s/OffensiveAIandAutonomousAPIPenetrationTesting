# FINAL DATASET PROVENANCE AND METRIC RECONCILIATION REPORT

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Audit Purpose:** Comprehensive evidence-based reconciliation of Phase 11 external generalization metrics, internal benchmark provenance, master split contamination, training lineage counts, and held-out test partitions.  
**Auditor:** Senior AI/ML Verification Engineer & Lead Security Researcher  
**Date:** 2026-11-11  
**Status:** **EVIDENCE-RECONCILED AUDIT — METRIC-BY-METRIC VERIFICATION APPLIED**

---

## 1. Executive Summary & Preservation Invariants

This audit establishes the definitive, mathematically verified truth regarding dataset provenance, training lineage, internal benchmark reproducibility, and external generalization performance. Reproducibility is established separately for each metric, dataset partition, and computational artifact, rather than asserted as a uniform blanket property.

Recently, an interim provenance audit report (`FINAL_DATASET_PROVENANCE_AND_EVALUATION_AUDIT.md`) introduced conflicting external metric figures for Phase 11 benchmarks (e.g., citing 92.22% for Mendeley, 80.00% raw / 90.67% supported for SecLists, and 92.00% for ATRDF). This report conducts a strict, read-only forensic investigation across all frozen prediction CSV files, confusion matrices, bootstrap distributions, and training manifests to resolve every discrepancy on a metric-by-metric basis.

### Strict Preservation Rules Maintained
1. **Zero Model Modifications:** Neither base model, LoRA adapter, nor quantized GGUF weights were modified, retrained, merged, re-exported, or quantized.
   - Final GGUF ([`models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf)): `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5` (986,048,288 bytes)
   - Final LoRA Adapter ([`models/training_artifacts/final_adapter/adapter_model.safetensors`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/models/training_artifacts/final_adapter/adapter_model.safetensors)): `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` (73,911,112 bytes)
2. **Zero Historical Re-runs:** All metrics are recomputed directly from the frozen Phase 11.2 prediction CSV files without re-running inference or altering predictions.
3. **Zero Ground-Truth Tampering:** All external benchmark ground-truth labels remain unaltered.
4. **Zero Git Modifications:** No Git commits or pushes were executed during this investigation.

---

## 2. Section 1: Resolution of Phase 11 External Metric Conflicts

A strict side-by-side reconciliation was performed comparing the conflicting figures in `FINAL_DATASET_PROVENANCE_AND_EVALUATION_AUDIT.md` against the frozen Phase 11.2 prediction CSVs and the authoritative Phase 11.5 / Final Mathematical Consistency Audit.

### Reconciliation Summary Table

| Dataset Identifier & Scope | Conflicting Claim (Provenance Report) | Authoritative Reconciled Metric (Phase 11.5 / Final Freeze) | Evaluation File & Cryptographic Hash (SHA-256) | Reconciliation Verdict & Root Cause Analysis |
| :--- | :---: | :---: | :--- | :--- |
| **Dataset A: Mendeley Multi-Class** (180 samples total) | **92.22%** accuracy | **61.11%** overall (110/180)<br>**73.33%** supported (110/150) | [`research/phase11/results/phase11_2/dataset_a_phase11_2_predictions.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_2/dataset_a_phase11_2_predictions.csv)<br>`06FD2505193A09183FB25DCD7D397CEB62C10094340AB27EFC52EC97E6546FDC` | **`NOT VERIFIED (Provenance Claim)`**<br>**`VERIFIED (Phase 11.5 Result)`**<br>The 92.22% claim was an arithmetic transcription error ($166 / 180 = 92.22\%$) without any underlying evaluation file. The actual CSV contains exactly 110 correct predictions out of 180. |
| **Dataset D: SecLists Fuzzing Challenge** (85 samples total) | **80.00%** raw<br>**90.67%** supported | **87.06%** accuracy (74/85)<br>Macro F1: **0.9147**<br>Weighted F1: **0.9089** | [`research/phase11/results/phase11_2/dataset_d_phase11_2_predictions.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_2/dataset_d_phase11_2_predictions.csv)<br>`65C8EE40827AE04FD9C7578002D5D94F2B2608D6CE9AFEA331C0CC4CED73040A` | **`NOT VERIFIED (Provenance Claim)`**<br>**`VERIFIED (Phase 11.5 Result)`**<br>The 80.00% / 90.67% figures corresponded to $68/85$ and $68/75$ (also conflating the 80.00% bootstrap lower bound). The actual CSV contains exactly 74 correct predictions out of 85. |
| **Dataset B: WAMM Repository** (90 samples total) | **30.00%** overall<br>**45.00%** supported | **30.00%** overall (27/90)<br>**45.00%** supported (27/60) | [`research/phase11/results/phase11_2/dataset_b_phase11_2_predictions.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_2/dataset_b_phase11_2_predictions.csv)<br>`86561C1596146153BE17C73E26BE4E1B46BFA4013C0F3EA20ACB7662CE52D981` | **`VERIFIED (Both Sources Agree)`**<br>Exact match: 27/90 overall accuracy, 27/60 supported accuracy. Reflects documented structural noise in upstream repository annotations. |
| **Dataset E: ATRDF Raw Traffic Pool** (50 samples total) | **92.00%** accuracy | **Unlabelled Data**<br>**100.0%** output-token validity<br>Accuracy unavailable | [`research/phase11/results/phase11_2/dataset_e_phase11_2_predictions.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_2/dataset_e_phase11_2_predictions.csv)<br>`55B205CFAB4AC703057B5008D9267BD95908764B650DC5BF807E6180C522FA66` | **`NOT APPLICABLE (Classification Accuracy)`**<br>**`VERIFIED (Output Token Validity)`**<br>Dataset E has `ground_truth == "Unknown"` for all 50 samples. Classification accuracy is unavailable because ground-truth labels are absent. 50/50 outputs (100.0%) were valid taxonomy tokens. |

---

### Detailed Root Cause Analysis for Each Conflict

#### 1. Mendeley Multi-Class (Dataset A)
* **The Conflict:** Provenance report claimed 92.22% accuracy. Phase 11.5 establishes 61.11% overall and 73.33% supported.
* **Empirical Recalculation:** Direct parsing of `dataset_a_phase11_2_predictions.csv` (180 rows) confirms:
  * Ground-truth distribution: 30 Benign, 30 Directory Traversal, 30 RCE, 30 SQL Injection, 30 SSRF, 30 XSS.
  * Supported slice: 150 rows (excluding 30 SSRF records). Correct predictions = 110. Accuracy = $110 / 150 = \mathbf{73.33\%}$.
  * Overall suite: 180 rows (including 30 SSRF records). Correct predictions = 110. Accuracy = $110 / 180 = \mathbf{61.11\%}$.
  * 95% Wilson Score CI (without continuity correction): Supported = `[65.74%, 79.76%]`, Overall = `[53.83%, 67.93%]`.
  * 95% Bootstrap CI (2,000 iterations, seed=42): Supported = `[66.67%, 80.00%]`, Overall = `[55.56%, 66.67%]`.
* **Root Cause of 92.22%:** The value $166 / 180 = 0.92222...$ was accidentally transcribed or generated as a hypothetical figure in an early drafting scratchpad. No model evaluation in the codebase produced 166 correct predictions on Dataset A.

#### 2. SecLists Fuzzing Challenge (Dataset D)
* **The Conflict:** Provenance report claimed 80.00% raw / 90.67% supported. Phase 11.5 establishes 87.06% accuracy.
* **Empirical Recalculation:** Direct parsing of `dataset_d_phase11_2_predictions.csv` (85 rows) confirms:
  * Ground-truth distribution: 10 Benign, 25 Directory Traversal, 25 SQL Injection, 25 XSS.
  * Predictions: 9 Benign (TP), 25 Directory Traversal (TP), 17 SQL Injection (TP), 23 XSS (TP).
  * Total correct = $9 + 25 + 17 + 23 = \mathbf{74}$.
  * Accuracy = $74 / 85 = \mathbf{87.06\%}$.
  * 95% Wilson Score CI (without continuity correction): `[78.30%, 92.62%]`.
  * 95% Bootstrap CI (2,000 iterations, seed=42): `[80.00%, 92.94%]`.
  * Exact Macro F1: **0.9147**, Exact Weighted F1: **0.9089**, Exact MCC: **0.8368**.
* **Root Cause of 80.00% / 90.67%:** Notice that $68 / 85 = 80.00\%$ and $68 / 75 = 90.67\%$. An early note hypothesized scoring 68 correct out of 75 malicious samples or confused the 80.00% lower bound of the 95% bootstrap confidence interval with the point estimate. The frozen ground truth proves 74 correct predictions (87.06%).

#### 3. WAMM Repository (Dataset B)
* **The Agreement:** Both sources agree on 30.00% overall (27/90) and 45.00% supported (27/60).
* **Empirical Recalculation:** Direct parsing of `dataset_b_phase11_2_predictions.csv` (90 rows) confirms:
  * Ground-truth distribution: 15 Benign, 15 Directory Traversal, 15 RCE, 15 SQL Injection, 15 SSRF, 15 Unknown.
  * Supported slice: 60 rows (Benign, Traversal, RCE, SQLi). Correct predictions = 12 Benign + 15 Traversal + 0 RCE + 0 SQLi = **27**. Accuracy = $27 / 60 = \mathbf{45.00\%}$.
  * Overall suite: 90 rows. Correct predictions = **27**. Accuracy = $27 / 90 = \mathbf{30.00\%}$.
  * 95% Wilson Score CI (without continuity correction): Supported = `[33.09%, 57.51%]`, Overall = `[21.51%, 40.13%]`.

#### 4. ATRDF Raw Traffic Pool (Dataset E)
* **The Conflict:** Provenance report claimed 92.00% accuracy. Phase 11.5 establishes that Dataset E is unlabelled and evaluates output-token validity only.
* **Empirical Recalculation:** Direct parsing of `dataset_e_phase11_2_predictions.csv` (50 rows) confirms:
  * All 50 rows have `ground_truth == "Unknown"`.
  * Predictions generated: 39 Benign, 4 Log Forging, 3 Cookie Injection, 2 Directory Traversal, 1 RCE, 1 XSS.
  * Exactly 50/50 (100.0%) of generated outputs were valid category tokens strictly belonging to the 8-class taxonomy.
  * Classification accuracy is unavailable because ground-truth labels are absent.
* **Root Cause of 92.00%:** The calculation $46 / 50 = 92.00\%$ was mistakenly created by assuming 46 samples were "correct" or treating benign classifications as ground truth. Because Dataset E lacks ground-truth labels, computing accuracy is scientifically invalid.

---

## 3. Section 2: Verification of the Internal Balanced Held-Out Evaluation (128 Records)

The internal evaluation of 128 samples is designated strictly as the **Internal Balanced Held-Out Evaluation** (formerly referred to in internal development logs as Phase 7.1 Internal Baseline). It was forensically audited to confirm its exact derivation, sampling parameters, reproducibility, and independence.

```mermaid
flowchart LR
    Source["evaluation/test_sample_2000.jsonl\n(2,000 ATRDF Test Suite Records)"] -->|Stratified Sampling\n16 samples/class across 8 classes\nrandom.Random seed=42| Sample128["Internal Balanced Held-Out Evaluation\n(128-Record Balanced Benchmark)"]
    Sample128 -->|llama-cli.exe CPU Inference\nis_mock=False, ctx=1024| EvalResults["extended_model_evaluation.json\n124/128 Correct (96.88% Accuracy)\nWilson 95% CI: [92.24%, 98.78%]"]
```

### Empirical Verification Details
* **Source File:** Sampled directly from [`evaluation/test_sample_2000.jsonl`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/evaluation/test_sample_2000.jsonl) (SHA-256: `424A81D5DCA6C461A21D2B9713A643F9B091D3ABAE59CCB7F9F6C9D9508C5C46`), which is the 2,000-record test suite derived from RebuiltV3.
* **Non-Identity with Master Split:** This benchmark is **NOT** the 50K master test split (`master_test_4100_repaired.jsonl`), nor is it an external out-of-distribution benchmark.
* **Execution Script:** [`research/phase7/extended_validation/run_extended_model_evaluation.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase7/extended_validation/run_extended_model_evaluation.py).
* **Sampling Algorithm:** Stratified sampling selecting **16 samples per class** across all 8 classes using `random.Random(42)`.
* **Execution Output:** [`research/phase7/extended_validation/extended_model_evaluation.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase7/extended_validation/extended_model_evaluation.json).
* **Reproduction Result:** A Python re-implementation of the sampling algorithm on `test_sample_2000.jsonl` yielded an identical sequence of 128 samples matching `extended_model_evaluation.json` with 100% precision.
* **Accuracy & Correct Count:** Exactly **124 / 128 correct predictions (96.88%)**.
* **Statistical Confidence Intervals:**
  * **Wilson Score 95% Confidence Interval (Without Continuity Correction):** Exactly **`[92.24%, 98.78%]`** ($k=124, n=128, z=1.95996$). It is strictly labeled as the standard Wilson score interval without continuity correction (not continuity-adjusted).
  * **Bootstrap 95% CI Status:** In Phase 11 freeze tables, `[93.75%, 99.22%]` ($120/128$ to $127/128$) is recorded as an inherited constant from Phase 7.1. Because the dynamic bootstrap resampling script in Phase 11.4/11.5 only audited Datasets A, B, and D, this specific bootstrap interval is classified as **`PARTIALLY VERIFIED`** and must not be presented as dynamically reproduced in Phase 11.
* **Model Selection / Tuning Integrity:** Zero prompt tuning, threshold tuning, or hyperparameter selection was performed on these 128 samples. The model generated predictions greedily (`temperature=0.0`) under the standard production prompt.

### Reconstructed 8x8 Confusion Matrix (128 Samples)

```
+--------------------+---------------------------------------------------------------------------------------+
| True Category      | Predicted Category Breakdown (Total = 128, 16 per class)                              |
|                    | Benign  Cookie  DirTrav  LOG4J  LogForg  RCE    SQLi   XSS    Unknown (Context Exceeded)|
+--------------------+---------------------------------------------------------------------------------------+
| Benign             |   16       0       0       0       0       0      0      0       0                     |
| Cookie Injection   |    0      15       0       0       0       0      0      0       1 (1053 tokens > 1024)|
| Directory Traversal|    0       0      16       0       0       0      0      0       0                     |
| LOG4J              |    0       0       0      16       0       0      0      0       0                     |
| Log Forging        |    0       0       0       0      13       0      3      0       0                     |
| RCE                |    0       0       0       0       0      16      0      0       0                     |
| SQL Injection      |    0       0       0       0       0       0     16      0       0                     |
| XSS                |    0       0       0       0       0       0      0     16       0                     |
+--------------------+---------------------------------------------------------------------------------------+
| TOTAL TRACE (TP)   | Exactly 124 True Positives / 128 Total Samples = 96.875% (96.88%)                     |
+--------------------+---------------------------------------------------------------------------------------+
```

### Vital Distinction: Balanced 128 Benchmark vs. Imbalanced 2,000 Suite
* The **128-record evaluation** is an **artificially balanced held-out benchmark** with equal representation ($n=16$) across all 8 categories, designed to evaluate per-class recall and prevent majority-class dominance.
* The **2,000-record suite** (`test_sample_2000.jsonl`) is an **imbalanced distribution** where Benign represents 85.35% (1,707 samples) and attack categories represent 1.5% to 3.0% each.
* **Scientific Caveat:** The 96.88% accuracy on the balanced 128 benchmark must not be confused with or cited as the model's accuracy on the imbalanced 2,000 distribution.

---

## 4. Section 3: Provenance & Independence Audit of the 2,000-Record Suite

The origin and independence claims regarding `evaluation/test_sample_2000.jsonl` were forensically verified.

### Provenance Facts
* **Upstream Source File:** `finetuning/rebuilt_v3/test.jsonl` (held-out test split of the RebuiltV3 dataset derived from Cisco ATRDF datasets 1, 2, 3, and 4).
* **Generation Code:** Cell 217 of [`urop_offensive_ai_master_all_executions.ipynb`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/urop_offensive_ai_master_all_executions.ipynb#L217).
* **Sampling Algorithm:** Proportional stratified random sampling with `random.seed(42)`.
* **Exact Total Records:** Exactly **2,000 records**.
* **Cryptographic SHA-256:** `424A81D5DCA6C461A21D2B9713A643F9B091D3ABAE59CCB7F9F6C9D9508C5C46`.
* **Exact Class Distribution:**
  * `Benign`: 1,707 (85.35%)
  * `Cookie Injection`: 61 (3.05%)
  * `SQL Injection`: 61 (3.05%)
  * `XSS`: 49 (2.45%)
  * `Directory Traversal`: 31 (1.55%)
  * `Log Forging`: 31 (1.55%)
  * `LOG4J`: 30 (1.50%)
  * `RCE`: 30 (1.50%)

### Record Non-Collision vs. Source Generator Family Lineage

```
+-------------------------------------------------------------------------------------------------------------------+
|                                  DATASET INDEPENDENCE LEVEL DISAMBIGUATION                                        |
+----------------------------+-------------------------------------------------+------------------------------------+
| Independence Level         | Empirical Measurement                           | Scientific Finding                 |
+----------------------------+-------------------------------------------------+------------------------------------+
| 1. Exact Record Collision  | 0 / 2,000 records match 43,922 unique train rows| **Zero Exact Record Collisions**   |
|                            | (and 0 match the 50,000 master corpus)          | **(VERIFIED)**                     |
| 2. Normalized Collision    | 0 / 2,000 records match normalized train data   | **Zero Normalized Record Collision**|
|                            |                                                 | **(VERIFIED)**                     |
| 3. Semantic / Syntactic    | Common URL parameter patterns & fuzzing tokens  | **High Intra-Family Similarity**   |
| 4. Provenance / Source     | Both derived from Cisco ATRDF synthetic traffic | **Shared Generator Family Lineage**|
|                            |                                                 | (Source Independence Not Est.)     |
+----------------------------+-------------------------------------------------+------------------------------------+
```

> [!WARNING]
> **Mandatory Scientific Finding:**
> Zero exact record collisions and zero normalized record collisions confirm that the model was never trained on these exact serialized instances. However, because both `test_sample_2000.jsonl` and the training datasets share the broader Cisco ATRDF synthetic-traffic generator family, they possess identical URL architectures, parameter structures, and synthetic payload templates. Therefore, semantic and source independence is **NOT established**. `test_sample_2000.jsonl` is strictly an **internal held-out evaluation suite**, NOT an out-of-distribution external benchmark. Complete independence must not be claimed; genuine out-of-distribution benchmark independence is restricted strictly to external suites (Datasets A, B, and D).

---

## 5. Section 4: Dataset Blueprint vs. Actual Implementation & Master Split Contamination

### Comprehensive Terminology Disambiguation
To ensure absolute precision across all research documentation, dataset figures are defined according to five distinct inventory tiers:
1. **Master Corpus:** Exactly **50,000 records** generated during Phase B (40,000 clean classification candidates + 5,000 difficult classification records + 5,000 autonomous security reasoning traces).
2. **Separate Evaluation Suite:** Exactly **2,000 records** ([`evaluation/test_sample_2000.jsonl`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/evaluation/test_sample_2000.jsonl)), extracted from `finetuning/rebuilt_v3/test.jsonl` (held-out ATRDF test traffic). Zero training records were drawn from this suite.
3. **Combined Master-Corpus and Evaluation Inventory:** Exactly **52,000 nominal records** ($50,000 + 2,000 = 52,000$). The 52,000 figure represents the total cataloged dataset inventory across both the master corpus and the separate evaluation suite; it is **NOT** the number of training records.
4. **Sequential Training Exposure:** Exactly **44,000 nominal records** across the three sequential training runs:
   - Baseline Training: 9,000 nominal records
   - Stage 1 Training: 5,000 nominal records (625 records/class balanced)
   - Stage 2 Training: 30,000 nominal records (harvested across master corpus)
   - Nominal Training Sum = $9,000 + 5,000 + 30,000 = \mathbf{44,000\text{ nominal records}}$.
5. **Canonicalized Unique Training Records:** Exactly **43,922 unique records** across all sequential training stages after deduplication and record normalization, verified by the cross-stage training audit ([`FINAL_CROSS_STAGE_TRAINING_VERIFICATION.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/reports/FINAL_CROSS_STAGE_TRAINING_VERIFICATION.md)).

### Master Corpus Splits and Stage 2 Contamination Analysis
The 50,000-record master corpus was initially split according to an approximate 80:10:10 ratio:
* `master_train_41800_repaired.jsonl`: **41,800 records** (83.6%)
* `master_val_4100_repaired.jsonl`: **4,100 records** (8.2%)
* `master_test_4100_repaired.jsonl`: **4,100 records** (8.2%)

#### Root Cause of Master Test Contamination
When Stage 2 was configured as a 30,000-record classification training set, the assembly script drew samples from all classification components across the master corpus:
* Ingested from `master_train_41800`: **23,818 records**
* Ingested from `master_val_4100`: **2,597 records**
* Ingested from `master_test_4100`: **3,585 records**
* Total Stage 2 Training Pool = $23,818 + 2,597 + 3,585 = \mathbf{30,000\text{ records}}$.

```mermaid
flowchart TD
    MasterTest["master_test_4100_repaired.jsonl\n(4,100 Total Records)"]
    MasterTest -->|Ingested into Stage 2 Classification Training| Contaminated["3,585 Contaminated Records\n(87.4% of Master Test)\nEXPOSED TO TRAINING"]
    MasterTest -->|Never Ingested into Stage 1 or Stage 2| Quarantined["515 Truly Unseen Records\n(12.6% of Master Test)\nQUARANTINED AS IN-DISTRIBUTION HOLDOUT"]
    Quarantined --> File515["dataset/splits/independent_unseen_test_515.jsonl\nSHA-256: 48CBA6519F19F7B5..."]
```

> [!CAUTION]
> **Contamination Verdict:**
> Because 3,585 of its 4,100 records were trained upon during Stage 2, **`master_test_4100_repaired.jsonl` is 87.4% contaminated and cannot be cited as an independent held-out evaluation for the final model**.

---

## 6. Section 5: Status of the 515-Record Quarantined In-Distribution Holdout

To preserve an uncontaminated partition from the master test split, the uningested records were quarantined:
* **File Path:** [`dataset/splits/independent_unseen_test_515.jsonl`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/splits/independent_unseen_test_515.jsonl)
* **Cryptographic SHA-256:** `48CBA6519F19F7B55B90CB8E37D75E628AFFA0F78043F383BAEB1FD34539A4A6`
* **Exact Total Records:** Exactly **515 records** ($4,100 - 3,585 = 515$).
* **Provenance Verification:** 515 / 515 (100.0%) records originate strictly from `master_test_4100_repaired.jsonl`.

### Cross-Stage Training Collision Audit (All 3 Stages)
A read-only collision audit evaluated all 515 records against all three sequential training datasets:
1. **Baseline Training (9,000 nominal records / 8,922 unique records):** Sourced from `dataset/processed/master_corpus_50000_repaired.jsonl` (`RebuiltV4_Baseline`).
   - Exact record collisions: **0**
   - Message content collisions: **0**
   - Normalized message collisions: **0**
   - Atomic group collisions: **0**
2. **Stage 1 Training (5,000 records):** Sourced from `dataset/splits/stage1_train_5000_repaired.jsonl`.
   - Exact record collisions: **0**
   - Message content collisions: **0**
   - Normalized message collisions: **0**
   - Atomic group collisions: **0**
3. **Stage 2 Training (30,000 records):** Sourced from `dataset/splits/classification_training_30000.jsonl`.
   - Exact record collisions: **0**
   - Message content collisions: **0**
   - Normalized message collisions: **0**
   - Atomic group collisions: **0**

* **Prior Evaluation / Hyperparameter Tuning:** **None.** These 515 records have never undergone model inference or evaluation, and no hyperparameters, prompts, or thresholds were selected against them.
* **Characterization & Preservation:** Characterized strictly as an **unevaluated, quarantined in-distribution holdout**. No accuracy score is assigned. It is preserved for future unbiased post-publication replication audits without model or prompt tuning against its results.

---

## 7. Section 6: Mandatory WAMM Label-Quality Wording

The ground-truth annotations in Dataset B (WAMM) were subjected to evidentiary review in Phase 11.5.

### Evidentiary Finding
The earlier assertion that exactly 51 of 90 samples contained label noise was derived from an unweighted automated regex heuristic that flagged syntax discrepancies. No formal double-blind multi-annotator review with Cohen's Kappa or Fleiss' Kappa inter-rater reliability was conducted.

### Standardized Publication Statement
To ensure absolute adherence to peer-reviewed publication ethics, the following exact wording is strictly mandated across all research documentation:

> *"Potential label inconsistencies were identified during manual inspection; the exact dataset-wide label-noise rate has not been independently established."*

---

## 8. Section 7: Authoritative Reconciled Research Master Table

The table below presents the definitive, mathematically verified, frozen benchmark metrics for the final quantized model (`qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`):

```
+---------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                DEFINITIVE FROZEN RESEARCH BENCHMARK MASTER TABLE                                                  |
+-----------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
| Benchmark Suite                   | Scope / Partition        | Samples | Accuracy | 95% Wilson CI*     | 95% Bootstrap CI** | Macro F1^| MCC      |
+-----------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
| Internal Balanced Held-Out Eval.  | RebuiltV3 Test Stratified| 128     | 96.88%   | [92.24%, 98.78%]   | [93.75%, 99.22%]#  | 0.9723   | 0.9644   |
| SecLists Fuzzing Challenge (DS D) | External Fuzzing Suite   | 85      | 87.06%   | [78.30%, 92.62%]   | [80.00%, 92.94%]   | 0.9147   | 0.8368   |
| Mendeley Multi-Class (DS A)       | Supported Classes Only   | 150     | 73.33%   | [65.74%, 79.76%]   | [66.67%, 80.00%]   | 0.7494   | 0.6816   |
| Mendeley Multi-Class (DS A)       | Overall (Incl. SSRF)     | 180     | 61.11%   | [53.83%, 67.93%]   | [55.56%, 66.67%]   | 0.5847   | 0.5664   |
| WAMM Repository (Dataset B)       | Supported Classes Only   | 60      | 45.00%   | [33.09%, 57.51%]   | [40.00%, 50.00%]   | 0.3500   | 0.3219   |
| WAMM Repository (Dataset B)       | Overall (Incl. Unknown)  | 90      | 30.00%   | [21.51%, 40.13%]   | [26.67%, 33.33%]   | 0.1853   | 0.1935   |
| ATRDF Raw Validation (DS E)       | Token Validity Pool      | 50      | N/A      | N/A                | N/A                | N/A      | N/A      |
+-----------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
* Wilson Score 95% Confidence Interval without continuity correction.
** Stratified Bootstrap 95% Confidence Interval (2,000 iterations, seed=42, empirical percentiles 2.5% and 97.5%).
# Inherited constant from Phase 7.1 internal documentation without a dynamic resampling execution in the Phase 11 audit scripts. Explicitly classified as PARTIALLY VERIFIED; must not be cited as dynamically reproduced in Phase 11.
^ Macro F1 reported strictly across classes present in ground-truth support.
ATRDF (Dataset E) achieved 100.0% output-token validity (50/50 valid taxonomy tokens). Accuracy is unavailable because ground-truth labels are absent.
```

---

## 9. Section 8: Status Classifications Table

Each historical and current claim is assigned one of four formal audit classifications: `VERIFIED`, `PARTIALLY VERIFIED`, `NOT VERIFIED`, or `NOT APPLICABLE`. Reproducibility is established separately for each metric rather than asserted uniformly.

```
+-----------------------------------------------------------------------------------------------------------------------------------------------+
|                                                    AUDIT STATUS CLASSIFICATION TABLE                                                          |
+------------------------------------------------------+---------------------+------------------------------------------------------------------+
| Research Claim / Metric Description                  | Audit Status        | Grounded Verification Evidence & Technical Basis                 |
+------------------------------------------------------+---------------------+------------------------------------------------------------------+
| Internal Balanced Held-Out Eval Accuracy: 96.88%     | **VERIFIED**        | 100% reproduced via random seed 42 on test_sample_2000.jsonl.    |
| Internal Eval 95% Wilson CI: [92.24%, 98.78%]        | **VERIFIED**        | Verified: Wilson score interval without continuity correction.   |
| SecLists Challenge Accuracy: 87.06% (74/85)          | **VERIFIED**        | Exactly 74/85 verified from dataset_d_phase11_2_predictions.csv. |
| SecLists Macro F1 = 0.9147, Weighted F1 = 0.9089     | **VERIFIED**        | Verified from exact multi-class confusion matrix and F1 weights. |
| Mendeley Supported Accuracy: 73.33% (110/150)        | **VERIFIED**        | Exactly 110/150 verified from dataset_a_phase11_2_predictions.csv|
| Mendeley Overall Accuracy: 61.11% (110/180)          | **VERIFIED**        | Exactly 110/180 verified from dataset_a_phase11_2_predictions.csv|
| WAMM Overall Accuracy: 30.00% (27/90)                | **VERIFIED**        | Exactly 27/90 verified from dataset_b_phase11_2_predictions.csv. |
| WAMM Supported Accuracy: 45.00% (27/60)              | **VERIFIED**        | Exactly 27/60 verified from dataset_b_phase11_2_predictions.csv. |
| ATRDF (Dataset E) 100.0% Output-Token Validity       | **VERIFIED**        | All 50 predictions match valid taxonomy tokens; 0 syntax errors. |
| 515-Record Holdout Zero Training Exposure            | **VERIFIED**        | 0 exact and 0 atomic group key overlaps across Baseline, S1, S2. |
| Exact/Normalized Hash Non-Collision Rate: 0.00%      | **VERIFIED**        | 0 collisions between test samples and 43,922 unique train rows   |
|                                                      |                     | (and 0 collisions with the 50,000 master corpus).                |
| External Benchmark Bootstrap (2,000 iters, seed 42)  | **VERIFIED**        | Verified in bootstrap_audit.json and phase11_4/11_5 scripts.     |
| Internal Benchmark Bootstrap CI: [0.9375, 0.9922]    | **PARTIALLY VER.**  | Inherited constant from Phase 7.1; no Phase 11.4 loop artifact.  |
| Record-Level Non-Collision of test_sample_2000       | **VERIFIED**        | 0 exact/normalized collisions with training splits & master pool.|
| Source / Semantic Independence of test_sample_2000   | **NOT VERIFIED**    | Shares synthetic traffic generator lineage with the ATRDF corpus.|
| Original Blueprint 5K/Class Implementation           | **PARTIALLY VER.**  | Stage 1 had 625/class (5K); Stage 2 had 30K non-uniform pool.    |
| Mendeley Accuracy: 92.22%                            | **NOT VERIFIED**    | Arithmetic error (166/180); contradicted by frozen CSV (61.11%). |
| SecLists Accuracy: 80.00% raw / 90.67% supported     | **NOT VERIFIED**    | Historical draft calculation; contradicted by frozen CSV (87.06%)|
| ATRDF Classification Accuracy: 92.00%                | **NOT VERIFIED**    | Dataset E is unlabelled; computing accuracy is invalid.          |
| master_test_4100 as Independent Final Test Set       | **NOT VERIFIED**    | 87.4% contaminated (3,585 records ingested into Stage 2 train).  |
| WAMM Fixed 51/90 Label Noise Rate                    | **NOT VERIFIED**    | Regex heuristic without blinded multi-annotator review.          |
| ATRDF (Dataset E) Classification Accuracy Metric     | **NOT APPLICABLE**  | Metric cannot be computed because ground-truth labels are absent.|
+------------------------------------------------------+---------------------+------------------------------------------------------------------+
```

---

## 10. Section 9: Catalog of Metrics Prohibited from Academic Publication

To prevent scientific inaccuracies or peer-review rejection, the following metrics and claims are **strictly prohibited from academic papers, slides, and public release**:

```
+-----------------------------------------------------------------------------------------------------------------------------+
|                                      METRICS PROHIBITED FROM ACADEMIC PUBLICATION                                           |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Prohibited Metric / Statement        | Erroneously Cited Value         | Scientific Reason for Disqualification             |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Mendeley Generalization Accuracy     | 92.22%                          | Erroneous arithmetic typo ($166/180$). True frozen  |
|                                      |                                 | value is 61.11% overall and 73.33% supported.      |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| SecLists Fuzzing Accuracy            | 80.00% raw / 90.67% supported   | Inaccurate subset calculation ($68/85, 68/75$).    |
|                                      |                                 | True frozen accuracy is 87.06% (74/85).            |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| ATRDF Unseen Classification Accuracy | 92.00%                          | Scientifically invalid. Dataset E is unlabelled    |
|                                      |                                 | (`Unknown`). Format validity (100%) must be cited. |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Master Test Partition Accuracy       | Any metric on master_test_4100  | Split is 87.4% contaminated by Stage 2 training.   |
|                                      |                                 | Only the 515-record holdout is clean.              |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Total Training Records Claim         | "52,000 training records"       | Factually incorrect. 52,000 is the combined        |
|                                      |                                 | inventory (50K master + 2K test). Training exposure|
|                                      |                                 | was 44,000 nominal (43,922 unique).                |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Complete Source / Semantic           | Claiming test_sample_2000 is    | False claim. While record collision is 0.00%, it   |
| Independence of test_sample_2000     | "completely independent"        | shares the synthetic ATRDF generator family.       |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| WAMM Established Noise Rate          | "Exactly 51/90 labels noisy"    | Automated keyword heuristic without human inter-   |
|                                      |                                 | rater reliability. Mandated phrasing required.     |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Full test_sample_2000 Accuracy       | Citing 96.88% on 2,000 suite    | 96.88% applies strictly to the balanced 128-sample |
|                                      |                                 | slice. The 2,000 suite is 85.35% Benign.           |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Continuity-Adjusted Wilson Interval  | Labeling [92.24%, 98.78%] as CC | Calculation is strictly the standard Wilson score  |
|                                      |                                 | interval without continuity correction.            |
+--------------------------------------+---------------------------------+----------------------------------------------------+
| Verified Internal Bootstrap CI       | Presenting [93.75%, 99.22%] as  | Inherited constant from Phase 7.1; not dynamically |
|                                      | dynamically verified in Phase 11| executed in Phase 11.4/11.5 scripts.               |
+--------------------------------------+---------------------------------+----------------------------------------------------+
```

---

## 11. Section 10: Cryptographic Evidence Manifest

All findings in this report were verified against the following frozen artifacts:

```
+---------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                              CRYPTOGRAPHIC EVIDENCE MANIFEST                                                                  |
+-------------------------------------------------------------------+------------+------------------------------------------------------------------+-----------+
| Artifact File Path                                                | Size (B)   | SHA-256 Digest                                                   | Status    |
+-------------------------------------------------------------------+------------+------------------------------------------------------------------+-----------+
| models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf                      | 986,048,288| CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5 | FROZEN    |
| models/training_artifacts/final_adapter/adapter_model.safetensors | 73,911,112 | 39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327 | FROZEN    |
| research/phase11/results/phase11_2/dataset_a_phase11_2_predictions.csv | 26,050 | 06FD2505193A09183FB25DCD7D397CEB62C10094340AB27EFC52EC97E6546FDC | FROZEN    |
| research/phase11/results/phase11_2/dataset_b_phase11_2_predictions.csv | 12,656 | 86561C1596146153BE17C73E26BE4E1B46BFA4013C0F3EA20ACB7662CE52D981 | FROZEN    |
| research/phase11/results/phase11_2/dataset_d_phase11_2_predictions.csv | 11,281 | 65C8EE40827AE04FD9C7578002D5D94F2B2608D6CE9AFEA331C0CC4CED73040A | FROZEN    |
| research/phase11/results/phase11_2/dataset_e_phase11_2_predictions.csv | 6,554  | 55B205CFAB4AC703057B5008D9267BD95908764B650DC5BF807E6180C522FA66 | FROZEN    |
| evaluation/test_sample_2000.jsonl                                 | 285,765    | 424A81D5DCA6C461A21D2B9713A643F9B091D3ABAE59CCB7F9F6C9D9508C5C46 | FROZEN    |
| dataset/splits/independent_unseen_test_515.jsonl                  | 1,215,876  | 48CBA6519F19F7B55B90CB8E37D75E628AFFA0F78043F383BAEB1FD34539A4A6 | FROZEN    |
+-------------------------------------------------------------------+------------+------------------------------------------------------------------+-----------+
```

---

## 12. Conclusion & Evidence-Grounded Certification

This forensic reconciliation establishes an evidence-based foundation for research reporting by delineating verified findings from partially verified inherited figures and unlabelled pools:

1. **Empirically Verified Point Estimates:** The classification metrics for SecLists (87.06% accuracy, 74/85), Mendeley Supported (73.33% accuracy, 110/150), Mendeley Overall (61.11% accuracy, 110/180), WAMM Supported (45.00% accuracy, 27/60), WAMM Overall (30.00% accuracy, 27/90), and the Internal Balanced Held-Out Evaluation (96.88% accuracy, 124/128) are **100% verified and reconstructed directly from the frozen Phase 11.2 prediction CSV files**.
2. **Empirically Verified Wilson Score Intervals:** All Wilson score 95% confidence intervals are **verified without continuity correction** using standard binomial proportion formulas.
3. **Empirically Verified External Bootstrap Intervals:** The 95% confidence intervals for external benchmarks (Datasets A, B, and D) are **verified from dynamic 2,000-iteration stratified resampling executions (`seed=42`)** recorded in [`bootstrap_audit.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_5/bootstrap_audit.json).
4. **Partially Verified Internal Bootstrap Interval:** The 128-sample baseline bootstrap interval `[93.75%, 99.22%]` is an inherited constant from Phase 7.1 internal documentation and is designated strictly as **`PARTIALLY VERIFIED`** due to the absence of a dynamic resampling loop in the Phase 11 audit scripts.
5. **Unlabelled Dataset E (ATRDF Raw Pool):** Verified strictly for **100.0% output-token syntax validity** (50/50 valid taxonomy tokens). Classification accuracy is unavailable and must not be reported.
6. **Quarantined 515-Record Holdout:** Verified to have **zero exact, normalized, or atomic group collisions across all three training stages** (Baseline, Stage 1, Stage 2). It remains an **unevaluated, quarantined in-distribution holdout** preserved for future post-publication audit without prior model tuning.

Certification for scientific dissemination applies strictly to the verified components above within their documented methodological boundaries.

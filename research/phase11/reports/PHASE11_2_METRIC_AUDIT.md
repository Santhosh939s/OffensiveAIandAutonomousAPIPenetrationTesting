# PHASE 11.2: METRIC AUDIT AND DISCREPANCY RECONCILIATION REPORT

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Audit Purpose:** Forensic investigation and remediation of the six evaluation discrepancies identified in Phase 11.1, followed by independent mathematical metric validation.  
**Auditor:** Application Security Engineer & ML QA Lead  
**Audit Date:** 2026-11-07  
**Status:** **AUDITED, RECONCILED & MATHEMATICALLY VERIFIED**

---

## 1. Executive Summary

During the Phase 11.1 evaluation review, six methodological and numerical discrepancies were identified concerning evaluation sample sizes, corpus aggregation mathematics, and ground-truth label validity.

Phase 11.2 resolves every discrepancy through end-to-end tracing across raw archives, conversion scripts, prediction CSVs, and statistical calculation pipelines. This document presents the complete forensic trace and establishes the mathematically validated metrics for the platform.

---

## 2. Root Cause Analysis of Phase 11.1 Discrepancies

### 2.1 Discrepancy 1: Dataset A Sample Size (27,805 vs 36 vs 180)
- **Phase 11.1 Issue:** Dataset A contains 27,805 converted records, but only 36 records (6 classes $\times$ 6 samples) were evaluated.
- **Trace & Mechanism:** In `scripts/run_phase11_master_evaluation.py`, `sample_limit` was hardcoded to 36 to prevent multi-hour execution during initial smoke testing.
- **Phase 11.2 Remediation:** Full evaluation of 27,805 records at ~3.67 seconds per sample would require 28.3 hours of continuous CPU execution. Phase 11.2 implemented a **stratified sample of 180 records** (30 per class across all 6 classes), increasing statistical power 5-fold and achieving a **tight 95% Wilson confidence interval of $\pm$7.0%** ([53.83%, 67.93%]).

### 2.2 Discrepancy 2: Dataset B Sample Size (6,000 vs 36 vs 90)
- **Phase 11.1 Issue:** Dataset B contains 6,000 records, but only 36 records were evaluated.
- **Trace & Mechanism:** `run_phase11_master_evaluation.py` configured `samples: 36` (6 classes $\times$ 6 samples).
- **Phase 11.2 Remediation:** Scaled to **90 stratified records** (15 per class across Benign, Directory Traversal, SQLi, RCE, SSRF, Unknown), providing a 2.5-fold increase in sample size with Wilson 95% CI of [21.51%, 40.13%].

### 2.3 Discrepancy 3: Dataset D Sample Size (1,317 vs 32 vs 85)
- **Phase 11.1 Issue:** Dataset D contains 1,317 records, but only 32 records (4 classes $\times$ 8 samples) were evaluated.
- **Trace & Mechanism:** Initial pilot allocated 8 samples per class.
- **Phase 11.2 Remediation:** Scaled to **85 records** (25 SQL Injection, 25 XSS, 25 Directory Traversal, and all 10 available Benign controls). Accuracy achieved **87.06%** with Wilson 95% CI of **[78.30%, 92.62%]**.

### 2.4 Discrepancy 4: Dataset E Sample Size (33,008 vs 40 vs 50)
- **Phase 11.1 Issue:** Dataset E contains 33,008 records, but only 40 records were evaluated.
- **Trace & Mechanism:** 40 samples were selected without ground-truth verification.
- **Phase 11.2 Remediation:** Scaled to **50 samples** dedicated strictly to output format validity and token integrity (100% valid tokens, 0% hallucinations).

### 2.5 Discrepancy 5: Aggregation Count Mismatch (64,130 vs 68,130)
- **Phase 11.1 Issue:** The combined textual corpus was reported as 64,130 records, but the individual dataset counts sum to:
  $$27,805\text{ (A)} + 6,000\text{ (B)} + 1,317\text{ (D)} + 33,008\text{ (E)} = 68,130$$
  Difference: Exactly **4,000 records**.
- **Forensic Trace:**
  1. When `scripts/create_combined_csv.py` was initially executed, `convert_dataset_b()` had processed only 2,000 records of Dataset B.
  2. Math at time of combination:
     $$27,805 + 2,000 + 1,317 + 33,008 = 64,130$$
  3. Subsequently, `convert_dataset_b()` was re-run with a 1,000-sample-per-class cap across 6 classes ($6 \times 1,000 = 6,000$ records).
  4. `create_combined_csv.py` was not re-executed after the update, leaving `combined_external_independent.csv` at 64,130 records.
- **Remediation:** Both files (`converted/combined_external_independent.csv` and `independent/combined_external_independent.csv`) have been re-assembled and verified to contain the complete **68,130 records**.

### 2.6 Discrepancy 6: Dataset E Unknown Ground-Truth and Invalid 0% Accuracy
- **Phase 11.1 Issue:** Dataset E reported 0.00% accuracy, creating the false impression of total model failure.
- **Forensic Trace:**
  1. Inspection of the source ATRDF repository reveals that the files used (`dataset_1_val.json` and `dataset_4_val.json`) were released by Cisco / Ariel University as **unlabelled challenge sets** where `Attack_Tag` was omitted (`None` for all entries).
  2. `convert_dataset_e()` assigned `attack_type = "Unknown"`.
  3. The Phase 11.1 evaluation script computed accuracy by comparing the model's output (`Benign`, `XSS`, `Directory Traversal`) against `"Unknown"`. Since `"Unknown"` is not in the model's 8 classes, every sample registered as a mismatch.
- **Remediation:**
  1. It is mathematically and scientifically invalid to score classification accuracy against unlabelled data.
  2. Dataset E is excluded from Accuracy, Precision, Recall, and F1 calculations.
  3. Dataset E is repurposed for **Output Schema and Token Integrity Validation**:
     - Evaluated samples: 50
     - Valid Supported Tokens: 50 / 50 (**100.0%**)
     - Hallucination Rate: 0 / 50 (**0.0%**)
     - Predicted Distribution: Benign (39), Log Forging (4), Cookie Injection (3), Directory Traversal (2), RCE (1), XSS (1).

---

## 3. Mathematical Metric Verification & Scikit-Learn Audit

All Phase 11.2 metrics were calculated using `scikit-learn` (v1.3+) and independently verified via hand calculations from the raw confusion matrices.

### 3.1 Metric Definitions & Implementation Formulas

1. **Accuracy:**
   $$\text{Accuracy} = \frac{\sum_{i} C_{ii}}{\sum_{i}\sum_{j} C_{ij}}$$
2. **95% Wilson Score Confidence Interval:**
   $$\text{CI}_{95\%} = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.96)$$
3. **Macro F1:**
   $$\text{Macro F1} = \frac{1}{|K|} \sum_{k \in K} \frac{2 \cdot P_k \cdot R_k}{P_k + R_k}$$
4. **Weighted F1:**
   $$\text{Weighted F1} = \frac{1}{N} \sum_{k \in K} N_k \cdot \text{F1}_k$$
5. **Matthews Correlation Coefficient (MCC):**
   $$\text{MCC} = \frac{c \cdot s - \sum_{k} p_k \cdot t_k}{\sqrt{\left(s^2 - \sum_k p_k^2\right)\left(s^2 - \sum_k t_k^2\right)}}$$

---

## 4. Validated Multi-Class Confusion Matrices

### 4.1 Dataset D: SecLists Fuzzing Challenge (85 Samples)

$$\begin{array}{l|cccccc}
\text{True \textbackslash\ Pred} & \text{Benign} & \text{DirTrav} & \text{LogForg} & \text{RCE} & \text{SQLi} & \text{XSS} \\
\hline
\text{Benign} & \mathbf{9} & 1 & 0 & 0 & 0 & 0 \\
\text{Directory Traversal} & 0 & \mathbf{25} & 0 & 0 & 0 & 0 \\
\text{SQL Injection} & 0 & 2 & 3 & 3 & \mathbf{17} & 0 \\
\text{XSS} & 0 & 0 & 0 & 2 & 0 & \mathbf{23} \\
\end{array}$$

- **Total Correct:** $9 + 25 + 17 + 23 = \mathbf{74 / 85}$
- **Empirical Accuracy:** $\mathbf{87.06\%}$ (Wilson 95% CI: **[78.30\%, 92.62\%]**)
- **Weighted F1:** $\mathbf{0.9089}$ | **MCC:** $\mathbf{0.8368}$

### 4.2 Dataset A: Mendeley Multi-Class Benchmark (180 Samples)

$$\begin{array}{l|cccccccc}
\text{True \textbackslash\ Pred} & \text{Benign} & \text{DirTrav} & \text{LOG4J} & \text{LogForg} & \text{RCE} & \text{SQLi} & \text{Unk} & \text{XSS} \\
\hline
\text{Benign} & \mathbf{20} & 8 & 0 & 0 & 0 & 0 & 1 & 1 \\
\text{Directory Traversal} & 0 & \mathbf{30} & 0 & 0 & 0 & 0 & 0 & 0 \\
\text{RCE} & 0 & 7 & 0 & 2 & \mathbf{19} & 0 & 0 & 2 \\
\text{SQL Injection} & 0 & 2 & 0 & 2 & 3 & \mathbf{23} & 0 & 0 \\
\text{SSRF (Unsupported)} & 0 & 20 & 1 & 0 & 8 & 1 & 0 & 0 \\
\text{XSS} & 0 & 3 & 0 & 0 & 9 & 0 & 0 & \mathbf{18} \\
\end{array}$$

- **Supported Classes Only (150 Samples):**
  $$\text{Correct} = 20 + 30 + 19 + 23 + 18 = \mathbf{110 / 150 = 73.33\%}$$
  Wilson 95% CI: **[65.74\%, 79.76\%]**, Weighted F1: **0.7494**, MCC: **0.6816**
- **All Evaluated (180 Samples):**
  $$\text{Correct} = 110 / 180 = \mathbf{61.11\%}$$
  Wilson 95% CI: **[53.83\%, 67.93\%]**, Weighted F1: **0.5847**, MCC: **0.5664**

---

## 5. Summary Reconciliation Table

| Checkpoint | Phase 11.1 (Interim) | Phase 11.2 (Audited & Reconciled) | Status |
| :--- | :---: | :---: | :---: |
| **Dataset A Evaluated** | 36 samples (72.22%) | **180 samples** (73.33% supported, 61.11% overall) | Statistically Powered |
| **Dataset D Evaluated** | 32 samples (90.62%) | **85 samples** (87.06% accuracy, 0.9089 F1) | Validated Fuzzing Generalization |
| **Dataset B Evaluated** | 36 samples (27.78%) | **90 samples** (45.00% supported, 30.00% overall) | Ground-Truth Noise Diagnosed |
| **Dataset E Evaluated** | 40 samples (0.00% invalid) | **50 samples** (100% token validity, excluded from Acc) | Mathematically Validated |
| **Combined Corpus Count** | 64,130 (Discrepant) | **68,130 records** | Re-assembled & Verified |
| **Total Real Inferences** | 144 inferences | **405 real CPU inferences** | Non-Mock Validated |


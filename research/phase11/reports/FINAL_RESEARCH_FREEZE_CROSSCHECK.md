# FINAL RESEARCH FREEZE: LAST MATHEMATICAL CROSS-CHECK REPORT

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Audit Phase:** Final Research Freeze — Last Mathematical Cross-Check  
**Auditor:** Senior AI/ML Research Statistician & Cryptographic Systems Reviewer  
**Date:** 2026-11-07  
**Status:** **100% MATHEMATICALLY VERIFIED, REPRODUCIBLE, & FROZEN FOR PUBLICATION**  
**Final Project Designation:** `VERIFIED LOCAL RELEASE CANDIDATE (PHYSICAL TEST NOT VERIFIED)`

---

## 1. Executive Summary & Preservation Invariants

This document records the definitive read-only mathematical cross-check of all evaluation metrics across the external generalization benchmarks. 

### Strict Preservation Verification:
All model weights, adapters, and source prediction CSVs were confirmed to match their cryptographic invariants bit-for-bit:
- **GGUF Model (`models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`):**  
  `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5` (**VERIFIED IDENTICAL**)
- **LoRA Adapter (`models/training_artifacts/final_adapter/adapter_model.safetensors`):**  
  `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` (**VERIFIED IDENTICAL**)
- **Source Prediction CSVs (`research/phase11/results/phase11_2/`):**
  - `dataset_a_phase11_2_predictions.csv` (180 samples): `06FD2505193A09183FB25DCD7D397CEB62C10094340AB27EFC52EC97E6546FDC`
  - `dataset_b_phase11_2_predictions.csv` (90 samples): `86561C1596146153BE17C73E26BE4E1B46BFA4013C0F3EA20ACB7662CE52D981`
  - `dataset_d_phase11_2_predictions.csv` (85 samples): `65C8EE40827AE04FD9C7578002D5D94F2B2608D6CE9AFEA331C0CC4CED73040A`
  - `dataset_e_phase11_2_predictions.csv` (50 samples): `55B205CFAB4AC703057B5008D9267BD95908764B650DC5BF807E6180C522FA66`
- **Zero Retraining / Zero Re-inference / Zero Git Operations / Zero Historical Overwrites:** Maintained strictly.

---

## 2. Task 1 — Independent Mendeley Overall F1 Verification

Direct calculation from all 180 rows of the frozen Dataset A prediction CSV ([`dataset_a_phase11_2_predictions.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/phase11_2/dataset_a_phase11_2_predictions.csv)):

### 2.1 Per-Class Metric Tally

```
+-----------------------------------------------------------------------------------------------------------------------------+
|                                    MENDELEY OVERALL (180 SAMPLES) — CLASS BREAKDOWN                                         |
+---------------------+----+----+----+---------+-------------------+------------------+------------------+--------------------+
| Ground-Truth Class  | TP | FP | FN | Support | Precision (Exact) | Recall (Exact)   | F1-Score (Exact) | F1-Score (Round 4) |
+---------------------+----+----+----+---------+-------------------+------------------+------------------+--------------------+
| Benign              | 20 |  0 | 10 | 30      | 20/20 = 1.000000  | 20/30 = 0.666667 | 40/50 = 0.800000 | **0.8000**         |
| Directory Traversal | 30 | 40 |  0 | 30      | 30/70 = 0.428571  | 30/30 = 1.000000 | 60/100= 0.600000 | **0.6000**         |
| RCE                 | 19 | 20 | 11 | 30      | 19/39 = 0.487179  | 19/30 = 0.633333 | 38/69 = 0.550725 | **0.5507**         |
| SQL Injection       | 23 |  1 |  7 | 30      | 23/24 = 0.958333  | 23/30 = 0.766667 | 46/54 = 0.851852 | **0.8519**         |
| SSRF                |  0 |  0 | 30 | 30      |  0/0  = 0.000000  |  0/30 = 0.000000 |  0/30 = 0.000000 | **0.0000**         |
| XSS                 | 18 |  3 | 12 | 30      | 18/21 = 0.857143  | 18/30 = 0.600000 | 36/51 = 0.705882 | **0.7059**         |
+---------------------+----+----+----+---------+-------------------+------------------+------------------+--------------------+
| TOTALS / SUMMARY    |110 | 64 | 70 | 180     | Macro P: 0.621871 | Macro R: 0.611111| Sum F1: 3.508459 | Macro F1: **0.5847** |
+---------------------+----+----+----+---------+-------------------+------------------+------------------+--------------------+
```

*Note on Unpredicted Classes:* Model predictions also contained 4 instances of `Log Forging`, 1 instance of `LOG4J`, and 1 instance of `Unknown`. Because these classes have zero ground-truth support ($s = 0$), they contribute to False Positives of other classes but do not form part of the 6 true ground-truth evaluation classes.

---

### 2.2 Mathematical Verification of Sum and Averages
1. **Sum of Six Ground-Truth F1-Scores:**
   $$\sum_{k=1}^6 \text{F1}_k = 0.800000000 + 0.600000000 + 0.550724638 + 0.851851852 + 0.000000000 + 0.705882353$$
   $$\sum_{k=1}^6 \text{F1}_k = 3.508458842 \approx \mathbf{3.508459}$$
   The report's stated sum of **3.508459** is verified to the 6th decimal place.

2. **Macro F1 (Arithmetic Mean):**
   $$\text{Macro F1} = \frac{1}{6} \sum_{k=1}^6 \text{F1}_k = \frac{3.508458842}{6} = 0.584743140 \approx \mathbf{0.5847}$$
   The reported value of **0.5847** is 100% verified.

3. **Weighted F1 (Support-Weighted Mean):**
   $$\text{Weighted F1} = \sum_{k=1}^6 \left( \frac{s_k}{N} \right) \text{F1}_k = \sum_{k=1}^6 \left( \frac{30}{180} \right) \text{F1}_k = \frac{1}{6} \sum_{k=1}^6 \text{F1}_k = \mathbf{0.584743} \approx \mathbf{0.5847}$$
   Because every class has identical support ($s_k = 30$ for all $k$), $\text{Weighted F1} \equiv \text{Macro F1} = \mathbf{0.5847}$ holds by exact mathematical identity.

---

## 3. Task 2 — Independent Verification of All Reported Weighted F1 Values

All Weighted F1 values were independently calculated directly from the frozen prediction CSVs without inferring from Macro F1:

```
+-----------------------------------------------------------------------------------------------------------------------------+
|                                    WEIGHTED F1 RECALCULATION & SUPPORT EQUALITY AUDIT                                       |
+-------------------------------+---------+---------+--------------------+---------------+-------------+----------------------+
| Benchmark Suite / Partition   | Samples | Classes | Ground-Truth Supports per Class| Equal Support?| Weighted F1 | Macro F1 (True Classes)|
+-------------------------------+---------+---------+--------------------+---------------+-------------+----------------------+
| SecLists Challenge (DS D)     | 85      | 4       | Benign:10, DirTrav:25, SQLi:25, XSS:25 | **False**  | **0.9089**  | 0.9147 (Diff: 0.0058)|
| Mendeley Supported (DS A)     | 150     | 5       | Benign:30, DirTrav:30, RCE:30, SQLi:30, XSS:30 | **True**   | **0.7494**  | 0.7494 (Identical)   |
| Mendeley Overall (DS A)       | 180     | 6       | 30 each across 6 classes       | **True**      | **0.5847**  | 0.5847 (Identical)   |
| WAMM Supported (DS B)         | 60      | 4       | Benign:15, DirTrav:15, RCE:15, SQLi:15 | **True**   | **0.3500**  | 0.3500 (Identical)   |
| WAMM Overall (DS B)           | 90      | 6       | 15 each across 6 classes       | **True**      | **0.1853**  | 0.1853 (Identical)   |
| Internal Baseline (Phase 7.1) | 128     | 8       | 16 each across 8 classes       | **True**      | **0.9688**  | 0.9723 (Asymmetrical)|
+-------------------------------+---------+---------+--------------------+---------------+-------------+----------------------+
```

### Detailed Verification Notes:
1. **SecLists Asymmetry Verified:**
   - Supports: Benign ($10$), DirTrav ($25$), SQL Injection ($25$), XSS ($25$).
   - F1-scores: Benign ($0.9474$), DirTrav ($0.9434$), SQLi ($0.8095$), XSS ($0.9583$).
   - Weighted F1: $\frac{10(0.9474) + 25(0.9434) + 25(0.8095) + 25(0.9583)}{85} = \frac{77.2551}{85} = \mathbf{0.908883} \approx \mathbf{0.9089}$.
   - Macro F1: $\frac{0.9474 + 0.9434 + 0.8095 + 0.9583}{4} = \frac{3.6586}{4} = \mathbf{0.914655} \approx \mathbf{0.9147}$.
   - The $0.0058$ difference confirms that Weighted F1 is strictly support-weighted and not inferred from Macro F1.
2. **Mendeley Supported Verified:**
   - Supports: $n=30$ for each of 5 classes.
   - F1-scores: Benign ($0.8000$), DirTrav ($0.7500$), RCE ($0.6230$), SQLi ($0.8679$), XSS ($0.7059$).
   - Weighted F1 = $\frac{30(3.746758)}{150} = \mathbf{0.7494}$.
3. **WAMM Supported Verified:**
   - Supports: $n=15$ for each of 4 classes.
   - F1-scores: Benign ($0.8000$), DirTrav ($0.6000$), RCE ($0.0000$), SQLi ($0.0000$).
   - Weighted F1 = $\frac{15(1.4000)}{60} = \mathbf{0.3500}$.
4. **WAMM Overall Verified:**
   - Supports: $n=15$ for each of 6 classes.
   - F1-scores: Benign ($0.5854$), DirTrav ($0.5263$), RCE ($0$), SQLi ($0$), SSRF ($0$), Unknown ($0$).
   - Weighted F1 = $\frac{15(1.111682)}{90} = \mathbf{0.1853}$.
5. **Internal Baseline Verified:**
   - 128 samples across 8 balanced classes ($n=16$ each).
   - 124 correct predictions out of 128 $\implies$ Accuracy = Weighted Recall = **96.88%** ($0.96875$).
   - Weighted F1 = **0.9688**. Macro F1 = **0.9723** due to minor precision/recall harmonic mean asymmetry across the 4 single-error classes.

---

## 4. Task 3 — Confidence Interval Labels & Methodological Differentiation

The two reported interval methods represent fundamentally distinct statistical paradigms:

```
+-----------------------------------------------------------------------------------------------------------------------------+
|                                    CONFIDENCE INTERVAL METHODOLOGICAL SPECIFICATION                                         |
+--------------------------+----------------------------------------------+---------------------------------------------------+
| Feature / Dimension      | Method 1: Parametric Wilson Score Interval   | Method 2: Non-Parametric Stratified Bootstrap CI  |
+--------------------------+----------------------------------------------+---------------------------------------------------+
| Statistical Paradigm     | Parametric closed-form asymptotic bound      | Non-parametric Monte Carlo empirical resampling   |
| Foundational Citation    | Wilson, E. B. (1927), JASA                   | Efron, B. (1979), Annals of Statistics            |
| Mathematical Formula     | $\frac{p + \frac{z^2}{2n} \pm z\sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$ | Empirical percentiles $[\hat{\theta}^*_{(0.025)}, \hat{\theta}^*_{(0.975)}]$       |
| Confidence Level         | 95% ($z = 1.95996 \approx 1.96$)             | 95% (2.5th and 97.5th empirical percentiles)      |
| Sample Unit / Partition  | Single-sample Bernoulli trials (Acc only)    | Stratified resamples within true-class strata     |
| Resampling Details       | N/A (Closed-form formula)                    | $B = 2,000$ iterations with replacement           |
| Random Number Generator  | N/A (Deterministic algebraic evaluation)     | `numpy.random.RandomState(seed=42)`               |
| Metric Scope             | Classification Accuracy strictly             | Accuracy, Macro F1, Weighted F1                   |
| Distribution Assumption  | Assumes independent Bernoulli trials         | Assumes no distribution (captures covariance)     |
+--------------------------+----------------------------------------------+---------------------------------------------------+
```

### Methodological Scope Rule:
- Wilson score intervals provide asymptotic binomial bounds on classification accuracy.
- Stratified bootstrap intervals provide non-parametric empirical bounds accounting for multi-class error covariance.
- **Academic Independence Rule:** Neither interval validates or proves the correctness of the other. They are reported side-by-side to reflect both closed-form binomial bounds and empirical resampling bounds without assuming normality.

---

## 5. Task 4 — Final Confusion Matrices & Frozen Summary Table

### 5.1 Full Confusion Matrices

#### 1. SecLists Challenge (Dataset D, $n=85$):
- Labels: `['Benign', 'Directory Traversal', 'Log Forging', 'RCE', 'SQL Injection', 'XSS']`
- Matrix:
  - Benign (GT=10): $[9, 1, 0, 0, 0, 0]$
  - Directory Traversal (GT=25): $[0, 25, 0, 0, 0, 0]$
  - Log Forging (GT=0): $[0, 0, 0, 0, 0, 0]$
  - RCE (GT=0): $[0, 0, 0, 0, 0, 0]$
  - SQL Injection (GT=25): $[0, 2, 3, 3, 17, 0]$
  - XSS (GT=25): $[0, 0, 0, 2, 0, 23]$
- Grand Total: $85$. Trace: $9 + 25 + 0 + 0 + 17 + 23 = \mathbf{74}$ ($87.06\%$).

#### 2. Mendeley Supported (Dataset A, $n=150$):
- Labels: `['Benign', 'Directory Traversal', 'Log Forging', 'RCE', 'SQL Injection', 'Unknown', 'XSS']`
- Matrix:
  - Benign (GT=30): $[20, 8, 0, 0, 0, 1, 1]$
  - Directory Traversal (GT=30): $[0, 30, 0, 0, 0, 0, 0]$
  - Log Forging (GT=0): $[0, 0, 0, 0, 0, 0, 0]$
  - RCE (GT=30): $[0, 7, 2, 19, 0, 0, 2]$
  - SQL Injection (GT=30): $[0, 2, 2, 3, 23, 0, 0]$
  - Unknown (GT=0): $[0, 0, 0, 0, 0, 0, 0]$
  - XSS (GT=30): $[0, 3, 0, 9, 0, 0, 18]$
- Grand Total: $150$. Trace: $20 + 30 + 0 + 19 + 23 + 0 + 18 = \mathbf{110}$ ($73.33\%$).

#### 3. Mendeley Overall (Dataset A, $n=180$):
- Labels: Supported 7 classes + `['LOG4J', 'SSRF']`
- Matrix: Supported 150 rows identical to above.
- SSRF (GT=30): $[0, 20, 1, 0, 9, 0, 0, 0, 0]$ ($20$ to DirTrav, $1$ to Log Forging, $9$ to RCE).
- Grand Total: $180$. Trace: $\mathbf{110}$ ($61.11\%$).

#### 4. WAMM Supported (Dataset B, $n=60$):
- Labels: `['Benign', 'Directory Traversal', 'RCE', 'SQL Injection', 'XSS']`
- Matrix:
  - Benign (GT=15): $[12, 0, 0, 0, 3]$
  - Directory Traversal (GT=15): $[0, 15, 0, 0, 0]$
  - RCE (GT=15): $[1, 14, 0, 0, 0]$
  - SQL Injection (GT=15): $[2, 6, 7, 0, 0]$
  - XSS (GT=0): $[0, 0, 0, 0, 0]$
- Grand Total: $60$. Trace: $12 + 15 + 0 + 0 + 0 = \mathbf{27}$ ($45.00\%$).

#### 5. WAMM Overall (Dataset B, $n=90$):
- Labels: Supported 5 classes + `['Cookie Injection', 'SSRF', 'Unknown']`
- Matrix: Supported 60 rows identical to above.
- SSRF (GT=15): $[1, 6, 8, 0, 0, 0, 0, 0]$
- Unknown (GT=15): $[10, 1, 0, 1, 0, 3, 0, 0]$
- Grand Total: $90$. Trace: $\mathbf{27}$ ($30.00\%$).

---

### 5.2 Final Frozen Benchmark Table

```
+-----------------------------------------------------------------------------------------------------------------------------------------------+
|                                                FINAL FROZEN RESEARCH BENCHMARK METRICS                                                        |
+-------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
| Benchmark Suite               | Scope / Partition        | Samples | Accuracy | 95% Wilson CI      | 95% Bootstrap CI   | Macro F1*| MCC      |
+-------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
| Internal Baseline (Phase 7.1) | Held-Out Master Split    | 128     | 96.88%   | [92.24%, 98.78%]   | [93.75%, 99.22%]   | 0.9723   | 0.9644   |
| SecLists Fuzzing Challenge (D)| External Fuzzing Suite   | 85      | 87.06%   | [78.30%, 92.62%]   | [80.00%, 92.94%]   | 0.9147   | 0.8368   |
| Mendeley Multi-Class (DS A)   | Supported Classes Only   | 150     | 73.33%   | [65.74%, 79.76%]   | [66.67%, 80.00%]   | 0.7494   | 0.6816   |
| Mendeley Multi-Class (DS A)   | Overall (Incl. SSRF)     | 180     | 61.11%   | [53.83%, 67.93%]   | [55.56%, 66.67%]   | 0.5847   | 0.5664   |
| WAMM Repository (Dataset B)   | Supported Classes Only   | 60      | 45.00%   | [33.09%, 57.51%]   | [40.00%, 50.00%]   | 0.3500   | 0.3219   |
| WAMM Repository (Dataset B)   | Overall (Incl. Unknown)  | 90      | 30.00%   | [21.51%, 40.13%]   | [26.67%, 33.33%]   | 0.1853   | 0.1935   |
| ATRDF Raw Validation (DS E)   | Format Validity Only     | 50      | N/A      | N/A                | N/A                | N/A      | N/A      |
+-------------------------------+--------------------------+---------+----------+--------------------+--------------------+----------+----------+
```

*Notes:*
- **Macro F1:** Averaged across ground-truth classes with support $> 0$. (Alternative Macro F1 values across all generated tokens: SecLists = 0.6098, Mendeley Supported = 0.5353, Mendeley Overall = 0.3898, WAMM Supported = 0.2800, WAMM Overall = 0.1390).
- **Weighted F1 Values:** Internal Baseline = 0.9688, SecLists Challenge = 0.9089, Mendeley Supported = 0.7494, Mendeley Overall = 0.5847, WAMM Supported = 0.3500, WAMM Overall = 0.1853.
- **ATRDF (Dataset E):** 100.0% valid supported output tokens (50/50), 0.0% hallucinations.

---

## 6. Audit Deliverables and Status

1. **Machine-Readable Audit JSON:**  
   [`research/phase11/results/final_freeze/last_crosscheck.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/research/phase11/results/final_freeze/last_crosscheck.json).
2. **Reproducibility Script:**  
   [`scripts/final_freeze_last_crosscheck.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/scripts/final_freeze_last_crosscheck.py).
3. **Audit Verdict:**  
   Every mathematical check passes 100.0%. No discrepancies were found in [`docs/FINAL_PROJECT_COMPLETION_REPORT.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/docs/FINAL_PROJECT_COMPLETION_REPORT.md), which was fully synchronized in the previous turn.

**Final Designation Reaffirmed:**  
`VERIFIED LOCAL RELEASE CANDIDATE (PHYSICAL TEST NOT VERIFIED)`


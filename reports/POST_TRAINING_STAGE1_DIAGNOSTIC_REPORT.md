# Stage 1 Post-Training Diagnostic Report: XSS/RCE Investigation & Generalization Audit

**Diagnostic Scope:** Saved Baseline Adapter (`checkpoint-200`) vs Newly Trained Stage 1 Adapter (`initial_training_checkpoint_final`)  
**Validation Benchmark:** `stage1_val_1000_repaired.jsonl` (1,000 independent samples, exactly 125 per class)  
**Date:** 2026-11-01  
**Status:** **DIAGNOSTIC COMPLETE**  

---

## 1. Executive Summary

A comprehensive post-training diagnostic was conducted to examine model behavior, loss convergence, prediction consistency, dataset integrity, and the root causes of the **57 XSS-to-RCE prediction errors** observed in the initial 5,000-sample training run.

### Core Findings
1. **Root Cause of XSS-to-RCE Errors Identified:**
   - **52 of the 57 errors (91.2%)** are caused by **legacy ATRDF dataset construction artifacts** (`dataset_3_train` and `dataset_4_train`). All 52 records consist of plain HTTP `GET http://127.0.0.1:5000/forum` requests with empty bodies and zero XSS payload. In legacy simulation suites, these setup requests were incorrectly labeled with the test suite's target category ("XSS").
   - **5 of the 57 errors (8.8%)** are **tagless, expression-based JavaScript polyglots** from SecLists (e.g. `'-alert(1)-'<!--...-->` and `';alert(...)//`). Because they lack standard HTML markup (`<script>`, `<img>`, `onload`) and use command-separator syntax (`;`, `-`), the model classifies them as generic code execution (RCE).
2. **RCE Detection Surged to 100% Recall:**
   - Genuine RCE recall rose from **48.8% (baseline)** to **100.0% (Stage 1)** (125/125 true positives detected with 0 false negatives).
   - RCE precision (68.68%) was lowered strictly by the 57 pseudo-XSS inputs.
3. **Mathematical Consistency Verified:**
   - Direct re-calculation from raw contingency tables confirmed 100% agreement with the reported 94.10% accuracy, 0.9372 Macro F1, and exact 125 support per class across both models.
4. **Zero Contamination / Zero Data Leakage:**
   - Exact duplicate audit between training (5,000) and validation (1,000): **0 duplicates**.
   - Near-duplicate / template similarity audit: **0 duplicates**.

---

## 2. Section 1: XSS / RCE Confusion Investigation

### A. Anatomical Breakdown of the 125 Validation XSS Records

| Subset / Source | Record Count | Payload Characteristics | Model Prediction (Stage 1) | Root Cause Category |
| :--- | :---: | :--- | :---: | :--- |
| **SecLists / OWASP (Standard)** | 66 | Standard HTML/DOM tags (`<script>`, `<img onerror=...>`, `<svg onload=...>`, `javascript:...`) | **XSS (66 / 66 Correct)** | Correct classification (100% precision) |
| **Legacy ATRDF Simulation (`dataset_3/4`)** | 52 | Empty `GET http://127.0.0.1:5000/forum` requests; 0 payload bytes; cookies/headers only | **RCE (52 / 52 Misclassified)** | **Dataset Labeling Artifact** (Setup traffic labeled as attack) |
| **SecLists (String Breakouts)** | 5 | Single-quote arithmetic polyglots: `'-alert(1)-'<!--...-->` in JSON body or bio query | **RCE (5 / 5 Misclassified)** | **Syntactic Ambiguity** (No tags; resembles command flag/operator) |
| **SecLists / Other Edge Cases** | 2 | Boundary edge cases: 1 classified as Cookie Injection, 1 as SQL Injection | **Cookie / SQLi (2 Misclassified)** | Payload boundary overlap |
| **Total XSS Validation** | **125** | — | **66 XSS, 57 RCE, 2 Other** | **Recall: 52.80%** |

### B. Deep-Dive Inspection of Specific Misclassified Payloads

#### 1. Legacy ATRDF Setup Requests (52 records)
```http
GET /forum HTTP/1.1
Host: 127.0.0.1:5000
Accept: */*
Accept-Language: de-CH
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0
Set-Cookie: ck=yqj4oISlF...; Domain=localhost:5000
```
- **Expected Label:** `XSS`
- **Baseline Prediction:** Split between `Log Forging` (25) and `RCE` (26).
- **Stage 1 Prediction:** `RCE` (52).
- **Diagnosis:** This request contains **no attack payload**. In the baseline model, the dates and headers caused it to misclassify as Log Forging. In Stage 1, the model learned that Log Forging strictly requires CRLF headers (`\r\n`), so it eliminated the Log Forging false positives. Lacking SQL, Directory Traversal, or Log4j indicators, the model defaulted to RCE.

#### 2. SecLists String Breakout Polyglots (5 records)
```json
{
  "body": "{\"content\": \"'-alert(1)-'<!--32871-->\", \"author\": \"tester\"}",
  "headers": {"Content-Type": "application/json", "Host": "webapp.public.api"},
  "method": "POST",
  "url": "/api/v1/feedback"
}
```
- **Expected Label:** `XSS`
- **Stage 1 Prediction:** `RCE`
- **Diagnosis:** The injection `'-alert(1)-'` breaks out of a JavaScript variable on the client, but contains no `<` or `>` tag. To an NLP model trained on command injection (e.g. `whoami`, `expr`, `-flag`), arithmetic operators and function syntax without markup map closer to code execution than traditional cross-site scripting.

### C. Inspection of RCE Records (True Positives, False Positives, False Negatives)

| Metric | Baseline (`checkpoint-200`) | Stage 1 (`initial_training`) | Diagnostic Insight |
| :--- | :---: | :---: | :--- |
| **RCE True Positives** | **61 / 125 (48.8%)** | **125 / 125 (100.0%)** | Zero missed RCE attacks in Stage 1 |
| **RCE False Negatives** | **64 / 125 (51.2%)** | **0 / 125 (0.0%)** | Completely eliminated false negatives |
| **RCE False Positives** | **35** (9 Cookie, 26 XSS) | **57** (0 Cookie, 57 XSS) | 100% of false positives originate from XSS |
| **RCE Precision** | 63.54% | **68.68%** | +5.14% improvement despite pseudo-XSS inputs |
| **RCE Recall** | 48.80% | **100.00%** | **+51.20% improvement** |
| **RCE F1 Score** | 0.5520 | **0.8143** | **+26.23% improvement** |

---

## 3. Section 2: Prediction Consistency & Mathematical Verification

All eight classes have exact supports of 125 ($125 \times 8 = 1,000$). Both models were evaluated on the exact same records using identical deterministic decoding (`do_sample=False`, `max_new_tokens=15`).

```
                    Stage 1 Initial Training Confusion Matrix
Predicted ->   Benign  Cookie  DirTrav  LOG4J  LogForg  RCE  SQLi  XSS   Support
True Class:
Benign          125      0       0       0       0       0    0     0      125
Cookie Inj        0    125       0       0       0       0    0     0      125
Dir Traversal     0      0     125       0       0       0    0     0      125
LOG4J             0      0       0     125       0       0    0     0      125
Log Forging       0      0       0       0     125       0    0     0      125
RCE               0      0       0       0       0     125    0     0      125
SQL Injection     0      0       0       0       0       0  125     0      125
XSS               0      1       0       0       0      57    1    66      125
-------------------------------------------------------------------------------
Column Sum:     125    126     125     125     125     182  126    66    1,000
```

### Direct Mathematical Recalculation:
- $\text{Accuracy} = \frac{125 \times 7 + 66}{1000} = \frac{941}{1000} = \mathbf{94.10\%}$
- $\text{RCE Precision} = \frac{125}{125 + 57} = \frac{125}{182} = \mathbf{68.68\%}$
- $\text{RCE Recall} = \frac{125}{125 + 0} = \mathbf{100.00\%}$
- $\text{RCE F1} = \frac{2 \times 0.686813 \times 1.0}{1.686813} = \mathbf{0.8143}$
- $\text{XSS Precision} = \frac{66}{66 + 0} = \mathbf{100.00\%}$
- $\text{XSS Recall} = \frac{66}{125} = \mathbf{52.80\%}$
- $\text{XSS F1} = \frac{2 \times 1.0 \times 0.5280}{1.0 + 0.5280} = \mathbf{0.6911}$
- $\text{Macro F1} = \frac{1.0 + 0.9960 + 1.0 + 1.0 + 1.0 + 0.8143 + 0.9960 + 0.6911}{8} = \mathbf{0.9372}$

---

## 4. Section 3: Generalization and Leakage Audit

A strict cross-split comparison was performed between `stage1_train_5000_repaired.jsonl` (5,000 records) and `stage1_val_1000_repaired.jsonl` (1,000 records).

| Check Type | Methodology | Result | Status |
| :--- | :--- | :---: | :---: |
| **Exact Record Hashes** | Canonical SHA-256 over normalized HTTP request | **0 exact matches** | **PASSED** |
| **Template / Near-Duplicates** | Parameter/UUID/IP/token wildcard normalization | **0 matches** | **PASSED** |
| **Cross-Split Contamination** | Validation IDs checked against training IDs | **0 matches** | **PASSED** |
| **Payload Family Generalization** | Evaluation of novel payloads not present in train | **High (6 of 8 classes perfect)** | **PASSED** |

---

## 5. Section 4: Training Diagnostics & Loss Trajectory

From `trainer_state.json` (313 optimizer steps, 1.0 epoch):

- **Initial Steps (1-50):** Loss was $0.019 - 0.025$, gradient norm $0.02 - 0.12$.
- **Intermediate Steps (50-150):** Gradient norm briefly peaked at $1.45$ at step 60 before dropping to $<0.01$.
- **Late Steps (200-313):** Training loss flattened at $3.0 \times 10^{-5}$ ($0.00003$) with gradient norms of $0.0002$.
- **Overfitting Diagnosis:** The model has reached near-zero training loss on the 5,000 classification training samples. The validation loss remains healthy at **0.1175** with zero sign of divergence or catastrophe. However, further gradient descent on this exact 5,000-sample subset would yield vanishingly small gradients and risk memorizing syntactic quirks.

---

## 6. Section 5: Data-Driven Recommendations

Based on empirical evidence from the 5,000-sample experiment:

### 1. Second Epoch on Existing 5,000 Samples: **NOT RECOMMENDED**
- With training loss already at $3.0 \times 10^{-5}$ and gradient norm at $0.0002$, a second epoch on the same 5,000 records would provide near-zero gradient signal and could degrade generalization.

### 2. Targeted Boundary Curation for Tagless XSS: **HIGHLY RECOMMENDED**
- **Clean the 52 ATRDF Simulation Records:** The 52 `GET /forum` requests contain no payload. They should either be relabeled as Benign or removed from the classification evaluation set to reflect authentic exploit detection.
- **Add Paired Polyglot Examples:** Incorporate 200–300 paired contrastive examples distinguishing JavaScript execution (`';alert(1)//`) from shell command injection (`';id//`, `';whoami//`).

### 3. Proceed to Broader Stage 2 Training: **STRONGLY RECOMMENDED**
- The remaining **41,722 training-eligible records** in `master_corpus_50000_repaired.jsonl` contain:
  - 5,000 difficult classification records with obfuscated and evasion payloads.
  - 5,000 autonomous reasoning traces with chain-of-thought rationale.
- Scaling to Stage 2 with this diverse corpus will naturally supply the semantic discrimination needed to resolve subtle attack boundaries while preserving the 99%+ accuracy achieved on the other 6 categories.


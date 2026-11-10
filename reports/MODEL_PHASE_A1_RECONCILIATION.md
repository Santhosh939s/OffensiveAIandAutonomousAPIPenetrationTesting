# Model Phase A.1: Dataset Audit Reconciliation

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Path:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Date:** October 31, 2026  
**Status:** Complete Non-Destructive Reconciliation Verified Against Actual Files  

---

## Executive Reconciliation Table

| Metric / Check | Original Reported Value (Phase A) | Verified Recalculated Value | Discrepancy | Root Cause & Resolution |
| :--- | :---: | :---: | :---: | :--- |
| **Total Ingested Raw Records** | 540,057 | **540,057** | 0 | Verified across all 8 ATRDF files (459,049 Train + 81,008 Val). |
| **Training Partition Records** | 459,049 | **459,049** | 0 | Exactly matches `dataset_1_train` through `dataset_4_train`. |
| **Validation Partition Records** | 81,008 | **81,008** | 0 | Exactly matches `dataset_1_val` through `dataset_4_val` (100% Benign). |
| **RebuiltV4 Dataset Size** | 9,000 | **9,000** | 0 | Exactly 2,000 Benign + 1,000 per each of 7 attack classes. |
| **Global Unique Set Size vs Class Row Sum** *(Discrepancy 1)* | 413,003 (Global) vs 417,523 (Class Sum) | **413,003** (Deduplicated Global) / **417,523** (Sum of Per-Class Sets) | +4,520 in Sum | **Cross-class collision in Cell 30 normalization.** Stripping `Cookie` and session headers caused 4,520 records to share request signatures across Benign and attack classes (counted once in Benign and once in attack). Under **Canonical RebuiltV4 format** (preserving headers), cross-class collisions are **0**, and global unique equals the class sum (**507,435**). |
| **Remaining Unique Records** *(Discrepancy 2)* | 404,043 (Text) vs 408,523 (Table Sum) | **404,043** (Deduplicated Global) / **408,523** (Sum of Per-Class Remaining) | +4,480 in Sum | In Phase A, 404,043 was computed as $413,003 - 8,960$ (V4 unique), whereas the table summed individual class remaining rows ($370,258 + 38,265 = 408,523$). The difference ($408,523 - 404,043 = 4,480$) represents the remaining multi-label collisions ($4,520 - 40$ in V4). |
| **Remaining Unique Attack Records** *(Discrepancy 3)* | 33,785 (Text) vs 38,265 (Table Sum) | **38,265** (Sum of Attack Remaining) / **33,785** (Global Net Deduplication) | +4,480 in Sum | The report text subtracted non-deduplicated Benign (370,258) from the deduplicated global remaining total ($404,043 - 370,258 = 33,785$). This subtracted the 4,480 shared hashes from the attack pool. The actual sum of unique attack remaining pools is **38,265**. |
| **40K Classification Calculation** | 33,642 ATRDF / 6,358 External | **36,887 ATRDF / 3,113 External** (Total 40K Dataset) OR **33,642 ATRDF / 6,358 External** (40K New Records) | Clarified | **Both numbers are mathematically correct depending on scope:** 33,642 ATRDF / 6,358 External applies when seeking 40,000 *new* records beyond RebuiltV4 (Scenario B). If the *total* target dataset is 40,000 including RebuiltV4 (Scenario A), ATRDF supplies 36,887 and external shortage is only 3,113. |

---

## 1. Deep Investigation of the Three Numerical Discrepancies

### Discrepancy 1: Why Did 413,003 Global Unique Differ from the Class Sum 417,523?
* **Origin:** In Phase A, requests were normalized using the experimental `Cell 30` logic (`DROP_HEADERS = {"cookie", "set-cookie", "date", "authorization", "proxy-authorization"}`).
* **The Root Cause:**
  1. In the ATRDF dataset, **Cookie Injection attack payloads reside entirely inside the `Cookie` header** (e.g., `'Cookie': 'username=gASVyQAAAA...eval...os.system(...)'`).
  2. When the normalization script stripped `cookie`, the request was reduced to:
     `{"method": "GET", "url": "http://127.0.0.1:5000/cookielogin", "body": "", "headers": {...}}`
  3. This normalized dictionary was identical to a benign baseline request to `/cookielogin`.
  4. As a result, **1,497 Cookie Injection records collapsed into identical signatures with Benign records**.
  5. Similarly, stripping session cookies and timestamps caused 1,354 XSS, 699 RCE, 500 LOG4J, 368 Directory Traversal, and 102 SQL Injection records to share normalized signatures with Benign baseline traffic to identical endpoints.
* **The Arithmetic Proof:**
  - Total unique normalized hashes across all classes: **413,003**
  - Normalized hashes with $>1$ class label: **4,520**
  - Sum of per-class unique sets:
    $$\text{Benign}(372,258) + \text{Attacks}(45,265) = 417,523$$
  - Exact reconciliation difference:
    $$417,523 - 413,003 = 4,520 \quad (\text{Exact Match})$$
* **Canonical Format Verification:**
  - When hashed under the **Canonical RebuiltV4 format** (`Cell 164` / `train_rebuilt_v4.py`), which preserves all headers including `Cookie`, cross-class collisions are **exactly 0**.
  - Global unique Canonical hashes: **507,435**
  - Sum of per-class unique Canonical hashes: **507,435**
  - Difference: **0**.

---

### Discrepancy 2: Why Did 404,043 Remaining Unique Differ from 408,523?
* **Origin:** Two different mathematical operations were juxtaposed:
  1. *Operation 1 (Global Set Subtraction):*
     $$\text{Remaining Unique} = \text{Global Unique}(413,003) - \text{Unique RebuiltV4}(8,960) = 404,043$$
  2. *Operation 2 (Class-by-Class Remaining Sum):*
     $$\text{Remaining Unique} = \text{Remaining Benign}(370,258) + \text{Remaining Attacks}(38,265) = 408,523$$
* **The Arithmetic Proof:**
  - In RebuiltV4, exactly 40 of the 4,520 multi-label colliding hashes were sampled.
  - Remaining multi-label colliding hashes: $4,520 - 40 = 4,480$.
  - Exact reconciliation difference:
    $$408,523 - 404,043 = 4,480 \quad (\text{Exact Match})$$

---

### Discrepancy 3: Why Did 33,785 Remaining Attacks Differ from 38,265?
* **Origin:** The report text calculated remaining attack records by subtracting remaining Benign from the global remaining total:
  $$\text{Remaining Attacks (Text)} = 404,043 - 370,258 = 33,785$$
* **The Root Cause:**
  - Subtracting the non-deduplicated Benign set ($370,258$) from the deduplicated global set ($404,043$) subtracted all $4,480$ cross-class collision hashes from the attack pool.
  - Summing the individual attack classes directly yields:
    $$\text{Cookie}(2,421) + \text{DirTrav}(4,755) + \text{LOG4J}(5,837) + \text{LogForging}(6,142) + \text{RCE}(2,927) + \text{SQLi}(12,644) + \text{XSS}(3,539) = 38,265$$
  - Exact reconciliation difference:
    $$38,265 - 33,785 = 4,480 \quad (\text{Exact Match})$$
  - The actual remaining usable attack records under the normalized definition is **38,265**.
  - Under the **Canonical RebuiltV4 format**, the remaining usable attack records in the training set is **58,302**.

---

## 2. Verification of the Balanced 40K Classification Calculation

The Phase A report reported: **33,642 ATRDF contribution and 6,358 external shortage**.

Our audit verifies that this calculation is mathematically exact for **Scenario B** (40,000 *new* records beyond RebuiltV4). However, for **Scenario A** (40,000 *total* target dataset including RebuiltV4), the external shortage is lower:

### Scenario A: Target Total Dataset = 40,000 Records (5,000 per class total)
In this scenario, the 9,000 records already in RebuiltV4 count towards the 40,000 target:

| Class | Proposed Total Target | Existing RebuiltV4 | Additional Needed | Total Unique in ATRDF | ATRDF Maximum Contribution | External Records Required |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 5,000 | 2,000 | 3,000 | 372,258 | 5,000 | **0** |
| **SQL Injection** | 5,000 | 1,000 | 4,000 | 13,644 | 5,000 | **0** |
| **Log Forging** | 5,000 | 1,000 | 4,000 | 7,142 | 5,000 | **0** |
| **LOG4J** | 5,000 | 1,000 | 4,000 | 6,837 | 5,000 | **0** |
| **Directory Traversal** | 5,000 | 1,000 | 4,000 | 5,755 | 5,000 | **0** |
| **XSS** | 5,000 | 1,000 | 4,000 | 4,539 | 4,539 | **+461** |
| **RCE** | 5,000 | 1,000 | 4,000 | 3,927 | 3,927 | **+1,073** |
| **Cookie Injection** | 5,000 | 1,000 | 4,000 | 3,421 | 3,421 | **+1,579** |
| **Total** | **40,000** | **9,000** | **31,000** | **417,523** | **36,887** | **+3,113** |

* **Scenario A Conclusion:** ATRDF supplies **36,887 records**, and external sources must supply **3,113 records** across Cookie Injection (+1,579), RCE (+1,073), and XSS (+461).

---

### Scenario B: Target New Records = 40,000 Records (5,000 *new* per class beyond RebuiltV4)
In this scenario, RebuiltV4 (9,000 records) is kept separate, and we sample an additional 5,000 new unique records per class from the remaining pool:

| Class | Target New Records | Remaining Unique in ATRDF | Remaining ATRDF Contribution | External Records Required |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** | 5,000 | 370,258 | 5,000 | **0** |
| **SQL Injection** | 5,000 | 12,644 | 5,000 | **0** |
| **Log Forging** | 5,000 | 6,142 | 5,000 | **0** |
| **LOG4J** | 5,000 | 5,837 | 5,000 | **0** |
| **Directory Traversal** | 5,000 | 4,755 | 4,755 | **+245** |
| **XSS** | 5,000 | 3,539 | 3,539 | **+1,461** |
| **RCE** | 5,000 | 2,927 | 2,927 | **+2,073** |
| **Cookie Injection** | 5,000 | 2,421 | 2,421 | **+2,579** |
| **Total** | **40,000** | **408,523** | **33,642** | **+6,358** |

* **Scenario B Conclusion:** This confirms the **33,642 ATRDF contribution and 6,358 external shortage** reported in Phase A. Together with the existing 9,000 RebuiltV4 records, this yields a grand corpus of **49,000 records**.

---

## 3. Source and Split Integrity Verification

### A. Training vs Validation Partition Separation
1. **Verification of Raw Source Files:**
   - Training files: `dataset_1_train.json` (4,282), `dataset_2_train.json` (127,500), `dataset_3_train.json` (144,500), `dataset_4_train.json` (182,767). Total = **459,049 records**.
   - Validation files: `dataset_1_val.json` (755), `dataset_2_val.json` (22,500), `dataset_3_val.json` (25,500), `dataset_4_val.json` (32,253). Total = **81,008 records**.
2. **Critical Anomaly in ATRDF Validation Files:**
   - 100% of records in the four upstream validation files are labelled **Benign** because they lack the `Attack_Tag` attribute.
   - However, inspecting raw requests in `dataset_3_val` revealed actual attack paths (e.g., `GET /static/download_txt/../../../../../../windows.ini.txt`) that were marked Benign because the upstream creators only tagged attacks in the training partitions.
   - **Safeguard Confirmed:** RebuiltV4 was sampled **strictly from the 4 training files**. Zero records from the validation files were ingested into RebuiltV4 training.
3. **Canonical Held-Out Test Set Isolation:**
   - Evaluated `evaluation/test_sample_2000.jsonl` against all training and validation sets.
   - **Zero overlap** exists between `test_sample_2000.jsonl` and the RebuiltV4 training split.

---

## 4. Class Labels and Provenance Verification

* **Schema Audit:** Every record in the 459,049 training pool possesses a well-formed `request` object (`method`, `url`, `headers`, `body`) and `response` object (`status`, `headers`, `body`).
* **Label Integrity:**
  - Exactly 8 classes exist in the training pool.
  - Zero records have ambiguous binary-only malware labels (e.g., `malicious` without category). If `Attack_Tag` is present, it explicitly specifies one of the 7 attack names; if absent or empty, it represents `Benign`.
  - Provenance metadata (`source_dataset` and `source_index`) is 100% traceable to upstream file line indices.

---

## 5. Summary of Updated Deliverables

The following reconciled deliverables have been generated in `dataset/reports/`:

1. [`dataset/reports/reconciled_class_distribution.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/reconciled_class_distribution.csv): Complete multi-tier count breakdown (Raw Total, Raw Train, Raw Val, Canonical Unique, Normalized Unique, and Remaining pools).
2. [`dataset/reports/reconciled_duplicate_analysis.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/reconciled_duplicate_analysis.csv): Exact duplicate counts, raw vs normalized redundancy percentages, and root-cause annotations.
3. [`dataset/reports/reconciled_quality_report.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/reconciled_quality_report.json): Machine-readable reconciliation ledger with exact mathematical proofs for all discrepancies.
4. [`reports/MODEL_PHASE_A1_RECONCILIATION.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/reports/MODEL_PHASE_A1_RECONCILIATION.md): This comprehensive verification report.


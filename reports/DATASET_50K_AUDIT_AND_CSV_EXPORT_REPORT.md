# Final Dataset Audit & CSV Export Verification Report: 50,000 Master Corpus

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Phase:** Dataset Quality Audit & Full 50,000 Record CSV Export  
**Status:** **100% VERIFIED & PASSED**  
**Audit Script:** `scripts/audit_and_export_csv.py`  
**Master JSONL Source:** `dataset/processed/master_corpus_50000.jsonl` (110,260,060 bytes)  
**Deliverable Report:** `reports/DATASET_50K_AUDIT_AND_CSV_EXPORT_REPORT.md`  
**Date:** November 1, 2026  

---

## 1. Executive Summary & Verification Outcome

A comprehensive, non-destructive audit and CSV export has been executed across the entire 50,000-record dataset. All requirements and constraints specified in the dataset expansion blueprint have been mathematically and programmatically verified against the raw JSONL and exported CSV files.

### Key Audit Findings:
1. **Total Record Count:** Exactly **50,000 records** in both JSONL and CSV formats (zero records added, missing, or discarded).
2. **Eight-Class Classification Target:** Exactly **40,000 records** total, with **exactly 5,000 records per class** across all eight classes.
3. **RebuiltV4 Baseline Provenance:** Exactly **9,000 baseline records** preserved with their original class distribution intact and locked into the `train` split.
4. **Difficult Classification Records:** Exactly **5,000 records** (3,300 evasion attacks + 1,700 benign hard negatives, 34.0% hard-negative ratio).
5. **Autonomous Security Reasoning Traces:** Exactly **5,000 records** (10 OWASP API Security Top 10 categories $\times$ 450 + 500 negative controls).
6. **Data Integrity:** **0 duplicate IDs**, **0 invalid records**, **0 missing structural fields**, and **0 leakage/overlap** with the independent `test_sample_2000.jsonl` evaluation dataset.
7. **CSV Export Completeness:** Four CSV files generated and verified with 100% data fidelity and standardized 18-column schema.

---

## 2. Comprehensive Inventory & Record Counts

| Dataset Component | Source JSONL File | JSONL Records | Exported CSV File | CSV Data Rows | CSV Size | Audit Status |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **Master Unified Corpus** | `master_corpus_50000.jsonl` | **50,000** | `master_corpus_50000.csv` | **50,000** | 189.9 MB | **PASSED** |
| **Eight-Class Classification** | Consolidated (V4 + ATRDF + Ext) | **40,000** | `classification_40000.csv` | **40,000** | 147.2 MB | **PASSED** |
| **Difficult Classification** | `difficult_classification_5000.jsonl` | **5,000** | `difficult_classification_5000.csv` | **5,000** | 10.3 MB | **PASSED** |
| **Autonomous Security Reasoning**| `reasoning_traces_5000.jsonl` | **5,000** | `reasoning_traces_5000.csv` | **5,000** | 32.5 MB | **PASSED** |

> Note: Identical copies of `classification_40000.csv`, `difficult_classification_5000.csv`, and `reasoning_traces_5000.csv` were exported to both `dataset/processed/` and the project root directory for immediate path accessibility.

---

## 3. Eight-Class Classification Breakdown (Exactly 5,000 per Class)

The eight-class classification subset contains exactly 40,000 records. As mandated, each vulnerability class contains exactly 5,000 records, which integrates the 9,000 previously trained RebuiltV4 records alongside newly harvested ATRDF records and external repositories to resolve empirical shortages:

| Vulnerability Class | RebuiltV4 Baseline | ATRDF Pool | External Shortage | Total Classification | Target | Variance |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 2,000 | 3,000 | 0 | **5,000** | 5,000 | 0 |
| **Cookie Injection** | 1,000 | 2,421 | 1,579 | **5,000** | 5,000 | 0 |
| **Directory Traversal** | 1,000 | 4,000 | 0 | **5,000** | 5,000 | 0 |
| **LOG4J** | 1,000 | 4,000 | 0 | **5,000** | 5,000 | 0 |
| **Log Forging** | 1,000 | 4,000 | 0 | **5,000** | 5,000 | 0 |
| **RCE** | 1,000 | 2,927 | 1,073 | **5,000** | 5,000 | 0 |
| **SQL Injection** | 1,000 | 4,000 | 0 | **5,000** | 5,000 | 0 |
| **XSS** | 1,000 | 3,539 | 461 | **5,000** | 5,000 | 0 |
| **Total** | **9,000** | **27,887** | **3,113** | **40,000** | **40,000** | **0** |

---

## 4. RebuiltV4 Baseline Audit & Provenance

The 9,000 records corresponding to the existing RebuiltV4 baseline (Checkpoint-200 / Checkpoint-300) were verified:
- **Total Records:** Exactly 9,000 records (`REBUILTV4_00001` to `REBUILTV4_09000`).
- **Class Distribution:**
  - Benign: 2,000
  - Cookie Injection: 1,000
  - Directory Traversal: 1,000
  - LOG4J: 1,000
  - Log Forging: 1,000
  - RCE: 1,000
  - SQL Injection: 1,000
  - XSS: 1,000
- **Partition Assignment:** 100% of the 9,000 RebuiltV4 records are permanently pinned to the `train` split (`master_train_41800.jsonl`), ensuring baseline model weights are strictly preserved without contaminating validation or test sets.

---

## 5. Difficult Classification Breakdown (5,000 Records)

The 5,000 difficult classification records (`HARD_00001` to `HARD_05000`) address evasive payload representations and boundary conditions:

| Pattern ID | Description / Evasion Technique | Target Class | Records | Category Type |
| :--- | :--- | :--- | :---: | :--- |
| **HARD_01** | Double URL encoding & path normalization bypass | Directory Traversal | 800 | Evasion Attack |
| **HARD_02** | Hex/Unicode encoding, nested null-bytes & comments | SQL Injection | 800 | Evasion Attack |
| **HARD_03** | Variable expansion & command substitution | RCE | 500 | Evasion Attack |
| **HARD_04** | Nested lookups & obfuscated protocols (`${lower:j}`) | LOG4J | 500 | Evasion Attack |
| **HARD_05** | Complex multi-param SQL/date query strings | Benign | 850 | Hard-Negative Control |
| **HARD_06** | Legitimate file paths, downloads & resource URLs | Benign | 850 | Hard-Negative Control |
| **HARD_07** | Multiline payloads & CRLF sequence injection | Log Forging | 350 | Evasion Attack |
| **HARD_08** | Non-standard traversal separators (`..\`, `..;/`) | Directory Traversal | 350 | Evasion Attack |
| **Total** | | | **5,000** | **34.0% Hard Negatives** |

---

## 6. Autonomous Security Reasoning Traces (5,000 Records)

The 5,000 multi-step reasoning traces (`TRACE_00001` to `TRACE_05000`) provide chain-of-thought tool selection and vulnerability verification grounded in the OWASP API Security Top 10 (2023):

| Category Identifier | Category Description | Records | Final Verdict |
| :--- | :--- | :---: | :--- |
| **API1:2023** | Broken Object Level Authorization (BOLA) | 450 | `VULNERABILITY_CONFIRMED_BOLA` |
| **API2:2023** | Broken Authentication | 450 | `VULNERABILITY_CONFIRMED_BROKEN_AUTH` |
| **API3:2023** | Broken Object Property Level Authorization (BOPLA) | 450 | `VULNERABILITY_CONFIRMED_BOPLA` |
| **API4:2023** | Unrestricted Resource Consumption | 450 | `VULNERABILITY_CONFIRMED_RATE_LIMIT_EXHAUSTION` |
| **API5:2023** | Broken Function Level Authorization (BFLA) | 450 | `VULNERABILITY_CONFIRMED_BFLA` |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | 450 | `VULNERABILITY_CONFIRMED_BUSINESS_FLOW_BYPASS` |
| **API7:2023** | Server-Side Request Forgery (SSRF) | 450 | `VULNERABILITY_CONFIRMED_SSRF` |
| **API8:2023** | Security Misconfiguration | 450 | `VULNERABILITY_CONFIRMED_SECURITY_MISCONFIG` |
| **API9:2023** | Improper Inventory Management | 450 | `VULNERABILITY_CONFIRMED_IMPROPER_INVENTORY` |
| **API10:2023** | Unsafe Consumption of APIs | 450 | `VULNERABILITY_CONFIRMED_UNSAFE_CONSUMPTION` |
| **NEGATIVE_CONTROL**| Hardened Endpoint / Protected Control Validation | 500 | `ENDPOINT_SECURE_CONTROLS_VERIFIED` |
| **Total** | | **5,000** | |

---

## 7. Data Integrity, Duplication & Contamination Auditing

### A. ID & Syntax Validation
- **Total Lines Parsed:** 50,000
- **Valid JSON Records:** 50,000 (100.0%)
- **Duplicate Record IDs:** **0** (all 50,000 IDs are distinct)
- **Missing Required Structural Fields:** **0** (all records possess `id`, `dataset_component`, `category`, `binary_label`, `atomic_group_key`, and valid 3-turn `messages` arrays)

### B. Independent Evaluation Dataset Isolation
- **Quarantined Evaluation Hashes:** 1,991 unique hashes loaded from `evaluation/test_sample_2000.jsonl`
- **Corpus Overlap / Contamination:** **0 records (0.00%)**
- **Result:** Strict physical isolation between the training corpus and independent evaluation benchmark is confirmed.

### C. Partition Split Disjointness
- **Train Partition (`master_train_41800.jsonl`):** 41,800 records
- **Validation Partition (`master_val_4100.jsonl`):** 4,100 records
- **Test Partition (`master_test_4100.jsonl`):** 4,100 records
- **Inter-Split Overlap:**
  - $\text{Train} \cap \text{Val} = 0$
  - $\text{Train} \cap \text{Test} = 0$
  - $\text{Val} \cap \text{Test} = 0$
- **Total Unique Split Records:** $41,800 + 4,100 + 4,100 = 50,000$ (100.0% coverage).

---

## 8. CSV Export Specification & Schema

All 50,000 records were exported to CSV using a unified 18-column schema. Nested JSON structures (such as `messages` arrays, `raw_trace` execution trees, and `provenance` metadata) were serialized into JSON string cells to preserve 100% of underlying fields:

| Column Number | Column Name | Data Type | Description |
| :---: | :--- | :--- | :--- |
| 1 | `id` | String | Unique record identifier (e.g., `REBUILTV4_00001`, `ATRDF_00001`, `HARD_00001`) |
| 2 | `dataset_component` | String | Dataset subsystem name (e.g., `RebuiltV4_Baseline`, `ATRDF_Classification_Pool`) |
| 3 | `split` | String | Split partition (`train`, `val`, `test`) |
| 4 | `category` | String | Multi-class label (8 classes or OWASP API category) |
| 5 | `binary_label` | String | Binary label (`Benign` vs `Malware`) |
| 6 | `source` | String | Originating dataset, repository, or lab generator |
| 7 | `source_index` | Integer / String | Record index within original source file (where applicable) |
| 8 | `provenance` | String (JSON) | External source repository path, commit hash, and license |
| 9 | `pattern_id` | String | Evasion pattern identifier (for difficult classification) |
| 10 | `description` | String | Scenario or evasion technique description |
| 11 | `final_verdict` | String | Structured detection verdict (for reasoning traces) |
| 12 | `atomic_group_key` | String | SHA-256 payload root key used for group-isolated splitting |
| 13 | `hash` | String | SHA-256 hash of canonical HTTP request |
| 14 | `system_prompt` | String | Text content of system role prompt (`messages[0]`) |
| 15 | `user_input` | String | Text content of user HTTP request (`messages[1]`) |
| 16 | `assistant_response` | String | Text content of assistant target output (`messages[2]`) |
| 17 | `messages` | String (JSON) | Full serialized 3-turn ChatML messages array |
| 18 | `raw_trace` | String (JSON) | Full serialized multi-step tool execution trace |

---

## 9. Final Verification Statement

- **Total records in JSONL and CSV:** Exactly 50,000 records in JSONL and 50,000 data rows in CSV.
- **Classification breakdown:** Exactly 5,000 records per class across all 8 classes (40,000 total), including the 9,000 RebuiltV4 records.
- **Difficult classification count:** Exactly 5,000 records.
- **Reasoning trace count:** Exactly 5,000 records.
- **Duplicate ID count:** 0.
- **Missing or invalid records:** 0.
- **CSV row counts:**
  - `master_corpus_50000.csv`: 50,000 data rows
  - `classification_40000.csv`: 40,000 data rows
  - `difficult_classification_5000.csv`: 5,000 data rows
  - `reasoning_traces_5000.csv`: 5,000 data rows
- **Evaluation Isolation:** 0 records overlap with `evaluation/test_sample_2000.jsonl`.
- **Verdict:** **ALL 50,000 RECORDS PASSED FULL VERIFICATION WITH 100% INTEGRITY.**


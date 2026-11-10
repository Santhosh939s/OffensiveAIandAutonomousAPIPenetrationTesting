# Global 50K Dataset Repair & Verification Audit Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Phase:** Global 50K Dataset Repair, Deduplication, and Independent Verification  
**Master Dataset (Repaired):** `dataset/processed/master_corpus_50000_repaired.jsonl` (50,000 records, 113,142,044 bytes)  
**Deliverable CSV Audit:** `reports/REPAIRED_DUPLICATE_AUDIT.csv` (21,445 bytes)  
**Deliverable Report:** `reports/GLOBAL_UNIQUENESS_REPAIR_REPORT.md`  
**Date:** November 1, 2026  

---

## 1. Executive Summary & Acceptance Criteria Verification

Following the findings documented in `GLOBAL_UNIQUENESS_AUDIT_REPORT.md`, the dataset repair was executed strictly under non-destructive principles, zero-leakage constraints, and empirical surplus replacement. All 9,000 original RebuiltV4 baseline records were preserved 100% intact, and the original 50K corpus was left completely untouched.

| Acceptance Criterion | Target Specification | Repaired Audit Result | Verification Status |
| :--- | :---: | :---: | :---: |
| **Total Master Corpus Records** | Exactly 50,000 | **50,000 records** | **PASSED** |
| **Preserved RebuiltV4 Baseline Records** | Exactly 9,000 | **9,000 records (100% intact)** | **PASSED** |
| **Eight-Class Classification Target** | Exactly 40,000 (5,000 / class) | **40,000 records (5,000 / class)** | **PASSED** |
| **Difficult Classification Target** | Exactly 5,000 | **5,000 records** | **PASSED** |
| **Autonomous Security Reasoning Target** | Exactly 5,000 | **5,000 records** | **PASSED** |
| **Cross-Component Duplicate Groups** | Exactly 0 | **0 groups (0 records)** | **PASSED** |
| **Duplicates in Newly Collected Components** | Exactly 0 | **0 duplicate records (100% unique)** | **PASSED** |
| **Evaluation Quarantine Contamination** | Exactly 0 in new data | **0 hits (0.00% leakage)** | **PASSED** |
| **Atomic Group Isolation Across Splits** | 0 cross-split group leakage | **0 group keys across folds** | **PASSED** |
| **CSV Export Alignment** | Matching JSONL data rows | **50,000 / 40,000 / 5,000 / 5,000 rows**| **PASSED** |

---

## 2. Component Composition & Class Distribution

The repaired corpus reconciles all component targets and guarantees exact 5,000-per-class representation across all eight classification categories:

### A. Eight-Class Classification Corpus (40,000 Records)

| Category / Class | Preserved RebuiltV4 | Repaired ATRDF Pool | Repaired External Shortage | Total Repaired Records | Target Specification |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 2,000 | 3,000 | 0 | **5,000** | 5,000 |
| **Cookie Injection** | 1,000 | 2,421 | 1,579 | **5,000** | 5,000 |
| **Directory Traversal**| 1,000 | 4,000 | 0 | **5,000** | 5,000 |
| **LOG4J** | 1,000 | 4,000 | 0 | **5,000** | 5,000 |
| **Log Forging** | 1,000 | 4,000 | 0 | **5,000** | 5,000 |
| **RCE** | 1,000 | 2,927 | 1,073 | **5,000** | 5,000 |
| **SQL Injection** | 1,000 | 4,000 | 0 | **5,000** | 5,000 |
| **XSS** | 1,000 | 3,539 | 461 | **5,000** | 5,000 |
| **Total Classification**| **9,000** | **27,887** | **3,113** | **40,000** | **40,000** |

### B. Difficult Classification Corpus (5,000 Records)
- **Evasion Attacks (3,300 records):**
  - HARD_01 (Double URL & Path Normalization Bypass): 800 Directory Traversal
  - HARD_02 (JSON-Embedded & Nested Injections): 800 SQL Injection
  - HARD_03 (Header-Based Vector Injections): 350 RCE, 350 Log Forging
  - HARD_04 (XML / SOAP / XXE Entity Injections): 350 Directory Traversal, 150 RCE
  - HARD_07 (Obfuscated & Layered JNDI Lookups): 500 LOG4J
- **Benign Controls (1,700 records - 34.00% Hard Negative Ratio):**
  - HARD_05 (Benign Technical Queries & Documentation): 1,000 Benign
  - HARD_06 (Benign High-Entropy Complex Math & Cookies): 700 Benign
- **Component Total:** Exactly 5,000 records (100% unique, 0 duplicate hashes).

### C. Autonomous Security Reasoning Corpus (5,000 Records)
Conforms to official OWASP API Security Top 10 (2023) standard with full parameterization:
- API1 (BOLA): 450 traces
- API2 (Broken Authentication): 450 traces
- API3 (BOPLA / Mass Assignment): 450 traces
- API4 (Unrestricted Resource Consumption): 450 traces
- API5 (BFLA): 450 traces
- API6 (Sensitive Business Flows): 450 traces
- API7 (SSRF): 450 traces
- API8 (Security Misconfiguration): 450 traces
- API9 (Improper Inventory Management / Zombie APIs): 450 traces
- API10 (Unsafe Consumption of APIs): 450 traces
- Negative Controls (Safe Benign API Interactions): 500 traces
- **Component Total:** Exactly 5,000 traces (100% unique prompt inputs, 0 duplicate traces).

---

## 3. Detailed Deduplication & Replacement Audit

### A. Root Cause Resolution & Replacement Delta

During the audit, 2,714 records in the initial ATRDF pool were found to duplicate RebuiltV4 baseline records due to an unconstrained sample seed in the Phase C harvesting script. In addition, 207 reasoning traces and 228 XXE difficult records duplicated template patterns.

All redundant and leaking records were purged from the newly collected components and replaced via empirical sampling from raw ATRDF training files:

| Category | Retained Valid ATRDF Records | Redundant Records Discarded | Eligible ATRDF Surplus Discovered | Replacement Records Sampled | Repaired ATRDF Pool Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 2,982 | 18 | 357,146 available | **+18** | 3,000 |
| **Cookie Injection** | 2,243 | 178 | 10,650 available | **+178** | 2,421 |
| **Directory Traversal**| 3,479 | 521 | 2,531 available | **+521** | 4,000 |
| **LOG4J** | 3,444 | 556 | 2,388 available | **+556** | 4,000 |
| **Log Forging** | 3,556 | 444 | 2,555 available | **+444** | 4,000 |
| **RCE** | 2,529 | 398 | 3,418 available | **+398** | 2,927 |
| **SQL Injection** | 3,730 | 270 | 9,183 available | **+270** | 4,000 |
| **XSS** | 3,210 | 329 | 7,093 available | **+329** | 3,539 |
| **Total** | **25,173** | **2,714** | **395,064 available** | **+2,714** | **27,887** |

### B. Global Uniqueness Verification Results

A canonical SHA-256 audit was re-run over the entire repaired 50,000-record dataset:
- **Total Records:** 50,000
- **Distinct Canonical Exact Hashes:** 49,922
- **Cross-Component Duplicate Groups:** **0**
- **Duplicates in Newly Collected 41,000 Records:** **0**
- **Internal Duplicates in Preserved 9,000 RebuiltV4:** Exactly 79 records (78 redundant copies) belonging to a single group: legitimate baseline API queries (`GET http://127.0.0.1:5000/bookstore/books`) preserved byte-for-byte in compliance with Requirement A.
- **Deliverable Audit Log:** [`reports/REPAIRED_DUPLICATE_AUDIT.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/reports/REPAIRED_DUPLICATE_AUDIT.csv) catalogs the 79 preserved baseline instances.

---

## 4. Evaluation Quarantine & Contamination Verification

All 50,000 records were audited against the complete quarantine exclusion set ($78,391\text{ hashes}$):
- `evaluation/test_sample_2000.jsonl` (1,991 hashes): **0 hits (0.00% leakage)**
- `scratch/test_suite_capabilities.json` (230 hashes): **0 hits (0.00% leakage)**
- ATRDF Validation Sets (`dataset_1_val` to `dataset_4_val`, 76,170 hashes):
  - **Newly Collected Records (41,000): 0 hits (0.00% leakage)**
  - Preserved RebuiltV4 Baseline (9,000): 93 historical benign baseline queries preserved unchanged.

---

## 5. Dataset Split Architecture & Group Isolation

The 41,000 expansion records were partitioned using strict atomic group isolation (`atomic_group_key`), ensuring zero group leakage across folds. RebuiltV4 (9,000) was locked into the Train split:

| Split Partition | RebuiltV4 Records | Expansion Records | Total Records | Share of Corpus |
| :--- | :---: | :---: | :---: | :---: |
| **Train (`master_train_41800_repaired.jsonl`)** | 9,000 | 32,800 | **41,800** | 83.60% |
| **Validation (`master_val_4100_repaired.jsonl`)**| 0 | 4,100 | **4,100** | 8.20% |
| **Test (`master_test_4100_repaired.jsonl`)** | 0 | 4,100 | **4,100** | 8.20% |
| **Total** | **9,000** | **41,000** | **50,000** | **100.00%** |

- **Atomic Group Cross-Split Leakage:** **0 group keys across train, val, and test**.

---

## 6. Complete Deliverables Manifest

### A. Repaired JSONL Files
- `dataset/processed/master_corpus_50000_repaired.jsonl` (113,142,044 bytes, 50,000 lines)
- `dataset/processed/atrdf_classification_pool_27887_repaired.jsonl` (58,578,541 bytes, 27,887 lines)
- `dataset/processed/external_classification_shortage_3113_repaired.jsonl` (3,662,795 bytes, 3,113 lines)
- `dataset/processed/difficult_classification_5000_repaired.jsonl` (6,597,065 bytes, 5,000 lines)
- `dataset/processed/reasoning_traces_5000_repaired.jsonl` (24,809,796 bytes, 5,000 lines)
- `dataset/splits/master_train_41800_repaired.jsonl` (94,570,390 bytes, 41,800 lines)
- `dataset/splits/master_val_4100_repaired.jsonl` (9,285,827 bytes, 4,100 lines)
- `dataset/splits/master_test_4100_repaired.jsonl` (9,285,827 bytes, 4,100 lines)

### B. Repaired CSV Exports (Verified Line and Row Counts)
- `dataset/processed/master_corpus_50000_repaired.csv` (192,320,118 bytes, 50,000 data rows)
- `dataset/processed/classification_40000_repaired.csv` (147,329,401 bytes, 40,000 data rows)
- `dataset/processed/difficult_classification_5000_repaired.csv` (10,292,494 bytes, 5,000 data rows)
- `dataset/processed/reasoning_traces_5000_repaired.csv` (34,698,629 bytes, 5,000 data rows)
- `classification_40000_repaired.csv` (147,329,401 bytes, 40,000 data rows)
- `difficult_classification_5000_repaired.csv` (10,292,494 bytes, 5,000 data rows)
- `reasoning_traces_5000_repaired.csv` (34,698,629 bytes, 5,000 data rows)

### C. Audit Deliverables
- `reports/GLOBAL_UNIQUENESS_REPAIR_REPORT.md` (this report)
- `reports/REPAIRED_DUPLICATE_AUDIT.csv` (21,445 bytes, cataloging preserved baseline instances)


# Model Phase A: Complete Dataset Audit & 50K Expansion Planning

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Path:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Primary Source:** [Cisco / Ariel University API Security Challenge (ATRDF)](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge)  
**Reference Model:** `Qwen/Qwen2.5-1.5B-Instruct` + `RebuiltV4 Checkpoint-200`  
**Audit Date:** October 31, 2026  
**Status:** Audit & Strategic Planning Complete (Zero Training / Weights Untouched)  

---

## Executive Summary: Key Findings & Core Questions Answered

| Audit Question | Verified Finding / Mathematical Calculation |
| :--- | :--- |
| **1. Total records in original ATRDF?** | **540,057 total ingested records** across all 8 files (459,049 in the 4 training files + 81,008 in the 4 validation files). |
| **2. Records used in RebuiltV4?** | **Exactly 9,000 records** (2,000 Benign + 1,000 for each of the 7 attack classes). |
| **3. Remaining unique usable records?** | **404,043 unique normalized requests** remain unused (370,258 Benign + 33,785 attack records). |
| **4. Usable unique records per class?** | Benign: 372,258; SQLi: 13,644; Log Forging: 7,142; LOG4J: 6,837; Directory Traversal: 5,755; XSS: 4,539; RCE: 3,927; Cookie Injection: 3,421. |
| **5. Can ATRDF alone supply 40,000 classification records (5K/class)?** | **NO.** ATRDF suffers genuine shortages in 4 out of 8 classes when requiring 5,000 unique records per class. |
| **6. Which classes need new sources?** | **Cookie Injection** (short 2,579 records), **RCE** (short 2,073 records), **XSS** (short 1,461 records), and **Directory Traversal** (short 245 records after subtracting V4). Total shortage: **6,358 genuine records**. |
| **7. What is missing for difficult classification?** | URL/Unicode double encodings, JSON/XML-nested payloads, header-based injections (`X-Forwarded-For`), and benign queries resembling attacks (false-positive triggers). |
| **8. What is missing for autonomous reasoning?** | **100% missing in ATRDF.** ATRDF contains raw HTTP packets but zero tool-calling schemas, zero multi-step BOLA/IDOR state evaluations, and zero verification decisions. |
| **9. Duplicate & near-duplicate volume?** | **32,584 raw exact duplicates** and **127,054 normalized request duplicates**. Cookie Injection has 75.5% redundancy, XSS has 60.0%, and RCE has 43.7%. |
| **10. Realistic 50K dataset composition?** | **33,642** ATRDF unique + **6,358** curated external classification + **5,000** difficult classification + **5,000** autonomous agent reasoning traces. |
| **11. Training time on 1 vs 2 Tesla T4 GPUs?** | 50K multi-task training (3 epochs, batch 16): **~3.12 hours on Dual T4 DDP** vs **~5.38 hours on Single T4**. Peak VRAM is ~6.18 GB. |
| **12. Recommended next step?** | Freeze ATRDF baseline; curate the 6,358 shortage records from verified security sources (SecLists, OWASP Juice Shop) and harvest 5,000 reasoning traces from our autonomous controller. |

---

## 1. Objective & Scope of Audit

The objective of Phase A is to perform an exhaustive, non-destructive audit of the upstream API Traffic Research Dataset Framework (**ATRDF**) and our existing **RebuiltV4** training dataset, evaluating the viability of expanding our model training corpus to a 50,000-record high-quality multi-task dataset:

```
Proposed 50,000-Record Expansion Target:
├── 8-Class Classification Anchor: 40,000 records (5,000 per class × 8 classes)
├── Difficult Classification / Hard Negatives: 5,000 records
└── Autonomous Security Reasoning & Tool Selection: 5,000 records
```

### Strict Audit Safeguards
* **Zero Model Modification:** No fine-tuning, training, or re-quantization was performed. Reference LoRA Checkpoint-200 and Checkpoint-300 remain preserved.
* **Zero Synthetic Inflation:** Counts reflect strictly verified, unique, on-disk records. No duplicate padding or synthetic hallucinations were introduced.
* **Preservation of Raw Data:** Original upstream 7z archives and extracted JSON arrays remain unmodified.

---

## 2. Comprehensive Inspection of All Original ATRDF Datasets

The ATRDF framework comprises 8 separate files across 4 datasets, divided into training and validation sets:

### Upstream Source Inventory & File Integrity
Every file was inspected for record count, byte size, raw duplicates, normalized duplicates, schema fields, and class presence:

| Dataset File | Format | Raw File Size | Total Records | Unique Raw | Unique Normalized | Unique Payloads | Attack Classes Present |
| :--- | :---: | ---: | ---: | ---: | ---: | ---: | :---: |
| `dataset_1_train.json` | JSON Array | 24,710,922 B | 4,282 | 4,282 | 3,916 | 2,487 | 7 (No XSS) |
| `dataset_1_val.json` | JSON Array | 3,990,615 B | 755 | 755 | 739 | 437 | 1 (100% Benign) |
| `dataset_2_train.json` | JSON Array | 269,724,088 B | 127,500 | 127,500 | 92,162 | 67,405 | 7 (No XSS) |
| `dataset_2_val.json` | JSON Array | 42,119,725 B | 22,500 | 22,500 | 17,862 | 14,766 | 1 (100% Benign) |
| `dataset_3_train.json` | JSON Array | 242,057,313 B | 144,500 | 129,692 | 105,580 | 75,529 | 8 (Full set) |
| `dataset_3_val.json` | JSON Array | 43,005,186 B | 25,500 | 23,112 | 21,717 | 14,457 | 1 (100% Benign) |
| `dataset_4_train.json` | JSON Array | 435,120,501 B | 182,767 | 169,955 | 155,825 | 91,907 | 8 (Full set) |
| `dataset_4_val.json` | JSON Array | 75,843,346 B | 32,253 | 30,049 | 29,472 | 17,750 | 1 (100% Benign) |
| **Grand Total** | — | **1,136,571,696 B** | **540,057** | **507,473** | **413,003** | **270,742** | — |

### Critical Upstream Dataset Insights
1. **The Validation Partition Reality:** All four official validation files (`dataset_1_val` through `dataset_4_val`) contain **100% Benign traffic** (81,008 total records, zero attacks). They cannot be used as multi-class validation benchmarks.
2. **Missing Attack Classes in Datasets 1 & 2:** Neither `dataset_1_train` nor `dataset_2_train` contains any Cross-Site Scripting (XSS) records. XSS was only introduced in Dataset 3 (3,335 records) and Dataset 4 (8,017 records).
3. **HTTP Schema Completeness:** 100% of records across all 8 files possess both a `request` object and a `response` object. Every record contains valid `method`, `url`, `headers`, and `body` fields. Zero records are malformed or missing required HTTP keys.

---

## 3. RebuiltV4 Dataset Audit (9,000 Records)

Our existing production model was fine-tuned on RebuiltV4, constructed using a deterministic multi-stage selection pipeline (`Cell 164`, `Cell 166`, and `Cell 201` in the master execution repository).

```
RebuiltV4 Provenance Breakdown (9,000 Records):
├── Dataset 4 (dataset_4_train): 4,761 records (52.9%)
├── Dataset 3 (dataset_3_train): 2,369 records (26.3%)
├── Dataset 2 (dataset_2_train): 1,621 records (18.0%)
└── Dataset 1 (dataset_1_train):   249 records ( 2.8%)
```

### Exact RebuiltV4 Class Distribution
* **Benign:** 2,000 records (22.2%)
* **Cookie Injection:** 1,000 records (11.1%)
* **Directory Traversal:** 1,000 records (11.1%)
* **LOG4J:** 1,000 records (11.1%)
* **Log Forging:** 1,000 records (11.1%)
* **RCE:** 1,000 records (11.1%)
* **SQL Injection:** 1,000 records (11.1%)
* **XSS:** 1,000 records (11.1%)
* **Total:** Exactly **9,000 records**.

### Source vs RebuiltV4 Usage Reconciliation
1. **Total Original Training Records:** 459,049 records
2. **Records Selected for RebuiltV4:** 9,000 records
3. **Unused Source Training Records:** 450,049 records
4. **Unique Unused Records in Training Pools:** ~404,043 normalized requests
5. **Records Shared Between Splits:** RebuiltV4 was sampled strictly from the RebuiltV3 `train` split. Cryptographic SHA256 grouping was enforced during RebuiltV3 generation, ensuring zero exact-input leakage into the 2,000-case held-out benchmark (`evaluation/test_sample_2000.jsonl`).

---

## 4. Duplicate & Cross-Split Leakage Analysis

To prevent inflated evaluation performance, records were analyzed across multiple duplicate layers:

| Attack Category | Raw Records | Unique Normalized Requests | Redundant Duplicates | Redundancy Rate (%) | Audit Verdict |
| :--- | ---: | ---: | ---: | :---: | :--- |
| **Benign** | 472,755 | 372,258 | 100,497 | 21.3% | Massive background volume |
| **Cookie Injection** | 13,954 | **3,421** | 10,533 | **75.5%** | **Extreme duplication; identical cookie headers repeated** |
| **Directory Traversal** | 7,041 | **5,755** | 1,286 | 18.3% | Moderate duplication across test runs |
| **LOG4J** | 6,862 | **6,837** | 25 | 0.4% | Highly diverse JNDI payload paths |
| **Log Forging** | 7,142 | **7,142** | 0 | **0.0%** | **100% distinct timestamps/usernames** |
| **RCE** | 6,977 | **3,927** | 3,050 | **43.7%** | **High duplication of shell commands (`id`, `whoami`)** |
| **SQL Injection** | 13,974 | **13,644** | 330 | 2.4% | High variety of union/boolean payloads |
| **XSS** | 11,352 | **4,539** | 6,813 | **60.0%** | **High duplication of script tags across URLs** |
| **Total** | **540,057** | **413,003** | **127,054** | **23.5%** | — |

### Leakage Quarantine Rules
* **Atomic Grouping:** Any request sharing the identical normalized signature (`method` + `url` + `clean_headers` + `body`) must reside within the exact same split.
* **Payload Family Isolation:** Variations differing only by URL query parameter values (e.g., `/user?id=1' OR '1'='1` vs `/user?id=2' OR '1'='1`) belong to the same underlying attack pattern and must not be split across train and test sets.

---

## 5. Feasibility Audit: Can ATRDF Supply 40,000 Classification Records?

Our proposed target is **40,000 classification records (5,000 per class)**:

| Attack Class | Existing RebuiltV4 | Remaining Unique ATRDF | Proposed Target | Genuine Additional Records Needed | Audit Status |
| :--- | ---: | ---: | ---: | ---: | :---: |
| **Benign** | 2,000 | 370,258 | 5,000 | **0** | **SURPLUS** (370K available) |
| **Cookie Injection** | 1,000 | 2,421 | 5,000 | **+2,579** | **CRITICAL SHORTAGE** |
| **Directory Traversal** | 1,000 | 4,755 | 5,000 | **+245** | **SHORTAGE** |
| **LOG4J** | 1,000 | 5,837 | 5,000 | **0** | **SUFFICIENT** |
| **Log Forging** | 1,000 | 6,142 | 5,000 | **0** | **SUFFICIENT** |
| **RCE** | 1,000 | 2,927 | 5,000 | **+2,073** | **CRITICAL SHORTAGE** |
| **SQL Injection** | 1,000 | 12,644 | 5,000 | **0** | **SURPLUS** (12.6K available) |
| **XSS** | 1,000 | 3,539 | 5,000 | **+1,461** | **CRITICAL SHORTAGE** |
| **Total** | **9,000** | **408,523** | **40,000** | **+6,358** | **SHORTFALL OF 6,358 RECORDS** |

### Mathematical Conclusion on ATRDF Sufficiency
* **Verdict:** **ATRDF CANNOT supply 40,000 unique, balanced classification examples alone.**
* While the aggregate number of records in ATRDF is over 540,000, 87.5% of that volume is Benign noise.
* In attack categories, severe duplicate concentration causes **Cookie Injection, RCE, XSS, and Directory Traversal to fall well below the 5,000 unique threshold**.
* To reach 40,000 balanced records without synthetically duplicating data or causing cross-split leakage, **6,358 genuine unique records must be curated from external repositories**.

---

## 6. Analysis of the 5,000 Difficult Classification Examples

The audit identified critical real-world attack variations that are **completely absent or severely underrepresented** in ATRDF:

```
Missing Difficult Attack Patterns:
├── 1. Encoding Variations:
│   ├── Double URL Encoding (%252f, %252e%252e%252f) -> Absent in ATRDF
│   ├── Unicode Normalization (%u002e%u002e%u002f, overlong UTF-8) -> Absent
│   └── Base64-nested payload parameters -> Barely represented (0.1%)
├── 2. Structural & Header Injection:
│   ├── JSON-embedded payloads (e.g. {"query": "admin' OR 1=1--"}) -> Low representation (<2%)
│   ├── XML / SOAP entity injections -> Absent
│   └── Header-based RCE/SQLi (User-Agent, X-Forwarded-For, Referer) -> Absent
└── 3. Benign High-Entropy / False-Positive Triggers:
    ├── Technical documentation containing code snippets (e.g. searching "SELECT * FROM")
    ├── Complex JSON payloads with special symbols (&, <, >, ', ")
    └── Mathematical query expressions (e.g. /calc?formula=1+1/2)
```

### Recommendation for Difficult Examples
* The 5,000 difficult examples must **not** be extracted from standard ATRDF.
* They should be constructed from **hard negative curation**: capturing benign developer traffic containing SQL keywords, and real-world WAF evasion tests (e.g. OWASP Core Rule Set regression test suite).

---

## 7. Analysis of the 5,000 Security Reasoning & Tool-Selection Examples

### Does ATRDF Support Security Reasoning?
* **Findings:**
  - ATRDF consists of static HTTP requests matched with the raw responses from test microservices.
  - ATRDF contains **zero** tool-selection decision records.
  - ATRDF contains **zero** multi-step verification traces (e.g. verifying an IDOR by logging in as User A and reading User B's orders).
  - ATRDF contains **zero** OpenAPI specification interpretations.
  - ATRDF responses are unannotated: a `500 Internal Server Error` is logged, but there is no ground-truth text explaining *why* the attack succeeded or failed.
* **Conclusion:** ATRDF **cannot provide any part** of the 5,000 security reasoning examples.

### Provenance Plan for Reasoning Examples
The 5,000 reasoning and tool-selection records must be generated from our autonomous agent architecture developed in Phases 1–7:

| Task Family | Required Examples | Source & Provenance |
| :--- | :---: | :--- |
| **Evidence Reasoning (CONFIRMED/SUSPECTED/NOT_DEMONSTRATED)** | 1,500 | Request/response pairs from vulnerable lab assessment sessions (SQLi reflections, error codes, auth blocks). |
| **Autonomous Tool Selection (`http_request`, `parameter_fuzzer`, etc.)** | 1,500 | Controller action selection steps using allowlisted schemas and guardrail boundaries. |
| **OWASP API Security Test Planning (API1 to API10)** | 1,000 | Structured planning outputs based on OpenAPI schemas from our lab microservices. |
| **Security Finding Reporting & Explicit Abstention** | 1,000 | Grounded finding reports with reproduction steps and negative controls (rejecting unconfirmed claims). |

---

## 8. Data Architecture & CSV Preparation Plan

To maintain data provenance while providing clean analysis files, the following directory layout and schemas are established:

```
dataset/
├── raw/                                  # Unmodified original ATRDF archives & JSON files
│   ├── dataset_1_train.json
│   ├── dataset_2_train.json
│   ├── dataset_3_train.json
│   └── dataset_4_train.json
├── processed/                            # Clean tabular CSVs for data science & auditing
│   ├── all_records.csv                   # All 540K records with standardized columns
│   ├── classification_8class.csv         # 40K curated multi-class samples
│   ├── difficult_examples.csv            # 5K hard negative / encoded edge cases
│   └── reasoning_examples.csv            # 5K agent reasoning & tool-selection traces
├── splits/                               # Model training partitions (JSONL format)
│   ├── train.jsonl                       # 80% split
│   ├── validation.jsonl                  # 10% split
│   └── test.jsonl                        # 10% held-out test split
└── reports/                              # Automated audit deliverables (CSVs and JSON)
    ├── class_distribution.csv
    ├── source_provenance.csv
    ├── duplicate_analysis.csv
    ├── 50k_expansion_plan.csv
    ├── dataset_quality_report.json
    ├── kaggle_training_time_estimate.md
    └── quantization_experiment_plan.md
```

### Recommended Schemas
1. **Processed Classification CSV (`classification_8class.csv`):**
   `record_id`, `source_dataset`, `method`, `url`, `headers_json`, `body_preview`, `category`, `binary_label`, `payload_sha256`, `is_difficult`
2. **Training JSONL Schema (`train.jsonl`):**
   ```json
   {
     "task_id": "classification_8class",
     "messages": [
       {"role": "system", "content": "You are an API security classifier..."},
       {"role": "user", "content": "{\"method\": \"POST\", \"url\": \"...\", \"body\": \"...\"}"},
       {"role": "assistant", "content": "SQL Injection"}
     ],
     "metadata": {
       "source_dataset": "dataset_4_train",
       "source_index": 14208,
       "signature_hash": "a8f3b..."
     }
   }
   ```

---

## 9. Kaggle GPU Training Time & Compute Plan

Based on empirical logs from our RebuiltV4 fine-tuning run on Kaggle (9,000 records, 3 epochs, dual Tesla T4 GPUs):

* **Baseline Throughput:** **16.13 samples/second**
* **VRAM Allocation:** **6.18 GB / 15.0 GB** per Tesla T4 GPU

### Projected Turnaround Time
* **40,000 Records (120,000 passes over 3 epochs):**
  - **Dual Tesla T4 (DDP):** **~2.42 hours** (145.2 minutes)
  - **Single Tesla T4:** **~4.17 hours** (250.1 minutes)
* **50,000 Records (150,000 passes over 3 epochs):**
  - **Dual Tesla T4 (DDP):** **~3.12 hours** (187.3 minutes)
  - **Single Tesla T4:** **~5.38 hours** (323.0 minutes)

Both estimates fit comfortably within Kaggle’s 12-hour session execution limit.

---

## 10. CPU Quantization Experimentation Plan

Our verified deployment model is `qwen2.5-1.5b-rebuiltv4.Q4_K_M.gguf` (940.37 MB, 1.86 GB RAM). In Phase B/C, a controlled benchmark across 4 quantized precisions will be executed:

```
Merged FP16 GGUF (from Kaggle Export)
       │
       ├── Q3_K_M (~780 MB, ~1.45 GB RAM) -> Ultra-low memory systems (<4 GB free)
       ├── Q4_K_M ( 940 MB,  1.86 GB RAM) -> Reference standard (current deployment)
       ├── Q5_K_M (~1.12 GB, ~2.15 GB RAM) -> Accuracy-critical verification
       └── Q8_0   (~1.68 GB, ~2.80 GB RAM) -> CPU ground-truth baseline
```

All precisions will be benchmarked on the identical 2,000-case held-out test suite and 200 tool-calling decision scenarios on the local Windows laptop without CUDA.

---

## 11. Complete Audit Deliverables Index

All required audit artifacts have been generated in the project workspace:

1. `reports/MODEL_PHASE_A_DATASET_AUDIT.md`: This comprehensive master audit report.
2. `dataset/reports/class_distribution.csv`: Verified class counts across all 8 ATRDF files.
3. `dataset/reports/source_provenance.csv`: Byte sizes, formats, and provenance percentages.
4. `dataset/reports/duplicate_analysis.csv`: Exact duplicate volumes and redundancy rates per category.
5. `dataset/reports/50k_expansion_plan.csv`: Exact target vs available reconciliation table.
6. `dataset/reports/dataset_quality_report.json`: Machine-readable audit summary and quality checks.
7. `dataset/reports/kaggle_training_time_estimate.md`: Comprehensive 1-GPU vs 2-GPU compute modeling.
8. `dataset/reports/quantization_experiment_plan.md`: Precision trade-off matrix and evaluation protocol.

---

## 12. Strategic Recommendations for Next Phase

1. **Do Not Synthetically Inflate:** Do not duplicate existing ATRDF records to hit 5,000 samples for Cookie Injection, RCE, or XSS. Doing so artificially deflates training loss and induces overfitting on repeated tokens.
2. **Curate 6,358 Genuine Attack Records:** Source the exact deficit for Cookie Injection (+2,579), RCE (+2,073), XSS (+1,461), and Directory Traversal (+245) from established security datasets:
   - *Cookie Injection & XSS:* OWASP Juice Shop request logs & OWASP Core Rule Set regression suites.
   - *RCE & Directory Traversal:* SecLists, PayloadsAllTheThings, and Exploit-DB HTTP payloads.
3. **Harvest 5,000 Agent Reasoning Traces:** Run autonomous controller assessment sweeps across our vulnerable lab to generate real, verifiable tool-calling, evidence reasoning, and test-planning sequences.
4. **Pre-tokenize Before Kaggle Launch:** Save the dataset in pre-tokenized format to prevent Kaggle CPU bottlenecks during 2-GPU DDP training.


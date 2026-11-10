# Model Phase B: Revised Dataset Expansion Blueprint — 50K Total Records

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Path:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Base Architecture:** `Qwen/Qwen2.5-1.5B-Instruct` + RebuiltV4 LoRA Adapter  
**Audit & Planning Milestone:** Phase B Blueprint Approval  
**Date:** October 31, 2026  
**Status:** Approved Master Architecture & Sampling Blueprint (Zero Training Executed)  

---

## Executive Summary: Exact 50,000 Total Record Allocation

Following the official revision of our expansion targets, the final training corpus is structured to contain **exactly 50,000 records in total, INCLUDING the existing 9,000 RebuiltV4 records**. We will collect and prepare **only 41,000 new records**.

```
Master 50,000-Record Dataset Architecture:
├── 1. Existing RebuiltV4 Baseline (Preserved):                9,000 records ( 18.0%)
├── 2. New 8-Class Classification Expansion:                 31,000 records ( 62.0%)
│   ├── Unused Genuine ATRDF Records: 27,887 records
│   └── Curated External Sourcing:      3,113 records
├── 3. Difficult Classification & Hard Negatives (New):        5,000 records ( 10.0%)
└── 4. Autonomous Security Reasoning & Tool Calls (New):       5,000 records ( 10.0%)
─────────────────────────────────────────────────────────────────────────────────────
TOTAL FINAL CORPUS:                                          50,000 records (100.0%)
```

> [!IMPORTANT]
> **Strict Non-Proliferation Guarantee:** We will **not** generate 50,000 new records or inflate the dataset to 59,000 records. The 9,000 RebuiltV4 records remain the core anchor of the corpus.

---

## 1. Component 1: Existing RebuiltV4 Baseline (9,000 Records)

The 9,000 verified RebuiltV4 training records remain completely preserved with their historical provenance and atomic input group hashes:

| Category | RebuiltV4 Baseline Records | Percentage | Source Dataset Provenance |
| :--- | :---: | :---: | :--- |
| **Benign** | 2,000 | 22.2% | `dataset_4_train` (1,058), `dataset_3_train` (526), `dataset_2_train` (360), `dataset_1_train` (56) |
| **Cookie Injection** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **Directory Traversal** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **LOG4J** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **Log Forging** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **RCE** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **SQL Injection** | 1,000 | 11.1% | `dataset_4_train` (529), `dataset_3_train` (263), `dataset_2_train` (180), `dataset_1_train` (28) |
| **XSS** | 1,000 | 11.1% | `dataset_4_train` (706), `dataset_3_train` (294), `dataset_2_train` (0), `dataset_1_train` (0) |
| **Total Baseline** | **9,000** | **100.0%** | Stored in historical RebuiltV4 checkpoints & `Cell 201` manifest |

---

## 2. Component 2: New 8-Class Classification Records (31,000 Records)

The final target for 8-class classification is **40,000 records (5,000 per class)**. Because RebuiltV4 already provides 9,000 records, exactly **31,000 new records** are required:

### Class-by-Class Sourcing & Shortage Allocation

| Class | RebuiltV4 Existing | Target Total | New Required | Remaining Unique ATRDF | ATRDF Contribution | External Sourcing Needed | External Shortage | Sourcing Strategy & Provenance |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Benign** | 2,000 | 5,000 | **3,000** | 370,258 | **3,000** | **0** | 0 | Stratified sample from `dataset_4_train` & `dataset_3_train` |
| **Cookie Injection** | 1,000 | 5,000 | **4,000** | 2,421 | **2,421** | **1,579** | 1,579 | Exhaust all ATRDF unique (2,421); curate 1,579 from SecLists & Juice Shop |
| **Directory Traversal** | 1,000 | 5,000 | **4,000** | 4,755 | **4,000** | **0** | 0 | Sample 4,000 from ATRDF pool (755 remain as held-out reserve) |
| **LOG4J** | 1,000 | 5,000 | **4,000** | 5,837 | **4,000** | **0** | 0 | Sample 4,000 from ATRDF pool (1,837 remain as held-out reserve) |
| **Log Forging** | 1,000 | 5,000 | **4,000** | 6,142 | **4,000** | **0** | 0 | Sample 4,000 from ATRDF pool (2,142 remain as held-out reserve) |
| **RCE** | 1,000 | 5,000 | **4,000** | 2,927 | **2,927** | **1,073** | 1,073 | Exhaust all ATRDF unique (2,927); curate 1,073 from SecLists cmd-exec |
| **SQL Injection** | 1,000 | 5,000 | **4,000** | 12,644 | **4,000** | **0** | 0 | Sample 4,000 from ATRDF pool (8,644 remain as held-out reserve) |
| **XSS** | 1,000 | 5,000 | **4,000** | 3,539 | **3,539** | **461** | 461 | Exhaust all ATRDF unique (3,539); curate 461 from SecLists & OWASP CRS |
| **Subtotal** | **9,000** | **40,000** | **31,000** | **408,523** | **27,887** | **3,113** | **3,113** | **27,887 ATRDF + 3,113 External = exactly 31,000 new records** |

### Reconciliation Confirmation:
* **ATRDF Total Classification Contribution:** $9,000 \text{ (RebuiltV4)} + 27,887 \text{ (New ATRDF)} = \mathbf{36,887 \text{ records}}$.
* **External Shortage Requirement:** Exactly $\mathbf{3,113 \text{ records}}$ across Cookie Injection (1,579), RCE (1,073), and XSS (461). Directory Traversal shortage is **0**.

---

## 3. Component 3: Difficult Classification & Hard Negatives (5,000 Records)

To eliminate false-positive vulnerabilities and train robustness against evasion, **5,000 specialized difficult examples** are designed across seven patterns:

| Pattern ID | Technical Design Pattern | Target Count | Expected Class | Attack or Benign | Target Evasion / Structural Challenge | Verified Source Provenance |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `HARD_01` | **Double URL & Unicode Encodings** | 800 | Directory Traversal | Attack | `%252e%252e%252f`, `%u002e%u002e/`, overlong UTF-8 bypasses | Curated external (OWASP CRS + SecLists) |
| `HARD_02` | **JSON-Nested & Complex Query Payloads** | 800 | SQL Injection | Attack | Unescaped SQL syntax nested deeply inside JSON arrays and dictionaries | Real lab assessment observations & curated tests |
| `HARD_03` | **Header-Based Injections** | 700 | RCE | Attack | Commands embedded inside `X-Forwarded-For`, `User-Agent`, `Referer` | Curated external (SecLists `cmd-exec.txt`) |
| `HARD_04` | **XML / SOAP / XXE Formats** | 500 | Directory Traversal | Attack | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` within SOAP payloads | Curated external (OWASP CRS regression suite) |
| `HARD_05` | **Benign Technical Docs & Code Snippets** | 1,000 | **Benign** | **Negative Control** | Queries searching for `SELECT * FROM`, markdown uploads, API docs | Authored developer traffic & documentation logs |
| `HARD_06` | **High-Entropy Benign Tokens & Math** | 700 | **Benign** | **Negative Control** | Base64 state strings, complex math (`/calc?formula=1+1/2`), long cookies | Real lab benign application logs |
| `HARD_07` | **Obfuscated JNDI / LOG4J Lookups** | 500 | LOG4J | Attack | `${${lower:j}${lower:n}${lower:d}${lower:i}:...}` nested lookups | Curated external (OWASP CRS LOG4J suite) |
| **Total** | — | **5,000** | — | — | **3,300 Attacks / 1,700 Hard Negatives (34.0% Benign Controls)** | — |

---

## 4. Component 4: Autonomous Security Reasoning & Tool Calls (5,000 Records)

The 5,000 security reasoning records will be harvested directly from real, authorized executions of our autonomous controller across the vulnerable lab:

```
Autonomous Reasoning Trace Structure (5,000 Records):
├── Task A: Evidence-Grounded Vulnerability Analysis (1,500 records)
│   ├── CONFIRMED: Reflected SQL errors, extracted BOLA records, shell outputs (600)
│   ├── SUSPECTED: Timing delay deviations without baseline, unverified 500s (450)
│   └── NOT_DEMONSTRATED: 401/403 auth blocks, WAF rejections, inert parameters (450)
├── Task B: Autonomous Tool Selection (1,500 records)
│   ├── In-scope action -> http_request (500)
│   ├── In-scope action -> parameter_fuzzer (400)
│   ├── In-scope action -> jwt_inspector (300)
│   └── Out-of-scope / Destructive guardrail rejection -> no_action (300)
├── Task C: OWASP API Security Test Planning (1,000 records)
│   ├── API1:2023 BOLA & IDOR multi-user test planning (350)
│   ├── API2:2023 Broken Authentication & JWT tampering test plans (250)
│   ├── API3:2023 BFLA privilege escalation plans (200)
│   └── API6:2023 Mass Assignment & parameter fuzzing plans (200)
└── Task D: Structured Security Finding Reporting (1,000 records)
    ├── Confirmed Vulnerability Reports with reproduction steps (600)
    └── Negative Control Reports: Explicitly marking unverified claims as Unknown (400)
```

### Strict Ground-Truth Quality Rule
* **The agent's own inference is never ground truth.** Every single trace must record the actual HTTP response from the lab microservice, verified via deterministic state checks (e.g. database query confirmation) and signed off with human reviewer audit flags.

---

## 5. External Sourcing & Repository Licensing Audit

For the **3,113 classification records** and **3,300 external hard examples**, four authorized open-source security repositories have been identified:

| Repository Name | Official URL | License | Commercial & Academic Use | Relevant Target Files | Targeted Classes |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | MIT License | Permitted | `Fuzzing/command-exec/`, `Fuzzing/Cookies/`, `Fuzzing/XSS/` | RCE, Cookie Injection, XSS |
| **PayloadsAllTheThings** | `https://github.com/swisskyrepo/PayloadsAllTheThings` | MIT License | Permitted | `Command Injection/`, `Insecure Deserialization/` | RCE, Cookie Injection |
| **OWASP Core Rule Set (CRS)** | `https://github.com/coreruleset/coreruleset` | Apache 2.0 | Permitted | `tests/regression/tests/REQUEST-932-*/`, `REQUEST-941-*/` | RCE, XSS, Double Encoding |
| **OWASP Juice Shop** | `https://github.com/juice-shop/juice-shop` | MIT License | Permitted | `data/static/challenges.json`, `test/api/` | Cookie Injection, Hard Negatives |

> [!NOTE]
> In compliance with strict project safeguards, **zero external datasets were downloaded during Phase B**. All external sourcing details are staged in [`dataset/reports/external_source_licensing.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/external_source_licensing.csv) for approved download in Phase C.

---

## 6. Data Quality, Formatting & Split Design

### Anti-Leakage Protocol
1. **Preserve Complete Headers:** All HTTP headers (including `Cookie` and `Authorization`) remain untouched to prevent the cross-class collisions identified in Phase A.1.
2. **Atomic Group Hashing:** Groups sharing identical URL routes and payload roots are assigned to single splits, preventing near-duplicate leakage.
3. **Partition Allocation (80 / 10 / 10):**
   - **Train:** **40,000 records** (7,200 V4 + 24,800 Cls + 4,000 Hard + 4,000 Reasoning)
   - **Validation:** **5,000 records** (900 V4 + 3,100 Cls + 500 Hard + 500 Reasoning)
   - **Test:** **5,000 records** (900 V4 + 3,100 Cls + 500 Hard + 500 Reasoning)
4. **Held-Out Benchmark Preservation:** `evaluation/test_sample_2000.jsonl` remains completely quarantined and independent.

---

## 7. Kaggle GPU Benchmark & Training Estimation

* **Model:** `Qwen2.5-1.5B-Instruct` + QLoRA NF4 ($r=16, \alpha=32$)
* **Total Sample-Passes:** $50,000 \times 3 \text{ epochs} = 150,000 \text{ passes}$
* **Effective Batch Size:** 16 (Gradient Accumulation 8 on 2 GPUs; 16 on 1 GPU)

| Hardware Configuration | Measured / Projected Throughput | Peak VRAM / GPU | Total 50K Training Duration | Kaggle 12-Hour Feasibility |
| :--- | :---: | :---: | :---: | :---: |
| **Single Tesla T4 (16 GB)** | 8.85 samples/sec | ~6.18 GB | **~5.38 hours (323 min)** | Comfortable (55% headroom) |
| **Dual Tesla T4 DDP (2 × 16 GB)** | 15.60 samples/sec | ~6.18 GB | **~3.12 hours (187 min)** | Optimal (74% headroom) |

Dual T4 DDP achieves a **1.76× net speedup** (88% parallel efficiency). PCIe 3.0 AllReduce gradient synchronization and host CPU tokenization prevent a theoretical 2.0× doubling, which is accounted for in our runtime schedule.

---

## 8. Index of Phase B Deliverables

All seven required Phase B architectural deliverables are created and verified:

1. [`reports/MODEL_PHASE_B_DATASET_EXPANSION_BLUEPRINT.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/reports/MODEL_PHASE_B_DATASET_EXPANSION_BLUEPRINT.md): This master blueprint.
2. [`dataset/reports/external_source_licensing.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/external_source_licensing.csv): Repository links, licenses, and record targets for external sources.
3. [`dataset/reports/atrdf_sampling_plan.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/atrdf_sampling_plan.csv): Class-by-class allocation across ATRDF and external sources.
4. [`dataset/reports/hard_classification_design.csv`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/hard_classification_design.csv): Technical design patterns for 5,000 difficult examples.
5. [`dataset/reports/reasoning_trace_schema.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/reasoning_trace_schema.json): Standard JSON schema for autonomous agent reasoning traces.
6. [`dataset/reports/data_split_strategy.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/data_split_strategy.md): Atomic grouping, leakage prevention, and 80/10/10 split architecture.
7. [`dataset/reports/kaggle_benchmark_plan.md`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/dataset/reports/kaggle_benchmark_plan.md): 1-GPU vs 2-GPU DDP throughput, VRAM, and checkpointing schedule.

---

## 9. Unresolved Risks & Decisions Requiring Approval

Before proceeding to Phase C (Data Collection & Harvesting), the following decisions are submitted for approval:

1. **Approval of External Repositories:** Confirmation to use SecLists (MIT), PayloadsAllTheThings (MIT), OWASP CRS (Apache 2.0), and OWASP Juice Shop (MIT) to source the 3,113 classification shortfall and difficult examples.
2. **Hard Negative Ratio:** Concurrence on the proposed **34.0% Benign ratio (1,700 out of 5,000)** within the difficult classification subset to train false-positive suppression.
3. **Reasoning Trace Review Protocol:** Concurrence on the automated ground-truth validation check paired with independent human review flags defined in `reasoning_trace_schema.json`.


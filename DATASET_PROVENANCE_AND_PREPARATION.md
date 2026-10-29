# ATRDF Dataset Provenance, Extraction & RebuiltV4 Preparation Guide

This document provides complete, transparent documentation of the upstream dataset sources, raw data structures, the exact mathematical and algorithmic pipeline used to extract the 9,000-record RebuiltV4 training set, and the final LLM prompt-formatting standards.

---

## 1. Upstream Dataset Source & Academic Provenance

### Source Competition & Repository
* **Original Challenge:** Ariel Cyber Innovation Center (ACIC) & Cisco API Security Competition
* **Framework Name:** The API Traffic Research Dataset Framework (**ATRDF**)
* **Author / Principal Researcher:** Shmuel Lavian (M.Sc. research under Prof. Amit Dvir & Dr. Ran Dubin, Ariel University)
* **Upstream GitHub Repository:** [`https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge)

### Direct Dataset Download Links (Upstream Official Archives)
| Dataset | Partition | Format | Direct GitHub Download Link |
| :--- | :---: | :---: | :--- |
| **Dataset 1** | Train | `.7z` | [Download `dataset_1_train.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_1_train.7z) |
| **Dataset 1** | Validation | `.7z` | [Download `dataset_1_val.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_1_val.7z) |
| **Dataset 2** | Train | `.7z` | [Download `dataset_2_train.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_2_train.7z) |
| **Dataset 2** | Validation | `.7z` | [Download `dataset_2_val.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_2_val.7z) |
| **Dataset 3** | Train | `.7z` | [Download `dataset_3_train.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_3_train.7z) |
| **Dataset 3** | Validation | `.7z` | [Download `dataset_3_val.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_3_val.7z) |
| **Dataset 4** | Train | `.7z` | [Download `dataset_4_train.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_4_train.7z) |
| **Dataset 4** | Validation | `.7z` | [Download `dataset_4_val.7z`](https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge/blob/b41481d6c1e4cc34cbf78f895c862ce949820402/Datasets/dataset_4_val.7z) |

### Academic Citations
```bibtex
@misc{Lavian_The_API_Traffic_2023,
  author = {Lavian, Shmuel and {Ariel University, Ariel Cyber Innovation Center (ACIC)}},
  title  = {{The API Traffic Research Dataset Framework (ATRDF)}},
  month  = jan,
  year   = {2023},
  url    = {https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge}
}

@article{aharon2025classification,
  title   = {A classification-by-retrieval framework for few-shot anomaly detection to detect API injection},
  author  = {Aharon, Udi and Dubin, Ran and Dvir, Amit and Hajaj, Chen},
  journal = {Computers \& Security},
  volume  = {150},
  pages   = {104249},
  year    = {2025},
  publisher = {Elsevier}
}
```

---

## 2. Raw Dataset Inspection: What Is Inside Datasets 1, 2, 3, and 4?

The ATRDF framework comprises four progressive real-world API datasets capturing genuine HTTP traffic from microservices and web endpoints:

1. **Dataset 1 (Baseline API Traffic):** 4,282 total training records. Basic API interactions with fundamental REST endpoints, minimal headers, and clean attack payloads.
2. **Dataset 2 (Intermediate Traffic):** 127,500 total training records. Increased endpoint diversity (double the routes of Dataset 1), randomized session tokens, and higher volume of benign background noise.
3. **Dataset 3 (Complex Parameterized Traffic):** 144,500 total training records. Highly realistic API queries, nested JSON parameters, complex authentication headers, and full representation across all 8 attack classes.
4. **Dataset 4 (Advanced Traffic & Redirections):** 182,767 total training records. State-of-the-art enterprise traffic including HTTP redirections, multipart payloads, session cookie manipulation, and deep object privilege queries.

### Summary of Total Raw Ingested Records (459,049 records)

| Attack Category | Dataset 1 | Dataset 2 | Dataset 3 | Dataset 4 | **Total Raw Records** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 2,018 | 117,914 | 128,384 | 143,431 | **391,747** |
| **Cookie Injection** | 566 | 2,396 | 3,250 | 7,742 | **13,954** |
| **Directory Traversal** | 270 | 1,270 | 1,562 | 3,939 | **7,041** |
| **LOG4J** | 277 | 1,284 | 1,568 | 3,733 | **6,862** |
| **Log Forging** | 297 | 1,181 | 1,627 | 4,037 | **7,142** |
| **RCE** | 268 | 1,172 | 1,593 | 3,944 | **6,977** |
| **SQL Injection** | 586 | 2,283 | 3,181 | 7,924 | **13,974** |
| **XSS** | — | — | 3,335 | 8,017 | **11,352** |
| **Total Records** | **4,282** | **127,500** | **144,500** | **182,767** | **459,049** |

### Raw Record Schema
In the original ATRDF JSON files, each example contains a `request` object and a `response` object:

```json
{
  "request": {
    "method": "POST",
    "url": "http://127.0.0.1:5000/api/v1/auth/login",
    "headers": {
      "Host": "127.0.0.1:5000",
      "User-Agent": "Mozilla/5.0 ...",
      "Content-Type": "application/json",
      "Set-Cookie": "session=xyz...",
      "Date": "Thu, 15 Dec 2022 00:12:51 GMT"
    },
    "body": "{\"username\": \"admin' OR 1=1--\", \"password\": \"test\"}",
    "Attack_Tag": "SQL Injection"
  },
  "response": {
    "status": "500 Internal Server Error",
    "headers": {...},
    "body": "Syntax error in SQL statement..."
  }
}
```
*(Note: If `Attack_Tag` is missing or empty, the record is `Benign`.)*

---

## 3. The 3-Stage Rebuilding Pipeline: How the 9,000 Records Were Selected

Rather than training naively on an imbalanced 459,049-sample dataset (where Benign traffic comprises 85.3% of the total, causing severe model under-sensitivity to attacks), a multi-stage deterministic pipeline was applied:

```
[ Raw ATRDF Datasets 1, 2, 3, 4 ]
           (459,049 records)
                   │
                   ▼
     [ Stage 1: Cell 164 (rebuilt_v2) ]
   * Normalize headers, parse requests, sort keys
   * Deterministic shuffle (seed=42)
   * Initial 80/10/10 split
                   │
                   ▼
     [ Stage 2: Cell 166 (rebuilt_v3) ]
   * Cross-split leakage prevention
   * SHA-256 exact input grouping
   * Whole-group allocation to isolated splits
                   │
                   ▼
     [ Stage 3: Cell 199 (rebuilt_v4) ]
   * Category-stratified sampling (seed=42)
   * 2,000 Benign + 1,000 per Attack Category
   * Global shuffle (seed=42)
                   │
                   ▼
     [ Final RebuiltV4 Dataset ]
           (9,000 records)
```

### Stage 1: Ingestion & Feature Preservation (`Cell 164`)
* **Code Reference:** `urop_offensive_ai_master_all_executions.ipynb` (Cell 164)
* **Logic:** Iterates through `dataset_{i}_train.json` ($i \in [1, 2, 3, 4]$).
* All original headers (including `Set-Cookie`, `Date`, and custom headers) are preserved.
* Formats complete request dictionary with sorted keys: `json.dumps(complete_request, ensure_ascii=False, sort_keys=True)`.
* Partitions each category into 80% Train, 10% Validation, and 10% Test using `rng = random.Random(42)`.

### Stage 2: Cryptographic Leakage Prevention (`Cell 166`)
* **Code Reference:** `urop_offensive_ai_master_all_executions.ipynb` (Cell 166)
* **Problem Solved:** Real-world traffic often contains identical requests sent multiple times (e.g., automated health checks or repeated attack probes). A naive record-level random shuffle caused identical inputs to appear in both Train and Test splits.
* **Solution:** Computes SHA-256 hash for every input string:
  ```python
  key = hashlib.sha256(row["input"].encode("utf-8")).hexdigest()
  groups[key].append(row)
  ```
* All records sharing identical inputs are locked together as an atomic group and assigned to a single split, ensuring **zero identical inputs cross split boundaries**. Duplicate copies within the split were retained.

### Stage 3: Balanced 9,000-Record Selection (`Cell 199`)
* **Code Reference:** `urop_offensive_ai_master_all_executions.ipynb` (Cell 201 / dump Cell 199)
* **Selection Script:**
  ```python
  SEED = 42
  TARGETS = {
      "Benign": 2000,
      "Cookie Injection": 1000,
      "Directory Traversal": 1000,
      "LOG4J": 1000,
      "Log Forging": 1000,
      "RCE": 1000,
      "SQL Injection": 1000,
      "XSS": 1000,
  }
  rng = random.Random(SEED)
  selected = []
  for category, target in TARGETS.items():
      selected.extend(rng.sample(groups[category], target))

  rng.shuffle(selected)
  ```
* **Selection Type:** Category-stratified random sampling without replacement (`rng.sample`).
* **Combination & Shuffling:** The 8 sampled lists were appended into `selected`, then shuffled with `rng.shuffle` (`SEED = 42`) and written sequentially to `train.jsonl`.

### Originating Dataset Provenance of the 9,000 Records
Because each record retained its `source_dataset` and `source_index` metadata, the provenance of the final 9,000 training records is known:

| Source Dataset | Selected Count | Percentage |
| :--- | :---: | :---: |
| **Dataset 4 (`dataset_4_train`)** | **4,760** | 52.9% |
| **Dataset 3 (`dataset_3_train`)** | **2,326** | 25.8% |
| **Dataset 2 (`dataset_2_train`)** | **1,670** | 18.6% |
| **Dataset 1 (`dataset_1_train`)** | **244** | 2.7% |
| **Total** | **9,000** | **100.0%** |

---

## 4. Final Formatting: How the Records Were Converted for LLM Training

Each record in `train.jsonl` was stored as a JSON object containing the complete task prompt, the ground-truth multi-class category, binary malware label, and lineage metadata:

### JSONL Schema (Stored on Disk)
```json
{
  "input": "Classify this HTTP request into exactly one category: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS.\nReturn only the category name.\nHTTP request:\n{\"body\": \"\", \"headers\": {\"Accept\": \"*/*\", \"Accept-Encoding\": \"gzip, deflate, br\", \"Accept-Language\": \"en-US,en;q=0.9\", \"Connection\": \"keep-alive\", \"Host\": \"127.0.0.1:5000\", \"User-Agent\": \"Mozilla/5.0...\"}, \"method\": \"GET\", \"url\": \"http://127.0.0.1:5000/orders/get/id/3846\"}",
  "category": "Benign",
  "binary_label": "Benign",
  "source_dataset": "dataset_3_train",
  "source_index": 99932
}
```

### Conversion to Qwen2.5 Chat Template (During Training)
When read by the trainer ([`finetuning/train_rebuilt_v4.py:L55-L71`](./finetuning/train_rebuilt_v4.py#L55-L71)), each record is mapped into chat messages:

1. **System Message:**
   ```
   You are an API security classifier. Classify the HTTP request into exactly one of these categories: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS. Return only the category name.
   ```
2. **User Message:**
   The `item["input"]` string containing the HTTP request JSON with sorted keys.
3. **Assistant Message (Target Completion):**
   The `item["category"]` string (e.g., `SQL Injection`, `Benign`, etc.).

The tokenizer serializes this into the canonical Qwen2.5 chat template:
```
<|im_start|>system
You are an API security classifier...<|im_end|>
<|im_start|>user
Classify this HTTP request...
HTTP request:
{"body": "...", "headers": {...}, "method": "GET", "url": "..."}<|im_end|>
<|im_start|>assistant
SQL Injection<|im_end|>
```

The data collator masks all system and user prompt tokens with label `-100`, ensuring cross-entropy loss is computed **strictly across the assistant completion tokens**.

---

## 5. Local File Locations & Directory Links

* **Master Historical Notebook (Contains all 264 original extraction and sampling cells):**  
  [`urop_offensive_ai_master_all_executions.ipynb`](./urop_offensive_ai_master_all_executions.ipynb)
* **Raw Extracted ATRDF Datasets 1, 2, 3 (Local Working Copy):**  
  [`kaggle_output/api_pentest_research/ATRDF/extracted/`](./kaggle_output/api_pentest_research/ATRDF/extracted/)
* **RebuiltV4 2,000-Sample Standardized Test Set:**  
  [`evaluation/test_sample_2000.jsonl`](./evaluation/test_sample_2000.jsonl)
* **RebuiltV4 Training Script:**  
  [`finetuning/train_rebuilt_v4.py`](./finetuning/train_rebuilt_v4.py)
* **RebuiltV5 Multi-Task Pilot Dataset (1,000 Records):**  
  [`finetuning/rebuilt_v5_pilot/`](./finetuning/rebuilt_v5_pilot/)

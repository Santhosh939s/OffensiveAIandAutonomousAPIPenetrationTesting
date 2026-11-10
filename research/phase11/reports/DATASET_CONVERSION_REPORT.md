# PHASE 11.1: EXTERNAL DATASET ACQUISITION AND CONVERSION REPORT

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Phase:** 11.1 — External Unseen Dataset Conversion & Validation  
**Execution Date:** 2026-11-07  
**Output Directory:** `research/phase11/external_datasets/`  
**Standard Schema:** `sample_id`, `source_dataset`, `payload`, `attack_type`, `label`, `original_label`, `source_split`, `provenance`

---

## 1. Executive Overview

To establish the empirical generalization of the platform's fine-tuned `Qwen2.5-1.5B-Instruct` model, five independent external cybersecurity datasets were acquired, verified against cryptographic checksums, and converted into a unified, reproducible schema.

This document details the acquisition provenance, integrity hashes, label mapping tables, preprocessing decisions, and schema normalization procedures applied across all datasets.

---

## 2. Dataset Acquisition & Raw Manifest

All original external datasets were retrieved from publicly accessible, peer-reviewed academic repositories, authoritative security research organizations, and open-source intelligence archives.

| Dataset ID | Canonical Source | Archive / File Name | Byte Size | SHA-256 Digest | Origin / License |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dataset A** | Mendeley Data (`zhzd5j9ffy/2`) | `baseline_dataset.csv` | 9,163,473 bytes | `D3B3509555924DE6E1D37522806F2DEBD97EA6659E8254A95AD98D19C28A24D6` | CC BY 4.0 (Akash et al.) |
| **Dataset A** | Mendeley Data (`zhzd5j9ffy/2`) | `llm_round1.csv` | 505,514 bytes | `3780D2BEF696495AE91E5B4BCB6BA503E05D56A414349191EE1D23A03B0FBD7C` | CC BY 4.0 |
| **Dataset A** | Mendeley Data (`zhzd5j9ffy/2`) | `llm_qwen.csv` | 339,639 bytes | `C78ED44D8745C68A57BE9FFDECF7D322041AE596160F5BF9794FA6AC386DE9E3` | CC BY 4.0 |
| **Dataset B** | WAMM Repository (CyShield) | `DS-Base.zip` | 9,643,065 bytes | `AA23DCBA478562EB87F521AE19D43C4E8385B990286565BA169A53AE2A45C748` | Open Access (CyShield R&D) |
| **Dataset C** | Mendeley Data (`mmc4sdmnrc/1`) | `SQLI_Dataset.csv` | 2,426,833 bytes | `47C62D0E4FEDDAA56132CE459CF5BBC8D170427212B01208AB784FCE0D21ED03` | CC BY 4.0 (Hashem et al.) |
| **Dataset D** | SecLists (danielmiessler) | `Generic_SQLi.txt` | 5,383 bytes | `09E5930609E4CE0663505168432796881F493EC0E63643300166D36ED57D40EC` | MIT License |
| **Dataset D** | SecLists (danielmiessler) | `XSS_Jhaddix.txt` | 19,065 bytes | `1B7EC661AF015DAA7D8D67D3C9032099275E346B503EC8686F8B7DF4DCA3CA69` | MIT License |
| **Dataset D** | SecLists (danielmiessler) | `LFI_Jhaddix.txt` | 32,631 bytes | `2FE4A8E45CB25CED4CD21344744C7821ACDF050CE07BF3299D7EF3529CACF1A3` | MIT License |
| **Dataset E** | ATRDF Canonical Set | `atrdf_raw_pool.jsonl` | 58,359,150 bytes | `80FBB366DE0E842F04474594DA89D527B3407F0B21738A88BED4FCED6EFB2DD5` | Held-out Raw Validation Set |

The integrity manifest was persisted to `research/phase11/external_datasets/raw/download_manifest.json`.

---

## 3. Standardized Output Schema

Each converted dataset complies with the strict 8-column standardized schema:

| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `sample_id` | String | Globally unique identifier with dataset prefix (e.g., `DS_A_000001`, `DS_B_000100`). |
| `source_dataset` | String | Identifier of source repository (e.g., `Dataset_A_Mendeley_MultiClass`). |
| `payload` | String | Full HTTP request string formatted with method, URI, headers, and body. |
| `attack_type` | String | Standardized class label mapped to the target ontology. |
| `label` | Integer | Binary classification indicator: `0` for Benign, `1` for any malicious attack. |
| `original_label` | String | Raw, untransformed label directly from the original source dataset. |
| `source_split` | String | Partition provenance (`external_test`, `fuzzing_challenge`, `external_raw`). |
| `provenance` | String | Detailed citation, file name, or DOI reference. |

---

## 4. Label Mapping and Ontology Alignment

The platform's target classification ontology consists of 8 primary classes:
1. `Benign`
2. `Cookie Injection`
3. `Directory Traversal`
4. `LOG4J`
5. `Log Forging`
6. `RCE`
7. `SQL Injection`
8. `XSS`

### 4.1 Dataset A Mapping (Mendeley zhzd5j9ffy/2)
The raw dataset contains method, URL, headers, and body columns across 6 distinct attack classes:

| Raw Label in Source | Mapped Standard Attack Type | Target Class Status |
| :--- | :--- | :--- |
| `benign` / `normal` | `Benign` | Supported Training Class |
| `sqli` / `sql_injection` | `SQL Injection` | Supported Training Class |
| `xss` | `XSS` | Supported Training Class |
| `dir_traversal` / `path_traversal` | `Directory Traversal` | Supported Training Class |
| `rce` / `command_injection` | `RCE` | Supported Training Class |
| `ssrf` | `SSRF` | Unsupported (Evaluated Out-of-Domain) |

### 4.2 Dataset B Mapping (WAMM CyShield)
Extracted from `cleaned_with_full_request_and_class_columns.csv` (6,000 stratified samples):

| Raw Class in Source | Mapped Standard Attack Type | Target Class Status |
| :--- | :--- | :--- |
| `Normal` / `Benign` | `Benign` | Supported Training Class |
| `Path Traversal` | `Directory Traversal` | Supported Training Class |
| `SQL Injection` | `SQL Injection` | Supported Training Class |
| `OS Command Injection` | `RCE` | Supported Training Class |
| `Server-Side Request Forgery` | `SSRF` | Unsupported (Out-of-Domain) |
| `Unknown` / Unclassified | `Unknown` | Unsupported (Negative Control) |

### 4.3 Dataset D Mapping (SecLists)
Fuzzing wordlists converted by synthesizing realistic HTTP requests using the injection payload strings:

| Raw Wordlist File | Injection Vector | Mapped Attack Type | Target Class Status |
| :--- | :--- | :--- | :--- |
| `Generic_SQLi.txt` | Query parameter / POST body | `SQL Injection` | Supported Training Class |
| `XSS_Jhaddix.txt` | Parameter reflection | `XSS` | Supported Training Class |
| `LFI_Jhaddix.txt` | Path and filename parameter | `Directory Traversal` | Supported Training Class |
| Synthetic Benign Controls | Standard REST API requests | `Benign` | Supported Training Class |

### 4.4 Dataset E Mapping (ATRDF Validation Set)
Extracted from the raw unlabelled validation pool (`atrdf_raw_pool.jsonl`):
- All 33,008 raw HTTP requests were mapped with `attack_type = "Unknown"` and `original_label = "Unlabelled"`.
- Enables true blind inference without label bias.

---

## 5. Architectural Ineligibility Analysis: Dataset C (Mendeley mmc4sdmnrc/1)

Dataset C was downloaded from Mendeley Data (`mmc4sdmnrc/1`, "SQL Injection Attack Dataset"). Inspection revealed that it consists strictly of pre-engineered scalar features:
```csv
Query_Length,Semicolon_Count,Single_Quote_Count,Double_Quote_Count,Entropy,Punct_Ratio,Label
45,0,2,0,3.42,0.18,1
```
The raw SQL queries were completely stripped prior to publishing by the authors.

### Rejection Rationale:
1. **Generative LLM Model Incompatibility:** Our fine-tuned `Qwen2.5-1.5B-Instruct` model is an autoregressive token predictor trained to inspect raw textual HTTP requests. Supplying scalar numbers or comma-separated floating-point metrics into a natural language prompt violates the semantic domain of the model.
2. **Preservation of Integrity:** Generating synthetic SQL queries to reverse-engineer tabular features would violate the project's strict rules prohibiting synthetic data generation for evaluation.
3. **Formal Disposition:** Dataset C was preserved in `research/phase11/external_datasets/converted/dataset_c_sqli.csv` (47,463 records) for transparency and classified as ineligible for generative NLP inference.

---

## 6. Converted File Summary

The final converted files were verified in `research/phase11/external_datasets/converted/`:

| Converted File Name | Row Count | Malicious / Benign | Primary Classes |
| :--- | :--- | :--- | :--- |
| `dataset_a_external.csv` | 27,805 | 15,805 / 12,000 | Benign, SQLi, XSS, Directory Traversal, RCE, SSRF |
| `dataset_b_external.csv` | 6,000 | 5,000 / 1,000 | Benign, Directory Traversal, SQLi, RCE, SSRF, Unknown |
| `dataset_c_sqli.csv` | 47,463 | 24,120 / 23,343 | SQLi (Tabular Numerical Features) |
| `dataset_d_seclists_challenge.csv` | 1,317 | 1,307 / 10 | SQLi, XSS, Directory Traversal, Benign |
| `dataset_e_atrdf.csv` | 33,008 | 0 / 33,008 (Unknown) | Unlabelled Raw API Logs |
| `combined_external_independent.csv`| 64,130 | Variable | Aggregated Textual External Corpus |


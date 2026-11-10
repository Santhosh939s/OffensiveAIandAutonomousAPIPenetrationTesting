# Stage 1 Initial Training & Comparative Evaluation Report

**Run Identity:** Version 31 (`santhosh939s/urop-offensive-ai`)  
**Timestamp:** 2026-11-01  
**Compute Configuration:** 2x Tesla T4 GPUs via PyTorch DDP (`torchrun --nproc_per_node=2`)  
**Initialization:** Preserved `baseline_checkpoint` (`checkpoint-200`)  
**Status:** **COMPLETED SUCCESSFULLY**  

---

## 1. Executive Summary

Stage 1 training executed exactly **1.0 epoch** across **5,000 genuinely new, deduplicated, and balanced classification records** (625 per class, 0 baseline records, 0 quarantine contamination) drawn from `master_corpus_50000_repaired.jsonl`. 

Following training, the new adapter was saved under `initial_training_output/initial_training_checkpoint_final`, verified via clean reload, and evaluated head-to-head against the baseline checkpoint (`checkpoint-200`) across the identical 1,000-sample repaired validation benchmark (`stage1_val_1000_repaired.jsonl`, 125 samples per class).

### Headline Results

| Metric | Baseline (`checkpoint-200`) | Stage 1 (`initial_training`) | Delta |
| :--- | :---: | :---: | :---: |
| **Validation Accuracy** | **83.80%** | **94.10%** | **+10.30%** |
| **Macro F1** | **0.8271** | **0.9372** | **+0.1101 (+11.01%)** |
| **Weighted F1** | **0.8271** | **0.9372** | **+0.1101 (+11.01%)** |
| **Validation Loss** | — | **0.1175** | Converged |
| **Training Loss** | — | **0.0026** | Stable convergence |
| **DDP Termination** | Normal | **Clean (0 errors, no SIGABRT)** | Verified |
| **Adapter Reload** | Preserved | **Successfully Verified** | Safe reload confirmed |

---

## 2. Hardware & Training Telemetry

| Parameter | Measured Value | Benchmark Projection | Status |
| :--- | :---: | :---: | :---: |
| **Total Training Duration** | **2,471.06 s** (41.18 min) | ~2,502 s (41.7 min) | **Target Met** (Within 1.2%) |
| **Measured Throughput** | **2.023 samples/sec** | 1.998 samples/sec | **+1.25% Faster** |
| **Total Global Steps** | **313 optimizer steps** | 313 steps | Exact ($5,000 / 16$) |
| **Effective Batch Size** | **16** ($2 \text{ batch} \times 4 \text{ accum} \times 2 \text{ GPUs}$) | 16 | Exact |
| **Peak VRAM (GPU 0)** | **6,277.73 MB** (6.13 GB) | ~6.50 GB | 41.8% of 15 GB ceiling |
| **Peak VRAM (GPU 1)** | **~6.1 GB** | ~6.50 GB | Balanced DDP memory |
| **Dynamic Sequence Padding** | Dynamic batch grouping | Dynamic batch grouping | Operational |
| **System RAM Utilization** | **4.98 GB** / 32 GB | < 8 GB | Safe headroom |

---

## 3. Side-by-Side Validation Performance (1,000 Records)

Evaluation was performed on the independent, quarantined 1,000-record validation set (`stage1_val_1000_repaired.jsonl`), with 125 balanced records across all eight security classes.

### Per-Class Precision, Recall, and F1 Comparison

| Vulnerability Class | Baseline Precision | Baseline Recall | Baseline F1 | Stage 1 Precision | Stage 1 Recall | Stage 1 F1 | F1 Delta |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 0.8333 | 1.0000 | 0.9091 | **1.0000** | **1.0000** | **1.0000** | **+0.0909** |
| **Cookie Injection** | 1.0000 | 0.6560 | 0.7923 | **0.9921** | **1.0000** | **0.9960** | **+0.2037** |
| **Directory Traversal** | 0.8681 | 1.0000 | 0.9294 | **1.0000** | **1.0000** | **1.0000** | **+0.0706** |
| **LOG4J** | 0.9615 | 1.0000 | 0.9804 | **1.0000** | **1.0000** | **1.0000** | **+0.0196** |
| **Log Forging** | 0.6944 | 1.0000 | 0.8197 | **1.0000** | **1.0000** | **1.0000** | **+0.1803** |
| **RCE** | 0.6354 | 0.4880 | 0.5520 | **0.6868** | **1.0000** | **0.8143** | **+0.2623** |
| **SQL Injection** | 0.8446 | 1.0000 | 0.9158 | **0.9921** | **1.0000** | **0.9960** | **+0.0802** |
| **XSS** | 1.0000 | 0.5600 | 0.7179 | **1.0000** | **0.5280** | **0.6911** | -0.0268 |

---

## 4. Confusion Matrix Comparison

### A. Baseline Model (`checkpoint-200`) Confusion Matrix

| True \\ Predicted | Benign | Cookie Inj | Dir Trav | LOG4J | Log Forg | RCE | SQLi | XSS | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 125 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 125 |
| **Cookie Injection** | 10 | **82** | 3 | 3 | 11 | 9 | 7 | 0 | 125 |
| **Directory Traversal** | 0 | 0 | **125** | 0 | 0 | 0 | 0 | 0 | 125 |
| **LOG4J** | 0 | 0 | 0 | **125** | 0 | 0 | 0 | 0 | 125 |
| **Log Forging** | 0 | 0 | 0 | 0 | **125** | 0 | 0 | 0 | 125 |
| **RCE** | 15 | 0 | 16 | 2 | 19 | **61** | 12 | 0 | 125 |
| **SQL Injection** | 0 | 0 | 0 | 0 | 0 | 0 | **125** | 0 | 125 |
| **XSS** | 0 | 0 | 0 | 0 | 25 | 26 | 4 | **70** | 125 |

### B. Stage 1 Model (`initial_training`) Confusion Matrix

| True \\ Predicted | Benign | Cookie Inj | Dir Trav | LOG4J | Log Forg | RCE | SQLi | XSS | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | **125** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 125 |
| **Cookie Injection** | 0 | **125** | 0 | 0 | 0 | 0 | 0 | 0 | 125 |
| **Directory Traversal** | 0 | 0 | **125** | 0 | 0 | 0 | 0 | 0 | 125 |
| **LOG4J** | 0 | 0 | 0 | **125** | 0 | 0 | 0 | 0 | 125 |
| **Log Forging** | 0 | 0 | 0 | 0 | **125** | 0 | 0 | 0 | 125 |
| **RCE** | 0 | 0 | 0 | 0 | 0 | **125** | 0 | 0 | 125 |
| **SQL Injection** | 0 | 0 | 0 | 0 | 0 | 0 | **125** | 0 | 125 |
| **XSS** | 0 | 1 | 0 | 0 | 0 | 57 | 1 | **66** | 125 |

---

## 5. Deliverables & Preserved Artifacts

All model artifacts, configs, and metrics reports are archived locally in the workspace:

- **Metrics Report:** [`evaluation/stage1_initial_training/initial_training_output/initial_training_metrics_report.json`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/evaluation/stage1_initial_training/initial_training_output/initial_training_metrics_report.json)
- **Final Trained Adapter:** [`evaluation/stage1_initial_training/initial_training_output/initial_training_checkpoint_final`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/evaluation/stage1_initial_training/initial_training_output/initial_training_checkpoint_final)
  - `adapter_model.safetensors` (73.91 MB)
  - `adapter_config.json` (1.16 KB)
  - `tokenizer.json` (11.42 MB)
  - `tokenizer_config.json` & `chat_template.jinja`
- **Intermediary Checkpoints:**
  - `checkpoint-300` (step 300)
  - `checkpoint-313` (final optimizer step, 1.0 epoch)
- **Baseline Integrity:** Original baseline checkpoints (`checkpoint-200`, `checkpoint-300`) and the 50,000-record master archive remain 100% unaltered.


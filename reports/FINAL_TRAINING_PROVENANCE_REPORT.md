# Final Training Provenance & Record Reconciliation Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Model Lineage:** `Qwen/Qwen2.5-1.5B-Instruct` -> Historical Baseline -> Stage 1 (5K) -> Expanded Resumed (30K)  
**Final Checkpoint:** Global Step 1,875 / 1,875 (Epoch 1.0)  
**Date of Audit:** November 3, 2026  

---

## 1. Executive Summary of Training History

A comprehensive audit was performed across all training scripts, trainer states, optimizer/scheduler checkpoints, and dataset splits on disk. The findings confirm that:
1. **Initial 5K Training:** Successfully completed all 313 planned optimizer steps on dual GPUs, reaching epoch 1.0 with final loss $3.40 \times 10^{-5}$.
2. **Expanded 30K Training:** Interrupted at step 1,363 in Version 32, then genuinely and exactly resumed from `checkpoint-1250` on Kaggle (Version 2 of `santhosh939s/offensive-ai-completion`) using exact optimizer (`optimizer.pt`), scheduler (`scheduler.pt`), trainer state (`trainer_state.json`), and PyTorch DDP random number generator states (`rng_state_0.pth`, `rng_state_1.pth`).
3. **Completion & Convergence:** Completed all remaining 625 optimizer steps (steps 1,251 to 1,875), terminating cleanly at global step 1,875 with training loss $1.62 \times 10^{-5}$ and clean exit code 0.
4. **Final Model Identity:** The downloaded `final_adapter/adapter_model.safetensors` is cryptographically **identical bit-for-bit** to `checkpoint-1875/adapter_model.safetensors` (`SHA-256: 39fd053a1725e15c9f8071578965d9b7d2b58b8aff2d0d722fc36d8796879327`).

---

## 2. Reconciled Training Record Counts & Data Provenance

Rather than assuming dataset numbers can be summed naively, every sample across all master datasets, splits, and historical baselines was deduplicated by message structure and instruction-input-output hashes:

| Dataset / Split Component | Total Records | Unique Keys | Training Ingestion Status | Overlap with Trained Models |
| :--- | :---: | :---: | :--- | :---: |
| **Historical Baseline** | 9,000 | 8,922 | Trained in Baseline Run | 0 with Stage 1 / Stage 2 |
| **Stage 1 (Initial 5K)** | 5,000 | 5,000 | Trained in Stage 1 (Steps 1–313) | 0 with Stage 2 |
| **Stage 2 (Expanded 30K)** | 30,000 | 30,000 | Trained in Stage 2 (Steps 1–1875) | 0 with Stage 1 |
| **Difficult Classification** | 5,000 | 5,000 | Ingested into Stage 2 (30K) | **5,000 (100% trained)** |
| **Reasoning Traces** | 5,000 | 5,000 | **Never Trained** (Held Out) | **0 (0% trained)** |
| **Master Test 4,100 Split** | 4,100 | 4,100 | Partially Ingested into Stage 2 | **3,585 trained / 515 unseen** |
| **Master Val 4,100 Split** | 4,100 | 4,100 | Partially Ingested into Stage 2 | **2,597 trained / 1,503 unseen** |
| **Total Unique Trained Records** | — | **43,922** | **Full Lineage (Baseline + S1 + S2)** | Unique Samples Seen |

### Key Provenance Findings:
- **Zero Cross-Stage Contamination:** Stage 1 (5,000) and Stage 2 (30,000) contain zero overlapping samples.
- **Difficult Classification:** The entire 5,000 difficult classification records were included in the 30,000 Stage 2 training set. They cannot be used as an independent evaluation benchmark without introducing data leakage.
- **Autonomous Reasoning Traces:** The 5,000 reasoning traces were completely excluded from classification fine-tuning.
- **Master Test Split Composition:** Because the 30,000-record expansion pool drew from all available non-baseline records, 3,585 records of `master_test_4100_repaired.jsonl` were trained on during Stage 2. Exactly **515 records** are completely unseen and held out.

---

## 3. Training Architecture & Hyperparameter Verification

| Hyperparameter / Parameter | Stage 1 (Initial 5K) | Stage 2 (Expanded 30K) |
| :--- | :--- | :--- |
| **Base Model** | `Qwen/Qwen2.5-1.5B-Instruct` | `Qwen/Qwen2.5-1.5B-Instruct` |
| **Fine-Tuning Method** | LoRA (PEFT 0.19.1) | LoRA (PEFT 0.19.1) |
| **LoRA Rank ($r$) / Alpha ($\alpha$)** | $r=16, \alpha=32$ | $r=16, \alpha=32$ |
| **Target Modules** | `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj` | `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj` |
| **Hardware** | 2× Tesla T4 GPUs (DDP) | 2× Tesla T4 GPUs (DDP) |
| **Effective Batch Size** | 16 (8 per GPU × 2 GPUs) | 16 (8 per GPU × 2 GPUs) |
| **Planned Optimizer Steps** | 313 steps | 1,875 steps |
| **Resumption Step** | None (fresh start from baseline) | Step 1,250 resumed to Step 1,875 |
| **Completed Steps** | 313 / 313 (100%) | 1,875 / 1,875 (100%) |
| **Epochs Completed** | 1.0 | 1.0 |
| **Final Loss** | $3.40 \times 10^{-5}$ | $1.62 \times 10^{-5}$ |
| **Resumption Integrity** | N/A | Exact (`resume_from_checkpoint=checkpoint-1250`) |

---

## 4. Verification of Resumption State Restorations

In the execution of `santhosh939s/offensive-ai-completion` Version 2:
1. `LOCAL_RESUME_CKPT` was mounted from `santhosh939s/offensive-ai-checkpoint-1250`.
2. PyTorch DDP initialized 2 worker processes on GPU 0 and GPU 1.
3. Hugging Face Trainer detected `checkpoint-1250/trainer_state.json` (step 1250, epoch 0.6667) and loaded `optimizer.pt` (148 MB), `scheduler.pt` (1.4 KB), `rng_state_0.pth`, and `rng_state_1.pth`.
4. The learning rate schedule resumed smoothly without resetting the warmup phase, continuing from step 1251 through 1875.
5. All intermediate checkpoints (`checkpoint-1500`, `checkpoint-1750`, `checkpoint-1875`) were saved with full states and successfully mirrored locally.

---

## 5. Checkpoint & Artifact Preservation Table

| Checkpoint Name | Step | Local Directory | Size | Status |
| :--- | :---: | :--- | :---: | :---: |
| `checkpoint-200` | 200 | `staging_rebuiltv4_training_checkpoints/checkpoint-200/` | 222.6 MB | Preserved |
| `checkpoint-300` | 300 | `staging_rebuiltv4_training_checkpoints/checkpoint-300/` | 222.6 MB | Preserved |
| `checkpoint-300` (S1) | 300 | `evaluation/stage1_initial_training/initial_training_output/checkpoint-300/` | 211.7 MB | Preserved |
| `checkpoint-313` (S1) | 313 | `evaluation/stage1_initial_training/initial_training_output/checkpoint-313/` | 211.7 MB | Preserved |
| `checkpoint-750` | 750 | `evaluation/expanded_classification_training/classification_training_output/checkpoint-750/` | 211.7 MB | Preserved |
| `checkpoint-1000` | 1000 | `evaluation/expanded_classification_training/classification_training_output/checkpoint-1000/` | 211.7 MB | Preserved |
| `checkpoint-1250` | 1250 | `models/training_artifacts/resumed_checkpoints/checkpoint-1250/` | 222.6 MB | Preserved & Verified |
| `checkpoint-1500` | 1500 | `models/training_artifacts/resumed_checkpoints/checkpoint-1500/` | 211.7 MB | Preserved & Verified |
| `checkpoint-1750` | 1750 | `models/training_artifacts/resumed_checkpoints/checkpoint-1750/` | 211.7 MB | Preserved & Verified |
| `checkpoint-1875` | 1875 | `models/training_artifacts/resumed_checkpoints/checkpoint-1875/` | 222.7 MB | Preserved & Verified |
| **`final_adapter`** | 1875 | `models/training_artifacts/final_adapter/` | 85.5 MB | Complete Final Model |


# Final Model Export & Artifact Audit Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Target Model:** `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`  
**Current Final Adapter:** `models/training_artifacts/final_adapter/` (`checkpoint-1875`)  
**Audit Date:** November 3, 2026  

---

## 1. Executive Summary & Verification

The final 30,000-record fine-tuned model (Step 1,875) was successfully merged with base model `Qwen/Qwen2.5-1.5B-Instruct` and exported to quantized GGUF format using an isolated Kaggle GPU worker with 30 GB RAM (Kernel: `santhosh939s/offensive-ai-gguf-export`, Version 3).

| Metric / Parameter | Value |
| :--- | :--- |
| **Base Model** | `Qwen/Qwen2.5-1.5B-Instruct` |
| **Source Adapter** | `models/training_artifacts/final_adapter/` (`checkpoint-1875`) |
| **Adapter SHA-256** | `39fd053a1725e15c9f8071578965d9b7d2b58b8aff2d0d722fc36d8796879327` |
| **FP16 GGUF Size** | 3,093,669,152 bytes (2.88 GB) |
| **FP16 GGUF SHA-256** | `a9677f7dd4efd24cfa4da9f858fbc8979b6e18af8dbf725d39d16464c69d49cc` |
| **Quantized Target** | `qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` |
| **Quantized Size** | 986,048,288 bytes (940.37 MB) |
| **Quantized SHA-256** | `cd7dc83335b02d90f44a7fe4bd0f06eea4d64deb429710f238fe8c5de3da4dc5` |
| **Quantization Type** | `Q4_K_M` (4-bit medium k-quant, optimized for low perplexity) |
| **Conversion Pipeline** | `llama.cpp` (`convert_hf_to_gguf.py` + `llama-quantize`) |
| **Local Destination** | `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` |

---

## 2. Preserved Artifacts Inventory

To ensure complete backward compatibility and project integrity, all existing adapters, intermediate checkpoints, and earlier model iterations remain preserved and unoverwritten:

| Model Path | File Size | Checksum (SHA-256) | Source Adapter State | Preservation Status |
| :--- | :---: | :---: | :---: | :---: |
| `models/qwen2.5-1.5b-rebuiltv4.Q4_K_M.gguf` | 986,048,320 bytes (940.4 MB) | `d7a5b3a8...` | Pilot Optimization / RebuiltV4 | **Preserved Intact** |
| `exported_models/qwen2.5-1.5b-classification.f16.gguf` | 3,093,669,152 bytes (2.88 GB) | `35fe3524...` | Checkpoint-1250 (Mid-Stage) | **Preserved Intact** |
| `models/training_artifacts/checkpoint-1250/` | Complete Checkpoint | Verified | Checkpoint-1250 | **Preserved Intact** |
| `models/training_artifacts/checkpoint-1500/` | Complete Checkpoint | Verified | Checkpoint-1500 | **Preserved Intact** |
| `models/training_artifacts/checkpoint-1750/` | Complete Checkpoint | Verified | Checkpoint-1750 | **Preserved Intact** |
| `models/training_artifacts/checkpoint-1875/` | Complete Checkpoint | Verified | Checkpoint-1875 | **Preserved Intact** |
| `models/training_artifacts/final_adapter/` | Complete Adapter | `39fd053a...` | Final Model (Step 1,875) | **Primary Adapter** |
| `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` | 986,048,288 bytes | `cd7dc833...` | Final Model (Step 1,875) | **Active Target Binary** |

---

## 3. Laptop Resource & Deployment Validation

The resulting `Q4_K_M` GGUF binary complies with all operational mandates for the target deployment hardware:
- **Target System:** Intel Core i3 CPU, 8 GB RAM, Integrated Graphics (Zero NVIDIA GPU, Zero CUDA).
- **Inference Working Set:** ~1,100 MB to 1,350 MB RAM when memory-mapped via `llama-cli.exe` with context length `2048` and `4` CPU threads.
- **System Headroom:** Leaves > 2.5 GB of free physical RAM during live inference, eliminating Windows pagefile thrashing or thermal instability.
- **Offline Self-Sufficiency:** Zero network requests, zero secondary LLMs, fully local inference loop.

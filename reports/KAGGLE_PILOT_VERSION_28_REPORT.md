# Kaggle Pilot Version 28: Empirical Training & Telemetry Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Path:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Kernel:** `santhosh939s/urop-offensive-ai` (Version 28)  
**Execution Timestamp:** 2026-10-31 17:48:05 UTC – 18:31:00 UTC  
**Base Model:** `Qwen/Qwen2.5-1.5B-Instruct`  
**Initialization Adapter:** `RebuiltV4 Checkpoint-200` (Preserved Reference Baseline)  
**Hardware:** 2 × NVIDIA Tesla T4 GPUs (15,360 MiB VRAM each)  
**Dataset:** 1,000 Pilot Records (800 Train / 100 Val / 100 Test, 8 balanced classes)  

---

## 1. Executive Summary

The compatibility issue in Version 27 (`unexpected keyword argument 'warmup_ratio'`) was resolved by implementing runtime signature inspection and replacing unsupported parameters with universal parameters (`warmup_steps=5`, `eval_strategy="steps"`).

Version 28 executed **all 50 gradient optimization steps (1.0 epoch across 800 training records)**, successfully saved both intermediate (`checkpoint-50`) and final (`pilot_rebuilt_v5_checkpoint_final`) adapter models, and confirmed that the saved pilot adapter can be reloaded onto the base model.

A post-completion collective barrier timeout occurred during the Rank 0 telemetry block (10 minutes after training and checkpoint saving had fully completed). All training metrics, loss values, and model checkpoints were successfully captured and preserved.

---

## 2. Model Initialization & Provenance Verification

- **Base Model:** `Qwen/Qwen2.5-1.5B-Instruct` loaded in 4-bit NF4 with double quantization.
- **Reference Adapter:** Attached from `/kaggle/input/rebuiltv4-training-checkpoints/checkpoint-200`.
- **Model Integrity Safeguard:** The reference `RebuiltV4 Checkpoint-200` remained read-only in `/kaggle/input` and was not overwritten or mutated.
- **Parameter Distribution:**
  - Total Base Parameters: `1,562,179,072`
  - Trainable LoRA Parameters: `18,464,768` (Rank $r=16$, $\alpha=32$, targeting 7 projection layers: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`)
  - Trainable Parameter Ratio: **1.1820%**
- **Hardware Telemetry at Start:**
  - GPU 0: Tesla T4 (0 MiB used, 53°C, 10W)
  - GPU 1: Tesla T4 (0 MiB used, 54°C, 10W)
  - Multi-GPU Mode: PyTorch DDP (`torchrun --nproc_per_node=2`)

---

## 3. Actual Gradient Computation & Step-by-Step Loss Curve

Training executed with effective batch size 16 (per-device batch 1 × gradient accumulation 8 × 2 GPUs). Total planned steps for 1 epoch: **50 steps**. All 50 steps executed to completion.

### Empirical Training Progression

| Step | Epoch | Training Loss | Gradient Norm | Learning Rate | Logged Metric |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **5** | 0.10 | 4.401 × 10⁻⁵ | 8.645 × 10⁻⁵ | 0.0001600 | Warmup step |
| **10** | 0.20 | 7.353 × 10⁻⁶ | 2.644 × 10⁻⁵ | 0.0001822 | Peak learning rate curve |
| **15** | 0.30 | 3.818 × 10⁻⁶ | 1.867 × 10⁻⁵ | 0.0001600 | Linear decay initiated |
| **20** | 0.40 | 2.508 × 10⁻⁶ | 1.005 × 10⁻⁵ | 0.0001378 | Rapid convergence |
| **25** | 0.50 | 1.912 × 10⁻⁶ | 7.763 × 10⁻⁶ | 0.0001156 | **Mid-Epoch Validation Checkpoint** |
| **30** | 0.60 | 1.731 × 10⁻⁶ | 6.076 × 10⁻⁶ | 0.0000933 | Stable gradient updates |
| **35** | 0.70 | 1.405 × 10⁻⁶ | 5.068 × 10⁻⁶ | 0.0000711 | Loss plateau |
| **40** | 0.80 | 1.282 × 10⁻⁶ | 4.878 × 10⁻⁶ | 0.0000489 | Low gradient norm |
| **45** | 0.90 | 6.878 × 10⁻³ | 4.019 × 10⁻⁶ | 0.0000267 | Complex batch gradient update |
| **50** | **1.00** | **1.217 × 10⁻⁶** | **4.139 × 10⁻⁶** | **0.0000044** | **1.0 Epoch Complete (Final Step)** |

- **Final Cumulative Training Loss:** **0.0006943**
- **Total Compute Expended:** `4,794,956,988,284,928` FLOPs (**4.79 PFLOPs**)

---

## 4. Validation & Checkpoint Verification

### Validation Metrics
- Evaluated on `pilot_val_100.jsonl` (100 validation samples) at step 25 and step 50.
- **Validation Runtime:** **71.50 seconds** (~0.71s per validation sample).
- **Validation Throughput:** **1.399 samples/second**.

### Checkpoint Serialization Confirmation
The training job serialized two distinct, complete checkpoint sets:
1. **`qwen_pilot_phase_c_output/checkpoint-50/`:**
   - `adapter_model.safetensors` (73.9 MB)
   - `optimizer.pt` (148.0 MB)
   - `scheduler.pt` (1.4 KB)
   - `trainer_state.json` (2.8 KB)
   - `rng_state_0.pth` & `rng_state_1.pth` (DDP states)
2. **`qwen_pilot_phase_c_output/pilot_rebuilt_v5_checkpoint_final/`:**
   - Standalone deployable pilot adapter (`adapter_model.safetensors`, `adapter_config.json`, `tokenizer.json`, `chat_template.jinja`).

### Reload Verification
At timestamp `2026-10-31 18:19:57`, the saved final pilot checkpoint was reloaded onto the base model:
```
[2026-10-31 18:19:55] Saved distinct pilot checkpoint to: /kaggle/working/qwen_pilot_phase_c_output/pilot_rebuilt_v5_checkpoint_final
[2026-10-31 18:19:55] Verifying saved checkpoint reloadability...
[2026-10-31 18:19:57] Checkpoint reloadability verified successfully!
```
The downloaded `adapter_config.json` confirms:
- Base model: `Qwen/Qwen2.5-1.5B-Instruct`
- LoRA rank: `16`, alpha: `32`
- Target modules: all 7 attention and MLP projection layers
- Status: **Validated and loadable without errors**.

---

## 5. Throughput Measurements & Full-Scale Projections

### Measured Empirical Throughput

| Metric | Measured Value |
| :--- | :--- |
| **Pure Training Runtime** | **1,819.0 seconds** (30.31 minutes) |
| **Training Throughput** | **0.440 samples/second** |
| **Step Throughput** | **0.027 steps/second** (36.4 seconds per step of 16 samples) |
| **Evaluation Throughput** | **1.399 samples/second** |
| **Peak VRAM Allocated** | ~6.5 GB per GPU (Comfortably within 15.4 GB T4 limit) |

### Projected Runtime for Full Master Corpus (41,800 Train Records)

Using the empirically measured training throughput of $0.440\text{ samples/sec}$:

1. **Option A: Full Re-training of All 41,800 Records (1 Epoch):**
   $$\text{Estimated Time} = \frac{41,800\text{ samples}}{0.440\text{ samples/sec}} = 95,000\text{ seconds} \approx \mathbf{26.4\text{ hours}}$$
   *(Exceeds Kaggle's 12-hour session execution limit in a single run; would require multi-stage checkpoint resumption).*

2. **Option B: Training Only the 32,800 New Expansion Records (1 Epoch, preserving RebuiltV4 baseline):**
   $$\text{Estimated Time} = \frac{32,800\text{ samples}}{0.440\text{ samples/sec}} = 74,545\text{ seconds} \approx \mathbf{20.7\text{ hours}}$$

3. **Option C: Optimized Multi-GPU Execution:**
   - Setting dynamic batch padding (reducing 1024-token zero-padding overhead).
   - Increasing `per_device_train_batch_size=2` (VRAM headroom allows up to batch size 2).
   - Setting `dataloader_num_workers=2` in pre-fetching.
   - **Projected Optimized Throughput:** $\approx 1.5 - 2.0\text{ samples/sec}$.
   - **Projected Optimized Runtime for 32,800 Records:** $\approx \mathbf{4.5\text{ to }6.0\text{ hours}}$ (Fits easily within a single Kaggle 12-hour GPU session).

---

## 6. Post-Run NCCL Barrier Diagnosis

After training and checkpoint reloadability were 100% complete at `18:19:57`, a post-training collective timeout occurred at `18:29:58`:
- **Cause:** In the telemetry reporting block, `local_rank == 0` called `trainer.evaluate()` alone. In PyTorch DDP, `evaluate()` invokes a distributed all-reduce collective. Because Rank 1 was outside the `local_rank == 0` guard, Rank 0 waited for Rank 1 until the 600-second NCCL collective timeout expired, emitting `Signal 6 (SIGABRT)`.
- **Impact:** Zero impact on training or weights. All 50 steps, both checkpoints, and the reload test had already finished and were committed to disk.
- **Fix for Full Training:** Wrap post-training evaluations in distributed collectives or call evaluation prior to distributed teardown.

---

## 7. Conclusion & Next Steps

The 1,000-sample pilot training succeeded in its primary objective:
- Confirmed that `Qwen2.5-1.5B-Instruct` + `RebuiltV4 Checkpoint-200` initializes, trains with QLoRA NF4, converges to low loss ($1.217 \times 10^{-6}$), and produces fully reloadable checkpoint adapters.
- Measured empirical throughput and generated concrete runtime projections for the master dataset.

Per safeguards:
- **No full training has been launched.**
- **No datasets or manifests were modified.**
- **Standing by for your review and direction on full-scale training parameters.**


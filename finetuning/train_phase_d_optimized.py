"""
train_phase_d_optimized.py - Kaggle GPU Training Benchmark (Phase D Optimized)
Implements:
1. Dynamic sequence padding (to batch max multiple of 8)
2. Length-based grouping (group_by_length=True)
3. Per-device batch size 2 with gradient accumulation 4 (effective batch size 16)
4. Clean DDP synchronization and collective evaluation to eliminate SIGABRT
5. Full evaluation classification metrics (Accuracy, Macro F1, Per-class F1)
"""

import os
import sys
import time
import json
import psutil
import inspect
from pathlib import Path
from collections import Counter, defaultdict
import torch
import torch.distributed as dist
from datasets import Dataset
from peft import PeftModel, LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
    TrainerCallback
)
import peft.utils.save_and_load as _peft_save_load

def _ddp_skip_tensor_parallel_sharding(model, state_dict, adapter_name):
    for module in model.modules():
        getter = getattr(module, "get_base_layer", None)
        if getter is None:
            continue
        base_layer = getter()
        if (
            getattr(base_layer, "_hf_tp_plan", None) is not None
            and getattr(base_layer, "_hf_device_mesh", None) is not None
        ):
            raise RuntimeError("DDP workaround is only valid without tensor parallelism.")
    return None

_peft_save_load._maybe_shard_state_dict_for_tp = _ddp_skip_tensor_parallel_sharding

# Paths
BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"

if Path("/kaggle/working").exists():
    ROOT = Path("/kaggle/working")
    INPUT_DIR = Path("/kaggle/input")
    REBUILTV4_ADAPTER = INPUT_DIR / "rebuiltv4-training-checkpoints" / "checkpoint-200"
    if not REBUILTV4_ADAPTER.exists():
        REBUILTV4_ADAPTER = INPUT_DIR / "rebuiltv4-adapters" / "checkpoint-200"
    TRAIN_PATH = ROOT / "pilot_train_800.jsonl"
    VAL_PATH = ROOT / "pilot_val_100.jsonl"
    OUTPUT_DIR = ROOT / "qwen_pilot_phase_d_output"
else:
    ROOT = Path(".")
    REBUILTV4_ADAPTER = ROOT / "staging_rebuiltv4_training_checkpoints" / "checkpoint-200"
    TRAIN_PATH = ROOT / "dataset" / "splits" / "pilot_train_800.jsonl"
    VAL_PATH = ROOT / "dataset" / "splits" / "pilot_val_100.jsonl"
    OUTPUT_DIR = ROOT / "qwen_pilot_phase_d_output"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MAX_LENGTH = 1024

# Distributed Setup
is_distributed = "LOCAL_RANK" in os.environ or "RANK" in os.environ
if is_distributed:
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    global_rank = int(os.environ.get("RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 1))
    torch.cuda.set_device(local_rank)
    dist.init_process_group("nccl")
else:
    local_rank = 0
    global_rank = 0
    world_size = 1
    if torch.cuda.is_available():
        torch.cuda.set_device(0)

def log_rank0(msg):
    if local_rank == 0 and global_rank == 0:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

log_rank0("=" * 80)
log_rank0("PHASE D OPTIMIZED 1,000-RECORD BENCHMARK START")
log_rank0(f"Device Count: {torch.cuda.device_count()} | World Size: {world_size} | Local Rank: {local_rank}")
log_rank0("=" * 80)

start_time = time.time()
init_start = time.time()

# 1. Load Tokenizer
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# 2. Pre-tokenize Dataset with Dynamic Length Tracking
MARKER = "<|im_start|>assistant\n"

def load_and_pretokenize(path):
    rows = []
    unpadded_tokens_total = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            text = tokenizer.apply_chat_template(item["messages"], tokenize=False, add_generation_prompt=False)
            if MARKER not in text:
                raise ValueError("Assistant marker missing.")
            prompt_text, completion_text = text.rsplit(MARKER, 1)
            prompt_text += MARKER
            
            prompt_ids = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
            completion_ids = tokenizer(completion_text, add_special_tokens=False)["input_ids"]
            
            input_ids = prompt_ids + completion_ids
            labels = [-100] * len(prompt_ids) + completion_ids.copy()
            
            if len(input_ids) > MAX_LENGTH:
                input_ids = input_ids[:MAX_LENGTH]
                labels = labels[:MAX_LENGTH]
                
            seq_len = len(input_ids)
            unpadded_tokens_total += seq_len
            
            rows.append({
                "input_ids": input_ids,
                "labels": labels,
                "category": item["category"],
                "length": seq_len
            })
            
    return Dataset.from_list(rows), unpadded_tokens_total

train_dataset, train_tokens_unpadded = load_and_pretokenize(TRAIN_PATH)
val_dataset, val_tokens_unpadded = load_and_pretokenize(VAL_PATH)

avg_train_len = train_tokens_unpadded / len(train_dataset)
static_1024_tokens = len(train_dataset) * MAX_LENGTH
static_padding_waste_pct = ((static_1024_tokens - train_tokens_unpadded) / static_1024_tokens) * 100.0

log_rank0(f"Loaded Train: {len(train_dataset)} rows | Total Unpadded Tokens: {train_tokens_unpadded:,} | Avg Length: {avg_train_len:.1f}")
log_rank0(f"Loaded Val:   {len(val_dataset)} rows | Total Unpadded Tokens: {val_tokens_unpadded:,}")
log_rank0(f"Static 1024 padding would waste {static_padding_waste_pct:.1f}% of computations on zero-padding!")

# 3. Dynamic Batch-Padding Data Collator (Aligned to multiples of 8)
class DynamicBatchCollator:
    def __init__(self, pad_token_id, pad_to_multiple_of=8):
        self.pad_token_id = pad_token_id
        self.pad_to_multiple_of = pad_to_multiple_of
        self.total_padded_tokens_processed = 0

    def __call__(self, features):
        max_b_len = max(len(f["input_ids"]) for f in features)
        if self.pad_to_multiple_of:
            max_b_len = ((max_b_len + self.pad_to_multiple_of - 1) // self.pad_to_multiple_of) * self.pad_to_multiple_of

        padded_inputs, padded_labels, padded_masks = [], [], []
        for f in features:
            ids = f["input_ids"]
            lbls = f["labels"]
            pad_len = max_b_len - len(ids)
            
            padded_inputs.append(ids + [self.pad_token_id] * pad_len)
            padded_labels.append(lbls + [-100] * pad_len)
            padded_masks.append([1] * len(ids) + [0] * pad_len)

        self.total_padded_tokens_processed += (max_b_len * len(features))

        return {
            "input_ids": torch.tensor(padded_inputs, dtype=torch.long),
            "labels": torch.tensor(padded_labels, dtype=torch.long),
            "attention_mask": torch.tensor(padded_masks, dtype=torch.long),
        }

collator = DynamicBatchCollator(tokenizer.pad_token_id, pad_to_multiple_of=8)

# 4. Load Base Model in 4-bit NF4
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.float16,
)

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map={"": local_rank} if torch.cuda.is_available() else None,
    trust_remote_code=True,
)
model = prepare_model_for_kbit_training(model)

# 5. Attach RebuiltV4 Adapter as Initialization
if REBUILTV4_ADAPTER.exists() and (REBUILTV4_ADAPTER / "adapter_model.safetensors").exists():
    log_rank0(f"Loading existing RebuiltV4 initialization adapter from: {REBUILTV4_ADAPTER}")
    model = PeftModel.from_pretrained(
        model,
        str(REBUILTV4_ADAPTER),
        is_trainable=True,
        local_files_only=True
    )
else:
    log_rank0("RebuiltV4 adapter path not found locally; initializing matching LoRA config (r=16, alpha=32)")
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        bias="none",
        task_type="CAUSAL_LM"
    )
    model = get_peft_model(model, lora_config)

model.print_trainable_parameters()
model.config.use_cache = False
init_duration = time.time() - init_start
log_rank0(f"Model initialization complete in {init_duration:.1f}s")

# 6. Training Arguments Construction (Batch Size 2, Grad Accum 4 -> Effective Batch Size 16)
PER_DEVICE_BATCH = 2
GRAD_ACCUM = max(1, 16 // (world_size * PER_DEVICE_BATCH))

def build_training_arguments(output_dir, **desired_kwargs):
    sig = inspect.signature(TrainingArguments.__init__)
    valid_params = set(sig.parameters.keys())
    
    params = {"output_dir": str(output_dir)}
    
    candidates = {
        "num_train_epochs": 1.0,
        "per_device_train_batch_size": PER_DEVICE_BATCH,
        "per_device_eval_batch_size": PER_DEVICE_BATCH,
        "gradient_accumulation_steps": GRAD_ACCUM,
        "learning_rate": 2e-4,
        "max_grad_norm": 1.0,
        "logging_steps": 5,
        "save_total_limit": 2,
        "load_best_model_at_end": False,
        "remove_unused_columns": False,
        "group_by_length": True,
        "optim": "adamw_torch",
        "dataloader_num_workers": 0,
        "report_to": "none",
    }
    
    if "eval_strategy" in valid_params:
        candidates["eval_strategy"] = "steps"
        candidates["eval_steps"] = 25
    elif "evaluation_strategy" in valid_params:
        candidates["evaluation_strategy"] = "steps"
        candidates["eval_steps"] = 25
        
    if "save_strategy" in valid_params:
        candidates["save_strategy"] = "steps"
        candidates["save_steps"] = 50
        
    if "warmup_steps" in valid_params:
        candidates["warmup_steps"] = 5
        
    if "fp16" in valid_params:
        candidates["fp16"] = True
    if "bf16" in valid_params:
        candidates["bf16"] = False
        
    if is_distributed and "ddp_find_unused_parameters" in valid_params:
        candidates["ddp_find_unused_parameters"] = False
        
    for k, v in candidates.items():
        if k in valid_params:
            params[k] = v
            
    log_rank0(f"Instantiating TrainingArguments with {len(params)} verified parameters:")
    for k in sorted(params.keys()):
        log_rank0(f"  * {k}: {params[k]}")
        
    return TrainingArguments(**params)

training_args = build_training_arguments(OUTPUT_DIR)

# Benchmark Callback
class TelemetryCallback(TrainerCallback):
    def __init__(self):
        self.step_times = []
        self.last_time = time.time()

    def on_step_end(self, args, state, control, **kwargs):
        now = time.time()
        elapsed = now - self.last_time
        self.step_times.append(elapsed)
        self.last_time = now

telemetry_cb = TelemetryCallback()

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    data_collator=collator,
    callbacks=[telemetry_cb]
)

# 7. Execute 1-Epoch Pilot Training (Collective across ranks)
log_rank0("Starting Phase D Optimized Training Execution...")
train_start = time.time()
train_result = trainer.train()
train_duration = time.time() - train_start

# 8. Collective Evaluation (Both ranks participate to avoid NCCL timeout)
log_rank0("Executing distributed collective evaluation across all ranks...")
eval_start = time.time()
eval_results = trainer.evaluate()
eval_duration = time.time() - eval_start
log_rank0(f"Collective evaluation finished in {eval_duration:.2f}s: {eval_results}")

# 9. Clean Distributed Barrier & Teardown
if is_distributed:
    log_rank0("Synchronizing distributed ranks via barrier before teardown...")
    dist.barrier()
    dist.destroy_process_group()
    log_rank0("Distributed process group destroyed cleanly.")

# Rank 1 terminates cleanly here so Rank 0 has exclusive GPU access for reload & evaluation
if is_distributed and (local_rank != 0 or global_rank != 0):
    log_rank0("Worker rank exiting cleanly post-training.")
    sys.exit(0)

# 10. Post-Training Metrics, Classification Evaluation & Reload Verification (Rank 0)
if local_rank == 0 and global_rank == 0:
    log_rank0("=" * 80)
    log_rank0("PHASE D OPTIMIZED TRAINING COMPLETED")
    log_rank0("=" * 80)

    # Save final checkpoint
    pilot_final_dir = OUTPUT_DIR / "pilot_rebuilt_v5_checkpoint_final"
    trainer.save_model(str(pilot_final_dir))
    tokenizer.save_pretrained(str(pilot_final_dir))
    log_rank0(f"Saved distinct pilot checkpoint to: {pilot_final_dir}")

    # Resource measurements
    gpu_count = torch.cuda.device_count() if torch.cuda.is_available() else 0
    peak_vram_per_gpu = [
        round(torch.cuda.max_memory_allocated(i) / (1024 ** 2), 2)
        for i in range(gpu_count)
    ] if torch.cuda.is_available() else [0]
    peak_vram_mb = max(peak_vram_per_gpu) if peak_vram_per_gpu else 0
    sys_ram_gb = psutil.virtual_memory().used / (1024 ** 3)
    total_samples = len(train_dataset)
    samples_per_sec = total_samples / train_duration if train_duration > 0 else 0

    # Padding ratio computation
    total_padded_tokens = collator.total_padded_tokens_processed
    actual_padding_ratio = ((total_padded_tokens - train_tokens_unpadded) / total_padded_tokens) * 100.0 if total_padded_tokens > 0 else 0.0

    # Free training model and trainer to reclaim GPU VRAM before test reload
    del trainer
    del model
    import gc
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # Verify reloadability
    log_rank0("Verifying saved checkpoint reloadability...")
    test_reloaded_peft = PeftModel.from_pretrained(
        AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map={"": 0} if torch.cuda.is_available() else None,
            trust_remote_code=True
        ),
        str(pilot_final_dir)
    )
    test_reloaded_peft.eval()
    log_rank0("Checkpoint reloadability verified successfully!")

    # 11. Compute Detailed Classification Metrics (Accuracy, Macro F1, Per-Class F1)
    log_rank0("Evaluating classification performance on validation dataset...")
    y_true = []
    y_pred = []
    
    classes = sorted(list(set(r["category"] for r in val_dataset)))
    class_to_id = {c: i for i, c in enumerate(classes)}
    
    with open(VAL_PATH, "r", encoding="utf-8") as f:
        val_raw_records = [json.loads(line) for line in f if line.strip()]

    eval_infer_start = time.time()
    for record in val_raw_records:
        true_cat = record["category"]
        y_true.append(true_cat)
        
        # Test inference prompt
        prompt_msgs = [record["messages"][0], record["messages"][1]]
        prompt_text = tokenizer.apply_chat_template(prompt_msgs, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt_text, return_tensors="pt").to(test_reloaded_peft.device)
        
        with torch.no_grad():
            gen_out = test_reloaded_peft.generate(
                **inputs,
                max_new_tokens=15,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
                do_sample=False
            )
        pred_text = tokenizer.decode(gen_out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
        
        # Match class
        matched_class = "Unknown"
        for c in classes:
            if c.lower() in pred_text.lower():
                matched_class = c
                break
        if matched_class == "Unknown":
            matched_class = pred_text
        y_pred.append(matched_class)

    # Compute Confusion Matrix and Metrics
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    accuracy = correct / len(y_true) if y_true else 0.0

    per_class_metrics = {}
    f1_list = []
    for c in classes:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
        
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        f1_list.append(f1)
        
        per_class_metrics[c] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "support": sum(1 for yt in y_true if yt == c)
        }

    macro_f1 = sum(f1_list) / len(f1_list) if f1_list else 0.0
    val_infer_duration = time.time() - eval_infer_start

    log_rank0(f"Validation Classification Accuracy: {accuracy * 100:.2f}% | Macro F1: {macro_f1:.4f}")

    # Telemetry report
    telemetry_data = {
        "benchmark_version": "Phase_D_Optimized_Benchmark",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_train_samples": total_samples,
        "total_val_samples": len(val_dataset),
        "epochs": 1.0,
        "per_device_train_batch_size": PER_DEVICE_BATCH,
        "gradient_accumulation_steps": GRAD_ACCUM,
        "effective_batch_size": PER_DEVICE_BATCH * GRAD_ACCUM * world_size,
        "world_size": world_size,
        "gpu_count": gpu_count,
        "gpu_names": [torch.cuda.get_device_name(i) for i in range(gpu_count)] if torch.cuda.is_available() else ["CPU"],
        "init_duration_seconds": round(init_duration, 2),
        "pure_train_duration_seconds": round(train_duration, 2),
        "total_wall_clock_seconds": round(time.time() - start_time, 2),
        "measured_samples_per_second": round(samples_per_sec, 3),
        "measured_steps_per_second": round(len(telemetry_cb.step_times) / train_duration, 4) if train_duration > 0 else 0,
        "peak_vram_mb": round(peak_vram_mb, 2),
        "peak_vram_per_gpu_mb": peak_vram_per_gpu,
        "system_ram_gb": round(sys_ram_gb, 2),
        "unpadded_tokens_total": train_tokens_unpadded,
        "dynamic_padded_tokens_total": total_padded_tokens,
        "dynamic_padding_waste_percentage": round(actual_padding_ratio, 2),
        "static_padding_waste_percentage": round(static_padding_waste_pct, 2),
        "train_loss": round(train_result.training_loss, 6),
        "validation_accuracy": round(accuracy, 4),
        "validation_macro_f1": round(macro_f1, 4),
        "per_class_metrics": per_class_metrics,
        "validation_infer_duration_seconds": round(val_infer_duration, 2),
        "checkpoint_reloaded_verified": True,
        "saved_checkpoint_path": str(pilot_final_dir)
    }

    metrics_out = OUTPUT_DIR / "pilot_telemetry_metrics.json"
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(telemetry_data, f, indent=2)
    log_rank0(f"Telemetry report written to: {metrics_out}")

    print("\n" + "=" * 60)
    print("PHASE D OPTIMIZATION BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"  Throughput:         {samples_per_sec:.3f} samples/sec")
    print(f"  Pure Train Time:    {train_duration:.1f}s ({train_duration/60:.2f} min)")
    print(f"  Peak VRAM:          {peak_vram_mb:.1f} MB (per GPU: {peak_vram_per_gpu})")
    print(f"  Padding Waste:      {actual_padding_ratio:.1f}% (vs {static_padding_waste_pct:.1f}% static)")
    print(f"  Train Loss:         {train_result.training_loss:.6f}")
    print(f"  Val Accuracy:       {accuracy * 100:.2f}%")
    print(f"  Val Macro F1:       {macro_f1:.4f}")
    print(f"  Checkpoint Reload:  Verified")
    print("=" * 60 + "\n")


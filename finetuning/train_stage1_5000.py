"""
train_stage1_5000.py - Kaggle 2x Tesla T4 GPU Training Script (Stage 1: 5,000 New Records)
Configuration:
1. Model Initialization: Preserved Baseline Checkpoint-200 adapter on top of Qwen2.5-1.5B-Instruct
2. Training Dataset: stage1_train_5000_repaired.jsonl (5,000 genuinely new classification records, 625/class)
3. Validation Dataset: stage1_val_1000_repaired.jsonl (1,000 balanced validation records, 125/class)
4. Training Scope: Exactly 1 epoch (313 optimizer steps)
5. Hardware: 2x Tesla T4 GPUs via PyTorch DDP (torchrun --nproc_per_node=2)
6. Throughput Optimization: Dynamic sequence padding, group_by_length=True, effective batch size 16
7. Post-Training Evaluation: Full metrics (Accuracy, Macro F1, Weighted F1, Per-class Precision/Recall/F1, Confusion Matrix)
   compared against the Baseline Checkpoint-200 on identical validation records.
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
    BASELINE_ADAPTER = INPUT_DIR / "baseline-checkpoints" / "checkpoint-200"
    if not BASELINE_ADAPTER.exists():
        BASELINE_ADAPTER = INPUT_DIR / "rebuiltv4-training-checkpoints" / "checkpoint-200"
    if not BASELINE_ADAPTER.exists():
        BASELINE_ADAPTER = INPUT_DIR / "rebuiltv4-adapters" / "checkpoint-200"
    TRAIN_PATH = INPUT_DIR / "offensive-ai-training-stage1" / "stage1_train_5000_repaired.jsonl"
    if not TRAIN_PATH.exists():
        TRAIN_PATH = ROOT / "stage1_train_5000_repaired.jsonl"
    VAL_PATH = INPUT_DIR / "offensive-ai-training-stage1" / "stage1_val_1000_repaired.jsonl"
    if not VAL_PATH.exists():
        VAL_PATH = ROOT / "stage1_val_1000_repaired.jsonl"
    OUTPUT_DIR = ROOT / "initial_training_output"
else:
    ROOT = Path(".")
    BASELINE_ADAPTER = ROOT / "staging_baseline_checkpoints" / "checkpoint-200"
    if not BASELINE_ADAPTER.exists():
        BASELINE_ADAPTER = ROOT / "staging_rebuiltv4_training_checkpoints" / "checkpoint-200"
    TRAIN_PATH = ROOT / "dataset" / "splits" / "stage1_train_5000_repaired.jsonl"
    VAL_PATH = ROOT / "dataset" / "splits" / "stage1_val_1000_repaired.jsonl"
    OUTPUT_DIR = ROOT / "initial_training_output"

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
log_rank0("INITIAL TRAINING STAGE (5,000 NEW CLASSIFICATION RECORDS)")
log_rank0(f"Device Count: {torch.cuda.device_count()} | World Size: {world_size} | Local Rank: {local_rank}")
log_rank0(f"Training Dataset: {TRAIN_PATH}")
log_rank0(f"Validation Dataset: {VAL_PATH}")
log_rank0(f"Baseline Checkpoint: {BASELINE_ADAPTER}")
log_rank0(f"Output Directory: {OUTPUT_DIR}")
log_rank0("=" * 80)

start_time = time.time()

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

log_rank0("Loading and pre-tokenizing Stage 1 datasets...")
train_dataset, train_tokens_unpadded = load_and_pretokenize(TRAIN_PATH)
val_dataset, val_tokens_unpadded = load_and_pretokenize(VAL_PATH)
log_rank0(f"Stage 1 Train samples: {len(train_dataset):,} (Total unpadded tokens: {train_tokens_unpadded:,})")
log_rank0(f"Stage 1 Val samples:   {len(val_dataset):,} (Total unpadded tokens: {val_tokens_unpadded:,})")

# 3. Dynamic Padding Collator
class DynamicDataCollator:
    def __init__(self, pad_token_id: int, pad_to_multiple_of: int = 8):
        self.pad_token_id = pad_token_id
        self.pad_to_multiple_of = pad_to_multiple_of
        self.total_padded_tokens_processed = 0

    def __call__(self, features):
        max_len = max(len(f["input_ids"]) for f in features)
        if self.pad_to_multiple_of > 0 and (max_len % self.pad_to_multiple_of != 0):
            max_len = ((max_len // self.pad_to_multiple_of) + 1) * self.pad_to_multiple_of

        batch_input_ids = []
        batch_labels = []
        batch_attention_mask = []

        for f in features:
            inp = f["input_ids"]
            lab = f["labels"]
            pad_len = max_len - len(inp)

            padded_inp = inp + [self.pad_token_id] * pad_len
            padded_lab = lab + [-100] * pad_len
            attn_mask = [1] * len(inp) + [0] * pad_len

            batch_input_ids.append(padded_inp)
            batch_labels.append(padded_lab)
            batch_attention_mask.append(attn_mask)

        self.total_padded_tokens_processed += (len(features) * max_len)

        return {
            "input_ids": torch.tensor(batch_input_ids, dtype=torch.long),
            "labels": torch.tensor(batch_labels, dtype=torch.long),
            "attention_mask": torch.tensor(batch_attention_mask, dtype=torch.long)
        }

collator = DynamicDataCollator(pad_token_id=tokenizer.pad_token_id, pad_to_multiple_of=8)

# 4. Model Loading with BNB 4-Bit & Baseline Adapter Initialization
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True
)

log_rank0(f"Loading base model {BASE_MODEL}...")
device_map = {"": local_rank} if is_distributed and torch.cuda.is_available() else ("auto" if torch.cuda.is_available() else None)

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map=device_map,
    trust_remote_code=True,
    torch_dtype=torch.float16
)
base_model = prepare_model_for_kbit_training(base_model)

log_rank0(f"Loading preserved baseline adapter from: {BASELINE_ADAPTER}")
model = PeftModel.from_pretrained(
    base_model,
    str(BASELINE_ADAPTER),
    is_trainable=True,
    adapter_name="default"
)
model.print_trainable_parameters()

# 5. Training Arguments (Effective Batch Size 16 = 2 per device * 4 accum * 2 GPUs)
training_args_kwargs = {
    "output_dir": str(OUTPUT_DIR),
    "num_train_epochs": 1.0,
    "per_device_train_batch_size": 2,
    "per_device_eval_batch_size": 2,
    "gradient_accumulation_steps": 4,
    "learning_rate": 1e-4,
    "warmup_steps": 10,
    "lr_scheduler_type": "cosine",
    "fp16": True,
    "bf16": False,
    "logging_steps": 10,
    "evaluation_strategy": "no",
    "save_strategy": "steps",
    "save_steps": 100,
    "save_total_limit": 2,
    "group_by_length": True,
    "length_column_name": "length",
    "report_to": "none",
    "gradient_checkpointing": True,
    "dataloader_drop_last": False,
    "ddp_find_unused_parameters": False
}

valid_args = set(inspect.signature(TrainingArguments.__init__).parameters.keys())
filtered_args = {k: v for k, v in training_args_kwargs.items() if k in valid_args}
training_args = TrainingArguments(**filtered_args)

class TelemetryCallback(TrainerCallback):
    def __init__(self):
        super().__init__()
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

# 6. Execute Exactly 1-Epoch Training Execution (313 optimizer steps)
log_rank0("=" * 80)
log_rank0("STARTING STAGE 1 TRAINING (1 EPOCH / 313 STEPS)")
log_rank0("=" * 80)
train_start = time.time()
train_result = trainer.train()
train_duration = time.time() - train_start
log_rank0(f"Training completed in {train_duration:.2f} seconds.")

# 7. Distributed Collective Evaluation
log_rank0("Executing distributed collective evaluation across all ranks...")
eval_start = time.time()
eval_results = trainer.evaluate()
eval_duration = time.time() - eval_start
log_rank0(f"Collective evaluation finished in {eval_duration:.2f}s: {eval_results}")

# 8. Clean Distributed Barrier & Teardown
if is_distributed:
    log_rank0("Synchronizing distributed ranks via barrier before teardown...")
    dist.barrier()
    dist.destroy_process_group()
    log_rank0("Distributed process group destroyed cleanly.")

if is_distributed and (local_rank != 0 or global_rank != 0):
    log_rank0("Worker rank exiting cleanly post-training.")
    sys.exit(0)

# 9. Post-Training Evaluation & Baseline Comparison (Rank 0 Exclusive)
if local_rank == 0 and global_rank == 0:
    log_rank0("=" * 80)
    log_rank0("INITIAL TRAINING STAGE COMPLETED - EVALUATION & BASELINE COMPARISON")
    log_rank0("=" * 80)

    # Save final newly trained adapter separately
    final_adapter_dir = OUTPUT_DIR / "initial_training_checkpoint_final"
    trainer.save_model(str(final_adapter_dir))
    tokenizer.save_pretrained(str(final_adapter_dir))
    log_rank0(f"Saved distinct initial training adapter to: {final_adapter_dir}")

    # Telemetry measurements
    gpu_count = torch.cuda.device_count() if torch.cuda.is_available() else 0
    peak_vram_per_gpu = [
        round(torch.cuda.max_memory_allocated(i) / (1024 ** 2), 2)
        for i in range(gpu_count)
    ] if torch.cuda.is_available() else [0]
    peak_vram_mb = max(peak_vram_per_gpu) if peak_vram_per_gpu else 0
    sys_ram_gb = psutil.virtual_memory().used / (1024 ** 3)
    total_samples = len(train_dataset)
    samples_per_sec = total_samples / train_duration if train_duration > 0 else 0

    total_padded_tokens = collator.total_padded_tokens_processed
    actual_padding_ratio = ((total_padded_tokens - train_tokens_unpadded) / total_padded_tokens) * 100.0 if total_padded_tokens > 0 else 0.0

    # Free trainer and training model memory
    del trainer
    del model
    import gc
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # Verify reload of new adapter
    log_rank0("Verifying saved checkpoint reloadability...")
    trained_model = PeftModel.from_pretrained(
        AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map={"": 0} if torch.cuda.is_available() else None,
            trust_remote_code=True
        ),
        str(final_adapter_dir)
    )
    trained_model.eval()
    log_rank0("Newly trained adapter reloaded successfully!")

    # Helper function for evaluation
    classes = [
        "Benign", "Cookie Injection", "Directory Traversal", "LOG4J",
        "Log Forging", "RCE", "SQL Injection", "XSS"
    ]

    with open(VAL_PATH, "r", encoding="utf-8") as f:
        val_raw_records = [json.loads(line) for line in f if line.strip()]

    def evaluate_model_on_val(eval_model, model_name):
        log_rank0(f"\nEvaluating {model_name} on {len(val_raw_records)} validation samples...")
        y_true = []
        y_pred = []
        infer_start = time.time()
        
        for idx, rec in enumerate(val_raw_records):
            true_cat = rec["category"]
            y_true.append(true_cat)
            
            prompt_msgs = [rec["messages"][0], rec["messages"][1]]
            prompt_text = tokenizer.apply_chat_template(prompt_msgs, tokenize=False, add_generation_prompt=True)
            inputs = tokenizer(prompt_text, return_tensors="pt").to(eval_model.device)
            
            with torch.no_grad():
                gen_out = eval_model.generate(
                    **inputs,
                    max_new_tokens=15,
                    pad_token_id=tokenizer.pad_token_id,
                    eos_token_id=tokenizer.eos_token_id,
                    do_sample=False
                )
            pred_text = tokenizer.decode(gen_out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
            
            matched = "Unknown"
            for c in classes:
                if c.lower() in pred_text.lower():
                    matched = c
                    break
            if matched == "Unknown":
                matched = pred_text
            y_pred.append(matched)

        infer_duration = time.time() - infer_start
        correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
        accuracy = correct / len(y_true) if y_true else 0.0

        per_class = {}
        f1_list = []
        weighted_f1_sum = 0
        total_support = len(y_true)

        for c in classes:
            tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
            fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
            fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
            supp = sum(1 for yt in y_true if yt == c)

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            f1_list.append(f1)
            weighted_f1_sum += (f1 * supp)

            per_class[c] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "support": supp
            }

        macro_f1 = sum(f1_list) / len(f1_list) if f1_list else 0.0
        weighted_f1 = weighted_f1_sum / total_support if total_support > 0 else 0.0

        # Confusion matrix
        confusion_mat = {c_true: {c_pred: 0 for c_pred in classes + ["Unknown"]} for c_true in classes}
        for yt, yp in zip(y_true, y_pred):
            pred_col = yp if yp in classes else "Unknown"
            confusion_mat[yt][pred_col] += 1

        return {
            "model_name": model_name,
            "accuracy": round(accuracy, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "per_class": per_class,
            "confusion_matrix": confusion_mat,
            "inference_duration_seconds": round(infer_duration, 2)
        }

    # Evaluate newly trained model
    trained_metrics = evaluate_model_on_val(trained_model, "Initial_Training_Model")

    # Free trained model and load baseline adapter for exact comparison
    del trained_model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    log_rank0("Loading Baseline Model for comparative evaluation on identical validation records...")
    baseline_model = PeftModel.from_pretrained(
        AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map={"": 0} if torch.cuda.is_available() else None,
            trust_remote_code=True
        ),
        str(BASELINE_ADAPTER)
    )
    baseline_model.eval()
    baseline_metrics = evaluate_model_on_val(baseline_model, "Baseline_Model_Checkpoint200")

    del baseline_model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # Compile Final Stage 1 Deliverable Manifest
    final_manifest = {
        "status": "COMPLETED",
        "stage": "INITIAL_TRAINING_STAGE_1",
        "training_records": len(train_dataset),
        "validation_records": len(val_dataset),
        "epochs": 1.0,
        "optimizer_steps": train_result.global_step,
        "train_loss": round(train_result.training_loss, 4),
        "eval_loss": round(eval_results.get("eval_loss", 0.0), 4),
        "train_duration_seconds": round(train_duration, 2),
        "measured_throughput_samples_per_sec": round(samples_per_sec, 3),
        "peak_vram_mb": peak_vram_mb,
        "peak_vram_per_gpu": peak_vram_per_gpu,
        "system_ram_gb": round(sys_ram_gb, 2),
        "actual_padding_ratio_pct": round(actual_padding_ratio, 2),
        "saved_adapter_path": str(final_adapter_dir),
        "comparison_metrics": {
            "baseline": baseline_metrics,
            "initial_training": trained_metrics
        }
    }

    manifest_path = OUTPUT_DIR / "initial_training_metrics_report.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(final_manifest, f, indent=2)

    log_rank0("\n" + "=" * 80)
    log_rank0("COMPARATIVE EVALUATION SUMMARY (IDENTICAL 1,000 VALIDATION RECORDS):")
    log_rank0(f"  Baseline Accuracy:         {baseline_metrics['accuracy'] * 100:.2f}% | Macro F1: {baseline_metrics['macro_f1']:.4f}")
    log_rank0(f"  Initial Training Accuracy: {trained_metrics['accuracy'] * 100:.2f}% | Macro F1: {trained_metrics['macro_f1']:.4f}")
    log_rank0("=" * 80)
    log_rank0(f"Complete metrics report written to: {manifest_path}")
    log_rank0("INITIAL TRAINING RUN AND EVALUATION COMPLETED SUCCESSFULLY.")

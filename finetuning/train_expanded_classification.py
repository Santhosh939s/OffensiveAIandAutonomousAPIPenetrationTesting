"""
train_expanded_classification.py - 2x Tesla T4 GPU Training Script (30,000 Expanded Records)
Configuration:
1. Model Initialization: Initial Adapter (saved from initial training) on top of Qwen2.5-1.5B-Instruct
2. Training Dataset: classification_training_30000.jsonl (30,000 records, 100% unique, zero leak)
3. Validation Benchmarks:
   - Original Benchmark (1,000 records, 125/class)
   - Corrected Benchmark (1,000 records, 52 setup traffic relabeled to Benign)
   - Boundary Contrast Diagnostic Subset (700 records: 350 XSS / 350 RCE)
4. Training Scope: Exactly 1 epoch (1,875 optimizer steps) at learning rate 5e-5
5. Hardware: 2x Tesla T4 GPUs via PyTorch DDP (torchrun --nproc_per_node=2)
6. Throughput Optimization: Dynamic sequence padding, group_by_length=True, effective batch size 16
7. Post-Training Evaluation: 3-way comparative evaluation across Baseline, Initial, and Expanded models.
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

# Paths Configuration
BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"

if Path("/kaggle/working").exists():
    ROOT = Path("/kaggle/working")
    INPUT_DIR = Path("/kaggle/input")
    
    # Baseline Adapter
    BASELINE_ADAPTER = INPUT_DIR / "baseline-checkpoints" / "checkpoint-200"
    if not BASELINE_ADAPTER.exists():
        BASELINE_ADAPTER = INPUT_DIR / "rebuiltv4-training-checkpoints" / "checkpoint-200"
    if not BASELINE_ADAPTER.exists():
        BASELINE_ADAPTER = INPUT_DIR / "rebuiltv4-adapters" / "checkpoint-200"
        
    # Initial Adapter (input source for Stage 2)
    ds_dir = INPUT_DIR / "offensive-ai-classification-training"
    INITIAL_ADAPTER = ds_dir / "initial_adapter"
    if not INITIAL_ADAPTER.exists():
        INITIAL_ADAPTER = INPUT_DIR / "initial_training_output" / "initial_training_checkpoint_final"
        
    TRAIN_PATH = ds_dir / "classification_training_30000.jsonl"
    VAL_ORIG_PATH = ds_dir / "validation_benchmark_original_1000.jsonl"
    VAL_CORR_PATH = ds_dir / "validation_benchmark_corrected_1000.jsonl"
    BOUNDARY_PATH = ds_dir / "boundary_contrast_subset_700.jsonl"
    
    OUTPUT_DIR = ROOT / "classification_training_output"
else:
    ROOT = Path(".")
    BASELINE_ADAPTER = ROOT / "staging_baseline_checkpoints" / "checkpoint-200"
    INITIAL_ADAPTER = ROOT / "evaluation" / "stage1_initial_training" / "initial_training_output" / "initial_training_checkpoint_final"
    TRAIN_PATH = ROOT / "dataset" / "splits" / "classification_training_30000.jsonl"
    VAL_ORIG_PATH = ROOT / "dataset" / "splits" / "validation_benchmark_original_1000.jsonl"
    VAL_CORR_PATH = ROOT / "dataset" / "splits" / "validation_benchmark_corrected_1000.jsonl"
    BOUNDARY_PATH = ROOT / "dataset" / "splits" / "boundary_contrast_subset_700.jsonl"
    OUTPUT_DIR = ROOT / "classification_training_output"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MAX_LENGTH = 1024

# Distributed Setup
is_distributed = "LOCAL_RANK" in os.environ or "RANK" in os.environ
if is_distributed:
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    global_rank = int(os.environ.get("RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 1))
    torch.cuda.set_device(local_rank)
    if not dist.is_initialized():
        dist.init_process_group(backend="nccl")
else:
    local_rank = 0
    global_rank = 0
    world_size = 1

def log_rank0(msg):
    if global_rank == 0:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

log_rank0("=" * 80)
log_rank0(f"Starting Expanded Classification Training (30,000 Records)")
log_rank0(f"Distributed: {is_distributed} | Local Rank: {local_rank} | World Size: {world_size}")
log_rank0(f"Base Model:        {BASE_MODEL}")
log_rank0(f"Initial Adapter:   {INITIAL_ADAPTER}")
log_rank0(f"Training Dataset:  {TRAIN_PATH}")
log_rank0(f"Val Benchmark (Orig): {VAL_ORIG_PATH}")
log_rank0(f"Val Benchmark (Corr): {VAL_CORR_PATH}")
log_rank0(f"Boundary Dataset:     {BOUNDARY_PATH}")
log_rank0("=" * 80)

# Tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    str(INITIAL_ADAPTER) if INITIAL_ADAPTER.exists() else BASE_MODEL,
    trust_remote_code=True
)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

# 4-bit Quantization Config
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
    bnb_4bit_use_double_quant=True,
)

# Load Training Data
log_rank0(f"Loading 30,000 classification training samples...")
with open(TRAIN_PATH, "r", encoding="utf-8") as f:
    train_records = [json.loads(line) for line in f if line.strip()]

log_rank0(f"Loaded {len(train_records)} training records. Tokenizing...")

def format_records(records):
    formatted = []
    classes = [
        "Benign", "Cookie Injection", "Directory Traversal", "LOG4J",
        "Log Forging", "RCE", "SQL Injection", "XSS"
    ]
    for r in records:
        msgs = r["messages"]
        prompt_text = tokenizer.apply_chat_template(msgs[:2], tokenize=False, add_generation_prompt=True)
        response_text = msgs[2]["content"].strip() + tokenizer.eos_token
        full_text = prompt_text + response_text
        
        tokenized_prompt = tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
        tokenized_full = tokenizer(full_text, add_special_tokens=False)["input_ids"]
        
        if len(tokenized_full) > MAX_LENGTH:
            tokenized_full = tokenized_full[:MAX_LENGTH]
            
        labels = list(tokenized_full)
        prompt_len = min(len(tokenized_prompt), len(labels))
        for i in range(prompt_len):
            labels[i] = -100
            
        formatted.append({
            "input_ids": tokenized_full,
            "labels": labels,
            "length": len(tokenized_full)
        })
    return formatted

train_data = format_records(train_records)
train_dataset = Dataset.from_list(train_data)
log_rank0(f"Tokenized {len(train_dataset)} records.")

# Data Collator for dynamic padding
class DataCollatorForDynamicPadding:
    def __init__(self, pad_token_id, pad_label_id=-100):
        self.pad_token_id = pad_token_id
        self.pad_label_id = pad_label_id

    def __call__(self, features):
        batch_lens = [len(f["input_ids"]) for f in features]
        max_batch_len = max(batch_lens)
        
        batch_input_ids = []
        batch_labels = []
        batch_attention_mask = []

        for f in features:
            ids = f["input_ids"]
            labs = f["labels"]
            pad_len = max_batch_len - len(ids)
            
            padded_ids = ids + [self.pad_token_id] * pad_len
            padded_labs = labs + [self.pad_label_id] * pad_len
            attn_mask = [1] * len(ids) + [0] * pad_len

            batch_input_ids.append(padded_ids)
            batch_labels.append(padded_labs)
            batch_attention_mask.append(attn_mask)

        return {
            "input_ids": torch.tensor(batch_input_ids, dtype=torch.long),
            "labels": torch.tensor(batch_labels, dtype=torch.long),
            "attention_mask": torch.tensor(batch_attention_mask, dtype=torch.long),
        }

collator = DataCollatorForDynamicPadding(tokenizer.pad_token_id)

# Model Loading & Adapter Initialization
log_rank0(f"Loading Base Model: {BASE_MODEL}...")
device_map = {"": local_rank} if is_distributed else ({"": 0} if torch.cuda.is_available() else None)

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map=device_map,
    trust_remote_code=True
)
base_model = prepare_model_for_kbit_training(base_model)

log_rank0(f"Initializing adapter from Initial Adapter: {INITIAL_ADAPTER}...")
model = PeftModel.from_pretrained(
    base_model,
    str(INITIAL_ADAPTER),
    is_trainable=True
)
model.print_trainable_parameters()

# Dynamic Padding Telemetry Callback
class DynamicPaddingTelemetry(TrainerCallback):
    def __init__(self, max_length):
        self.max_length = max_length
        self.total_tokens = 0
        self.total_padded_tokens = 0

    def on_step_end(self, args, state, control, **kwargs):
        pass

# Training Arguments
train_args_kwargs = {
    "output_dir": str(OUTPUT_DIR),
    "learning_rate": 5e-5,
    "lr_scheduler_type": "cosine",
    "warmup_ratio": 0.05,
    "num_train_epochs": 1.0,
    "per_device_train_batch_size": 2,
    "gradient_accumulation_steps": 4,
    "bf16": torch.cuda.is_bf16_supported(),
    "fp16": not torch.cuda.is_bf16_supported() and torch.cuda.is_available(),
    "logging_steps": 25,
    "save_strategy": "steps",
    "save_steps": 250,
    "save_total_limit": 3,
    "group_by_length": True,
    "length_column_name": "length",
    "report_to": "none",
    "gradient_checkpointing": True,
    "dataloader_drop_last": False,
    "ddp_find_unused_parameters": False if is_distributed else None,
}

valid_args = inspect.signature(TrainingArguments.__init__).parameters
filtered_args = {k: v for k, v in train_args_kwargs.items() if k in valid_args and v is not None}
training_args = TrainingArguments(**filtered_args)

log_rank0("Instantiating Trainer...")
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    data_collator=collator,
)

# Execute Training
log_rank0("Starting 30,000-sample training run (1.0 epoch, 1,875 optimizer steps)...")
t_start = time.time()
train_result = trainer.train()
train_duration = time.time() - t_start
samples_per_sec = len(train_dataset) / train_duration if train_duration > 0 else 0.0

log_rank0("=" * 80)
log_rank0(f"TRAINING COMPLETE in {train_duration:.2f}s ({train_duration/60:.2f} min)")
log_rank0(f"Throughput: {samples_per_sec:.3f} samples/sec")
log_rank0(f"Global Steps: {train_result.global_step}")
log_rank0(f"Final Train Loss: {train_result.training_loss:.4f}")
log_rank0("=" * 80)

# Hardware Telemetry
peak_vram_mb = torch.cuda.max_memory_allocated() / (1024 * 1024) if torch.cuda.is_available() else 0.0
peak_vram_per_gpu = []
if torch.cuda.is_available():
    for d in range(torch.cuda.device_count()):
        peak_vram_per_gpu.append(round(torch.cuda.max_memory_allocated(d) / (1024 * 1024), 2))
sys_ram_gb = psutil.Process().memory_info().rss / (1024 * 1024 * 1024)

# Save Final Trained Adapter
final_adapter_dir = OUTPUT_DIR / "classification_training_checkpoint_final"
if global_rank == 0:
    log_rank0(f"Saving final trained adapter to {final_adapter_dir}...")
    trainer.save_model(str(final_adapter_dir))
    tokenizer.save_pretrained(str(final_adapter_dir))
    log_rank0("Final adapter saved successfully.")

# DDP Collective Synchronization
if is_distributed:
    dist.barrier()
    log_rank0("Collective DDP synchronization complete.")

# Comprehensive Evaluation on Rank 0
if global_rank == 0:
    log_rank0("\n" + "=" * 80)
    log_rank0("STARTING 3-WAY MULTI-BENCHMARK COMPARATIVE EVALUATION")
    log_rank0("=" * 80)
    
    del model
    del trainer
    del base_model
    import gc
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # Evaluation Helper
    classes = [
        "Benign", "Cookie Injection", "Directory Traversal", "LOG4J",
        "Log Forging", "RCE", "SQL Injection", "XSS"
    ]
    
    def evaluate_model_on_dataset(eval_model, dataset_path, eval_name):
        log_rank0(f"Evaluating {eval_name} on {dataset_path.name}...")
        with open(dataset_path, "r", encoding="utf-8") as f:
            raw_recs = [json.loads(line) for line in f if line.strip()]
            
        y_true = []
        y_pred = []
        t0 = time.time()
        
        for idx, rec in enumerate(raw_recs):
            y_true.append(rec["category"])
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

        dur = time.time() - t0
        correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
        acc = correct / len(y_true) if y_true else 0.0

        per_class = {}
        f1_list = []
        weighted_f1_sum = 0
        for c in classes:
            tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
            fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
            fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
            supp = sum(1 for yt in y_true if yt == c)

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            if supp > 0:
                f1_list.append(f1)
                weighted_f1_sum += (f1 * supp)

            per_class[c] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "support": supp
            }

        macro_f1 = sum(f1_list) / len(f1_list) if f1_list else 0.0
        weighted_f1 = weighted_f1_sum / len(y_true) if y_true else 0.0

        confusion_mat = {c_true: {c_pred: 0 for c_pred in classes + ["Unknown"]} for c_true in classes}
        for yt, yp in zip(y_true, y_pred):
            pred_col = yp if yp in classes else "Unknown"
            if yt in confusion_mat:
                confusion_mat[yt][pred_col] += 1

        return {
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "per_class": per_class,
            "confusion_matrix": confusion_mat,
            "duration_seconds": round(dur, 2)
        }

    def load_model_with_adapter(adapter_path):
        b = AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map={"": 0} if torch.cuda.is_available() else None,
            trust_remote_code=True
        )
        m = PeftModel.from_pretrained(b, str(adapter_path))
        m.eval()
        return m

    # 1. Evaluate Newly Trained Expanded Model
    log_rank0(f"Loading Newly Trained Model from {final_adapter_dir}...")
    trained_model = load_model_with_adapter(final_adapter_dir)
    trained_orig_val = evaluate_model_on_dataset(trained_model, VAL_ORIG_PATH, "Expanded_Model_on_Original_Val")
    trained_corr_val = evaluate_model_on_dataset(trained_model, VAL_CORR_PATH, "Expanded_Model_on_Corrected_Val")
    trained_boundary = evaluate_model_on_dataset(trained_model, BOUNDARY_PATH, "Expanded_Model_on_Boundary_Subset")
    del trained_model
    gc.collect()
    torch.cuda.empty_cache()

    # 2. Evaluate Initial Adapter Model
    log_rank0(f"Loading Initial Adapter Model from {INITIAL_ADAPTER}...")
    init_model = load_model_with_adapter(INITIAL_ADAPTER)
    init_orig_val = evaluate_model_on_dataset(init_model, VAL_ORIG_PATH, "Initial_Model_on_Original_Val")
    init_corr_val = evaluate_model_on_dataset(init_model, VAL_CORR_PATH, "Initial_Model_on_Corrected_Val")
    init_boundary = evaluate_model_on_dataset(init_model, BOUNDARY_PATH, "Initial_Model_on_Boundary_Subset")
    del init_model
    gc.collect()
    torch.cuda.empty_cache()

    # 3. Evaluate Baseline Adapter Model
    log_rank0(f"Loading Baseline Adapter Model from {BASELINE_ADAPTER}...")
    base_eval_model = load_model_with_adapter(BASELINE_ADAPTER)
    base_orig_val = evaluate_model_on_dataset(base_eval_model, VAL_ORIG_PATH, "Baseline_Model_on_Original_Val")
    base_corr_val = evaluate_model_on_dataset(base_eval_model, VAL_CORR_PATH, "Baseline_Model_on_Corrected_Val")
    base_boundary = evaluate_model_on_dataset(base_eval_model, BOUNDARY_PATH, "Baseline_Model_on_Boundary_Subset")
    del base_eval_model
    gc.collect()
    torch.cuda.empty_cache()

    # Compile Final Deliverable Report
    final_report = {
        "status": "COMPLETED",
        "experiment": "EXPANDED_CLASSIFICATION_TRAINING_30000",
        "training_records": len(train_dataset),
        "epochs": 1.0,
        "optimizer_steps": train_result.global_step,
        "train_loss": round(train_result.training_loss, 4),
        "train_duration_seconds": round(train_duration, 2),
        "measured_throughput_samples_per_sec": round(samples_per_sec, 3),
        "peak_vram_mb": peak_vram_mb,
        "peak_vram_per_gpu": peak_vram_per_gpu,
        "system_ram_gb": round(sys_ram_gb, 2),
        "saved_adapter_path": str(final_adapter_dir),
        "comparative_benchmarks": {
            "original_validation_benchmark_1000": {
                "baseline_model": base_orig_val,
                "initial_model": init_orig_val,
                "expanded_model": trained_orig_val
            },
            "corrected_validation_benchmark_1000": {
                "baseline_model": base_corr_val,
                "initial_model": init_corr_val,
                "expanded_model": trained_corr_val
            },
            "boundary_contrast_diagnostic_700": {
                "baseline_model": base_boundary,
                "initial_model": init_boundary,
                "expanded_model": trained_boundary
            }
        }
    }

    report_path = OUTPUT_DIR / "classification_training_metrics_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    log_rank0("\n" + "=" * 80)
    log_rank0("3-WAY COMPARATIVE BENCHMARK SUMMARY (ACCURACY / MACRO F1):")
    log_rank0("1. Original Benchmark (1,000 samples, 125/class):")
    log_rank0(f"   Baseline Adapter: {base_orig_val['accuracy']*100:.2f}% | F1: {base_orig_val['macro_f1']:.4f}")
    log_rank0(f"   Initial Adapter:  {init_orig_val['accuracy']*100:.2f}% | F1: {init_orig_val['macro_f1']:.4f}")
    log_rank0(f"   Expanded Adapter: {trained_orig_val['accuracy']*100:.2f}% | F1: {trained_orig_val['macro_f1']:.4f}")
    log_rank0("2. Corrected Benchmark (1,000 samples, 52 setup traffic relabeled to Benign):")
    log_rank0(f"   Baseline Adapter: {base_corr_val['accuracy']*100:.2f}% | F1: {base_corr_val['macro_f1']:.4f}")
    log_rank0(f"   Initial Adapter:  {init_corr_val['accuracy']*100:.2f}% | F1: {init_corr_val['macro_f1']:.4f}")
    log_rank0(f"   Expanded Adapter: {trained_corr_val['accuracy']*100:.2f}% | F1: {trained_corr_val['macro_f1']:.4f}")
    log_rank0("=" * 80)
    log_rank0(f"Complete report written to: {report_path}")
    log_rank0("TRAINING AND 3-WAY MULTI-BENCHMARK EVALUATION FINISHED SUCCESSFULLY.")


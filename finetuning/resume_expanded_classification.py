"""
resume_expanded_classification.py - Resumed 2x Tesla T4 GPU Training from Checkpoint-1250 (Full 30,000 Records)
Configuration:
1. Exact Resumption Point: Checkpoint-1250 (Step 1250 / 1875, loss=1.816e-5, epoch=0.6667)
2. Preserved Training Dataset: classification_training_30000.jsonl (30,000 records, SHA256: 394b43a16dba4e959e7d7b1e8f93dc22aa4f0af24a36b9db34b2b25c76f873dc)
3. Preserved Optimizer & Scheduler: Restored exactly from optimizer.pt and scheduler.pt (continuing LR ~1.25e-5)
4. Remaining Workload: Exactly 625 optimizer steps (Step 1251 -> 1875, remaining 10,000 samples)
5. Hardware: 2x Tesla T4 GPUs via PyTorch DDP (torchrun --nproc_per_node=2)
6. Checkpoint Strategy: Save every 125 steps (1375, 1500, 1625, 1750, 1875) with save_total_limit=5
7. Immediate Adapter Persistence: final adapter saved immediately to classification_training_checkpoint_final
8. Evaluation Scope: Original Val (1,000), Corrected Val (1,000), Boundary Subset (700), and Independent Test Set (4,100)
"""

import os
import sys
import time
import json
import shutil
import psutil
import inspect
from pathlib import Path
from collections import Counter, defaultdict
import torch
import torch.distributed as dist
from datasets import Dataset
from peft import PeftModel, BitsAndBytesConfig, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
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

# Paths Configuration
BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"

if Path("/kaggle/working").exists():
    ROOT = Path("/kaggle/working")
    INPUT_DIR = Path("/kaggle/input")
    
    # Dataset directory
    ds_dir = INPUT_DIR / "offensive-ai-classification-training"
    ckpt_input_dir = INPUT_DIR / "classification-checkpoint-1250"
    
    TRAIN_PATH = ds_dir / "classification_training_30000.jsonl"
    VAL_ORIG_PATH = ds_dir / "validation_benchmark_original_1000.jsonl"
    VAL_CORR_PATH = ds_dir / "validation_benchmark_corrected_1000.jsonl"
    BOUNDARY_PATH = ds_dir / "boundary_contrast_subset_700.jsonl"
    
    TEST_PATH = ckpt_input_dir / "master_test_4100_repaired.jsonl"
    if not TEST_PATH.exists():
        TEST_PATH = ds_dir / "master_test_4100_repaired.jsonl"
        
    RAW_RESUME_CKPT = ckpt_input_dir / "checkpoint-1250"
    OUTPUT_DIR = ROOT / "classification_training_output"
else:
    ROOT = Path(".")
    TRAIN_PATH = ROOT / "dataset" / "splits" / "classification_training_30000.jsonl"
    VAL_ORIG_PATH = ROOT / "dataset" / "splits" / "validation_benchmark_original_1000.jsonl"
    VAL_CORR_PATH = ROOT / "dataset" / "splits" / "validation_benchmark_corrected_1000.jsonl"
    BOUNDARY_PATH = ROOT / "dataset" / "splits" / "boundary_contrast_subset_700.jsonl"
    TEST_PATH = ROOT / "dataset" / "splits" / "master_test_4100_repaired.jsonl"
    RAW_RESUME_CKPT = ROOT / "evaluation" / "expanded_classification_training" / "classification_training_output" / "checkpoint-1250"
    OUTPUT_DIR = ROOT / "classification_training_output"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOCAL_RESUME_CKPT = OUTPUT_DIR / "checkpoint-1250"

# Stage Checkpoint-1250 to writeable directory on Rank 0
if global_rank == 0 and not LOCAL_RESUME_CKPT.exists():
    log_rank0(f"Staging Checkpoint-1250 from {RAW_RESUME_CKPT} to {LOCAL_RESUME_CKPT}...")
    shutil.copytree(str(RAW_RESUME_CKPT), str(LOCAL_RESUME_CKPT))
    log_rank0("Checkpoint-1250 staged successfully.")

if is_distributed:
    dist.barrier()

MAX_LENGTH = 1024

log_rank0("=" * 80)
log_rank0("RESUMING EXPANDED CLASSIFICATION TRAINING (30,000 TOTAL RECORDS)")
log_rank0(f"Resuming From:      {LOCAL_RESUME_CKPT}")
log_rank0(f"Distributed DDP:    {is_distributed} | Local Rank: {local_rank} | World Size: {world_size}")
log_rank0(f"Base Model:         {BASE_MODEL}")
log_rank0(f"Training Dataset:   {TRAIN_PATH}")
log_rank0(f"Val Benchmark Orig: {VAL_ORIG_PATH}")
log_rank0(f"Val Benchmark Corr: {VAL_CORR_PATH}")
log_rank0(f"Boundary Dataset:   {BOUNDARY_PATH}")
log_rank0(f"Test Dataset:       {TEST_PATH}")
log_rank0("=" * 80)

# Tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    str(LOCAL_RESUME_CKPT) if LOCAL_RESUME_CKPT.exists() else BASE_MODEL,
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
log_rank0("Loading 30,000 classification training samples...")
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

# Dynamic Padding Collator
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

# Model Loading & Base Architecture
log_rank0(f"Loading Base Model: {BASE_MODEL}...")
device_map = {"": local_rank} if is_distributed else ({"": 0} if torch.cuda.is_available() else None)

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map=device_map,
    trust_remote_code=True
)
base_model = prepare_model_for_kbit_training(base_model)

log_rank0(f"Attaching adapter from Checkpoint-1250: {LOCAL_RESUME_CKPT}...")
model = PeftModel.from_pretrained(
    base_model,
    str(LOCAL_RESUME_CKPT),
    is_trainable=True
)
model.print_trainable_parameters()

# Training Arguments
train_args_kwargs = {
    "output_dir": str(OUTPUT_DIR),
    "learning_rate": 5e-5,
    "lr_scheduler_type": "cosine",
    "warmup_ratio": 0.05,
    "num_train_epochs": 1.0,
    "max_steps": 1875,
    "per_device_train_batch_size": 2,
    "gradient_accumulation_steps": 4,
    "bf16": torch.cuda.is_bf16_supported(),
    "fp16": not torch.cuda.is_bf16_supported() and torch.cuda.is_available(),
    "logging_steps": 25,
    "save_strategy": "steps",
    "save_steps": 125,
    "save_total_limit": 5,
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

# Resumed Training Execution
log_rank0("=" * 80)
log_rank0(f"RESUMING TRAINING FROM STEP 1250 -> 1875 (Remaining 625 optimizer steps)...")
log_rank0("=" * 80)
t_start = time.time()
train_result = trainer.train(resume_from_checkpoint=str(LOCAL_RESUME_CKPT))
train_duration = time.time() - t_start

log_rank0("=" * 80)
log_rank0(f"REMAINING TRAINING COMPLETED in {train_duration:.2f}s ({train_duration/60:.2f} min)")
log_rank0(f"Final Global Step:  {train_result.global_step}")
log_rank0(f"Final Train Loss:   {train_result.training_loss:.4f}")
log_rank0("=" * 80)

# Save Final Trained Adapter IMMEDIATELY
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

# Post-Training Comprehensive Evaluation on Rank 0
if global_rank == 0:
    log_rank0("\n" + "=" * 80)
    log_rank0("STARTING COMPREHENSIVE FINAL MODEL EVALUATION")
    log_rank0("=" * 80)
    
    del model
    del trainer
    del base_model
    import gc
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    classes = [
        "Benign", "Cookie Injection", "Directory Traversal", "LOG4J",
        "Log Forging", "RCE", "SQL Injection", "XSS"
    ]
    
    def evaluate_model_on_dataset(eval_model, dataset_path, eval_name, max_samples=None):
        log_rank0(f"Evaluating on {dataset_path.name} ({eval_name})...")
        with open(dataset_path, "r", encoding="utf-8") as f:
            raw_recs = [json.loads(line) for line in f if line.strip()]
            
        if max_samples and len(raw_recs) > max_samples:
            log_rank0(f"Subsampling to {max_samples} balanced samples for bounded execution...")
            by_cat = defaultdict(list)
            for r in raw_recs:
                by_cat[r.get("category", "Benign")].append(r)
            per_cat_limit = max(1, max_samples // len(by_cat))
            raw_recs = [r for cat_items in by_cat.values() for r in cat_items[:per_cat_limit]]

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

        # Specific diagnostics
        benign_fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "Benign" and yp != "Benign")
        benign_total = sum(1 for yt in y_true if yt == "Benign")
        benign_fp_rate = benign_fp / benign_total if benign_total > 0 else 0.0

        xss_to_rce = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "XSS" and yp == "RCE")
        rce_to_xss = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "RCE" and yp == "XSS")

        return {
            "total_samples": len(y_true),
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "per_class": per_class,
            "confusion_matrix": confusion_mat,
            "diagnostics": {
                "benign_fp_count": benign_fp,
                "benign_fp_rate": round(benign_fp_rate, 4),
                "xss_classified_as_rce": xss_to_rce,
                "rce_classified_as_xss": rce_to_xss
            },
            "duration_seconds": round(dur, 2)
        }

    # Load Newly Trained Final Model
    log_rank0(f"Loading final trained model from {final_adapter_dir}...")
    b = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map={"": 0} if torch.cuda.is_available() else None,
        trust_remote_code=True
    )
    final_eval_model = PeftModel.from_pretrained(b, str(final_adapter_dir))
    final_eval_model.eval()

    eval_orig = evaluate_model_on_dataset(final_eval_model, VAL_ORIG_PATH, "Final_Model_Original_Val")
    eval_corr = evaluate_model_on_dataset(final_eval_model, VAL_CORR_PATH, "Final_Model_Corrected_Val")
    eval_boundary = evaluate_model_on_dataset(final_eval_model, BOUNDARY_PATH, "Final_Model_Boundary_Subset")
    
    eval_test = None
    if TEST_PATH.exists():
        eval_test = evaluate_model_on_dataset(final_eval_model, TEST_PATH, "Final_Model_Independent_Test", max_samples=1000)

    # Compile Final Report
    report = {
        "status": "COMPLETED",
        "experiment": "RESUMED_EXPANDED_CLASSIFICATION_TRAINING_30000",
        "resumed_from_checkpoint": str(LOCAL_RESUME_CKPT),
        "starting_step": 1250,
        "final_step": train_result.global_step,
        "total_planned_steps": 1875,
        "is_exact_resumption": True,
        "total_training_records": len(train_dataset),
        "completed_epochs": 1.0,
        "train_loss": round(train_result.training_loss, 4),
        "train_duration_seconds": round(train_duration, 2),
        "saved_final_adapter": str(final_adapter_dir),
        "benchmarks": {
            "original_validation_benchmark_1000": eval_orig,
            "corrected_validation_benchmark_1000": eval_corr,
            "boundary_contrast_diagnostic_700": eval_boundary,
            "independent_test_benchmark": eval_test
        }
    }

    report_path = OUTPUT_DIR / "classification_training_metrics_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    log_rank0("\n" + "=" * 80)
    log_rank0("FINAL MODEL BENCHMARK RESULTS (ACCURACY / MACRO F1):")
    log_rank0(f"1. Original Val (1,000):   Accuracy={eval_orig['accuracy']*100:.2f}% | Macro F1={eval_orig['macro_f1']:.4f} | Benign FP Rate={eval_orig['diagnostics']['benign_fp_rate']*100:.2f}%")
    log_rank0(f"2. Corrected Val (1,000):  Accuracy={eval_corr['accuracy']*100:.2f}% | Macro F1={eval_corr['macro_f1']:.4f} | Benign FP Rate={eval_corr['diagnostics']['benign_fp_rate']*100:.2f}%")
    log_rank0(f"3. Boundary Diagnostic (700): Accuracy={eval_boundary['accuracy']*100:.2f}% | Macro F1={eval_boundary['macro_f1']:.4f} | XSS->RCE={eval_boundary['diagnostics']['xss_classified_as_rce']}")
    if eval_test:
        log_rank0(f"4. Independent Test (1,000):  Accuracy={eval_test['accuracy']*100:.2f}% | Macro F1={eval_test['macro_f1']:.4f} | Benign FP Rate={eval_test['diagnostics']['benign_fp_rate']*100:.2f}%")
    log_rank0("=" * 80)
    log_rank0(f"Report written to: {report_path}")
    log_rank0("TRAINING AND COMPREHENSIVE BENCHMARK EVALUATION FINISHED SUCCESSFULLY.")


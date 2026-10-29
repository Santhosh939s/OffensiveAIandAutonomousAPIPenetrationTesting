"""
train_rebuilt_v5_pilot.py
RebuiltV5 Pilot Multi-Task Fine-Tuning Script.
PREPARED CONFIGURATION ONLY - DO NOT RUN WITHOUT EXPLICIT APPROVAL.

Target Base Model: Qwen/Qwen2.5-1.5B-Instruct
Dataset: finetuning/rebuilt_v5_pilot/train.jsonl (800) + val.jsonl (100)
Max Length: 2048 (increased for structured plans, JSON schemas, and reports)
Target Modules: ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
LoRA: r=16, alpha=32, dropout=0.05
"""

import os
import sys

# ── SAFETY GUARD: PREVENT ACCIDENTAL EXECUTION WITHOUT APPROVAL ──────────────
EXECUTION_PERMITTED = False  # Set to True only upon explicit user instruction

if not EXECUTION_PERMITTED:
    print("=" * 80)
    print("SAFETY INTERLOCK ENGAGED: train_rebuilt_v5_pilot.py is staged in PREPARE-ONLY mode.")
    print("Zero training steps or optimizer updates will be performed.")
    print("To execute, update EXECUTION_PERMITTED = True after formal user approval.")
    print("=" * 80)
    sys.exit(0)

import json
import torch
from pathlib import Path
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
)

# ── CONFIGURATION & PATHS ───────────────────────────────────────────────────
BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
SCRIPT_DIR = Path(__file__).resolve().parent
TRAIN_PATH = SCRIPT_DIR / "train.jsonl"
VAL_PATH   = SCRIPT_DIR / "val.jsonl"
OUTPUT_DIR = SCRIPT_DIR / "checkpoints_rebuilt_v5_pilot"
MAX_LENGTH = 2048
MIN_COMPLETION_TOKENS = 16
LOCK_PATH  = SCRIPT_DIR / ".training.lock"

# ── SINGLETON PROCESS LOCK (ENSURE ONLY ONE JOB CAN START) ───────────────────
local_rank = int(os.environ.get("LOCAL_RANK", 0))
global_rank = int(os.environ.get("RANK", 0))

def is_pid_running(pid: int) -> bool:
    """Check if process with given PID is currently active."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def acquire_singleton_lock():
    """Acquires lock file on Rank 0. Aborts if another active job holds the lock."""
    if global_rank != 0:
        return
    if LOCK_PATH.exists():
        try:
            with open(LOCK_PATH, "r", encoding="utf-8") as f:
                lock_data = json.load(f)
            locked_pid = lock_data.get("pid")
            if locked_pid and is_pid_running(locked_pid):
                print(f"[FATAL] Another training job is already active (PID: {locked_pid}).")
                print("Single-job constraint violated. Aborting launch to prevent concurrent training.")
                sys.exit(1)
            else:
                print(f"[WARNING] Found stale lock from dead PID {locked_pid}. Cleaning up stale lock.")
                LOCK_PATH.unlink(missing_ok=True)
        except Exception:
            LOCK_PATH.unlink(missing_ok=True)

    with open(LOCK_PATH, "w", encoding="utf-8") as f:
        json.dump({"pid": os.getpid(), "local_rank": local_rank, "global_rank": global_rank}, f)

def release_singleton_lock():
    """Releases lock file on Rank 0."""
    if global_rank == 0 and LOCK_PATH.exists():
        LOCK_PATH.unlink(missing_ok=True)

import atexit
atexit.register(release_singleton_lock)
acquire_singleton_lock()

# Multi-GPU / DDP device placement
if torch.cuda.is_available():
    torch.cuda.set_device(local_rank)

# ── DATA COLLATOR WITH EXPLICIT BOUNDARY HANDLING & LOSS MASKING ────────────
class MultiTaskCompletionCollator:
    """
    Masks prompt tokens (system + user) with -100 so cross-entropy loss is computed
    strictly across the assistant completion tokens.

    Explicit Boundary & Truncation Handling:
    - Enforces a minimum assistant completion budget (min_completion_tokens).
    - If prompt length exceeds (max_length - min_completion_tokens), the example is REJECTED.
    - If assistant completion exceeds available budget, it is safely truncated.
    - Asserts that completion labels are NEVER all masked (-100).
    - Guarantees final sequence length never exceeds max_length.
    """
    def __init__(self, tokenizer, max_length=2048, min_completion_tokens=16):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.min_completion_tokens = min_completion_tokens
        self.marker = "<|im_start|>assistant\n"

    def process_single(self, text):
        if self.marker not in text:
            raise ValueError("Assistant completion marker '<|im_start|>assistant\\n' missing in text.")

        prompt_text, completion_text = text.rsplit(self.marker, 1)
        prompt_text += self.marker

        prompt_ids = self.tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
        completion_ids = self.tokenizer(completion_text, add_special_tokens=False)["input_ids"]

        prompt_len = len(prompt_ids)
        comp_len = len(completion_ids)

        # Check prompt/completion boundary budget
        available_completion_budget = self.max_length - prompt_len

        if available_completion_budget < self.min_completion_tokens:
            raise ValueError(
                f"Overlength sequence rejected: prompt length ({prompt_len} tokens) leaves insufficient "
                f"completion budget ({available_completion_budget} < {self.min_completion_tokens} tokens) "
                f"under max_length={self.max_length}. Cannot retain both a valid prompt and a useful completion."
            )

        if comp_len == 0:
            raise ValueError("Empty assistant completion: cannot compute loss on zero completion tokens.")

        # Truncate completion if it exceeds available budget, retaining full prompt
        if comp_len > available_completion_budget:
            completion_ids = completion_ids[:available_completion_budget]

        input_ids = prompt_ids + completion_ids
        labels = [-100] * prompt_len + completion_ids.copy()

        # Invariant checks
        assert len(input_ids) <= self.max_length, f"Sequence length {len(input_ids)} exceeds max_length {self.max_length}"
        assert len(input_ids) == len(labels), "input_ids and labels length mismatch"
        assert any(l != -100 for l in labels), "All completion labels are masked (-100). Training supervision is absent."
        assert labels.count(-100) == prompt_len, "Prompt masking count does not match prompt length."

        return input_ids, labels

    def __call__(self, features):
        rows = []
        for feature in features:
            text = feature["text"]
            input_ids, labels = self.process_single(text)
            rows.append((input_ids, labels))

        max_len = max(len(ids) for ids, _ in rows)
        pad_id = self.tokenizer.pad_token_id

        input_batch, label_batch, mask_batch = [], [], []
        for ids, labels in rows:
            padding = max_len - len(ids)
            input_batch.append(ids + [pad_id] * padding)
            label_batch.append(labels + [-100] * padding)
            mask_batch.append([1] * len(ids) + [0] * padding)

        return {
            "input_ids": torch.tensor(input_batch, dtype=torch.long),
            "labels": torch.tensor(label_batch, dtype=torch.long),
            "attention_mask": torch.tensor(mask_batch, dtype=torch.long),
        }

def read_multitask_dataset(path, tokenizer):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                text = tokenizer.apply_chat_template(
                    item["messages"],
                    tokenize=False,
                    add_generation_prompt=False,
                )
                rows.append({"text": text})
    return Dataset.from_list(rows)

# ── MODEL & TOKENIZER INITIALIZATION ─────────────────────────────────────────
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
if tokenizer.pad_token_id is None:
    tokenizer.pad_token = tokenizer.eos_token

quant_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
)

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=quant_config,
    device_map={"": local_rank} if torch.cuda.is_available() else None,
)

base_model = prepare_model_for_kbit_training(
    base_model,
    use_gradient_checkpointing=True,
)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "up_proj", "down_proj", "gate_proj",
    ],
    task_type="CAUSAL_LM",
)

model = get_peft_model(base_model, lora_config)
model.config.use_cache = False
model.gradient_checkpointing_enable(
    gradient_checkpointing_kwargs={"use_reentrant": False}
)

train_dataset = read_multitask_dataset(TRAIN_PATH, tokenizer)
val_dataset = read_multitask_dataset(VAL_PATH, tokenizer)
collator = MultiTaskCompletionCollator(tokenizer, MAX_LENGTH)

# ── TRAINING ARGUMENTS ───────────────────────────────────────────────────────
args = TrainingArguments(
    output_dir=str(OUTPUT_DIR),
    num_train_epochs=3,
    max_steps=150,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=8,
    learning_rate=1.5e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.10,
    max_grad_norm=1.0,
    fp16=True,
    bf16=False,
    gradient_checkpointing=True,
    save_strategy="steps",
    save_steps=50,
    save_total_limit=3,
    load_best_model_at_end=False,
    logging_steps=10,
    eval_strategy="steps",
    eval_steps=25,
    remove_unused_columns=False,
    optim="adamw_torch",
    dataloader_num_workers=0,
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    data_collator=collator,
    processing_class=tokenizer,
)

if global_rank == 0:
    world_size = int(os.environ.get("WORLD_SIZE", 1))
    per_device_batch = args.per_device_train_batch_size
    grad_accum = args.gradient_accumulation_steps
    eff_batch = per_device_batch * grad_accum * world_size
    train_records = len(train_dataset)
    steps_per_epoch = train_records / eff_batch
    est_epochs = args.max_steps / steps_per_epoch

    print("\n" + "=" * 80)
    print("REBUILTV5 PILOT: RECONCILED BATCH SIZE & STEP CONFIGURATION")
    print("=" * 80)
    print(f"  * Training Set Size:              {train_records} samples")
    print(f"  * World Size (GPUs):              {world_size}")
    print(f"  * Per-Device Train Batch Size:    {per_device_batch}")
    print(f"  * Gradient Accumulation Steps:    {grad_accum}")
    print(f"  * Effective Batch Size:           {eff_batch} samples / optimizer step ({per_device_batch} x {grad_accum} x {world_size})")
    print(f"  * Dataset Batches (Steps) / Epoch:{steps_per_epoch:.1f} optimizer steps")
    print(f"  * Max Optimizer Steps:            {args.max_steps}")
    print(f"  * Estimated Epochs at 150 Steps:  {est_epochs:.2f} epochs")
    print(f"  * Checkpoint Save Steps:          {args.save_steps} (Checkpoints at step 50, 100, 150)")
    print(f"  * Eval Frequency:                 Every {args.eval_steps} steps against val.jsonl (100 samples)")
    print(f"  * Singleton Lock Status:          ACTIVE (Lockfile: {LOCK_PATH})")
    print("=" * 80)
    print("RebuiltV5 Pilot Trainer configured. Staged and ready for execution upon user authorization.\n")

"""
train_phase_c_pilot.py - Kaggle GPU Training Pilot (1,000 Verified Records)
Trains 1 epoch on the 1,000-sample classification pilot to measure actual training
throughput, peak VRAM, latency, and evaluate validation metrics.
"""

import os
import sys
import time
import json
import psutil
from pathlib import Path
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

# Detect environment: Kaggle vs Local
if Path("/kaggle/working").exists():
    ROOT = Path("/kaggle/working")
    INPUT_DIR = Path("/kaggle/input")
    # Adapter checkpoint 200 from Kaggle dataset input if attached
    REBUILTV4_ADAPTER = INPUT_DIR / "rebuiltv4-training-checkpoints" / "checkpoint-200"
    if not REBUILTV4_ADAPTER.exists():
        REBUILTV4_ADAPTER = INPUT_DIR / "rebuiltv4-adapters" / "checkpoint-200"
    TRAIN_PATH = ROOT / "pilot_train_800.jsonl"
    VAL_PATH = ROOT / "pilot_val_100.jsonl"
    OUTPUT_DIR = ROOT / "qwen_pilot_phase_c_output"
else:
    ROOT = Path(".")
    REBUILTV4_ADAPTER = ROOT / "staging_rebuiltv4_training_checkpoints" / "checkpoint-200"
    TRAIN_PATH = ROOT / "dataset" / "splits" / "pilot_train_800.jsonl"
    VAL_PATH = ROOT / "dataset" / "splits" / "pilot_val_100.jsonl"
    OUTPUT_DIR = ROOT / "qwen_pilot_phase_c_output"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MAX_LENGTH = 1024

# Distributed Setup
is_distributed = "LOCAL_RANK" in os.environ
if is_distributed:
    local_rank = int(os.environ["LOCAL_RANK"])
    world_size = int(os.environ["WORLD_SIZE"])
    torch.cuda.set_device(local_rank)
    dist.init_process_group("nccl")
else:
    local_rank = 0
    world_size = 1
    if torch.cuda.is_available():
        torch.cuda.set_device(0)

def log_rank0(msg):
    if local_rank == 0:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

log_rank0("=" * 80)
log_rank0("PHASE C 1,000-RECORD PILOT TRAINING START")
log_rank0(f"Device Count: {torch.cuda.device_count()} | World Size: {world_size} | Local Rank: {local_rank}")
log_rank0("=" * 80)

# Memory & Telemetry Tracking
start_time = time.time()
init_start = time.time()

# 1. Load Tokenizer
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# 2. Ingest Dataset
def load_split(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                # Apply chat template
                text = tokenizer.apply_chat_template(
                    item["messages"],
                    tokenize=False,
                    add_generation_prompt=False
                )
                rows.append({"text": text, "category": item["category"]})
    return Dataset.from_list(rows)

train_dataset = load_split(TRAIN_PATH)
val_dataset = load_split(VAL_PATH)
log_rank0(f"Loaded Train: {len(train_dataset)} rows | Val: {len(val_dataset)} rows")

# 3. Data Collator with Completion Masking
class ExplicitCompletionCollator:
    def __init__(self, tokenizer, max_length):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.marker = "<|im_start|>assistant\n"

    def __call__(self, features):
        input_ids_batch = []
        labels_batch = []
        attention_mask_batch = []

        for f in features:
            text = f["text"]
            if self.marker not in text:
                raise ValueError("Assistant marker missing.")
            prompt_text, completion_text = text.rsplit(self.marker, 1)
            prompt_text += self.marker

            prompt_ids = self.tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
            completion_ids = self.tokenizer(completion_text, add_special_tokens=False)["input_ids"]

            input_ids = prompt_ids + completion_ids
            labels = [-100] * len(prompt_ids) + completion_ids.copy()

            if len(input_ids) > self.max_length:
                input_ids = input_ids[:self.max_length]
                labels = labels[:self.max_length]

            attention_mask = [1] * len(input_ids)

            input_ids_batch.append(input_ids)
            labels_batch.append(labels)
            attention_mask_batch.append(attention_mask)

        # Pad batch
        max_b_len = max(len(ids) for ids in input_ids_batch)
        padded_inputs, padded_labels, padded_masks = [], [], []

        for ids, lbls, msks in zip(input_ids_batch, labels_batch, attention_mask_batch):
            pad_len = max_b_len - len(ids)
            padded_inputs.append(ids + [self.tokenizer.pad_token_id] * pad_len)
            padded_labels.append(lbls + [-100] * pad_len)
            padded_masks.append(msks + [0] * pad_len)

        return {
            "input_ids": torch.tensor(padded_inputs, dtype=torch.long),
            "labels": torch.tensor(padded_labels, dtype=torch.long),
            "attention_mask": torch.tensor(padded_masks, dtype=torch.long),
        }

collator = ExplicitCompletionCollator(tokenizer, MAX_LENGTH)

# 4. Load Base Model in 4-bit NF4
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
)

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map={"": local_rank} if torch.cuda.is_available() else None,
    trust_remote_code=True,
)
model = prepare_model_for_kbit_training(model)

# 5. Attach RebuiltV4 Adapter as Initialization if available, or initialize LoRA config
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

# 6. Training Arguments Construction with Dynamic Signature Inspection
import inspect

def build_training_arguments(output_dir, **desired_kwargs):
    sig = inspect.signature(TrainingArguments.__init__)
    valid_params = set(sig.parameters.keys())
    
    params = {"output_dir": str(output_dir)}
    
    candidates = {
        "num_train_epochs": 1.0,
        "per_device_train_batch_size": 1,
        "per_device_eval_batch_size": 1,
        "gradient_accumulation_steps": desired_kwargs.get("gradient_accumulation_steps", 16),
        "learning_rate": 2e-4,
        "max_grad_norm": 1.0,
        "logging_steps": 5,
        "save_total_limit": 2,
        "load_best_model_at_end": False,
        "remove_unused_columns": False,
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
    elif "warmup_ratio" in valid_params:
        candidates["warmup_ratio"] = 0.10
        
    if "fp16" in valid_params:
        candidates["fp16"] = not torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False
    if "bf16" in valid_params:
        candidates["bf16"] = torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False
        
    if is_distributed and "ddp_find_unused_parameters" in valid_params:
        candidates["ddp_find_unused_parameters"] = False
        
    for k, v in candidates.items():
        if k in valid_params:
            params[k] = v
            
    log_rank0(f"Instantiating TrainingArguments with {len(params)} verified parameters:")
    for k in sorted(params.keys()):
        log_rank0(f"  * {k}: {params[k]}")
        
    return TrainingArguments(**params)

grad_accum = max(1, 16 // world_size)
training_args = build_training_arguments(
    OUTPUT_DIR,
    gradient_accumulation_steps=grad_accum
)

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

# 7. Execute 1-Epoch Pilot Training
log_rank0("Starting Pilot Training Execution...")
train_start = time.time()
train_result = trainer.train()
train_duration = time.time() - train_start

# 8. Post-Training Metrics & Reload Verification
if local_rank == 0:
    log_rank0("=" * 80)
    log_rank0("PILOT TRAINING EXECUTION COMPLETED")
    log_rank0("=" * 80)

    # Save final pilot checkpoint separately
    pilot_final_dir = OUTPUT_DIR / "pilot_rebuilt_v5_checkpoint_final"
    trainer.save_model(str(pilot_final_dir))
    tokenizer.save_pretrained(str(pilot_final_dir))
    log_rank0(f"Saved distinct pilot checkpoint to: {pilot_final_dir}")

    # Verify reloading
    log_rank0("Verifying saved checkpoint reloadability...")
    test_reloaded_peft = PeftModel.from_pretrained(
        AutoModelForCausalLM.from_pretrained(
            BASE_MODEL,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True
        ),
        str(pilot_final_dir)
    )
    log_rank0("Checkpoint reloadability verified successfully!")

    # Resource measurements
    gpu_count = torch.cuda.device_count()
    peak_vram_per_gpu = [
        round(torch.cuda.max_memory_allocated(i) / (1024 ** 2), 2)
        for i in range(gpu_count)
    ] if torch.cuda.is_available() else [0]
    peak_vram_mb = max(peak_vram_per_gpu) if peak_vram_per_gpu else 0
    sys_ram_gb = psutil.virtual_memory().used / (1024 ** 3)
    total_samples = len(train_dataset)
    samples_per_sec = total_samples / train_duration if train_duration > 0 else 0

    eval_results = trainer.evaluate()

    telemetry_data = {
        "pilot_run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_samples": total_samples,
        "epochs": 1.0,
        "effective_batch_size": 16,
        "world_size": world_size,
        "gpu_count": gpu_count,
        "gpu_names": [torch.cuda.get_device_name(i) for i in range(gpu_count)] if torch.cuda.is_available() else ["CPU"],
        "init_duration_seconds": round(init_duration, 2),
        "pure_train_duration_seconds": round(train_duration, 2),
        "total_wall_clock_seconds": round(time.time() - start_time, 2),
        "measured_samples_per_second": round(samples_per_sec, 2),
        "peak_vram_mb": round(peak_vram_mb, 2),
        "peak_vram_per_gpu_mb": peak_vram_per_gpu,
        "system_ram_gb": round(sys_ram_gb, 2),
        "train_loss": round(train_result.training_loss, 4),
        "eval_loss": round(eval_results.get("eval_loss", 0.0), 4),
        "eval_runtime_seconds": round(eval_results.get("eval_runtime", 0.0), 2),
        "checkpoint_reloaded_verified": True,
        "saved_checkpoint_path": str(pilot_final_dir)
    }

    metrics_out = OUTPUT_DIR / "pilot_telemetry_metrics.json"
    with open(metrics_out, "w", encoding="utf-8") as f:
        json.dump(telemetry_data, f, indent=2)
    log_rank0(f"Telemetry report written to: {metrics_out}")

    print("\n--- Pilot Results Summary ---")
    print(f"  Throughput: {samples_per_sec:.2f} samples/sec")
    print(f"  Train Time: {train_duration:.1f}s ({train_duration/60:.2f} min)")
    print(f"  Peak VRAM:  {peak_vram_mb:.1f} MB")
    print(f"  Train Loss: {train_result.training_loss:.4f}")
    print(f"  Eval Loss:  {eval_results.get('eval_loss', 0.0):.4f}")

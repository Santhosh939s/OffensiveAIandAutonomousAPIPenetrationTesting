
import os
import json
import torch
import torch.distributed as dist
from pathlib import Path
import peft.utils.save_and_load as _peft_save_load
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
)

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
            raise RuntimeError(
                "DDP workaround is only valid without tensor parallelism."
            )
    return None

_peft_save_load._maybe_shard_state_dict_for_tp = _ddp_skip_tensor_parallel_sharding

BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
ROOT = Path("/kaggle/working/api_pentest_research")
DATA_DIR = ROOT / "finetuning" / "rebuilt_v4"
OUTPUT_DIR = ROOT / "qwen_api_security_lora_rebuilt_v4"
MAX_LENGTH = 1024

local_rank = int(os.environ["LOCAL_RANK"])
torch.cuda.set_device(local_rank)

TRAIN_PATH = DATA_DIR / "train.jsonl"
VAL_PATH = ROOT / "finetuning" / "rebuilt_v3" / "validation_sample_2000.jsonl"

SYSTEM_PROMPT = (
    "You are an API security classifier. "
    "Classify the HTTP request into exactly one of these categories: "
    "Benign, Cookie Injection, Directory Traversal, LOG4J, "
    "Log Forging, RCE, SQL Injection, or XSS. "
    "Return only the category name."
)

def read_text_dataset(path, tokenizer):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": item["input"]},
                {"role": "assistant", "content": item["category"]},
            ]
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
            rows.append({"text": text})
    return Dataset.from_list(rows)

class ExplicitCompletionCollator:
    def __init__(self, tokenizer, max_length):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.marker = "<|im_start|>assistant\n"

    def __call__(self, features):
        rows = []

        for feature in features:
            text = feature["text"]
            if self.marker not in text:
                raise ValueError("Assistant completion marker missing.")

            prompt_text, completion_text = text.rsplit(self.marker, 1)
            prompt_text += self.marker

            prompt_ids = self.tokenizer(
                prompt_text, add_special_tokens=False
            )["input_ids"]
            completion_ids = self.tokenizer(
                completion_text, add_special_tokens=False
            )["input_ids"]

            input_ids = prompt_ids + completion_ids
            labels = [-100] * len(prompt_ids) + completion_ids.copy()

            if len(input_ids) > self.max_length:
                excess = len(input_ids) - self.max_length
                if excess >= len(prompt_ids):
                    input_ids = input_ids[-self.max_length:]
                    labels = labels[-self.max_length:]
                else:
                    input_ids = input_ids[excess:]
                    labels = labels[excess:]

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
    device_map={"": local_rank},
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

train_dataset = read_text_dataset(TRAIN_PATH, tokenizer)
val_dataset = read_text_dataset(VAL_PATH, tokenizer)
collator = ExplicitCompletionCollator(tokenizer, MAX_LENGTH)

args = TrainingArguments(
    output_dir=str(OUTPUT_DIR),
    num_train_epochs=1,
    max_steps=300,
    per_device_train_batch_size=1,
    per_device_eval_batch_size=1,
    gradient_accumulation_steps=8,
    learning_rate=2e-4,
    max_grad_norm=1.0,
    fp16=True,
    bf16=False,
    gradient_checkpointing=True,
    save_strategy="steps",
    save_steps=100,
    save_total_limit=2,
    load_best_model_at_end=False,
    logging_steps=25,
    eval_strategy="steps",
    eval_steps=100,
    remove_unused_columns=False,
    ddp_find_unused_parameters=False,
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

if dist.is_initialized() and dist.get_rank() == 0:
    print("Distributed processes:", dist.get_world_size())
    print("Training examples:", len(train_dataset))
    print("Validation examples loaded:", len(val_dataset))
    print("Maximum sequence length:", MAX_LENGTH)
    print("Per-GPU batch size:", 1)
    print("Gradient accumulation:", 8)
    print("Effective batch size:", 16)
    print("Training from a fresh LoRA adapter.")
    print("Output directory:", OUTPUT_DIR)

trainer.train()
trainer.save_model(str(OUTPUT_DIR))
if trainer.is_world_process_zero():
    tokenizer.save_pretrained(str(OUTPUT_DIR))

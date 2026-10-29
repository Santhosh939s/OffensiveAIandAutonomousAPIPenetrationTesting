#!/usr/bin/env python3
"""
Step-4500 Non-Destructive Checkpoint Evaluation Pipeline
Reproducible, deterministic evaluation with dual-parser tracking (legacy vs normalized),
incremental persistence, duplicate auditing, and comprehensive metrics.
"""

import os
import sys
import json
import time
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix

VALID_CATEGORIES = [
    "Benign",
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS"
]

SYSTEM_PROMPT = (
    "You are an API security classifier. "
    "Classify the HTTP request into exactly one of these categories: "
    "Benign, Cookie Injection, Directory Traversal, LOG4J, "
    "Log Forging, RCE, SQL Injection, or XSS. "
    "Return only the category name."
)

def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate API Security Classification LoRA Checkpoint")
    parser.add_argument("--base-model", type=str, default="Qwen/Qwen2.5-1.5B-Instruct", help="Base model identifier")
    parser.add_argument("--adapter-path", type=str, default=None, help="Explicit path to LoRA adapter directory")
    parser.add_argument("--test-file", type=str, default=None, help="Path to test_sample_2000.jsonl")
    parser.add_argument("--output-dir", type=str, default=None, help="Destination directory for evaluation artifacts")
    parser.add_argument("--batch-size", type=int, default=8, help="Inference batch size")
    parser.add_argument("--max-length", type=int, default=1024, help="Max input sequence token length")
    parser.add_argument("--max-new-tokens", type=int, default=16, help="Maximum generated tokens")
    parser.add_argument("--smoke-test", action="store_true", help="Run quick 10-example smoke test")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of evaluation examples")
    parser.add_argument("--device", type=str, default="auto", help="Execution device (auto, cuda:0, cpu)")
    parser.add_argument("--git-commit", type=str, default="unknown", help="Git commit hash of running code")
    return parser.parse_args()

def locate_step4500_adapter(explicit_path=None):
    if explicit_path and os.path.exists(explicit_path):
        return Path(explicit_path)

    # Search candidates in Kaggle and local storage
    candidates = [
        Path("/kaggle/input/recovery/API_Security_Model_step4500/MSK_API_Security_Model"),
        Path("/kaggle/input/recovery/API_Security_Recovery_20261020_114027/recovery_20261020_114027/original_model/MSK_API_Security_Model_step4500/MSK_API_Security_Model"),
        Path("/kaggle/input/recovery/API_Security_Recovery_20261020_114027/recovery_20261020_114027/original_model/checkpoint-4500"),
        Path("kaggle_output/api_pentest_research/qwen_api_security_lora_resume_3000/checkpoint-4500"),
        Path("scratch/recovered_adapter/final_qwen_api_adapter"),
    ]
    for c in candidates:
        if c.exists() and (c / "adapter_config.json").exists():
            return c
    raise FileNotFoundError(f"Step-4500 adapter directory not found in known locations: {[str(c) for c in candidates]}")

def locate_test_file(explicit_path=None):
    if explicit_path and os.path.exists(explicit_path):
        return Path(explicit_path)
    candidates = [
        Path("/kaggle/input/recovery/API_Security_Recovery_20261020_114027/recovery_20261020_114027/evaluation/test_sample_2000.jsonl"),
        Path("/kaggle/working/api_pentest_research/finetuning/rebuilt_v4/test_sample_2000.jsonl"),
        Path("evaluation/test_sample_2000.jsonl"),
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError(f"Test dataset file not found in known locations: {[str(c) for c in candidates]}")

def parse_predictions(raw_text):
    clean = raw_text.strip()
    
    # 1. Legacy strict prefix parser (exact match with previous benchmark)
    legacy_pred = next((cat for cat in VALID_CATEGORIES if clean.startswith(cat)), "INVALID")
    
    # 2. Normalized case-insensitive and whitespace-stripped parser
    clean_lower = clean.lower()
    normalized_pred = "INVALID"
    for cat in VALID_CATEGORIES:
        if clean_lower.startswith(cat.lower()):
            normalized_pred = cat
            break
            
    # 3. Substring fallback if leading non-alphanumeric noise occurred
    if normalized_pred == "INVALID":
        for cat in VALID_CATEGORIES:
            if cat.lower() in clean_lower:
                normalized_pred = cat
                break
                
    return legacy_pred, normalized_pred

def audit_dataset(records):
    input_hashes = defaultdict(list)
    for idx, r in enumerate(records):
        h = hashlib.sha256(r["input"].encode("utf-8")).hexdigest()
        input_hashes[h].append((idx, r["category"]))
        
    duplicates = [items for items in input_hashes.values() if len(items) > 1]
    conflicts = [items for items in duplicates if len(set(x[1] for x in items)) > 1]
    
    return {
        "total_records": len(records),
        "unique_inputs": len(input_hashes),
        "duplicate_groups": len(duplicates),
        "conflicting_groups": len(conflicts),
        "class_distribution": dict(Counter(r["category"] for r in records))
    }

def main():
    args = parse_args()
    start_time = time.time()
    
    adapter_path = locate_step4500_adapter(args.adapter_path)
    test_file = locate_test_file(args.test_file)
    
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir) if args.output_dir else Path(f"/kaggle/working/eval_runs/eval_step4500_{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"=== STEP-4500 EVALUATION PIPELINE ===")
    print(f"Timestamp (UTC): {stamp}")
    print(f"Adapter Path:    {adapter_path}")
    print(f"Test File:       {test_file}")
    print(f"Output Dir:      {out_dir}")
    print(f"Smoke Test Mode: {args.smoke_test}")
    
    with open(test_file, "r", encoding="utf-8") as f:
        all_records = [json.loads(line) for line in f]
        
    audit_info = audit_dataset(all_records)
    print(f"\nDataset Audit: {audit_info['total_records']} total, {audit_info['unique_inputs']} unique, {audit_info['conflicting_groups']} conflicts")
    
    if args.smoke_test:
        eval_records = all_records[:10]
        print(f"[SMOKE TEST] Restricting to first {len(eval_records)} examples")
    elif args.limit:
        eval_records = all_records[:args.limit]
        print(f"[LIMIT] Restricting to first {len(eval_records)} examples")
    else:
        eval_records = all_records
        
    print(f"\nLoading Tokenizer from: {args.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, padding_side="left")
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        
    quant_used = "4bit_nf4"
    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True
    )
    
    print(f"Loading Base Model ({args.base_model}) with 4-bit NF4...")
    try:
        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            quantization_config=quant_config,
            torch_dtype=torch.float16,
            device_map="auto"
        )
    except Exception as e:
        print(f"[WARNING] 4-bit NF4 failed ({e}). Falling back to FP16 compute...")
        quant_used = "fp16_fallback"
        base_model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            torch_dtype=torch.float16,
            device_map="auto"
        )
        
    print(f"Attaching LoRA Adapter from: {adapter_path}")
    model = PeftModel.from_pretrained(base_model, str(adapter_path))
    model.eval()
    
    pred_file = out_dir / "predictions.jsonl"
    results = []
    legacy_preds = []
    norm_preds = []
    gold_labels = []
    
    print(f"\nBeginning inference on {len(eval_records)} examples (batch size: {args.batch_size})...")
    batch_size = args.batch_size
    
    with open(pred_file, "w", encoding="utf-8") as pf:
        for b_idx in range(0, len(eval_records), batch_size):
            batch_slice = eval_records[b_idx:b_idx + batch_size]
            batch_prompts = []
            
            for item in batch_slice:
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": item["input"]}
                ]
                formatted = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                batch_prompts.append(formatted)
                
            enc = tokenizer(
                batch_prompts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=args.max_length
            ).to(model.device)
            
            with torch.inference_mode():
                out_tokens = model.generate(
                    **enc,
                    max_new_tokens=args.max_new_tokens,
                    do_sample=False,
                    pad_token_id=tokenizer.pad_token_id,
                    eos_token_id=tokenizer.eos_token_id
                )
                
            gen_texts = tokenizer.batch_decode(
                out_tokens[:, enc["input_ids"].shape[1]:],
                skip_special_tokens=True
            )
            
            for item, raw in zip(batch_slice, gen_texts):
                legacy_p, norm_p = parse_predictions(raw)
                gold = item["category"]
                
                record = {
                    "gold": gold,
                    "legacy_pred": legacy_p,
                    "norm_pred": norm_p,
                    "raw_response": raw.strip(),
                    "match_legacy": (legacy_p == gold),
                    "match_norm": (norm_p == gold),
                    "input_snippet": item["input"][:150]
                }
                results.append(record)
                legacy_preds.append(legacy_p)
                norm_preds.append(norm_p)
                gold_labels.append(gold)
                
                # Incremental flush to disk
                pf.write(json.dumps(record) + "\n")
                pf.flush()
                
            if (b_idx + batch_size) % 100 == 0 or (b_idx + batch_size) >= len(eval_records):
                print(f"  Processed {min(b_idx + batch_size, len(eval_records))}/{len(eval_records)} examples...", flush=True)

    elapsed = time.time() - start_time
    ms_per_sample = (elapsed / len(eval_records)) * 1000
    
    # Compute metrics for both parsing regimes
    def compute_metrics_dict(preds):
        return {
            "accuracy": float(accuracy_score(gold_labels, preds)),
            "macro_f1": float(f1_score(gold_labels, preds, labels=VALID_CATEGORIES, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(gold_labels, preds, labels=VALID_CATEGORIES, average="weighted", zero_division=0)),
            "invalid_count": int(preds.count("INVALID")),
            "classification_report": classification_report(
                gold_labels, preds, labels=VALID_CATEGORIES, zero_division=0, output_dict=True
            ),
            "confusion_matrix": confusion_matrix(gold_labels, preds, labels=VALID_CATEGORIES).tolist()
        }
        
    metrics_legacy = compute_metrics_dict(legacy_preds)
    metrics_norm = compute_metrics_dict(norm_preds)
    
    metrics_payload = {
        "model": "Step-4500",
        "checkpoint_path": str(adapter_path),
        "evaluated_records": len(eval_records),
        "elapsed_seconds": round(elapsed, 2),
        "ms_per_sample": round(ms_per_sample, 2),
        "quantization": quant_used,
        "legacy_parser_metrics": metrics_legacy,
        "normalized_parser_metrics": metrics_norm
    }
    
    with open(out_dir / "metrics.json", "w", encoding="utf-8") as mf:
        json.dump(metrics_payload, mf, indent=2)
        
    manifest = {
        "evaluation_name": "Step-4500 Held-Out Evaluation",
        "timestamp_utc": stamp,
        "git_commit": args.git_commit,
        "base_model": args.base_model,
        "adapter_path": str(adapter_path),
        "test_file": str(test_file),
        "dataset_audit": audit_info,
        "hardware": {
            "cuda_available": torch.cuda.is_available(),
            "device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
            "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
        },
        "settings": {
            "batch_size": args.batch_size,
            "max_length": args.max_length,
            "max_new_tokens": args.max_new_tokens,
            "do_sample": False,
            "quantization": quant_used
        },
        "output_directory": str(out_dir)
    }
    with open(out_dir / "manifest.json", "w", encoding="utf-8") as manf:
        json.dump(manifest, manf, indent=2)
        
    print("\n=== EVALUATION COMPLETED SUCCESSFULLY ===")
    print(f"Elapsed Time:      {elapsed:.1f}s ({ms_per_sample:.1f} ms/sample)")
    print(f"Legacy Accuracy:   {metrics_legacy['accuracy']*100:.2f}% (Invalid: {metrics_legacy['invalid_count']})")
    print(f"Normalized Acc:    {metrics_norm['accuracy']*100:.2f}% (Invalid: {metrics_norm['invalid_count']})")
    print(f"Legacy Macro F1:   {metrics_legacy['macro_f1']:.4f}")
    print(f"Normalized Macro:  {metrics_norm['macro_f1']:.4f}")
    print(f"\nArtifacts saved in: {out_dir}")
    print(f"  - {pred_file}")
    print(f"  - {out_dir / 'metrics.json'}")
    print(f"  - {out_dir / 'manifest.json'}")

if __name__ == "__main__":
    main()

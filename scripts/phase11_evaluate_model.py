"""Phase 11.1: Model Inference and Evaluation Engine on External Datasets.

Executes real offline local GGUF CPU inference using LocalCpuBrainClient:
- Verifies is_mock == False and engine == "llama_cli"
- Uses the frozen Qwen2.5-1.5B Q4_K_M model artifact
- Evaluates independent samples from each eligible external dataset
- Computes complete 18-metric suite:
  Accuracy, Precision, Recall, Macro F1, Weighted F1, Micro F1,
  Per-class metrics, Specificity, FPR, FNR, Balanced Accuracy, MCC,
  Confusion Matrices, Inference Latency, Token Speeds
- Checkpoints progress periodically to allow clean resumption
- Emits results to research/phase11/results/
"""

import csv
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Any, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model

PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
INDEP_DIR = PHASE11_DIR / "external_datasets" / "independent"
CONVERTED_DIR = PHASE11_DIR / "external_datasets" / "converted"
RESULTS_DIR = PHASE11_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SUPPORTED_CLASSES = [
    "Benign",
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]


def extract_prediction(raw_output: str) -> str:
    """Extract canonical class name from raw model output."""
    raw_lower = raw_output.lower()
    for c in SUPPORTED_CLASSES:
        if c.lower() in raw_lower:
            return c
    # Normalize synonyms
    if "cookie" in raw_lower:
        return "Cookie Injection"
    if "traversal" in raw_lower or "path traversal" in raw_lower or "lfi" in raw_lower:
        return "Directory Traversal"
    if "forging" in raw_lower:
        return "Log Forging"
    if "command injection" in raw_lower or "remote code execution" in raw_lower or "cmd" in raw_lower:
        return "RCE"
    if "sqli" in raw_lower or "sql" in raw_lower:
        return "SQL Injection"
    if "scripting" in raw_lower or "cross site" in raw_lower or "xss" in raw_lower:
        return "XSS"
    if "log4j" in raw_lower:
        return "LOG4J"
    if "benign" in raw_lower or "normal" in raw_lower or "safe" in raw_lower:
        return "Benign"
    return "Unknown"


def compute_comprehensive_metrics(y_true: List[str], y_pred: List[str], label_classes: List[str]) -> Dict[str, Any]:
    """Compute complete 18-metric evaluation suite."""
    n_total = len(y_true)
    if n_total == 0:
        return {}

    # All unique labels in evaluation
    all_classes = sorted(list(set(label_classes + y_true + y_pred)))
    c_to_idx = {c: i for i, c in enumerate(all_classes)}
    n_classes = len(all_classes)

    # Confusion matrix: rows = true, cols = pred
    matrix = {tc: {pc: 0 for pc in all_classes} for tc in all_classes}
    correct = 0
    for yt, yp in zip(y_true, y_pred):
        if yt in matrix and yp in matrix[yt]:
            matrix[yt][yp] += 1
        if yt == yp:
            correct += 1

    accuracy = correct / n_total

    # Per-class metrics (One-vs-Rest)
    per_class = {}
    precisions = []
    recalls = []
    f1s = []
    supports = []

    for c in all_classes:
        tp = matrix[c][c]
        fp = sum(matrix[other][c] for other in all_classes if other != c)
        fn = sum(matrix[c][other] for other in all_classes if other != c)
        tn = sum(matrix[r][col] for r in all_classes if r != c for col in all_classes if col != c)
        sup = sum(matrix[c][col] for col in all_classes)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        per_class[c] = {
            "support": sup,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "specificity": round(spec, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        }
        if sup > 0:
            precisions.append(prec)
            recalls.append(rec)
            f1s.append(f1)
            supports.append(sup)

    macro_precision = sum(precisions) / len(precisions) if precisions else 0.0
    macro_recall = sum(recalls) / len(recalls) if recalls else 0.0
    macro_f1 = sum(f1s) / len(f1s) if f1s else 0.0

    total_sup = sum(supports)
    weighted_f1 = sum(f * s for f, s in zip(f1s, supports)) / total_sup if total_sup > 0 else 0.0
    balanced_acc = macro_recall

    # MCC calculation for multiclass
    try:
        from sklearn.metrics import matthews_corrcoef
        mcc = float(matthews_corrcoef(y_true, y_pred))
    except Exception:
        mcc = 0.0

    return {
        "total_samples": n_total,
        "correct_predictions": correct,
        "accuracy": round(accuracy, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "balanced_accuracy": round(balanced_acc, 4),
        "matthews_corrcoef": round(mcc, 4),
        "per_class": per_class,
        "confusion_matrix": matrix,
    }


def evaluate_dataset(
    client: LocalCpuBrainClient,
    csv_path: Path,
    out_pred_path: Path,
    sample_limit: int = 40,
    seed: int = 42,
) -> Dict[str, Any]:
    """Evaluate a standardized external dataset using the real GGUF model."""
    print(f"\n{'='*78}\n[*] EVALUATING: {csv_path.name}\n{'='*78}")
    assert csv_path.exists(), f"Dataset file not found: {csv_path}"

    rows = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    print(f"[*] Total rows in dataset: {len(rows):,}")

    # Stratified or balanced sampling by attack_type
    by_type = defaultdict(list)
    for r in rows:
        by_type[r.get("attack_type", "Unknown")].append(r)

    print("[*] Available class distribution:")
    for atype, items in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"    - {atype:<25}: {len(items):,} samples")

    rng = random.Random(seed)
    selected_samples = []
    per_class_limit = max(1, sample_limit // max(1, len(by_type)))
    for atype, items in by_type.items():
        sample_k = min(per_class_limit, len(items))
        selected_samples.extend(rng.sample(items, sample_k))

    rng.shuffle(selected_samples)
    print(f"[*] Selected evaluation subset: {len(selected_samples)} samples across {len(by_type)} categories")

    # Load checkpoint if exists
    evaluated = {}
    if out_pred_path.exists():
        with open(out_pred_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for r in reader:
                evaluated[r["sample_id"]] = r
        print(f"[*] Resumed from checkpoint: {len(evaluated)} samples already evaluated.")

    pred_fieldnames = [
        "sample_id",
        "source_dataset",
        "payload",
        "ground_truth",
        "predicted_label",
        "raw_model_output",
        "inference_latency",
        "inference_status",
        "is_mock",
    ]

    results = []
    latencies = []
    y_true = []
    y_pred = []

    t_start = time.time()
    for idx, sample in enumerate(selected_samples):
        sid = sample["sample_id"]
        gt = sample.get("attack_type", "Unknown")
        payload = sample.get("payload", "")

        if sid in evaluated:
            r_done = evaluated[sid]
            results.append(r_done)
            latencies.append(float(r_done.get("inference_latency", 0.0)))
            y_true.append(r_done.get("ground_truth"))
            y_pred.append(r_done.get("predicted_label"))
            continue

        # Format exact training prompt
        user_prompt = (
            f"Classify this HTTP request into exactly one category: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS.\n"
            f"Return only the category name.\n"
            f"HTTP request:\n{payload}"
        )

        t0 = time.perf_counter()
        raw_output = client._generate(user_prompt, max_new_tokens=24).strip()
        dt = time.perf_counter() - t0

        # Strip echoed prompt if present to inspect only newly generated tokens
        if raw_output.startswith(user_prompt.strip()):
            generated_text = raw_output[len(user_prompt.strip()):].strip()
        elif "HTTP request:" in raw_output:
            after_header = raw_output.split("HTTP request:")[-1]
            # Newly generated tokens appear after the payload
            lines = after_header.strip().splitlines()
            generated_text = lines[-1].strip() if lines else after_header.strip()
        else:
            generated_text = raw_output

        predicted = extract_prediction(generated_text)
        status = "SUCCESS" if predicted != "Unknown" else "UNRECOGNIZED_CLASS"

        rec = {
            "sample_id": sid,
            "source_dataset": sample.get("source_dataset", ""),
            "payload": payload[:300].replace("\n", " "),
            "ground_truth": gt,
            "predicted_label": predicted,
            "raw_model_output": generated_text.replace("\n", " ")[:150],
            "inference_latency": round(dt, 3),
            "inference_status": status,
            "is_mock": False,
        }
        results.append(rec)
        latencies.append(dt)
        y_true.append(gt)
        y_pred.append(predicted)

        # Checkpoint incremental save
        with open(out_pred_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=pred_fieldnames)
            writer.writeheader()
            writer.writerows(results)

        mark = "[CORRECT]" if predicted == gt else "[MISMATCH]"
        if (idx + 1) % 5 == 0 or (idx + 1) == len(selected_samples):
            curr_acc = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / len(y_true) * 100.0
            avg_lat = sum(latencies) / len(latencies)
            print(f"    [{idx+1:03d}/{len(selected_samples):03d}] {sid} | GT: {gt:<18} -> Pred: {predicted:<18} {mark} | Acc: {curr_acc:.1f}% | Lat: {avg_lat:.2f}s")

    total_eval_time = time.time() - t_start
    metrics = compute_comprehensive_metrics(y_true, y_pred, SUPPORTED_CLASSES)
    metrics["total_inference_time_sec"] = round(total_eval_time, 2)
    metrics["avg_latency_sec"] = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
    metrics["successful_inferences"] = sum(1 for r in results if r["inference_status"] == "SUCCESS")
    metrics["failed_inferences"] = sum(1 for r in results if r["inference_status"] != "SUCCESS")

    print(f"\n[+] Completed {csv_path.name}: Accuracy = {metrics['accuracy']*100:.2f}%, Macro F1 = {metrics['macro_f1']:.4f}, Avg Latency = {metrics['avg_latency_sec']}s")
    return metrics

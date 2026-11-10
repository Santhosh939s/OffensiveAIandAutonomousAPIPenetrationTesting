"""Phase 7.0: Comprehensive Empirical Model Evaluation on Local CPU.

Evaluates the real Qwen2.5-1.5B Q4_K_M GGUF model via llama-cli on a balanced,
stratified held-out test benchmark from evaluation/test_sample_2000.jsonl.

Strictly non-mock execution. Measures:
- Inference success rate
- Valid category rate
- Overall accuracy, macro F1, weighted F1
- Per-class precision, recall, F1, TP, FP, FN
- Per-sample and average inference latency (seconds)
- Token generation throughput (tokens/sec)
- Confusion matrix
"""

import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model

CLASSES = [
    "Benign",
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]


def load_stratified_test_benchmark(filepath: Path, samples_per_class: int = 8, seed: int = 42):
    """Load an exactly balanced stratified sample from test_sample_2000.jsonl."""
    by_class = defaultdict(list)
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            cat = item.get("category")
            if cat in CLASSES:
                by_class[cat].append(item)

    rng = random.Random(seed)
    selected = []
    for cat in CLASSES:
        pool = by_class[cat]
        chosen = rng.sample(pool, min(samples_per_class, len(pool)))
        selected.extend(chosen)

    rng.shuffle(selected)
    return selected


def main():
    print("=" * 78)
    print("   PHASE 7.0: REAL GGUF CPU MODEL BENCHMARK EVALUATION")
    print("=" * 78)

    model_path = find_default_gguf_model()
    print(f"[*] Target GGUF Model Artifact: {model_path}")
    assert model_path and os.path.exists(model_path), "GGUF model artifact missing!"

    # Initialize real CPU client (strictly non-mock)
    client = LocalCpuBrainClient(
        model_path=model_path,
        allow_mock_fallback=False,
        n_threads=4,
        n_ctx=1024,
    )
    print(f"[*] Inference Runtime: {client.engine} (is_mock: {client.is_mock}, cli: {client._cli_path})")
    assert client.engine == "llama_cli" and not client.is_mock, "CRITICAL: Real model engine required!"

    dataset_path = PROJECT_ROOT / "evaluation" / "test_sample_2000.jsonl"
    samples_per_class = 8  # 8 * 8 = 64 balanced test cases
    test_set = load_stratified_test_benchmark(dataset_path, samples_per_class=samples_per_class, seed=42)
    print(f"[*] Evaluation Benchmark: {len(test_set)} stratified records across {len(CLASSES)} classes ({samples_per_class}/class)")

    results = []
    latencies = []
    token_speeds = []
    y_true = []
    y_pred = []

    start_eval_time = time.time()
    for idx, item in enumerate(test_set):
        expected = item["category"]
        prompt = item["input"]

        t0 = time.time()
        raw_output = client._generate(prompt, max_new_tokens=32).strip()
        dt = time.time() - t0

        # Normalization and extraction
        predicted = "Unknown"
        for c in CLASSES:
            if c.lower() in raw_output.lower():
                predicted = c
                break
        if predicted == "Unknown" and "cookie" in raw_output.lower():
            predicted = "Cookie Injection"
        if predicted == "Unknown" and "traversal" in raw_output.lower():
            predicted = "Directory Traversal"
        if predicted == "Unknown" and "forging" in raw_output.lower():
            predicted = "Log Forging"

        tokens = len(raw_output.split())
        tps = round(tokens / dt, 2) if dt > 0 else 0.0

        is_correct = (predicted == expected)
        latencies.append(dt)
        token_speeds.append(tps)
        y_true.append(expected)
        y_pred.append(predicted)

        record = {
            "index": idx + 1,
            "expected": expected,
            "predicted": predicted,
            "raw_output": raw_output,
            "is_correct": is_correct,
            "latency_seconds": round(dt, 3),
            "tokens_generated": tokens,
            "tokens_per_second": tps,
        }
        results.append(record)

        status_marker = "[CORRECT]" if is_correct else "[MISMATCH]"
        print(f" [{idx+1:2d}/{len(test_set):2d}] {status_marker:10} Exp: {expected:20} Pred: {predicted:20} Latency: {dt:.2f}s ({tps:.1f} tok/s)")

    total_eval_duration = time.time() - start_eval_time

    # Calculate metrics
    total = len(test_set)
    correct = sum(1 for r in results if r["is_correct"])
    accuracy = correct / total if total > 0 else 0.0
    valid_predictions = sum(1 for r in results if r["predicted"] in CLASSES)
    valid_rate = valid_predictions / total if total > 0 else 0.0

    # Per-class metrics
    class_metrics = {}
    for c in CLASSES:
        tp = sum(1 for r in results if r["expected"] == c and r["predicted"] == c)
        fp = sum(1 for r in results if r["expected"] != c and r["predicted"] == c)
        fn = sum(1 for r in results if r["expected"] == c and r["predicted"] != c)
        tn = sum(1 for r in results if r["expected"] != c and r["predicted"] != c)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        class_metrics[c] = {
            "samples": samples_per_class,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
        }

    macro_f1 = sum(m["f1_score"] for m in class_metrics.values()) / len(CLASSES)
    # Weighted F1
    weighted_f1 = sum(m["f1_score"] * m["samples"] for m in class_metrics.values()) / total

    # Confusion matrix
    matrix = {c: {c2: 0 for c2 in CLASSES + ["Unknown"]} for c in CLASSES}
    for r in results:
        matrix[r["expected"]][r["predicted"]] += 1

    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    avg_tps = sum(token_speeds) / len(token_speeds) if token_speeds else 0.0

    summary = {
        "model_file": os.path.basename(str(model_path)),
        "evaluation_dataset": "evaluation/test_sample_2000.jsonl (Stratified Held-Out)",
        "total_samples": total,
        "classes_evaluated": len(CLASSES),
        "samples_per_class": samples_per_class,
        "total_duration_seconds": round(total_eval_duration, 2),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "accuracy_percent": round(accuracy * 100, 2),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "valid_structured_response_rate": round(valid_rate, 4),
            "valid_structured_response_percent": round(valid_rate * 100, 2),
            "total_correct": correct,
            "total_incorrect": total - correct,
            "average_latency_seconds": round(avg_lat, 3),
            "min_latency_seconds": round(min(latencies), 3) if latencies else 0.0,
            "max_latency_seconds": round(max(latencies), 3) if latencies else 0.0,
            "average_tokens_per_second": round(avg_tps, 2),
        },
        "per_class_metrics": class_metrics,
        "confusion_matrix": matrix,
        "raw_results": results,
    }

    out_file = PROJECT_ROOT / "research" / "phase7" / "model_evaluation_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 78)
    print("   EVALUATION SUMMARY & EMPIRICAL METRICS")
    print("=" * 78)
    print(f" Total Samples Evaluated : {total} ({samples_per_class} per class)")
    print(f" Overall Accuracy        : {accuracy * 100:.2f}% ({correct}/{total})")
    print(f" Macro F1-Score          : {macro_f1:.4f}")
    print(f" Weighted F1-Score       : {weighted_f1:.4f}")
    print(f" Valid Category Rate     : {valid_rate * 100:.2f}%")
    print(f" Average Latency         : {avg_lat:.2f}s per inference")
    print(f" Average Generation Speed: {avg_tps:.2f} tokens/sec")
    print(f" Total Test Duration     : {total_eval_duration:.1f}s")
    print(f" Output Results Saved To : {out_file}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()


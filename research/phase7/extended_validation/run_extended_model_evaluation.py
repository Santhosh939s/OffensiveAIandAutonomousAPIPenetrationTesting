"""Phase 7.1: Extended Model Evaluation with Statistical Confidence Intervals.

Evaluates the real Qwen2.5-1.5B Q4_K_M GGUF model via local llama-cli.exe CPU inference
across a 128-sample stratified held-out benchmark (16 samples/class across all 8 classes)
from evaluation/test_sample_2000.jsonl using the exact trained prompt and classification parser.

Computes:
- Empirical accuracy, precision, recall, and F1-score
- Macro and weighted averages
- Exact confusion matrix
- Wilson score 95% confidence intervals for overall accuracy and per-class metrics
- Generation latency and token throughput
"""

import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
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


def wilson_score_interval(successes: int, total: int, z: float = 1.95996) -> dict:
    """Calculate the Wilson score confidence interval for a binomial proportion."""
    if total == 0:
        return {"proportion": 0.0, "ci_lower": 0.0, "ci_upper": 0.0, "margin_of_error": 0.0}
    p_hat = successes / total
    denom = 1.0 + (z**2) / total
    centre = (p_hat + (z**2) / (2.0 * total)) / denom
    half_width = (z * math.sqrt((p_hat * (1.0 - p_hat)) / total + (z**2) / (4.0 * (total**2)))) / denom
    lower = max(0.0, centre - half_width)
    upper = min(1.0, centre + half_width)
    return {
        "proportion": round(p_hat, 4),
        "ci_lower": round(lower, 4),
        "ci_upper": round(upper, 4),
        "margin_of_error": round(half_width, 4),
    }


def load_stratified_test_benchmark(filepath: Path, samples_per_class: int = 16, seed: int = 42):
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
    print("[*] Available class pool counts in test_sample_2000.jsonl:")
    for cat in CLASSES:
        pool = by_class[cat]
        chosen = rng.sample(pool, min(samples_per_class, len(pool)))
        selected.extend(chosen)
        print(f"    - {cat:<25}: {len(chosen)} sampled (pool size: {len(pool)})")

    rng.shuffle(selected)
    return selected


def main():
    print("=" * 78)
    print("   PHASE 7.1: EXTENDED MODEL EVALUATION (128 STRATIFIED SAMPLES)")
    print("=" * 78)

    model_path = find_default_gguf_model()
    print(f"[*] Target GGUF Model Artifact: {model_path}")
    assert model_path and os.path.exists(model_path), "GGUF model artifact missing!"

    # Strictly non-mock real CPU client
    client = LocalCpuBrainClient(
        model_path=model_path,
        allow_mock_fallback=False,
        n_threads=4,
        n_ctx=1024,
    )
    print(f"[*] Inference Runtime: {client.engine} (is_mock: {client.is_mock})")
    assert client.engine == "llama_cli" and not client.is_mock, "CRITICAL: Real model engine required!"

    dataset_path = PROJECT_ROOT / "evaluation" / "test_sample_2000.jsonl"
    samples_per_class = 16  # 16 * 8 = 128 balanced test cases
    test_set = load_stratified_test_benchmark(dataset_path, samples_per_class=samples_per_class, seed=42)
    print(f"[*] Evaluation Benchmark: {len(test_set)} stratified records across {len(CLASSES)} classes ({samples_per_class}/class)\n")

    results = []
    latencies = []
    token_speeds = []
    y_true = []
    y_pred = []
    confusion = {true_c: {pred_c: 0 for pred_c in CLASSES} for true_c in CLASSES}

    start_eval_time = time.time()
    for idx, item in enumerate(test_set):
        expected = item["category"]
        prompt = item["input"]

        t0 = time.time()
        raw_output = client._generate(prompt, max_new_tokens=32).strip()
        dt = time.time() - t0

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
        if predicted in CLASSES:
            confusion[expected][predicted] += 1

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
        if (idx + 1) % 16 == 0 or (idx + 1) == len(test_set):
            current_correct = sum(1 for r in results if r["is_correct"])
            current_acc = (current_correct / (idx + 1)) * 100.0
            avg_lat = sum(latencies) / len(latencies)
            print(f" [{idx+1:3d}/{len(test_set):3d}] {status_marker:10} Exp: {expected:20} Pred: {predicted:20} | Acc: {current_acc:5.2f}% | Lat: {avg_lat:.2f}s")

    total_eval_duration = time.time() - start_eval_time

    # Calculate metrics
    total_samples = len(results)
    correct_count = sum(1 for r in results if r["is_correct"])
    overall_accuracy = correct_count / total_samples
    overall_ci = wilson_score_interval(correct_count, total_samples)

    class_metrics = {}
    macro_p, macro_r, macro_f = [], [], []
    weighted_p, weighted_r, weighted_f = [], [], []

    for c in CLASSES:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
        total_c = tp + fn

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        rec_ci = wilson_score_interval(tp, total_c)

        class_metrics[c] = {
            "samples": total_c,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "recall_95ci": rec_ci,
        }

        macro_p.append(prec)
        macro_r.append(rec)
        macro_f.append(f1)

        w = total_c / total_samples
        weighted_p.append(prec * w)
        weighted_r.append(rec * w)
        weighted_f.append(f1 * w)

    macro_avg = {
        "precision": round(sum(macro_p) / len(CLASSES), 4),
        "recall": round(sum(macro_r) / len(CLASSES), 4),
        "f1_score": round(sum(macro_f) / len(CLASSES), 4),
    }
    weighted_avg = {
        "precision": round(sum(weighted_p), 4),
        "recall": round(sum(weighted_r), 4),
        "f1_score": round(sum(weighted_f), 4),
    }

    summary = {
        "evaluation_timestamp": time.time(),
        "model_file": os.path.basename(str(model_path)),
        "model_engine": client.engine,
        "is_mock": client.is_mock,
        "total_samples": total_samples,
        "correct_predictions": correct_count,
        "overall_accuracy": round(overall_accuracy, 4),
        "accuracy_95ci": overall_ci,
        "macro_metrics": macro_avg,
        "weighted_metrics": weighted_avg,
        "class_metrics": class_metrics,
        "confusion_matrix": confusion,
        "latency": {
            "total_duration_seconds": round(total_eval_duration, 2),
            "avg_latency_seconds": round(sum(latencies) / len(latencies), 3),
            "min_latency_seconds": round(min(latencies), 3),
            "max_latency_seconds": round(max(latencies), 3),
            "avg_tokens_per_second": round(sum(token_speeds) / len(token_speeds), 2),
        },
        "sample_predictions": results,
    }

    out_file = PROJECT_ROOT / "research" / "phase7" / "extended_validation" / "extended_model_evaluation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 78)
    print("   PHASE 7.1: EXTENDED MODEL EVALUATION COMPLETE")
    print("=" * 78)
    print(f" Total Samples Evaluated : {total_samples}")
    print(f" Correct Predictions     : {correct_count} / {total_samples}")
    print(f" Overall Accuracy        : {overall_accuracy * 100:.2f}% (95% CI: [{overall_ci['ci_lower']*100:.2f}%, {overall_ci['ci_upper']*100:.2f}%])")
    print(f" Macro F1-Score          : {macro_avg['f1_score']:.4f}")
    print(f" Weighted F1-Score       : {weighted_avg['f1_score']:.4f}")
    print(f" Average Latency per Run : {sum(latencies)/len(latencies):.2f}s")
    print(f" Total Evaluation Time   : {total_eval_duration:.2f}s ({total_eval_duration/60:.2f} minutes)")
    print(f" Results Saved To        : {out_file}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()

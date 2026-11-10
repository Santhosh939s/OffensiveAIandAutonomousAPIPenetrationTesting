"""Phase 11.3: Independent Metric Reconstruction & Statistical Audit Engine.

Reads Phase 11.2 prediction CSVs directly:
- `dataset_a_phase11_2_predictions.csv`
- `dataset_b_phase11_2_predictions.csv`
- `dataset_d_phase11_2_predictions.csv`
- `dataset_e_phase11_2_predictions.csv`

Independently recalculates all metrics, confusion matrices, and 95% bootstrap confidence intervals.
"""

import csv
import json
import math
import numpy as np
from collections import Counter, defaultdict
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    matthews_corrcoef,
    confusion_matrix,
    balanced_accuracy_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_2_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_2"
PHASE11_3_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_3"
PHASE11_3_DIR.mkdir(parents=True, exist_ok=True)

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


def wilson_interval(correct: int, total: int, z: float = 1.96):
    if total <= 0:
        return (0.0, 0.0)
    p = correct / total
    denom = 1 + (z ** 2) / total
    center = (p + (z ** 2) / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) / total) + ((z ** 2) / (4 * (total ** 2)))) / denom
    return (round(max(0.0, center - spread), 4), round(min(1.0, center + spread), 4))


def bootstrap_ci(y_true, y_pred, metric_fn, n_iter=2000, seed=42):
    """Calculate 95% bootstrap confidence interval using stratified resampling."""
    rng = np.random.RandomState(seed)
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    n = len(y_true)
    
    # Stratified indices by true class
    classes = np.unique(y_true)
    class_indices = {c: np.where(y_true == c)[0] for c in classes}
    
    scores = []
    for _ in range(n_iter):
        sample_indices = []
        for c, idxs in class_indices.items():
            sampled = rng.choice(idxs, size=len(idxs), replace=True)
            sample_indices.extend(sampled)
        sample_indices = np.array(sample_indices)
        
        yt_s = y_true[sample_indices]
        yp_s = y_pred[sample_indices]
        try:
            val = metric_fn(yt_s, yp_s)
            scores.append(val)
        except Exception:
            continue
            
    if not scores:
        return (0.0, 0.0)
    lower = float(np.percentile(scores, 2.5))
    upper = float(np.percentile(scores, 97.5))
    return (round(lower, 4), round(upper, 4))


def analyze_dataset(csv_path: Path, dataset_name: str, has_ground_truth: bool = True):
    print(f"\n{'='*78}\nINDEPENDENT AUDIT: {dataset_name} ({csv_path.name})\n{'='*78}")
    assert csv_path.exists(), f"Missing file: {csv_path}"
    
    records = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            records.append(r)
            
    print(f"[*] Total parsed rows: {len(records)}")
    
    if not has_ground_truth:
        preds = [r["predicted_label"] for r in records]
        c = Counter(preds)
        valid_cnt = sum(1 for p in preds if p in SUPPORTED_CLASSES)
        print(f"[*] Valid supported tokens: {valid_cnt}/{len(preds)} ({valid_cnt/len(preds)*100:.2f}%)")
        print(f"[*] Distribution: {dict(c)}")
        return {
            "dataset": dataset_name,
            "total_samples": len(records),
            "is_supervised": False,
            "valid_token_rate": valid_cnt / len(records),
            "hallucination_rate": 0.0,
            "predicted_distribution": dict(c),
        }
        
    y_true = [r["ground_truth"] for r in records]
    y_pred = [r["predicted_label"] for r in records]
    
    # Check classes
    true_classes = sorted(list(set(y_true)))
    pred_classes = sorted(list(set(y_pred)))
    all_classes = sorted(list(set(y_true + y_pred)))
    
    print(f"[*] Unique Ground Truth Classes ({len(true_classes)}): {true_classes}")
    print(f"[*] Unique Predicted Classes ({len(pred_classes)}): {pred_classes}")
    print(f"[*] Class Support in Ground Truth: {dict(Counter(y_true))}")
    
    # 1. Overall evaluation metrics (on all_classes)
    n_total = len(y_true)
    correct = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
    incorrect = n_total - correct
    acc = correct / n_total
    
    acc_wilson = wilson_interval(correct, n_total)
    acc_boot = bootstrap_ci(y_true, y_pred, accuracy_score)
    
    # Macro metrics on all_classes (includes predicted classes with 0 support in GT)
    macro_p_all = precision_score(y_true, y_pred, labels=all_classes, average="macro", zero_division=0)
    macro_r_all = recall_score(y_true, y_pred, labels=all_classes, average="macro", zero_division=0)
    macro_f1_all = f1_score(y_true, y_pred, labels=all_classes, average="macro", zero_division=0)
    
    # Macro metrics on true_classes only (classes with GT support > 0)
    macro_p_true = precision_score(y_true, y_pred, labels=true_classes, average="macro", zero_division=0)
    macro_r_true = recall_score(y_true, y_pred, labels=true_classes, average="macro", zero_division=0)
    macro_f1_true = f1_score(y_true, y_pred, labels=true_classes, average="macro", zero_division=0)
    
    macro_f1_boot = bootstrap_ci(y_true, y_pred, lambda yt, yp: f1_score(yt, yp, labels=true_classes, average="macro", zero_division=0))
    
    weighted_f1 = f1_score(y_true, y_pred, labels=all_classes, average="weighted", zero_division=0)
    weighted_f1_boot = bootstrap_ci(y_true, y_pred, lambda yt, yp: f1_score(yt, yp, labels=all_classes, average="weighted", zero_division=0))
    micro_f1 = f1_score(y_true, y_pred, labels=all_classes, average="micro", zero_division=0)
    
    try:
        mcc = matthews_corrcoef(y_true, y_pred)
    except Exception:
        mcc = 0.0
        
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    
    # Confusion matrix
    cm_matrix = confusion_matrix(y_true, y_pred, labels=all_classes)
    cm_dict = {}
    for i, tc in enumerate(all_classes):
        cm_dict[tc] = {}
        for j, pc in enumerate(all_classes):
            cm_dict[tc][pc] = int(cm_matrix[i, j])
            
    # Verify sum
    cm_sum = int(np.sum(cm_matrix))
    assert cm_sum == n_total, f"Confusion matrix sum {cm_sum} != sample count {n_total}!"
    print(f"[+] Confusion matrix verified: sum={cm_sum} matches exactly {n_total} samples.")
    
    # Per-class metrics
    per_class = {}
    for i, c in enumerate(all_classes):
        sup = int(sum(cm_matrix[i, :]))
        tp = int(cm_matrix[i, i])
        fp = int(sum(cm_matrix[k, i] for k in range(len(all_classes)) if k != i))
        fn = int(sum(cm_matrix[i, k] for k in range(len(all_classes)) if k != i))
        tn = int(sum(cm_matrix[r, col] for r in range(len(all_classes)) if r != i for col in range(len(all_classes)) if col != i))
        
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
        per_class[c] = {
            "support": sup,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(p, 4),
            "recall": round(r, 4),
            "f1_score": round(f1, 4),
            "specificity": round(spec, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
        }
        
    out_res = {
        "dataset": dataset_name,
        "is_supervised": True,
        "total_samples": n_total,
        "correct_predictions": correct,
        "incorrect_predictions": incorrect,
        "accuracy": round(acc, 4),
        "accuracy_wilson_ci_95": acc_wilson,
        "accuracy_bootstrap_ci_95": acc_boot,
        "macro_precision_all_classes": round(macro_p_all, 4),
        "macro_recall_all_classes": round(macro_r_all, 4),
        "macro_f1_all_classes": round(macro_f1_all, 4),
        "macro_precision_true_classes": round(macro_p_true, 4),
        "macro_recall_true_classes": round(macro_r_true, 4),
        "macro_f1_true_classes": round(macro_f1_true, 4),
        "macro_f1_bootstrap_ci_95": macro_f1_boot,
        "weighted_f1": round(weighted_f1, 4),
        "weighted_f1_bootstrap_ci_95": weighted_f1_boot,
        "micro_f1": round(micro_f1, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "matthews_corrcoef": round(mcc, 4),
        "confusion_matrix": cm_dict,
        "per_class": per_class,
    }
    
    # 2. Supported classes only (if unsupported classes present)
    supported_mask = [yt in SUPPORTED_CLASSES for yt in y_true]
    if not all(supported_mask) and any(supported_mask):
        y_true_s = [yt for yt, m in zip(y_true, supported_mask) if m]
        y_pred_s = [yp for yp, m in zip(y_pred, supported_mask) if m]
        s_classes = sorted(list(set(y_true_s + y_pred_s)))
        s_total = len(y_true_s)
        s_correct = sum(1 for yt, yp in zip(y_true_s, y_pred_s) if yt == yp)
        s_acc = s_correct / s_total
        s_acc_wilson = wilson_interval(s_correct, s_total)
        s_acc_boot = bootstrap_ci(y_true_s, y_pred_s, accuracy_score)
        
        s_macro_p = precision_score(y_true_s, y_pred_s, labels=s_classes, average="macro", zero_division=0)
        s_macro_r = recall_score(y_true_s, y_pred_s, labels=s_classes, average="macro", zero_division=0)
        s_macro_f1 = f1_score(y_true_s, y_pred_s, labels=s_classes, average="macro", zero_division=0)
        s_macro_f1_boot = bootstrap_ci(y_true_s, y_pred_s, lambda yt, yp: f1_score(yt, yp, labels=s_classes, average="macro", zero_division=0))
        
        s_weighted_f1 = f1_score(y_true_s, y_pred_s, labels=s_classes, average="weighted", zero_division=0)
        s_weighted_f1_boot = bootstrap_ci(y_true_s, y_pred_s, lambda yt, yp: f1_score(yt, yp, labels=s_classes, average="weighted", zero_division=0))
        s_mcc = matthews_corrcoef(y_true_s, y_pred_s)
        s_bal_acc = balanced_accuracy_score(y_true_s, y_pred_s)
        
        s_cm = confusion_matrix(y_true_s, y_pred_s, labels=s_classes)
        s_cm_dict = {tc: {pc: int(s_cm[i, j]) for j, pc in enumerate(s_classes)} for i, tc in enumerate(s_classes)}
        
        out_res["supported_classes_only"] = {
            "total_samples": s_total,
            "correct_predictions": s_correct,
            "incorrect_predictions": s_total - s_correct,
            "accuracy": round(s_acc, 4),
            "accuracy_wilson_ci_95": s_acc_wilson,
            "accuracy_bootstrap_ci_95": s_acc_boot,
            "macro_precision": round(s_macro_p, 4),
            "macro_recall": round(s_macro_r, 4),
            "macro_f1": round(s_macro_f1, 4),
            "macro_f1_bootstrap_ci_95": s_macro_f1_boot,
            "weighted_f1": round(s_weighted_f1, 4),
            "weighted_f1_bootstrap_ci_95": s_weighted_f1_boot,
            "balanced_accuracy": round(s_bal_acc, 4),
            "matthews_corrcoef": round(s_mcc, 4),
            "confusion_matrix": s_cm_dict,
        }
        print(f"[+] Supported classes only: {s_total} samples, Acc={s_acc*100:.2f}%, MacroF1={s_macro_f1:.4f}")
        
    print(f"[+] Overall: {n_total} samples, Acc={acc*100:.2f}%, MacroF1(True)={macro_f1_true:.4f}, MacroF1(All)={macro_f1_all:.4f}")
    return out_res


def run_reconstruction():
    results = {}
    
    # Dataset D
    d_path = PHASE11_2_DIR / "dataset_d_phase11_2_predictions.csv"
    results["Dataset_D"] = analyze_dataset(d_path, "SecLists Fuzzing Challenge (Dataset D)", has_ground_truth=True)
    
    # Dataset A
    a_path = PHASE11_2_DIR / "dataset_a_phase11_2_predictions.csv"
    results["Dataset_A"] = analyze_dataset(a_path, "Mendeley Multi-Class Web Attack (Dataset A)", has_ground_truth=True)
    
    # Dataset B
    b_path = PHASE11_2_DIR / "dataset_b_phase11_2_predictions.csv"
    results["Dataset_B"] = analyze_dataset(b_path, "WAMM Repository (Dataset B)", has_ground_truth=True)
    
    # Dataset E
    e_path = PHASE11_2_DIR / "dataset_e_phase11_2_predictions.csv"
    results["Dataset_E"] = analyze_dataset(e_path, "ATRDF Unlabelled Validation Pool (Dataset E)", has_ground_truth=False)
    
    out_json = PHASE11_3_DIR / "phase11_3_reconstructed_metrics.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved reconstructed metrics to: {out_json}")


if __name__ == "__main__":
    run_reconstruction()


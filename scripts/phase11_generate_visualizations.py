"""Phase 11.1: Visualizations Generator.

Generates the required charts in research/phase11/reports/figures/:
1. Confusion matrix for each eligible dataset
2. Per-class F1 comparison chart
3. Accuracy comparison chart
4. Precision, recall and F1 comparison
5. Class distribution chart
6. Inference latency chart
"""

import json
import os
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
RESULTS_DIR = PHASE11_DIR / "results"
FIGURES_DIR = PHASE11_DIR / "reports" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def plot_confusion_matrix(cm_data: dict, title: str, out_path: Path):
    """Plot an individual confusion matrix heatmap using matplotlib."""
    classes = sorted(list(cm_data.keys()))
    matrix = np.zeros((len(classes), len(classes)), dtype=int)
    for i, tc in enumerate(classes):
        for j, pc in enumerate(classes):
            matrix[i, j] = cm_data.get(tc, {}).get(pc, 0)

    fig, ax = plt.subplots(figsize=(8, 7))
    cax = ax.matshow(matrix, cmap="Blues", interpolation="nearest")
    fig.colorbar(cax)

    ax.set_xticks(range(len(classes)))
    ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=45, ha="left", fontsize=9)
    ax.set_yticklabels(classes, fontsize=9)
    ax.set_xlabel("Predicted Label", fontsize=11, fontweight="bold")
    ax.set_ylabel("True Ground Truth", fontsize=11, fontweight="bold")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=20)

    for i in range(len(classes)):
        for j in range(len(classes)):
            val = matrix[i, j]
            color = "white" if val > (matrix.max() / 2) else "black"
            ax.text(j, i, str(val), ha="center", va="center", color=color, fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    print(f"[+] Saved confusion matrix: {out_path.name}")


def generate_all_visualizations():
    metrics_path = RESULTS_DIR / "external_metrics.json"
    cm_path = RESULTS_DIR / "external_confusion_matrices.json"

    if not metrics_path.exists() or not cm_path.exists():
        print("[!] Metrics or confusion matrix JSON not found. Run evaluation first.")
        return

    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)
    with open(cm_path, "r", encoding="utf-8") as f:
        confusion = json.load(f)

    # 1. Confusion matrices
    for ds_id, cm_data in confusion.items():
        out_p = FIGURES_DIR / f"confusion_matrix_{ds_id.lower()}.png"
        plot_confusion_matrix(cm_data, f"Confusion Matrix: {ds_id}", out_p)

    # 2. Accuracy Comparison Chart
    ds_names = ["Internal Test"] + [ds_id for ds_id in metrics.keys()]
    accs = [96.88] + [metrics[ds_id]["accuracy"] * 100 for ds_id in metrics.keys()]
    colors = ["#2563EB"] + ["#10B981", "#F59E0B", "#8B5CF6", "#EC4899"][:len(metrics)]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(ds_names, accs, color=colors, width=0.55, edgecolor="#1F2937", linewidth=1.2)
    ax.set_ylabel("Accuracy (%)", fontsize=11, fontweight="bold")
    ax.set_title("Model Generalization: Internal vs External Dataset Accuracy", fontsize=12, fontweight="bold")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 2, f"{h:.2f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "accuracy_comparison.png", dpi=200)
    plt.close()
    print("[+] Saved accuracy comparison chart.")

    # 3. Precision, Recall, and F1 Comparison
    p_names = [ds_id for ds_id in metrics.keys()]
    precs = [metrics[ds_id]["macro_precision"] * 100 for ds_id in p_names]
    recs = [metrics[ds_id]["macro_recall"] * 100 for ds_id in p_names]
    f1s = [metrics[ds_id]["macro_f1"] * 100 for ds_id in p_names]

    x = np.arange(len(p_names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 5.5))
    r1 = ax.bar(x - width, precs, width, label="Precision", color="#3B82F6", edgecolor="#1F2937")
    r2 = ax.bar(x, recs, width, label="Recall", color="#10B981", edgecolor="#1F2937")
    r3 = ax.bar(x + width, f1s, width, label="Macro F1", color="#F59E0B", edgecolor="#1F2937")

    ax.set_ylabel("Metric Score (%)", fontsize=11, fontweight="bold")
    ax.set_title("External Generalization: Precision, Recall, and F1 by Dataset", fontsize=12, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(p_names, fontsize=10, fontweight="bold")
    ax.legend(frameon=True, facecolor="white", loc="lower right")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "precision_recall_f1.png", dpi=200)
    plt.close()
    print("[+] Saved precision_recall_f1 chart.")

    # 4. Per-Class F1 Score Comparison Across Datasets
    target_classes = ["Benign", "Directory Traversal", "RCE", "SQL Injection", "XSS"]
    fig, ax = plt.subplots(figsize=(11, 6))

    x_c = np.arange(len(target_classes))
    bar_w = 0.8 / max(1, len(metrics))

    for idx, (ds_id, m_dict) in enumerate(metrics.items()):
        pc = m_dict.get("per_class", {})
        scores = [pc.get(cls_name, {}).get("f1_score", 0.0) * 100 for cls_name in target_classes]
        offset = (idx - len(metrics) / 2 + 0.5) * bar_w
        ax.bar(x_c + offset, scores, bar_w, label=ds_id, edgecolor="#1F2937")

    ax.set_ylabel("F1 Score (%)", fontsize=11, fontweight="bold")
    ax.set_title("Per-Attack Class F1 Performance Across External Datasets", fontsize=12, fontweight="bold")
    ax.set_xticks(x_c)
    ax.set_xticklabels(target_classes, fontsize=10, fontweight="bold")
    ax.legend(loc="upper right")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "per_class_f1_comparison.png", dpi=200)
    plt.close()
    print("[+] Saved per_class_f1_comparison chart.")

    # 5. Class Distribution Chart
    sample_counts = {ds_id: m_dict["total_samples"] for ds_id, m_dict in metrics.items()}
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.pie(sample_counts.values(), labels=sample_counts.keys(), autopct="%1.1f%%", startangle=140, colors=["#3B82F6", "#10B981", "#F59E0B", "#8B5CF6"])
    ax.set_title("Evaluation Sample Distribution Across External Datasets", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "class_distribution.png", dpi=200)
    plt.close()
    print("[+] Saved class_distribution chart.")

    # 6. Inference Latency Chart
    latencies = [metrics[ds_id]["avg_latency_sec"] for ds_id in metrics.keys()]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(metrics.keys(), latencies, color="#6366F1", width=0.5, edgecolor="#1F2937")
    ax.set_ylabel("Avg Latency (Seconds)", fontsize=11, fontweight="bold")
    ax.set_title("Average CPU Inference Latency per External Dataset", fontsize=12, fontweight="bold")
    ax.set_ylim(0, max(latencies) * 1.3 if latencies else 15)
    for i, v in enumerate(latencies):
        ax.text(i, v + 0.3, f"{v:.2f}s", ha="center", fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "inference_latency.png", dpi=200)
    plt.close()
    print("[+] Saved inference_latency chart.")


if __name__ == "__main__":
    generate_all_visualizations()


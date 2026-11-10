"""Phase 11.2 Visualizations Generator.

Generates all charts in research/phase11/reports/figures/phase11_2/:
1. Confusion matrices (Datasets A, B, D)
2. Accuracy comparison chart with 95% Wilson confidence intervals
3. Supported classes vs all evaluated accuracy comparison
4. Per-class F1 comparison chart
5. Precision, Recall, and F1 comparison
6. Inference latency distribution chart
"""

import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
RESULTS_11_2 = PHASE11_DIR / "results" / "phase11_2"
FIGURES_11_2 = PHASE11_DIR / "reports" / "figures" / "phase11_2"
FIGURES_11_2.mkdir(parents=True, exist_ok=True)


def plot_cm(cm_data: dict, title: str, out_path: Path):
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
            color = "white" if val > (matrix.max() / 2) and matrix.max() > 0 else "black"
            ax.text(j, i, str(val), ha="center", va="center", color=color, fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()
    print(f"[+] Saved confusion matrix: {out_path.name}")


def generate_phase11_2_figures():
    metrics_path = RESULTS_11_2 / "phase11_2_metrics.json"
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    # 1. Confusion Matrices
    for ds_id in ["Dataset_A", "Dataset_B", "Dataset_D"]:
        if ds_id in metrics and "confusion_matrix" in metrics[ds_id]:
            out_p = FIGURES_11_2 / f"confusion_matrix_{ds_id.lower()}.png"
            plot_cm(metrics[ds_id]["confusion_matrix"], f"Phase 11.2 Confusion Matrix: {ds_id}", out_p)

    # 2. Accuracy Comparison with 95% Wilson Score Confidence Intervals
    names = [
        "Internal Baseline\n(Phase 7.1)",
        "SecLists Challenge\n(Dataset D)",
        "Mendeley Multi-Class\n(Supported Classes)",
        "Mendeley Multi-Class\n(All Evaluated)",
        "WAMM Repository\n(Supported Classes)",
        "WAMM Repository\n(All Evaluated)",
    ]
    accs = [
        96.88,
        metrics["Dataset_D"]["accuracy"] * 100,
        metrics["Dataset_A"]["supported_classes_only"]["accuracy"] * 100,
        metrics["Dataset_A"]["accuracy"] * 100,
        metrics["Dataset_B"]["supported_classes_only"]["accuracy"] * 100,
        metrics["Dataset_B"]["accuracy"] * 100,
    ]
    # Wilson CIs (lower, upper in %)
    ci_lowers = [
        92.20,
        metrics["Dataset_D"]["accuracy_ci_95"][0] * 100,
        metrics["Dataset_A"]["supported_classes_only"]["accuracy_ci_95"][0] * 100,
        metrics["Dataset_A"]["accuracy_ci_95"][0] * 100,
        metrics["Dataset_B"]["supported_classes_only"]["accuracy_ci_95"][0] * 100,
        metrics["Dataset_B"]["accuracy_ci_95"][0] * 100,
    ]
    ci_uppers = [
        98.82,
        metrics["Dataset_D"]["accuracy_ci_95"][1] * 100,
        metrics["Dataset_A"]["supported_classes_only"]["accuracy_ci_95"][1] * 100,
        metrics["Dataset_A"]["accuracy_ci_95"][1] * 100,
        metrics["Dataset_B"]["supported_classes_only"]["accuracy_ci_95"][1] * 100,
        metrics["Dataset_B"]["accuracy_ci_95"][1] * 100,
    ]

    err_lower = [a - cl for a, cl in zip(accs, ci_lowers)]
    err_upper = [cu - a for a, cu in zip(accs, ci_uppers)]

    fig, ax = plt.subplots(figsize=(11, 6))
    colors = ["#2563EB", "#10B981", "#3B82F6", "#60A5FA", "#F59E0B", "#FCD34D"]
    bars = ax.bar(names, accs, yerr=[err_lower, err_upper], capsize=5, color=colors, width=0.55, edgecolor="#1F2937", linewidth=1.2)
    ax.set_ylabel("Accuracy (%) with 95% Wilson CI", fontsize=11, fontweight="bold")
    ax.set_title("Phase 11.2 Generalization Accuracy with 95% Confidence Intervals", fontsize=13, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 3.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(FIGURES_11_2 / "accuracy_with_wilson_ci.png", dpi=200)
    plt.close()
    print("[+] Saved accuracy with Wilson CI chart.")

    # 3. Per-Class F1 Breakdown Comparison (SecLists vs Mendeley Supported)
    classes_eval = ["Benign", "Directory Traversal", "SQL Injection", "XSS"]
    d_f1 = [metrics["Dataset_D"]["per_class"][c]["f1_score"] * 100 for c in classes_eval]
    a_f1 = [metrics["Dataset_A"]["per_class"][c]["f1_score"] * 100 for c in classes_eval]

    x = np.arange(len(classes_eval))
    width = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    rects1 = ax.bar(x - width/2, d_f1, width, label="SecLists Challenge (DS D)", color="#10B981", edgecolor="#1F2937")
    rects2 = ax.bar(x + width/2, a_f1, width, label="Mendeley Multi-Class (DS A)", color="#3B82F6", edgecolor="#1F2937")

    ax.set_ylabel("F1 Score (%)", fontsize=11, fontweight="bold")
    ax.set_title("Per-Class F1 Generalization Comparison (Supported Classes)", fontsize=12, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(classes_eval, fontsize=10, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.legend(frameon=True)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for r in rects1:
        h = r.get_height()
        ax.text(r.get_x() + r.get_width()/2, h + 2, f"{h:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for r in rects2:
        h = r.get_height()
        ax.text(r.get_x() + r.get_width()/2, h + 2, f"{h:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    plt.savefig(FIGURES_11_2 / "per_class_f1_comparison.png", dpi=200)
    plt.close()
    print("[+] Saved per-class F1 comparison chart.")

    # 4. Latency Distribution
    lat_names = ["Dataset D (SecLists)", "Dataset A (Mendeley)", "Dataset B (WAMM)", "Dataset E (ATRDF)"]
    lat_vals = [
        metrics["Dataset_D"]["avg_latency_sec"],
        metrics["Dataset_A"]["avg_latency_sec"],
        metrics["Dataset_B"]["avg_latency_sec"],
        metrics["Dataset_E"]["avg_latency_sec"],
    ]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(lat_names, lat_vals, color=["#10B981", "#3B82F6", "#F59E0B", "#8B5CF6"], width=0.5, edgecolor="#1F2937")
    ax.set_ylabel("Average Latency (Seconds / Sample)", fontsize=11, fontweight="bold")
    ax.set_title("Phase 11.2 Real CPU Inference Latency (4 Threads, llama-cli.exe)", fontsize=12, fontweight="bold")
    ax.set_ylim(0, 6)
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for b in bars:
        h = b.get_height()
        ax.text(b.get_x() + b.get_width()/2, h + 0.15, f"{h:.2f}s", ha="center", va="bottom", fontsize=10, fontweight="bold")

    plt.tight_layout()
    plt.savefig(FIGURES_11_2 / "phase11_2_inference_latency.png", dpi=200)
    plt.close()
    print("[+] Saved latency chart.")


if __name__ == "__main__":
    generate_phase11_2_figures()


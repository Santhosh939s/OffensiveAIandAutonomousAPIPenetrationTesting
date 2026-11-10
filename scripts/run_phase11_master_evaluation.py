"""Phase 11.1: Master External Model Evaluation Runner.

Runs real offline CPU inference using the frozen GGUF model:
- `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`
- `models/bin/llama-cli.exe`
- Verifies is_mock is False
- Evaluates independent samples from Dataset A, Dataset B, Dataset D, and Dataset E
- Generates all required prediction CSVs, external_metrics.json, external_confusion_matrices.json,
  and external_evaluation_summary.csv
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model
from scripts.phase11_evaluate_model import evaluate_dataset

PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
INDEP_DIR = PHASE11_DIR / "external_datasets" / "independent"
RESULTS_DIR = PHASE11_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def run_master_evaluation():
    print("=" * 78)
    print("   PHASE 11.1: MASTER EXTERNAL MODEL EVALUATION")
    print("=" * 78)

    model_path = find_default_gguf_model()
    print(f"[*] Target GGUF Model Artifact: {model_path}")
    assert model_path and os.path.exists(model_path), "GGUF model artifact missing!"

    # Initialize real CPU inference client
    client = LocalCpuBrainClient(
        model_path=model_path,
        allow_mock_fallback=False,
        n_threads=4,
        n_ctx=1024,
    )
    print(f"[*] Inference Engine Runtime : {client.engine} (is_mock: {client.is_mock})")
    assert client.engine == "llama_cli" and not client.is_mock, "CRITICAL: Strictly non-mock engine required!"

    dataset_configs = [
        {
            "id": "Dataset_A",
            "name": "Multi-Class Web Attack (Mendeley zhzd5j9ffy/2)",
            "csv": INDEP_DIR / "dataset_a_external_independent.csv",
            "out": RESULTS_DIR / "dataset_a_predictions.csv",
            "samples": 36,  # 6 classes x 6 samples
        },
        {
            "id": "Dataset_B",
            "name": "WAMM Dataset Repository (CyShield)",
            "csv": INDEP_DIR / "dataset_b_external_independent.csv",
            "out": RESULTS_DIR / "dataset_b_predictions.csv",
            "samples": 36,  # 6 classes x 6 samples
        },
        {
            "id": "Dataset_D",
            "name": "SecLists Fuzzing Challenge (danielmiessler)",
            "csv": INDEP_DIR / "dataset_d_seclists_challenge_independent.csv",
            "out": RESULTS_DIR / "dataset_d_predictions.csv",
            "samples": 32,  # 4 classes x 8 samples
        },
        {
            "id": "Dataset_E",
            "name": "ATRDF Canonical Validation Sets (Cisco/Ariel)",
            "csv": INDEP_DIR / "dataset_e_atrdf_independent.csv",
            "out": RESULTS_DIR / "dataset_e_predictions.csv",
            "samples": 40,  # 8 classes x 5 samples
        },
    ]

    all_metrics = {}
    all_confusion = {}
    summary_rows = []

    # Internal baseline for comparison
    summary_rows.append({
        "Dataset": "Original Internal Test (Phase 7.1)",
        "Samples": 128,
        "Accuracy": 0.9688,
        "Macro_Precision": 0.9744,
        "Macro_Recall": 0.9688,
        "Macro_F1": 0.9723,
        "Weighted_F1": 0.9688,
        "Balanced_Accuracy": 0.9688,
        "MCC": 0.9644,
        "Avg_Latency_Sec": 8.96,
        "Status": "Internal Held-out Baseline",
    })

    t0_all = time.time()
    for cfg in dataset_configs:
        ds_id = cfg["id"]
        csv_file = cfg["csv"]
        out_file = cfg["out"]
        n_samples = cfg["samples"]

        if not csv_file.exists():
            print(f"[!] Skipping {ds_id}: file {csv_file.name} does not exist.")
            continue

        metrics = evaluate_dataset(
            client=client,
            csv_path=csv_file,
            out_pred_path=out_file,
            sample_limit=n_samples,
            seed=42,
        )

        all_metrics[ds_id] = metrics
        all_confusion[ds_id] = metrics.get("confusion_matrix", {})

        summary_rows.append({
            "Dataset": f"{ds_id} ({cfg['name']})",
            "Samples": metrics["total_samples"],
            "Accuracy": metrics["accuracy"],
            "Macro_Precision": metrics["macro_precision"],
            "Macro_Recall": metrics["macro_recall"],
            "Macro_F1": metrics["macro_f1"],
            "Weighted_F1": metrics["weighted_f1"],
            "Balanced_Accuracy": metrics["balanced_accuracy"],
            "MCC": metrics["matthews_corrcoef"],
            "Avg_Latency_Sec": metrics["avg_latency_sec"],
            "Status": "Evaluated Real GGUF",
        })

    # Dataset C documentation (Tabular features, ineligible for text prompt)
    summary_rows.append({
        "Dataset": "Dataset_C (Mendeley mmc4sdmnrc/1)",
        "Samples": 47463,
        "Accuracy": "N/A (Tabular)",
        "Macro_Precision": "N/A",
        "Macro_Recall": "N/A",
        "Macro_F1": "N/A",
        "Weighted_F1": "N/A",
        "Balanced_Accuracy": "N/A",
        "MCC": "N/A",
        "Avg_Latency_Sec": "N/A",
        "Status": "Ineligible: Pre-engineered numerical features only (no raw SQL text)",
    })

    # Save summary metrics JSON
    with open(RESULTS_DIR / "external_metrics.json", "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)

    # Save confusion matrices JSON
    with open(RESULTS_DIR / "external_confusion_matrices.json", "w", encoding="utf-8") as f:
        json.dump(all_confusion, f, indent=2)

    # Save summary CSV
    summary_csv_path = RESULTS_DIR / "external_evaluation_summary.csv"
    with open(summary_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    client.close()
    dt_total = time.time() - t0_all
    print("\n" + "=" * 78)
    print(f"MASTER EVALUATION COMPLETE in {dt_total:.2f}s ({dt_total/60:.2f} min)")
    print("=" * 78)
    for r in summary_rows:
        print(f" - {r['Dataset']:<45}: Acc={r['Accuracy']} | Macro F1={r['Macro_F1']}")


if __name__ == "__main__":
    run_master_evaluation()

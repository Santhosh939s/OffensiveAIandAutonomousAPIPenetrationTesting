import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
PHASE11_4_DIR = PHASE11_DIR / "results" / "phase11_4"

def get_hash(fpath: Path) -> str:
    assert fpath.exists(), f"Missing file: {fpath}"
    return hashlib.sha256(fpath.read_bytes()).hexdigest().upper()

def generate_manifest():
    manifest = {
        "project": "Offensive AI and Autonomous API Penetration Testing",
        "phase": "Phase 11.4 — Final Statistical Verification and Research Results Freeze",
        "freeze_timestamp": "2026-11-07T18:00:00+05:30",
        "freeze_status": "FROZEN_FOR_ACADEMIC_PUBLICATION",
        "frozen_models": {
            "gguf_model": {
                "path": "models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf",
                "sha256": get_hash(PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"),
                "status": "FROZEN",
            },
            "lora_adapter": {
                "path": "models/training_artifacts/final_adapter/adapter_model.safetensors",
                "sha256": get_hash(PROJECT_ROOT / "models" / "training_artifacts" / "final_adapter" / "adapter_model.safetensors"),
                "status": "FROZEN",
            },
            "inference_engine": "models/bin/llama-cli.exe (Native local Windows binary, offline CPU)",
        },
        "source_prediction_csvs": {
            "dataset_a": {
                "path": "research/phase11/results/phase11_2/dataset_a_phase11_2_predictions.csv",
                "sha256": get_hash(PHASE11_DIR / "results" / "phase11_2" / "dataset_a_phase11_2_predictions.csv"),
                "sample_count": 180,
                "supported_samples": 150,
                "unsupported_samples": 30,
            },
            "dataset_b": {
                "path": "research/phase11/results/phase11_2/dataset_b_phase11_2_predictions.csv",
                "sha256": get_hash(PHASE11_DIR / "results" / "phase11_2" / "dataset_b_phase11_2_predictions.csv"),
                "sample_count": 90,
                "supported_samples": 60,
                "unsupported_samples": 30,
            },
            "dataset_d": {
                "path": "research/phase11/results/phase11_2/dataset_d_phase11_2_predictions.csv",
                "sha256": get_hash(PHASE11_DIR / "results" / "phase11_2" / "dataset_d_phase11_2_predictions.csv"),
                "sample_count": 85,
                "supported_samples": 85,
                "unsupported_samples": 0,
            },
            "dataset_e": {
                "path": "research/phase11/results/phase11_2/dataset_e_phase11_2_predictions.csv",
                "sha256": get_hash(PHASE11_DIR / "results" / "phase11_2" / "dataset_e_phase11_2_predictions.csv"),
                "sample_count": 50,
                "nature": "Unlabelled Raw Network Traffic (Output Token Validity Only)",
            },
        },
        "converted_benchmark_corpora": {
            "dataset_a_external.csv": {
                "path": "research/phase11/external_datasets/converted/dataset_a_external.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "dataset_a_external.csv"),
                "records": 27805,
            },
            "dataset_b_external.csv": {
                "path": "research/phase11/external_datasets/converted/dataset_b_external.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "dataset_b_external.csv"),
                "records": 6000,
            },
            "dataset_c_sqli.csv": {
                "path": "research/phase11/external_datasets/converted/dataset_c_sqli.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "dataset_c_sqli.csv"),
                "records": 47463,
                "status": "Ineligible: Tabular Scalar Features (No Raw SQL Text)",
            },
            "dataset_d_seclists_challenge.csv": {
                "path": "research/phase11/external_datasets/converted/dataset_d_seclists_challenge.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "dataset_d_seclists_challenge.csv"),
                "records": 1317,
            },
            "dataset_e_atrdf.csv": {
                "path": "research/phase11/external_datasets/converted/dataset_e_atrdf.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "dataset_e_atrdf.csv"),
                "records": 33008,
            },
            "combined_external_independent.csv": {
                "path": "research/phase11/external_datasets/converted/combined_external_independent.csv",
                "sha256": get_hash(PHASE11_DIR / "external_datasets" / "converted" / "combined_external_independent.csv"),
                "records": 68130,
            },
        },
        "statistical_bootstrap_parameters": {
            "iterations": 2000,
            "resampling_strategy": "Stratified within ground-truth classes",
            "seed": 42,
            "confidence_level": 0.95,
            "percentiles": [2.5, 97.5],
            "independent_implementations_verified": 2,
        },
    }

    out_path = PHASE11_4_DIR / "research_results_manifest.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Saved frozen research results manifest to: {out_path}")

if __name__ == "__main__":
    generate_manifest()


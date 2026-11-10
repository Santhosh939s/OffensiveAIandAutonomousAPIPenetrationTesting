"""Phase 11.5: WAMM Label Quality & Evidentiary Rigor Audit Engine.

Evaluates the Phase 11.3 claim that 51 of 90 WAMM evaluation samples (56.7%) contain 'ground-truth label noise'.
Audits the methodology, keyword matching heuristics, and evidentiary basis.
Applies strict academic standards and outputs:
`research/phase11/results/phase11_5/wamm_label_quality_audit.json`
"""

import csv
import json
import urllib.parse
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_2_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_2"
PHASE11_3_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_3"
PHASE11_5_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_5"
PHASE11_5_DIR.mkdir(parents=True, exist_ok=True)


def main():
    print("=" * 80)
    print("   PHASE 11.5: WAMM GROUND-TRUTH QUALITY & EVIDENTIARY AUDIT")
    print("=" * 80)

    # 1. Load Phase 11.2 prediction CSV (frozen source)
    csv_path = PHASE11_2_DIR / "dataset_b_phase11_2_predictions.csv"
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        records = list(csv.DictReader(f))

    # 2. Load Phase 11.3 heuristic audit results if available
    audit_3_path = PHASE11_3_DIR / "wamm_ground_truth_audit.json"
    audit_3_records = []
    if audit_3_path.exists():
        with open(audit_3_path, "r", encoding="utf-8") as f:
            audit_3_records = json.load(f)

    # 3. Analyze heuristic mismatch records
    mismatches = []
    agreements = []
    for r in audit_3_records:
        if not r.get("wamm_matches_technical", False):
            mismatches.append(r)
        else:
            agreements.append(r)

    # Breakdown by original WAMM label
    mismatch_by_label = Counter(r["original_wamm_label"] for r in mismatches)
    agreement_by_label = Counter(r["original_wamm_label"] for r in agreements)

    # 4. Rigorous Evidentiary Assessment
    evidentiary_assessment = {
        "claimed_metric": "51 / 90 samples (56.7%) label noise",
        "underlying_methodology": "Automated keyword matching heuristic (scripts/phase11_3_wamm_review.py)",
        "methodological_deficiencies": [
            "Lack of formal multi-annotator blind review protocol",
            "No calculation of inter-annotator agreement statistics (e.g., Cohen's Kappa or Fleiss' Kappa)",
            "Heuristic rules rely on static string matching (e.g. searching for '/etc/passwd' or 'union select') which may miss subtle attack variants or context-dependent exploits",
            "Single-reviewer subjective adjudication without independent blinded cross-verification",
            "Original WAMM repository labeling intent and attack generation schema (CyShield R&D) not formally documented in peer-reviewed source literature",
        ],
        "academic_qualification_required": True,
        "mandated_academic_statement": (
            "Potential label inconsistencies were identified during manual inspection; "
            "the exact dataset-wide label-noise rate has not been independently established."
        ),
        "dataset_preservation_policy": "STRICT PRESERVATION — Original WAMM ground-truth labels remain untouched and unmodified in all benchmark artifacts.",
    }

    audit_deliverable = {
        "audit_phase": "Phase 11.5",
        "dataset_name": "WAMM Repository (Dataset B)",
        "source_prediction_file": str(csv_path.relative_to(PROJECT_ROOT)),
        "total_samples_audited": len(records),
        "heuristic_review_summary": {
            "total_heuristic_reviews": len(audit_3_records),
            "heuristic_agreements": len(agreements),
            "heuristic_mismatches": len(mismatches),
            "heuristic_mismatch_rate": len(mismatches) / len(audit_3_records) if audit_3_records else 0.0,
            "mismatches_by_original_label": dict(mismatch_by_label),
            "agreements_by_original_label": dict(agreement_by_label),
        },
        "evidentiary_assessment": evidentiary_assessment,
        "sample_case_studies": [
            {
                "sample_id": "WAMM_0001",
                "original_label": "Directory Traversal",
                "model_prediction": "Directory Traversal",
                "payload_snippet": "/cgi-bin/test-cgi?file=../../../../../../../../../../../../etc/passwd",
                "heuristic_ruling": "Directory Traversal / LFI",
                "finding": "Both model and heuristic agree with WAMM ground truth.",
            },
            {
                "sample_id": "WAMM_0046",
                "original_label": "RCE",
                "model_prediction": "Directory Traversal",
                "payload_snippet": "/index.php?page=../../../../etc/passwd",
                "heuristic_ruling": "Directory Traversal / LFI",
                "finding": "Payload exhibits classic directory traversal syntax against /etc/passwd, but was cataloged under RCE in WAMM. Model classified as Directory Traversal. Illustrates taxonomy ambiguity between LFI and code execution.",
            },
            {
                "sample_id": "WAMM_0076",
                "original_label": "SSRF",
                "model_prediction": "Directory Traversal",
                "payload_snippet": "/proxy?url=../../../../etc/shadow",
                "heuristic_ruling": "Directory Traversal / LFI",
                "finding": "Parameter name 'url' suggests SSRF vector, but argument is local file path traversal. Demonstrates multi-vector attack ambiguity.",
            },
        ],
    }

    out_file = PHASE11_5_DIR / "wamm_label_quality_audit.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(audit_deliverable, f, indent=2)
    print(f"[+] Saved WAMM label quality audit deliverable to: {out_file}")


if __name__ == "__main__":
    main()


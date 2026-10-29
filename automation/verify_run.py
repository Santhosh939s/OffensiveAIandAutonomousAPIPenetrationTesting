import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

def compute_file_sha256(file_path: Path) -> str:
    """Calculates SHA256 hash of a local file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()

def verify_checksum_file(run_dir: Path, checksum_file_name: str = "manifest_checksums.sha256") -> Tuple[bool, List[str]]:
    """Verifies that all files listed in manifest_checksums.sha256 match their disk hash."""
    checksum_path = run_dir / checksum_file_name
    if not checksum_path.exists():
        # Fallback to checking root or subdirectories
        matches = list(run_dir.glob(f"**/{checksum_file_name}"))
        if matches:
            checksum_path = matches[0]
        else:
            return False, [f"Checksum manifest '{checksum_file_name}' not found in {run_dir}"]

    issues = []
    base_dir = checksum_path.parent

    with open(checksum_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                issues.append(f"Malformed checksum line {line_num}: '{line}'")
                continue
            expected_hash, rel_path = parts
            target_file = base_dir / rel_path.strip()
            if not target_file.exists():
                issues.append(f"Missing file specified in checksums: {target_file}")
                continue
            actual_hash = compute_file_sha256(target_file)
            if actual_hash.lower() != expected_hash.lower():
                issues.append(
                    f"Checksum mismatch on {target_file.name}: "
                    f"expected {expected_hash}, calculated {actual_hash}"
                )

    passed = len(issues) == 0
    return passed, issues

def verify_predictions_jsonl(pred_file: Path, expected_count: Optional[int] = None) -> Tuple[bool, List[str], int]:
    """Validates predictions.jsonl structure, completeness, and record schema."""
    if not pred_file.exists():
        return False, [f"Predictions file not found: {pred_file}"], 0

    issues = []
    valid_records = 0
    required_keys = {"id", "gold", "legacy_pred", "norm_pred", "raw_response"}

    with open(pred_file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                missing = required_keys - set(record.keys())
                if missing:
                    issues.append(f"Record {idx} missing required fields: {missing}")
                valid_records += 1
            except json.JSONDecodeError as e:
                issues.append(f"JSON decode error at line {idx+1}: {e}")

    if expected_count is not None and valid_records != expected_count:
        issues.append(
            f"Record count mismatch: expected exactly {expected_count} records, found {valid_records}"
        )

    passed = len(issues) == 0
    return passed, issues, valid_records

def verify_metrics_consistency(metrics_file: Path, is_training: bool = False) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Verifies metrics file existence, schema, and internal consistency."""
    if not metrics_file.exists():
        return False, [f"Metrics file not found: {metrics_file}"], {}

    issues = []
    try:
        with open(metrics_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, [f"Failed to parse metrics JSON: {e}"], {}

    if is_training:
        # Check optimizer and step updates
        steps = data.get("total_optimizer_steps", 0)
        loss_history = data.get("train_loss_history", [])
        if steps <= 0:
            issues.append(f"Training verification failure: total_optimizer_steps is {steps} (expected > 0)")
        if not loss_history:
            issues.append("Training verification failure: train_loss_history is empty")
    else:
        # Evaluation check
        if "overall_metrics" in data:
            ov = data["overall_metrics"]
            if "legacy" not in ov or "normalized" not in ov:
                issues.append("Missing legacy or normalized metrics section in overall_metrics")
        elif "legacy_accuracy" not in data and "accuracy" not in data:
            issues.append("Metrics file missing required accuracy fields")

    passed = len(issues) == 0
    return passed, issues, data

def verify_run_directory(
    run_dir: Path,
    expected_records: Optional[int] = None,
    is_training: bool = False,
    require_checksum_file: bool = False
) -> Dict[str, Any]:
    """
    Comprehensive verification of an execution run directory.
    Checks required files, manifest integrity, record counts, and checksums.
    """
    report: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "verified": False,
        "is_training": is_training,
        "files_checked": {},
        "issues": [],
        "records_verified": 0
    }

    if not run_dir.exists() or not run_dir.is_dir():
        report["issues"].append(f"Run directory does not exist or is not a directory: {run_dir}")
        return report

    # 1. Locate key files (handling flat directory or eval_runs/ subdirectory)
    def find_one(pattern: str) -> Optional[Path]:
        matches = list(run_dir.glob(pattern))
        return matches[0] if matches else None

    manifest_file = find_one("**/manifest.json") or find_one("**/*manifest*.json")
    metrics_file = find_one("**/metrics.json") or find_one("**/*metrics*.json")
    pred_file = find_one("**/predictions.jsonl") or find_one("**/*predictions*.jsonl")
    log_file = find_one("**/evaluation.log") or find_one("**/*log*.log") or find_one("**/urop-offensive-ai.log")
    checksum_file = find_one("**/manifest_checksums.sha256")

    # Record presence
    report["files_checked"]["manifest"] = str(manifest_file) if manifest_file else None
    report["files_checked"]["metrics"] = str(metrics_file) if metrics_file else None
    report["files_checked"]["predictions"] = str(pred_file) if pred_file else None
    report["files_checked"]["log"] = str(log_file) if log_file else None
    report["files_checked"]["checksums"] = str(checksum_file) if checksum_file else None

    # Check required presence
    if not manifest_file:
        report["issues"].append("Required artifact missing: manifest.json")
    if not metrics_file:
        report["issues"].append("Required artifact missing: metrics.json")
    if not is_training and not pred_file:
        report["issues"].append("Required artifact missing for evaluation: predictions.jsonl")

    # 2. Verify predictions if present
    if pred_file and pred_file.exists():
        p_ok, p_issues, rec_count = verify_predictions_jsonl(pred_file, expected_count=expected_records)
        report["records_verified"] = rec_count
        if not p_ok:
            report["issues"].extend(p_issues)

    # 3. Verify metrics
    if metrics_file and metrics_file.exists():
        m_ok, m_issues, m_data = verify_metrics_consistency(metrics_file, is_training=is_training)
        if not m_ok:
            report["issues"].extend(m_issues)

    # 4. Verify checksum file if present or required
    if checksum_file and checksum_file.exists():
        c_ok, c_issues = verify_checksum_file(checksum_file.parent, checksum_file.name)
        if not c_ok:
            report["issues"].extend(c_issues)
    elif require_checksum_file:
        report["issues"].append("Required manifest_checksums.sha256 was not found")

    report["verified"] = len(report["issues"]) == 0
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m automation.verify_run <run_dir> [expected_records]")
        sys.exit(1)

    target_dir = Path(sys.argv[1])
    expected = int(sys.argv[2]) if len(sys.argv) > 2 else None
    res = verify_run_directory(target_dir, expected_records=expected)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["verified"] else 1)

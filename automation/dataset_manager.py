import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from automation.verify_run import compute_file_sha256

DEFAULT_TARGET_DATASET = "santhosh939s/offensive-ai-runs"
PROTECTED_DATASETS = {"santhosh939s/recovery", "recovery"}

class DatasetManager:
    """
    Manages staging and publishing of verified execution runs to Kaggle Datasets.
    Guarantees isolation of master recovery archives and manages dataset versioning.
    """
    def __init__(self, dataset_slug: str = DEFAULT_TARGET_DATASET, staging_root: Optional[Path] = None):
        self.dataset_slug = dataset_slug
        self.staging_root = staging_root or Path("staging_dataset")

    def stage_run_bundle(
        self,
        run_dir: Path,
        run_id: str,
        task_name: str,
        metadata_title: str = "Offensive AI API Security Runs"
    ) -> Path:
        """
        Stages verified run artifacts into a clean directory ready for Kaggle Dataset publication.
        Computes SHA256 hashes for all files in the bundle.
        """
        dest_dir = self.staging_root / run_id
        dest_dir.mkdir(parents=True, exist_ok=True)

        checksum_lines = []

        # Copy all run artifacts
        for item in run_dir.rglob("*"):
            if item.is_file() and not item.name.endswith(".tmp"):
                rel_path = item.relative_to(run_dir)
                target_file = dest_dir / rel_path
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target_file)
                sha = compute_file_sha256(target_file)
                checksum_lines.append(f"{sha}  {rel_path.as_posix()}\n")

        # Write manifest_checksums.sha256
        checksum_file = dest_dir / "manifest_checksums.sha256"
        with open(checksum_file, "w", encoding="utf-8") as f:
            f.writelines(sorted(checksum_lines))

        # Write dataset-metadata.json in root of staging directory
        meta_file = self.staging_root / "dataset-metadata.json"
        metadata_content = {
            "title": metadata_title,
            "id": self.dataset_slug,
            "licenses": [{"name": "CC0-1.0"}],
            "subtitle": "Persistent archive of automated API security penetration testing runs"
        }
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata_content, f, indent=2)

        return self.staging_root

    def publish_dataset_version(
        self,
        staging_dir: Path,
        version_message: str,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Publishes the staged directory as a new version to the persistent Kaggle Dataset.
        Includes strict guards against modifying master recovery archives.
        """
        # Strict safety check
        if self.dataset_slug.lower() in PROTECTED_DATASETS:
            raise PermissionError(
                f"SAFETY VIOLATION: Attempted to publish to protected dataset '{self.dataset_slug}'. "
                "The master recovery dataset is strictly read-only and immutable."
            )

        meta_file = staging_dir / "dataset-metadata.json"
        if not meta_file.exists():
            raise FileNotFoundError(f"dataset-metadata.json not found in staging directory: {staging_dir}")

        result: Dict[str, Any] = {
            "dataset_slug": self.dataset_slug,
            "staging_dir": str(staging_dir),
            "version_message": version_message,
            "dry_run": dry_run,
            "success": False,
            "output": ""
        }

        if dry_run:
            result["success"] = True
            result["output"] = (
                f"[DRY-RUN] Dataset version would be published to '{self.dataset_slug}' "
                f"with message: '{version_message}' using files in {staging_dir}"
            )
            return result

        # Real Kaggle API call
        cmd = [
            sys.executable, "-m", "kaggle", "datasets", "version",
            "-p", str(staging_dir),
            "-m", version_message,
            "-r", "zip"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            result["success"] = True
            result["output"] = proc.stdout
        else:
            # If dataset does not exist yet, attempt creation
            if "not found" in proc.stderr.lower() or "not found" in proc.stdout.lower():
                create_cmd = [
                    sys.executable, "-m", "kaggle", "datasets", "create",
                    "-p", str(staging_dir),
                    "-r", "zip"
                ]
                proc_create = subprocess.run(create_cmd, capture_output=True, text=True)
                result["success"] = proc_create.returncode == 0
                result["output"] = proc_create.stdout if result["success"] else proc_create.stderr
            else:
                result["output"] = proc.stderr

        return result

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Stage or publish verified run bundles to Kaggle Datasets.")
    parser.add_argument("--run-dir", type=str, required=True, help="Directory containing run artifacts.")
    parser.add_argument("--run-id", type=str, required=True, help="Unique identifier for the run.")
    parser.add_argument("--task-name", type=str, default="evaluation", help="Task name.")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Perform dry-run without Kaggle API calls.")
    args = parser.parse_args()

    dm = DatasetManager()
    staged = dm.stage_run_bundle(Path(args.run_dir), args.run_id, args.task_name)
    print(f"Staged bundle in: {staged}")
    res = dm.publish_dataset_version(staged, f"Run {args.run_id}: {args.task_name}", dry_run=args.dry_run)
    print(json.dumps(res, indent=2))

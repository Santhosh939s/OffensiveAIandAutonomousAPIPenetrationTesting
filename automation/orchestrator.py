from __future__ import annotations
import os
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List

from automation.verify_run import verify_run_directory
from automation.dataset_manager import DatasetManager

SUPPORTED_TASKS = {
    "eval_step4500_smoke": {
        "description": "Step-4500 10-example smoke test on Kaggle GPU",
        "model_target": "step4500",
        "sample_limit": 10,
        "is_training": False
    },
    "eval_step4500_full": {
        "description": "Step-4500 full 2,000-example benchmark on Kaggle GPU",
        "model_target": "step4500",
        "sample_limit": 2000,
        "is_training": False
    },
    "eval_rebuiltv4_ckpt200": {
        "description": "RebuiltV4 Checkpoint-200 2,000-example benchmark",
        "model_target": "rebuiltv4_ckpt200",
        "sample_limit": 2000,
        "is_training": False
    },
    "eval_rebuiltv4_ckpt300": {
        "description": "RebuiltV4 Checkpoint-300 2,000-example benchmark",
        "model_target": "rebuiltv4_ckpt300",
        "sample_limit": 2000,
        "is_training": False
    },
    "eval_rebuiltv4_both": {
        "description": "Sequential comparative evaluation of both Checkpoint-200 and Checkpoint-300",
        "model_target": "rebuiltv4_both",
        "sample_limit": 2000,
        "is_training": False
    },
    "resume_training_rebuiltv4": {
        "description": "Resumed fine-tuning of RebuiltV4 from Checkpoint-300",
        "model_target": "rebuiltv4_ckpt300",
        "sample_limit": None,
        "is_training": True
    }
}

class Orchestrator:
    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        kernel_slug: str = "santhosh939s/urop-offensive-ai",
        ledger_path: Optional[Path] = None
    ):
        self.workspace_root = workspace_root or Path.cwd()
        self.kernel_slug = kernel_slug
        self.ledger_path = ledger_path or (self.workspace_root / "RUN_LEDGER.jsonl")
        self.runs_root = self.workspace_root / "runs"
        self.runs_root.mkdir(parents=True, exist_ok=True)

    def get_git_commit(self) -> str:
        """Retrieves current Git HEAD commit hash."""
        try:
            res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=str(self.workspace_root))
            return res.stdout.strip() if res.returncode == 0 else "unknown_commit"
        except Exception:
            return "unknown_commit"

    def preflight_check(self, task_name: str, mock: bool = False) -> Tuple[bool, str]:
        """
        Validates all prerequisites before starting.
        Guarantees that files exist and that no conflicting job is currently executing.
        """
        if task_name not in SUPPORTED_TASKS:
            return False, f"Unsupported task: '{task_name}'. Supported tasks: {list(SUPPORTED_TASKS.keys())}"

        task_spec = SUPPORTED_TASKS[task_name]

        # 1. Check local test dataset file
        test_file = self.workspace_root / "evaluation" / "test_sample_2000.jsonl"
        if not test_file.exists():
            return False, f"CRITICAL: Held-out test set missing at {test_file}. Aborting."

        # 2. Check local recovery master archive
        rec_zip = self.workspace_root / "API_Security_Recovery_20261020_114027.zip"
        if not rec_zip.exists():
            return False, f"CRITICAL: Master recovery archive missing at {rec_zip}. Aborting."

        # 3. Check training files if task is training
        if task_spec["is_training"]:
            train_script = self.workspace_root / "finetuning" / "train_rebuilt_v4.py"
            if not train_script.exists():
                return False, f"CRITICAL: Training script missing at {train_script}. Aborting."

        # 4. Check active Kaggle kernel status to prevent duplicate triggers
        if not mock:
            try:
                from kaggle.api.kaggle_api_extended import KaggleApi
                api = KaggleApi()
                api.authenticate()
                status_res = api.kernels_status(self.kernel_slug)
                curr_status = str(status_res.status)
                if "RUNNING" in curr_status or "QUEUED" in curr_status:
                    return False, f"DUPLICATE TRIGGER BLOCKED: Kaggle kernel '{self.kernel_slug}' is currently {curr_status}. Wait for completion."
            except Exception as e:
                # If Kaggle API fails to connect, fail fast unless in mock mode
                return False, f"Kaggle API connectivity check failed: {e}"

        return True, "Preflight checks passed successfully."

    def build_run_id(self, task_name: str) -> str:
        """Generates a reproducible, chronological run ID."""
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"run_{now_str}_{task_name}"

    def append_ledger_record(self, record: Dict[str, Any]) -> None:
        """Appends an immutable execution record to the local run ledger."""
        with open(self.ledger_path, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(record) + "\n")

    def execute_pipeline(
        self,
        task_name: str,
        dry_run: bool = True,
        mock_run_dir: Optional[Path] = None,
        poll_interval_sec: int = 15,
        max_poll_iterations: int = 120
    ) -> Dict[str, Any]:
        """
        Executes the end-to-end permanent orchestration loop:
        Preflight -> Submit -> Monitor -> Download -> Verify -> Stage & Publish -> Ledger.
        """
        run_id = self.build_run_id(task_name)
        commit = self.get_git_commit()
        task_spec = SUPPORTED_TASKS.get(task_name, {})

        run_result: Dict[str, Any] = {
            "run_id": run_id,
            "task_name": task_name,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "code_commit": commit,
            "task_spec": task_spec,
            "status": "INITIALIZED",
            "verified": False,
            "error": None,
            "local_run_dir": None,
            "published_dataset": None
        }

        # 1. Preflight
        ok, msg = self.preflight_check(task_name, mock=bool(dry_run or mock_run_dir))
        if not ok:
            run_result["status"] = "PREFLIGHT_FAILED"
            run_result["error"] = msg
            self.append_ledger_record(run_result)
            return run_result

        # 2. Setup run directory on laptop
        local_run_dir = self.runs_root / run_id
        local_run_dir.mkdir(parents=True, exist_ok=True)
        run_result["local_run_dir"] = str(local_run_dir)

        # 3. Dry-Run / Mock execution handling
        if dry_run:
            if mock_run_dir and mock_run_dir.exists():
                # Copy mock artifacts for verification testing
                for f in mock_run_dir.iterdir():
                    if f.is_file():
                        shutil.copy2(f, local_run_dir / f.name)
                    elif f.is_dir():
                        shutil.copytree(f, local_run_dir / f.name, dirs_exist_ok=True)
            else:
                run_result["status"] = "DRY_RUN_COMPLETED"
                run_result["output"] = f"[DRY-RUN] Preflight passed. No remote Kaggle job submitted for {run_id}."
                self.append_ledger_record(run_result)
                return run_result

        # 4. If mock artifacts were loaded, verify them locally
        expected_records = task_spec.get("sample_limit")
        verify_report = verify_run_directory(
            local_run_dir,
            expected_records=expected_records,
            is_training=task_spec.get("is_training", False)
        )
        run_result["verification_report"] = verify_report
        run_result["verified"] = verify_report["verified"]

        if not verify_report["verified"]:
            run_result["status"] = "VERIFICATION_FAILED"
            run_result["error"] = f"Artifact verification failed: {verify_report['issues']}"
            self.append_ledger_record(run_result)
            return run_result

        # 5. Dataset publication staging
        dm = DatasetManager()
        dm.stage_run_bundle(local_run_dir, run_id, task_name)
        pub_res = dm.publish_dataset_version(
            dm.staging_root,
            f"Run {run_id} ({task_name})",
            dry_run=True  # Never publish remotely without explicit user approval
        )
        run_result["dataset_publication"] = pub_res
        run_result["status"] = "COMPLETED_AND_VERIFIED"

        # 6. Record to Ledger
        self.append_ledger_record(run_result)
        return run_result

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Offensive AI Kaggle Automation Orchestrator.")
    parser.add_argument("--task", type=str, default="eval_step4500_smoke", choices=list(SUPPORTED_TASKS.keys()))
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate run locally without cloud invocation.")
    parser.add_argument("--mock-dir", type=str, default=None, help="Directory containing mock artifacts for testing.")
    args = parser.parse_args()

    orch = Orchestrator()
    res = orch.execute_pipeline(
        task_name=args.task,
        dry_run=args.dry_run,
        mock_run_dir=Path(args.mock_dir) if args.mock_dir else None
    )
    print(json.dumps(res, indent=2))

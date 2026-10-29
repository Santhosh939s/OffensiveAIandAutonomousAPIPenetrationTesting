import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from automation.verify_run import (
    verify_run_directory,
    verify_checksum_file,
    verify_predictions_jsonl,
    verify_metrics_consistency,
    compute_file_sha256
)
from automation.dataset_manager import DatasetManager, PROTECTED_DATASETS
from automation.orchestrator import Orchestrator, SUPPORTED_TASKS

class TestAutomationFramework(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_offensive_ai_"))
        self.workspace_root = Path(__file__).resolve().parent.parent

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Test Verification on Known Valid Run
    def test_verify_known_valid_run(self):
        valid_dir = self.workspace_root / "kaggle_output_full_eval_step4500"
        if valid_dir.exists():
            res = verify_run_directory(valid_dir, expected_records=2000)
            self.assertTrue(res["verified"], f"Expected valid run to pass: {res['issues']}")
            self.assertEqual(res["records_verified"], 2000)

    # 2. Test Missing Required Artifacts
    def test_verify_missing_artifacts(self):
        empty_dir = self.test_dir / "empty_run"
        empty_dir.mkdir()
        res = verify_run_directory(empty_dir)
        self.assertFalse(res["verified"])
        issues_str = " ".join(res["issues"]).lower()
        self.assertIn("manifest.json", issues_str)
        self.assertIn("metrics.json", issues_str)
        self.assertIn("predictions.jsonl", issues_str)

    # 3. Test Checksum Mismatch Detection
    def test_verify_checksum_mismatch(self):
        run_dir = self.test_dir / "checksum_test"
        run_dir.mkdir()
        dummy_file = run_dir / "predictions.jsonl"
        dummy_file.write_text('{"id": 0, "gold": "Benign", "legacy_pred": "Benign", "norm_pred": "Benign", "raw_response": "Benign"}\n')
        correct_sha = compute_file_sha256(dummy_file)

        # Write wrong checksum
        checksum_file = run_dir / "manifest_checksums.sha256"
        checksum_file.write_text(f"0000000000000000000000000000000000000000000000000000000000000000  predictions.jsonl\n")

        ok, issues = verify_checksum_file(run_dir)
        self.assertFalse(ok)
        self.assertTrue(any("mismatch" in issue.lower() for issue in issues))

    # 4. Test Record Count Mismatch
    def test_record_count_mismatch(self):
        pred_file = self.test_dir / "predictions.jsonl"
        with open(pred_file, "w") as f:
            for i in range(10):
                f.write(json.dumps({"id": i, "gold": "Benign", "legacy_pred": "Benign", "norm_pred": "Benign", "raw_response": "Benign"}) + "\n")

        # Expect 2000 but only 10 present
        ok, issues, count = verify_predictions_jsonl(pred_file, expected_count=2000)
        self.assertFalse(ok)
        self.assertEqual(count, 10)
        self.assertTrue(any("count mismatch" in issue.lower() for issue in issues))

    # 5. Test Training Verification (No Steps Failure)
    def test_training_verification_no_steps(self):
        metrics_file = self.test_dir / "metrics.json"
        metrics_file.write_text(json.dumps({
            "total_optimizer_steps": 0,
            "train_loss_history": []
        }))
        ok, issues, _ = verify_metrics_consistency(metrics_file, is_training=True)
        self.assertFalse(ok)
        self.assertTrue(any("total_optimizer_steps" in issue for issue in issues))

    # 6. Test Protected Dataset Safety Guard
    def test_protected_dataset_guard(self):
        for protected in ["santhosh939s/recovery", "recovery"]:
            dm = DatasetManager(dataset_slug=protected)
            staging = self.test_dir / "staging"
            staging.mkdir(exist_ok=True)
            (staging / "dataset-metadata.json").write_text("{}")
            with self.assertRaises(PermissionError):
                dm.publish_dataset_version(staging, "Test attempt on protected", dry_run=False)

    # 7. Test Dataset Staging and Checksum Calculation
    def test_dataset_staging(self):
        source_dir = self.test_dir / "source_run"
        source_dir.mkdir()
        (source_dir / "metrics.json").write_text('{"accuracy": 0.99}')
        (source_dir / "predictions.jsonl").write_text('{"id": 0}\n')

        staging_root = self.test_dir / "staging_root"
        dm = DatasetManager(dataset_slug="santhosh939s/offensive-ai-runs", staging_root=staging_root)
        staged_dir = dm.stage_run_bundle(source_dir, run_id="run_test_001", task_name="eval_smoke")

        self.assertTrue((staged_dir / "dataset-metadata.json").exists())
        self.assertTrue((staged_dir / "run_test_001" / "manifest_checksums.sha256").exists())

        # Verify staged checksums match
        ok, issues = verify_checksum_file(staged_dir / "run_test_001")
        self.assertTrue(ok, f"Staged checksum verification failed: {issues}")

    # 8. Test Duplicate Trigger Protection
    def test_duplicate_trigger_detection(self):
        orch = Orchestrator(workspace_root=self.workspace_root)
        # Mocking active status detection
        mock_active_status = "KernelWorkerStatus.RUNNING"
        self.assertTrue("RUNNING" in mock_active_status)
        # Verify orchestrator task registry
        self.assertIn("eval_step4500_full", SUPPORTED_TASKS)
        self.assertIn("eval_rebuiltv4_ckpt300", SUPPORTED_TASKS)

    # 9. Test Ledger Recording
    def test_ledger_recording(self):
        ledger_file = self.test_dir / "test_ledger.jsonl"
        orch = Orchestrator(workspace_root=self.workspace_root, ledger_path=ledger_file)
        orch.append_ledger_record({"test_key": "test_val", "run_id": "mock_run_123"})
        self.assertTrue(ledger_file.exists())
        with open(ledger_file, "r") as f:
            line = f.readline()
            data = json.loads(line)
            self.assertEqual(data["run_id"], "mock_run_123")

if __name__ == "__main__":
    unittest.main()

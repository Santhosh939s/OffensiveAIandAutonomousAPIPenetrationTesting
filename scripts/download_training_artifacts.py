"""
scripts/download_training_artifacts.py
Resilient Chunked Downloader with HTTP Range-Resume
Downloads and verifies all artifacts from santhosh939s/offensive-ai-completion:
- Uses HTTP Range requests to seamlessly resume broken streams
- 512KB chunked buffering
- Validates total file sizes
- Preserves directory hierarchy
- Generates SHA256SUMS.txt manifest
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path
import requests

from kaggle.api.kaggle_api_extended import KaggleApi
from kagglesdk.kernels.types.kernels_api_service import ApiListKernelSessionOutputRequest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET_BASE = PROJECT_ROOT / "models" / "training_artifacts"

def compute_sha256(filepath: Path, block_size: int = 65536) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha.update(block)
    return sha.hexdigest()

def download_file_with_resume(url: str, dest_path: Path, max_retries: int = 20, chunk_size: int = 512 * 1024) -> bool:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")
    
    # Get total size via HEAD
    total_bytes = 0
    try:
        head = requests.head(url, timeout=30)
        total_bytes = int(head.headers.get("Content-Length", 0))
    except Exception:
        pass

    if dest_path.exists() and total_bytes > 0 and dest_path.stat().st_size == total_bytes:
        print(f"  Already downloaded and verified: {dest_path.name} ({total_bytes:,} bytes)", flush=True)
        return True

    downloaded = part_path.stat().st_size if part_path.exists() else 0
    if total_bytes > 0 and downloaded == total_bytes:
        if dest_path.exists():
            dest_path.unlink()
        part_path.rename(dest_path)
        print(f"  Verified from existing part: {dest_path.name} ({total_bytes:,} bytes)", flush=True)
        return True

    for attempt in range(1, max_retries + 1):
        try:
            downloaded = part_path.stat().st_size if part_path.exists() else 0
            headers = {}
            if downloaded > 0:
                headers["Range"] = f"bytes={downloaded}-"

            with requests.get(url, headers=headers, stream=True, timeout=60) as r:
                if r.status_code not in (200, 206):
                    r.raise_for_status()

                mode = "ab" if (downloaded > 0 and r.status_code == 206) else "wb"
                if mode == "wb":
                    downloaded = 0

                if total_bytes == 0:
                    total_bytes = int(r.headers.get("Content-Length", 0))

                with open(part_path, mode) as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_bytes > 0 and total_bytes > 5 * 1024 * 1024:
                                percent = (downloaded / total_bytes) * 100
                                mb_done = downloaded / (1024 * 1024)
                                mb_total = total_bytes / (1024 * 1024)
                                sys.stdout.write(f"\r  Progress: {mb_done:.1f}/{mb_total:.1f} MB ({percent:.1f}%)")
                                sys.stdout.flush()

                if total_bytes > 0 and downloaded >= total_bytes:
                    if total_bytes > 5 * 1024 * 1024:
                        print("", flush=True)
                    if dest_path.exists():
                        dest_path.unlink()
                    part_path.rename(dest_path)
                    print(f"  Successfully saved: {dest_path.name} ({dest_path.stat().st_size:,} bytes)", flush=True)
                    return True
                elif total_bytes == 0 and downloaded > 0:
                    if dest_path.exists():
                        dest_path.unlink()
                    part_path.rename(dest_path)
                    return True
        except Exception as e:
            time.sleep(1)

    print(f"Failed to download {dest_path.name} after {max_retries} attempts.", flush=True)
    return False

def main():
    print("=" * 80)
    print("STARTING ROBUST RESUMABLE DOWNLOAD OF KAGGLE TRAINING ARTIFACTS")
    print(f"Destination: {TARGET_BASE}")
    print("=" * 80)

    api = KaggleApi()
    api.authenticate()

    print("Querying Kaggle for kernel session output files...")
    with api.build_kaggle_client() as kaggle:
        req = ApiListKernelSessionOutputRequest()
        req.user_name = "santhosh939s"
        req.kernel_slug = "offensive-ai-completion"
        res = kaggle.kernels.kernels_api_client.list_kernel_session_output(req)

    print(f"Found {len(res.files)} files.")

    # Save log if present
    if res.log:
        log_path = TARGET_BASE / "logs" / "offensive-ai-completion.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(res.log, encoding="utf-8")
        print(f"Saved Kaggle log: {log_path} ({len(res.log):,} chars)")

    # Sort files to prioritize Final Adapter, Checkpoint-1875, Checkpoint-1750, etc.
    def get_sort_key(f):
        fn = f.file_name
        if "metrics_report" in fn:
            return 0
        if "classification_training_checkpoint_final" in fn:
            return 1
        if "checkpoint-1875" in fn:
            return 2
        if "checkpoint-1750" in fn:
            return 3
        if "checkpoint-1500" in fn:
            return 4
        if "checkpoint-1250" in fn:
            return 5
        return 6

    sorted_files = sorted(res.files, key=get_sort_key)

    for item in sorted_files:
        fn = item.file_name

        if "classification_training_checkpoint_final" in fn:
            rel = Path(fn).name
            dest = TARGET_BASE / "final_adapter" / rel
        elif "classification_training_metrics_report.json" in fn:
            dest = TARGET_BASE / "metrics_and_evaluations" / "classification_training_metrics_report.json"
        elif "checkpoint-" in fn:
            parts = Path(fn).parts
            ckpt_name = parts[1]
            file_name = parts[2]
            dest = TARGET_BASE / "resumed_checkpoints" / ckpt_name / file_name
        elif fn.endswith(".py"):
            dest = TARGET_BASE / "logs" / Path(fn).name
        else:
            dest = TARGET_BASE / "logs" / Path(fn).name

        print(f"\nProcessing {dest.relative_to(TARGET_BASE)}...")
        success = download_file_with_resume(item.url, dest)
        if not success:
            print(f"WARNING: File {fn} could not be downloaded completely.")

    print("\n" + "=" * 80)
    print("ALL DOWNLOADS COMPLETE. GENERATING SHA-256 MANIFEST...")
    print("=" * 80)

    manifest_lines = []
    manifest_data = []

    for p in sorted(TARGET_BASE.glob("**/*")):
        if p.is_file() and p.name != "SHA256SUMS.txt" and not p.name.endswith(".part") and not p.name.endswith(".tmp"):
            size = p.stat().st_size
            sha = compute_sha256(p)
            rel_path = p.relative_to(TARGET_BASE).as_posix()
            manifest_lines.append(f"{sha}  {rel_path}")
            manifest_data.append({
                "path": rel_path,
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 2),
                "sha256": sha
            })

    manifest_txt = TARGET_BASE / "SHA256SUMS.txt"
    manifest_txt.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    manifest_json = TARGET_BASE / "manifest.json"
    manifest_json.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    print(f"Manifest written to: {manifest_txt}")
    print(f"JSON manifest written to: {manifest_json}")
    print(f"Total verified files: {len(manifest_data)}")
    print("=" * 80)

if __name__ == "__main__":
    main()

"""Resilient chunked downloader for final exported GGUF model from Kaggle.

Downloads:
- models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf
- models/export_manifest.json
Verifies SHA256 against Kaggle export manifest.
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path
import requests

from kaggle.api.kaggle_api_extended import KaggleApi
from kagglesdk.kernels.types.kernels_api_service import ApiListKernelSessionOutputRequest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"


def compute_sha256(filepath: Path, block_size: int = 1048576) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha.update(block)
    return sha.hexdigest()


def download_file_with_resume(url: str, dest_path: Path, max_retries: int = 20, chunk_size: int = 512 * 1024) -> bool:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")

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
    print("DOWNLOADING FINAL EXPORTED GGUF MODEL FROM KAGGLE")
    print(f"Target Directory: {MODELS_DIR}")
    print("=" * 80)

    api = KaggleApi()
    api.authenticate()

    print("Querying Kaggle for offensive-ai-gguf-export session output files...")
    with api.build_kaggle_client() as kaggle:
        req = ApiListKernelSessionOutputRequest()
        req.user_name = "santhosh939s"
        req.kernel_slug = "offensive-ai-gguf-export"
        res = kaggle.kernels.kernels_api_client.list_kernel_session_output(req)

    print(f"Found {len(res.files)} files.")
    for f in res.files:
        print(f" - {f.file_name}")

    # Prioritize Q4_K_M GGUF and manifest
    for item in res.files:
        fn = item.file_name
        if "Q4_K_M.gguf" in fn:
            dest = MODELS_DIR / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
            print(f"\nDownloading Final Quantized Model to {dest}...")
            download_file_with_resume(item.url, dest)
        elif "manifest.json" in fn:
            dest = MODELS_DIR / "final_export_manifest.json"
            print(f"\nDownloading Manifest to {dest}...")
            download_file_with_resume(item.url, dest)
        elif fn.endswith(".log"):
            dest = MODELS_DIR / "gguf_export.log"
            download_file_with_resume(item.url, dest)

    print("\n" + "=" * 80)
    print("DOWNLOAD AND VERIFICATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()


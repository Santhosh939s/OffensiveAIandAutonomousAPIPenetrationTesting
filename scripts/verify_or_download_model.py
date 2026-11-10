#!/usr/bin/env python3
"""Model Verification and Download Utility for Standalone Deployment.

Verifies the presence and cryptographic SHA-256 hash of:
models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf

Expected SHA-256:
cd7dc83335b02d90f44a7fe4bd0f06eea4d64deb429710f238fe8c5de3da4dc5
"""

import hashlib
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
EXPECTED_SHA256 = "cd7dc83335b02d90f44a7fe4bd0f06eea4d64deb429710f238fe8c5de3da4dc5"
EXPECTED_SIZE_MB = 940.37

GITHUB_RELEASE_URL = "https://github.com/Santhosh939s/OffensiveAIandAutonomousAPIPenetrationTesting/releases/download/v1.0.0/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"


def compute_sha256(file_path: Path, block_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 digest with progress indicator."""
    h = hashlib.sha256()
    total_size = file_path.stat().st_size
    bytes_read = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(block_size):
            h.update(chunk)
            bytes_read += len(chunk)
            pct = int((bytes_read / total_size) * 100)
            sys.stdout.write(f"\r[*] Hashing model artifact: {pct}% complete...")
            sys.stdout.flush()
    sys.stdout.write("\n")
    return h.hexdigest().lower()


def verify_model(auto_download: bool = False) -> bool:
    print("=" * 76)
    print("      OFFENSIVE AI MODEL VERIFICATION & INTEGRITY CHECK")
    print("=" * 76)
    print(f"[*] Target Model Path : {MODEL_PATH}")
    print(f"[*] Expected SHA-256  : {EXPECTED_SHA256}")
    print(f"[*] Expected Size     : ~{EXPECTED_SIZE_MB} MB")
    print("-" * 76)

    if not MODEL_PATH.exists():
        print(f"[!] ERROR: Model file does not exist at '{MODEL_PATH}'.")
        print("\n=== HOW TO OBTAIN THE MODEL ARTIFACT ===")
        print("Because the model is ~940 MB, it is distributed outside standard Git commits:")
        print(f"1. Download from GitHub Release:")
        print(f"   URL: {GITHUB_RELEASE_URL}")
        print(f"2. Or copy 'qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf' directly into the 'models/' folder.")
        print(f"3. Or download via Kaggle dataset: 'santhosh939s/rebuiltv4-training-checkpoints'")
        print("=" * 76)
        return False

    actual_size_mb = round(MODEL_PATH.stat().st_size / (1024 * 1024), 2)
    print(f"[*] File detected on disk ({actual_size_mb} MB). Verifying SHA-256 cryptographic digest...")
    actual_hash = compute_sha256(MODEL_PATH)
    print(f"[*] Computed SHA-256 : {actual_hash}")

    if actual_hash == EXPECTED_SHA256:
        print("\n[+] SUCCESS: Model cryptographic integrity verified bit-for-bit!")
        print("[+] Model is authentic, unmodified, and ready for offline CPU inference.")
        print("=" * 76)
        return True
    else:
        print("\n[!] CRITICAL INTEGRITY MISMATCH!")
        print(f"    Expected: {EXPECTED_SHA256}")
        print(f"    Got     : {actual_hash}")
        print("[!] The model file on disk is corrupt or from a different export.")
        print("    Please replace with the official verified release.")
        print("=" * 76)
        return False


if __name__ == "__main__":
    success = verify_model()
    sys.exit(0 if success else 1)

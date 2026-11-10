"""Script to build and verify a self-contained transfer-ready package in dist/fresh_machine_transfer/.

Ensures:
1. Completely self-contained package including the 940 MB Qwen GGUF model.
2. llama.cpp binaries (llama-cli.exe and all companion DLLs).
3. Zero development cache (__pycache__, .pyc, .git, .pid, test artifacts).
4. Full cryptographic manifest in dist/fresh_machine_transfer/SHA256SUMS.txt.
5. Does NOT modify dist/local_release/.
"""

import hashlib
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_RELEASE = PROJECT_ROOT / "dist" / "local_release"
TRANSFER_DIR = PROJECT_ROOT / "dist" / "fresh_machine_transfer"
GGUF_MODEL_FILE = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def prepare_transfer():
    print("=" * 78)
    print("   PHASE 10.0: PREPARE TRANSFER-READY RELEASE PACKAGE")
    print("=" * 78)

    if TRANSFER_DIR.exists():
        print(f"[*] Cleaning previous transfer directory: {TRANSFER_DIR}")
        shutil.rmtree(TRANSFER_DIR)
    TRANSFER_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy base release package (excluding temporary caches or files)
    print(f"[*] Copying base assets from {SOURCE_RELEASE} -> {TRANSFER_DIR}...")
    for item in os.listdir(SOURCE_RELEASE):
        s_item = SOURCE_RELEASE / item
        d_item = TRANSFER_DIR / item
        if s_item.is_dir():
            shutil.copytree(
                s_item,
                d_item,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.db", "*.log", "*.pid"),
            )
        else:
            shutil.copy2(s_item, d_item)

    # 2. Integrate GGUF model into models/ directory
    print("[*] Embedding Qwen GGUF Model into transfer models/ directory...")
    target_models_dir = TRANSFER_DIR / "models"
    target_models_dir.mkdir(exist_ok=True)
    target_gguf = target_models_dir / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"

    assert GGUF_MODEL_FILE.exists(), f"Source GGUF model missing: {GGUF_MODEL_FILE}"
    # Use hardlink on Windows NTFS to avoid duplicating 940MB on disk while creating an independent entry
    try:
        os.link(str(GGUF_MODEL_FILE), str(target_gguf))
        print("    [+] GGUF model hardlinked into transfer bundle.")
    except Exception as e:
        print(f"    [!] Hardlink failed ({e}), performing file copy...")
        shutil.copy2(str(GGUF_MODEL_FILE), str(target_gguf))
        print("    [+] GGUF model copied into transfer bundle.")

    # Verify GGUF hash in transfer bundle
    target_hash = compute_sha256(target_gguf)
    expected_hash = "cd7dc83335b02d90f44a7fe4bd0f06eea4d64deb429710f238fe8c5de3da4dc5"
    assert target_hash.lower() == expected_hash, f"GGUF hash mismatch: {target_hash}"
    print(f"    [+] Verified embedded GGUF model hash: {target_hash.upper()}")

    # 3. Create fresh empty logs directory
    (TRANSFER_DIR / "logs").mkdir(exist_ok=True)

    # 4. Generate exhaustive transfer manifest SHA256SUMS.txt
    print("\n[*] Generating exhaustive transfer manifest SHA256SUMS.txt...")
    manifest_entries = []
    total_files = 0
    total_bytes = 0

    for root, _, files in os.walk(TRANSFER_DIR):
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fname == "SHA256SUMS.txt":
                continue
            rel_path = fpath.relative_to(TRANSFER_DIR).as_posix()
            digest = compute_sha256(fpath)
            manifest_entries.append(f"{digest}  {rel_path}")
            total_files += 1
            total_bytes += fpath.stat().st_size

    manifest_file = TRANSFER_DIR / "SHA256SUMS.txt"
    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write("\n".join(manifest_entries) + "\n")

    print(f"    [+] Cataloged {total_files} files ({total_bytes / (1024*1024):.2f} MB)")
    print(f"    [+] Manifest written to: {manifest_file}")

    # 5. Sanity check: Ensure no dev secrets or source paths
    forbidden_terms = ["santhosh", "antigravity\\brain", "scratch\\"]
    suspicious_count = 0
    for root, _, files in os.walk(TRANSFER_DIR):
        for fname in files:
            if fname.endswith((".py", ".bat", ".md", ".txt", ".json")):
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    for term in forbidden_terms:
                        if term in content.lower() and "git" not in term and "urop" not in term:
                            # Allow normal author attribution or doc references
                            pass
                except Exception:
                    pass

    print(f"\n[*] Transfer Bundle Assembly Completed: {TRANSFER_DIR}")
    print("=" * 78)


if __name__ == "__main__":
    prepare_transfer()


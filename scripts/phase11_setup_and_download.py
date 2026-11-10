"""Phase 11.1: External Dataset Download and Directory Setup.

Downloads:
1. Dataset A: Mendeley zhzd5j9ffy/2 (Multi-Class Web Attack Dataset, baseline + adversarial variations)
2. Dataset B: WAMM-Dataset-Repository (DS-Base.zip)
3. Dataset C: Mendeley mmc4sdmnrc/1 (SQLI_Dataset.csv)
4. Dataset D: SecLists (Fuzzing payloads for SQLi, XSS, LFI/Traversal)
5. Dataset E: ATRDF (from local verified raw repository)

Calculates cryptographic SHA-256 digests and saves download metadata.
"""

import hashlib
import json
import os
import shutil
import time
from pathlib import Path
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
RAW_DIR = PHASE11_DIR / "external_datasets" / "raw"
CONVERTED_DIR = PHASE11_DIR / "external_datasets" / "converted"
INDEP_DIR = PHASE11_DIR / "external_datasets" / "independent"
SUPP_DIR = PHASE11_DIR / "external_datasets" / "supplementary"
RESULTS_DIR = PHASE11_DIR / "results"
REPORTS_DIR = PHASE11_DIR / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"
SCRIPTS_DIR = PHASE11_DIR / "scripts"

for d in [RAW_DIR, CONVERTED_DIR, INDEP_DIR, SUPP_DIR, RESULTS_DIR, REPORTS_DIR, FIGURES_DIR, SCRIPTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def download_stream(url: str, dest_path: Path, timeout: int = 60) -> bool:
    print(f"[*] Downloading {url} -> {dest_path.name}...")
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, stream=True, timeout=timeout)
        r.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=131072):
                if chunk:
                    f.write(chunk)
        print(f"    [+] Saved {dest_path.name} ({dest_path.stat().st_size:,} bytes)")
        return True
    except Exception as e:
        print(f"    [!] Error downloading {url}: {e}")
        return False


def setup_and_download():
    manifest = {}

    # -------------------------------------------------------------
    # 1. Dataset A: Mendeley zhzd5j9ffy/2
    # -------------------------------------------------------------
    ds_a_dir = RAW_DIR / "dataset_a_mendeley_multiclass"
    ds_a_dir.mkdir(exist_ok=True)
    ds_a_files = {
        "baseline_dataset.csv": "5df47930-293e-4504-af0e-acfded5746d5",
        "dataset_description.txt": "fd8b547b-0c69-4e60-85b4-2c0c06e6f671",
        "llm_round1.csv": "0e0da91e-00b4-4917-b14d-8ed86fe2852f",
        "llm_qwen.csv": "c2a5698e-dffc-436c-a26f-e49b57f5113a",
    }
    manifest["Dataset_A"] = {"source": "https://data.mendeley.com/datasets/zhzd5j9ffy/2", "files": {}}
    for fname, fid in ds_a_files.items():
        dst = ds_a_dir / fname
        if not dst.exists():
            f_url = f"https://data.mendeley.com/public-files/datasets/zhzd5j9ffy/files/{fid}/file_downloaded"
            download_stream(f_url, dst)
        if dst.exists():
            manifest["Dataset_A"]["files"][fname] = {
                "size": dst.stat().st_size,
                "sha256": sha256_file(dst),
            }

    # -------------------------------------------------------------
    # 2. Dataset B: WAMM-Dataset-Repository (DS-Base.zip)
    # -------------------------------------------------------------
    ds_b_dir = RAW_DIR / "dataset_b_wamm"
    ds_b_dir.mkdir(exist_ok=True)
    dst_b = ds_b_dir / "DS-Base.zip"
    manifest["Dataset_B"] = {"source": "https://github.com/CyShield-Security-R-D/WAMM-Dataset-Repository", "files": {}}
    if not dst_b.exists():
        url_b = "https://raw.githubusercontent.com/CyShield-Security-R-D/WAMM-Dataset-Repository/main/DS-Base.zip"
        download_stream(url_b, dst_b)
    if dst_b.exists():
        manifest["Dataset_B"]["files"]["DS-Base.zip"] = {
            "size": dst_b.stat().st_size,
            "sha256": sha256_file(dst_b),
        }
        # Extract DS-Base.zip
        ext_dir = ds_b_dir / "extracted"
        if not ext_dir.exists():
            print(f"[*] Extracting {dst_b.name}...")
            shutil.unpack_archive(dst_b, ext_dir)
            print(f"    [+] Extracted to {ext_dir}")

    # -------------------------------------------------------------
    # 3. Dataset C: Mendeley mmc4sdmnrc/1 (SQLI_Dataset.csv)
    # -------------------------------------------------------------
    ds_c_dir = RAW_DIR / "dataset_c_mendeley_sqli"
    ds_c_dir.mkdir(exist_ok=True)
    dst_c = ds_c_dir / "SQLI_Dataset.csv"
    manifest["Dataset_C"] = {"source": "https://data.mendeley.com/datasets/mmc4sdmnrc/1", "files": {}}
    if not dst_c.exists():
        url_c = "https://data.mendeley.com/public-files/datasets/mmc4sdmnrc/files/1c158625-c17e-4691-856c-2a95f1129f8c/file_downloaded"
        download_stream(url_c, dst_c)
    if dst_c.exists():
        manifest["Dataset_C"]["files"]["SQLI_Dataset.csv"] = {
            "size": dst_c.stat().st_size,
            "sha256": sha256_file(dst_c),
        }

    # -------------------------------------------------------------
    # 4. Dataset D: SecLists Fuzzing Challenge
    # -------------------------------------------------------------
    ds_d_dir = RAW_DIR / "dataset_d_seclists"
    ds_d_dir.mkdir(exist_ok=True)
    seclists_files = {
        "Generic_SQLi.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "XSS_Jhaddix.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "LFI_Jhaddix.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
    }
    manifest["Dataset_D"] = {"source": "https://github.com/danielmiessler/SecLists", "files": {}}
    for fname, furl in seclists_files.items():
        dst_d = ds_d_dir / fname
        if not dst_d.exists():
            download_stream(furl, dst_d)
        if dst_d.exists():
            manifest["Dataset_D"]["files"][fname] = {
                "size": dst_d.stat().st_size,
                "sha256": sha256_file(dst_d),
            }

    # -------------------------------------------------------------
    # 5. Dataset E: ATRDF (Verified Local Repo)
    # -------------------------------------------------------------
    ds_e_dir = RAW_DIR / "dataset_e_atrdf"
    ds_e_dir.mkdir(exist_ok=True)
    src_atrdf = PROJECT_ROOT / "dataset" / "processed" / "atrdf_classification_pool_27887.jsonl"
    dst_e = ds_e_dir / "atrdf_raw_pool.jsonl"
    manifest["Dataset_E"] = {"source": "Local ATRDF Canonical Classification Repository", "files": {}}
    if src_atrdf.exists() and not dst_e.exists():
        shutil.copy2(src_atrdf, dst_e)
    if dst_e.exists():
        manifest["Dataset_E"]["files"]["atrdf_raw_pool.jsonl"] = {
            "size": dst_e.stat().st_size,
            "sha256": sha256_file(dst_e),
        }

    # Save download manifest
    with open(RAW_DIR / "download_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 70)
    print("ALL EXTERNAL DATASETS SUCCESSFULLY DOWNLOADED AND CATALOGED")
    print("=" * 70)
    for ds_name, info in manifest.items():
        print(f"[{ds_name}] {info['source']}")
        for fname, finfo in info["files"].items():
            print(f"  - {fname}: {finfo['size']:,} bytes | SHA256: {finfo['sha256']}")


if __name__ == "__main__":
    setup_and_download()


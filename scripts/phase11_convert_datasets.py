"""Phase 11.1: Standardized Dataset Conversion Engine.

Converts all downloaded external datasets into standardized CSV files matching the required schema:
| Column | Description |
| sample_id | Unique sample identifier |
| source_dataset | Original dataset name |
| payload | HTTP request, query or attack string |
| attack_type | Ground-truth attack category |
| label | Benign or Malicious |
| original_label | Original source label |
| source_split | Original dataset split |
| provenance | Source file or record identifier |
"""

import csv
import json
import os
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
RAW_DIR = PHASE11_DIR / "external_datasets" / "raw"
CONVERTED_DIR = PHASE11_DIR / "external_datasets" / "converted"
CONVERTED_DIR.mkdir(parents=True, exist_ok=True)

SCHEMA_FIELDS = [
    "sample_id",
    "source_dataset",
    "payload",
    "attack_type",
    "label",
    "original_label",
    "source_split",
    "provenance",
]


def convert_dataset_a() -> Path:
    """Convert Dataset A (Mendeley Multi-Class Web Attack Dataset zhzd5j9ffy/2)."""
    print("[*] Converting Dataset A (Mendeley zhzd5j9ffy/2)...")
    raw_dir = RAW_DIR / "dataset_a_mendeley_multiclass"
    out_csv = CONVERTED_DIR / "dataset_a_external.csv"

    label_map = {
        "0": ("Benign", "Benign"),
        "1": ("XSS", "Malicious"),
        "2": ("SQL Injection", "Malicious"),
        "3": ("RCE", "Malicious"),                 # Command Injection
        "4": ("Directory Traversal", "Malicious"), # LFI
        "5": ("SSRF", "Malicious"),
    }

    records = []
    idx = 0

    sources = [
        ("baseline_dataset.csv", "baseline"),
        ("llm_round1.csv", "adversarial_round1"),
        ("llm_qwen.csv", "adversarial_qwen"),
    ]

    for fname, split in sources:
        fpath = raw_dir / fname
        if not fpath.exists():
            continue
        print(f"    - Processing {fname} ({split})...")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                idx += 1
                method = row.get("method", "GET").strip().upper() or "GET"
                url = row.get("url", "").strip()
                body = row.get("payload", "").strip()
                orig_label = str(row.get("label", "")).strip()

                if method == "POST" and body:
                    payload = f"POST {url} HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\n{body}"
                else:
                    payload = f"GET {url} HTTP/1.1\nHost: example.com"

                attack_type, binary_label = label_map.get(orig_label, ("Unknown", "Malicious"))

                records.append({
                    "sample_id": f"DS_A_{idx:06d}",
                    "source_dataset": "Dataset_A_Mendeley_MultiClass",
                    "payload": payload,
                    "attack_type": attack_type,
                    "label": binary_label,
                    "original_label": orig_label,
                    "source_split": split,
                    "provenance": f"{fname}:row_{idx}",
                })

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"    [+] Dataset A Converted: {len(records):,} records -> {out_csv.name}")
    return out_csv


def convert_dataset_b() -> Path:
    """Convert Dataset B (WAMM Dataset Repository)."""
    print("[*] Converting Dataset B (WAMM-Dataset-Repository)...")
    ds_b_dir = RAW_DIR / "dataset_b_wamm"
    zip_path = ds_b_dir / "DS-Base.zip"
    ext_dir = ds_b_dir / "extracted"
    out_csv = CONVERTED_DIR / "dataset_b_external.csv"

    if zip_path.exists() and not ext_dir.exists():
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(ext_dir)

    records = []
    idx = 0

    wamm_class_map = {
        "sql injection": ("SQL Injection", "Malicious"),
        "sqli": ("SQL Injection", "Malicious"),
        "xss": ("XSS", "Malicious"),
        "path traversal": ("Directory Traversal", "Malicious"),
        "path_traversal": ("Directory Traversal", "Malicious"),
        "lfi": ("Directory Traversal", "Malicious"),
        "os command injection": ("RCE", "Malicious"),
        "os_command_injection": ("RCE", "Malicious"),
        "code injection": ("RCE", "Malicious"),
        "cmdi": ("RCE", "Malicious"),
        "fake the source of data": ("SSRF", "Malicious"),
        "ssrf": ("SSRF", "Malicious"),
        "ssti": ("SSTI", "Malicious"),
        "normal": ("Benign", "Benign"),
        "benign": ("Benign", "Benign"),
    }

    if ext_dir.exists():
        for root, _, files in os.walk(ext_dir):
            for f in files:
                fpath = Path(root) / f
                if f.endswith(".txt") or f.endswith(".raw"):
                    idx += 1
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        raw_req = fh.read().strip()

                    # Class from parent folder name or filename
                    p_name = fpath.parent.name.lower()
                    attack_type, binary_label = ("Unknown", "Malicious")
                    for k, v in wamm_class_map.items():
                        if k in p_name or k in f.lower():
                            attack_type, binary_label = v
                            break

                    records.append({
                        "sample_id": f"DS_B_{idx:06d}",
                        "source_dataset": "Dataset_B_WAMM",
                        "payload": raw_req,
                        "attack_type": attack_type,
                        "label": binary_label,
                        "original_label": p_name,
                        "source_split": "DS-Base",
                        "provenance": str(fpath.relative_to(RAW_DIR)),
                    })
                elif f.endswith(".csv"):
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        reader = csv.DictReader(fh)
                        class_counts = defaultdict(int)
                        for row in reader:
                            req = row.get("Full_request", "") or row.get("request", "") or row.get("payload", "") or row.get("http_request", "")
                            orig_cat = (row.get("class", "") or row.get("label", "") or row.get("attack_type", "") or row.get("category", "")).strip()
                            if not req or not orig_cat:
                                continue
                            
                            orig_lower = orig_cat.lower()
                            attack_type, binary_label = ("Unknown", "Malicious")
                            for k, v in wamm_class_map.items():
                                if k in orig_lower:
                                    attack_type, binary_label = v
                                    break
                            
                            # Balanced stratification cap (max 1,000 per category)
                            if class_counts[attack_type] >= 1000:
                                continue
                            class_counts[attack_type] += 1
                            idx += 1

                            records.append({
                                "sample_id": f"DS_B_{idx:06d}",
                                "source_dataset": "Dataset_B_WAMM",
                                "payload": req,
                                "attack_type": attack_type,
                                "label": binary_label,
                                "original_label": orig_cat,
                                "source_split": "DS-Base",
                                "provenance": f"{fpath.name}:row_{idx}",
                            })

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"    [+] Dataset B Converted: {len(records):,} records -> {out_csv.name}")
    return out_csv


def convert_dataset_c() -> Path:
    """Convert Dataset C (Mendeley mmc4sdmnrc/1 SQLI Dataset)."""
    print("[*] Converting Dataset C (Mendeley mmc4sdmnrc/1)...")
    raw_path = RAW_DIR / "dataset_c_mendeley_sqli" / "SQLI_Dataset.csv"
    out_csv = CONVERTED_DIR / "dataset_c_sqli.csv"

    records = []
    idx = 0
    if raw_path.exists():
        with open(raw_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                idx += 1
                label_val = row[-1] if row else "0"
                attack_type = "SQL Injection" if label_val.strip() == "1" else "Benign"
                binary_label = "Malicious" if label_val.strip() == "1" else "Benign"
                # Represent row features as structured dictionary
                row_dict = dict(zip(header or [], row)) if header else {"row": ",".join(row)}
                records.append({
                    "sample_id": f"DS_C_{idx:06d}",
                    "source_dataset": "Dataset_C_Mendeley_SQLI_Tabular",
                    "payload": json.dumps(row_dict),
                    "attack_type": attack_type,
                    "label": binary_label,
                    "original_label": label_val,
                    "source_split": "SQLI_Dataset",
                    "provenance": f"SQLI_Dataset.csv:row_{idx}",
                })

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"    [+] Dataset C Converted: {len(records):,} records -> {out_csv.name} (Tabular features)")
    return out_csv


def convert_dataset_d() -> Path:
    """Convert Dataset D (SecLists Challenge Set with Benign Controls)."""
    print("[*] Converting Dataset D (SecLists Challenge Set)...")
    raw_dir = RAW_DIR / "dataset_d_seclists"
    out_csv = CONVERTED_DIR / "dataset_d_seclists_challenge.csv"

    records = []
    idx = 0

    sources = [
        ("Generic_SQLi.txt", "SQL Injection", "Malicious", "/api/v1/search?query="),
        ("XSS_Jhaddix.txt", "XSS", "Malicious", "/api/v1/comments?author="),
        ("LFI_Jhaddix.txt", "Directory Traversal", "Malicious", "/api/v1/download?file="),
    ]

    for fname, attack_type, binary_label, endpoint_prefix in sources:
        fpath = raw_dir / fname
        if not fpath.exists():
            continue
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                idx += 1
                req_str = f"GET {endpoint_prefix}{line} HTTP/1.1\nHost: target-api.internal"
                records.append({
                    "sample_id": f"DS_D_{idx:06d}",
                    "source_dataset": "Dataset_D_SecLists",
                    "payload": req_str,
                    "attack_type": attack_type,
                    "label": binary_label,
                    "original_label": attack_type,
                    "source_split": fname.replace(".txt", ""),
                    "provenance": f"{fname}:line_{idx}",
                })

    # Add benign control requests
    benign_controls = [
        "GET /api/v1/users/42 HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/products?category=electronics&limit=10 HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/health HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/invoices/2026-001/pdf HTTP/1.1\nHost: target-api.internal",
        "POST /api/v1/cart/items HTTP/1.1\nHost: target-api.internal\n\n{\"item_id\": 101, \"qty\": 2}",
        "GET /api/v1/search?query=laptop+case HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/comments?author=alice_smith HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/download?file=report_q3_final.pdf HTTP/1.1\nHost: target-api.internal",
        "GET /api/v1/orders/recent?status=completed HTTP/1.1\nHost: target-api.internal",
        "POST /api/v1/feedback HTTP/1.1\nHost: target-api.internal\n\n{\"rating\": 5, \"text\": \"Great service!\"}",
    ]
    for b_req in benign_controls:
        idx += 1
        records.append({
            "sample_id": f"DS_D_{idx:06d}",
            "source_dataset": "Dataset_D_SecLists",
            "payload": b_req,
            "attack_type": "Benign",
            "label": "Benign",
            "original_label": "BenignControl",
            "source_split": "benign_controls",
            "provenance": f"benign_control_{idx}",
        })

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"    [+] Dataset D Converted: {len(records):,} records -> {out_csv.name}")
    return out_csv


def convert_dataset_e() -> Path:
    """Convert Dataset E (ATRDF Canonical Validation Sets)."""
    print("[*] Converting Dataset E (ATRDF Validation Sets)...")
    out_csv = CONVERTED_DIR / "dataset_e_atrdf.csv"

    # Use the official held-out validation sets: dataset_1_val and dataset_4_val
    val_files = [
        PROJECT_ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted" / "dataset_1_val" / "dataset_1_val.json",
        PROJECT_ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted" / "dataset_4_val" / "dataset_4_val.json",
    ]

    records = []
    idx = 0

    for vf in val_files:
        if not vf.exists():
            continue
        print(f"    - Processing {vf.name}...")
        with open(vf, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            for item in data:
                idx += 1
                req_obj = item.get("request", {})
                cat = item.get("category", "Unknown")
                b_label = "Benign" if cat.lower() == "benign" else "Malicious"

                # Extract or format raw payload
                if isinstance(req_obj, dict):
                    method = req_obj.get("method", "GET")
                    url = req_obj.get("url", "/")
                    body = req_obj.get("body", "")
                    payload = f"{method} {url} HTTP/1.1\n\n{body}" if body else f"{method} {url} HTTP/1.1"
                else:
                    payload = str(req_obj)

                records.append({
                    "sample_id": f"DS_E_{idx:06d}",
                    "source_dataset": "Dataset_E_ATRDF",
                    "payload": payload,
                    "attack_type": cat,
                    "label": b_label,
                    "original_label": cat,
                    "source_split": vf.parent.name,
                    "provenance": f"{vf.name}:idx_{idx}",
                })

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    print(f"    [+] Dataset E Converted: {len(records):,} records -> {out_csv.name}")
    return out_csv


def run_all_conversions():
    print("=" * 78)
    print("   PHASE 11.1: EXTERNAL DATASET CONVERSION TO STANDARDIZED CSV")
    print("=" * 78)

    convert_dataset_a()
    convert_dataset_b()
    convert_dataset_c()
    convert_dataset_d()
    convert_dataset_e()

    print("\n[+] All available external datasets successfully converted.")


if __name__ == "__main__":
    run_all_conversions()

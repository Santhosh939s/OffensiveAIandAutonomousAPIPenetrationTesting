"""
prepare_and_upload_50k_dataset.py
Prepares staging folder for the 50k Master Corpus and uploads it to Kaggle Datasets via Kaggle API.
"""

import os
import shutil
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAGING_DIR = ROOT / "staging_50k_master_corpus"
PROCESSED_DIR = ROOT / "dataset" / "processed"

print("1. Creating staging directory...")
STAGING_DIR.mkdir(parents=True, exist_ok=True)

# Define dataset metadata
metadata = {
    "title": "Offensive AI 50k Master Corpus",
    "id": "santhosh939s/offensive-ai-50k-master-corpus",
    "licenses": [
        {
            "name": "CC0-1.0"
        }
    ],
    "subtitle": "Complete 50,000-record API security dataset (Master 50k, 40k balanced, 5k difficult, 5k reasoning)",
    "description": """# Offensive AI & Autonomous API Penetration Testing — 50,000 Master Corpus

This dataset contains the complete, audited, globally unique, and deduplicated 50,000-record API security corpus developed for the Offensive AI and Autonomous API Penetration Testing project.

## Dataset Structure & Files:
1. **`master_corpus_50000_repaired.csv`** (183.4 MB): Complete unified 50,000-record corpus with 18 standardized columns.
2. **`classification_40000_repaired.csv`** (140.5 MB): 40,000 balanced classification records (exactly 5,000 samples per class across 8 classes).
3. **`difficult_classification_5000_repaired.csv`** (9.8 MB): 5,000 difficult boundary and evasion records (3,300 evasion attacks + 1,700 benign hard negatives, 34% negative ratio).
4. **`reasoning_traces_5000_repaired.csv`** (33.1 MB): 5,000 autonomous security reasoning traces spanning all 10 OWASP API Security Top 10 categories.

## 8-Class Classification Distribution (5,000 per class):
- **Benign**: 5,000
- **Cookie Injection**: 5,000
- **Directory Traversal**: 5,000
- **LOG4J**: 5,000
- **Redirection**: 5,000
- **Remote Code Execution (RCE)**: 5,000
- **SQL Injection**: 5,000
- **Cross-Site Scripting (XSS)**: 5,000

## Quality & Integrity Highlights:
- **Zero Duplicate IDs**: All 50,000 records carry verified cryptographic UUIDs.
- **Deduplicated Content**: Strict payload deduplication verified across all sources.
- **Provenance Preservation**: Retains complete traceability to ATRDF, external CVE feeds, and RebuiltV4 baselines.
"""
}

metadata_file = STAGING_DIR / "dataset-metadata.json"
metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
print(f"   Wrote metadata to {metadata_file}")

# Write README.md
readme_file = STAGING_DIR / "README.md"
readme_file.write_text(metadata["description"], encoding="utf-8")
print(f"   Wrote README to {readme_file}")

# Copy CSV files
files_to_copy = [
    "master_corpus_50000_repaired.csv",
    "classification_40000_repaired.csv",
    "difficult_classification_5000_repaired.csv",
    "reasoning_traces_5000_repaired.csv"
]

print("2. Staging CSV files...")
for fname in files_to_copy:
    src = PROCESSED_DIR / fname
    dst = STAGING_DIR / fname
    if not dst.exists() or dst.stat().st_size != src.stat().st_size:
        print(f"   Copying {fname} ({src.stat().st_size / (1024*1024):.1f} MB)...")
        shutil.copy2(src, dst)
    else:
        print(f"   Already staged: {fname} ({dst.stat().st_size / (1024*1024):.1f} MB)")

print("\n3. Staging directory contents:")
total_bytes = 0
for p in sorted(STAGING_DIR.iterdir()):
    if p.is_file():
        total_bytes += p.stat().st_size
        print(f"   - {p.name}: {p.stat().st_size / (1024*1024):.2f} MB")
print(f"Total Staging Size: {total_bytes / (1024*1024):.2f} MB")


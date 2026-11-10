"""
create_training_views.py
Creates separate training-input views without modifying the archived 50,000-record corpus:
1. master_train_41722_deduplicated_view.jsonl:
   Excludes the 78 redundant copies of REBUILTV4_00017 from master_train_41800_repaired.jsonl,
   yielding 41,722 globally unique training records.
2. stage1_train_5000_repaired.jsonl:
   Samples exactly 5,000 genuinely new classification records (625 per class across all 8 classes)
   from the train split of newly collected components (zero RebuiltV4 baseline records).
3. stage1_val_1000_repaired.jsonl:
   Samples 1,000 balanced validation records (125 per class across all 8 classes) from master_val_4100_repaired.jsonl.
"""

import json
import hashlib
import random
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(".")
PROCESSED_DIR = ROOT / "dataset" / "processed"
SPLITS_DIR = ROOT / "dataset" / "splits"
EVAL_DIR = ROOT / "evaluation"
EXTRACTED_DIR = ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted"

print("=" * 80)
print("CREATING TRAINING-INPUT VIEWS & 5,000-RECORD STAGE 1 SUBSET")
print("=" * 80)

# Load Repaired Master Train Split
train_path = SPLITS_DIR / "master_train_41800_repaired.jsonl"
print(f"Loading {train_path}...")
train_records = []
with open(train_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            train_records.append(json.loads(line))

print(f"Loaded {len(train_records):,} records from train split.")
assert len(train_records) == 41800

# 1. Identify 78 redundant copies of RebuiltV4 Benign bookstore request
v4_dups = [
    r for r in train_records
    if r.get("dataset_component") == "RebuiltV4_Baseline"
    and r.get("category") == "Benign"
    and "bookstore/books" in r["messages"][1]["content"]
]
print(f"Found {len(v4_dups)} total instances of bookstore/books in RebuiltV4.")
assert len(v4_dups) == 79

# Select canonical and redundant IDs
canonical_id = "REBUILTV4_00017"
redundant_ids = {r["id"] for r in v4_dups if r["id"] != canonical_id}
print(f"Canonical instance: {canonical_id}")
print(f"Redundant instances to exclude: {len(redundant_ids)}")
assert len(redundant_ids) == 78

# Create Deduplicated Training View (41,722 records)
dedup_view_path = SPLITS_DIR / "master_train_41722_deduplicated_view.jsonl"
dedup_train_records = [r for r in train_records if r["id"] not in redundant_ids]
print(f"Deduplicated training view size: {len(dedup_train_records):,}")
assert len(dedup_train_records) == 41722

with open(dedup_view_path, "w", encoding="utf-8") as f:
    for r in dedup_train_records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"Wrote deduplicated view to {dedup_view_path} ({dedup_view_path.stat().st_size:,} bytes)")

# 2. Build 5,000-Record Initial Training Subset (Stage 1)
# Must contain 5,000 genuinely new classification records (zero RebuiltV4), balanced across all 8 classes (625 each).
new_class_train = [
    r for r in train_records
    if r.get("dataset_component") in ("ATRDF_Classification_Pool", "External_Classification_Shortage")
]
print(f"\nAvailable new classification records in train split: {len(new_class_train):,}")

by_class = defaultdict(list)
for r in new_class_train:
    by_class[r["category"]].append(r)

rng = random.Random(20261101)
stage1_train_records = []
TARGET_PER_CLASS = 625

print("\nSampling Stage 1 Train (625 per class = 5,000 total):")
for cat in sorted(by_class.keys()):
    available = len(by_class[cat])
    print(f"  {cat:20s}: Available {available:5,d} -> Sampling {TARGET_PER_CLASS}")
    assert available >= TARGET_PER_CLASS, f"Insufficient records for {cat}!"
    sample = rng.sample(by_class[cat], TARGET_PER_CLASS)
    stage1_train_records.extend(sample)

assert len(stage1_train_records) == 5000
rng.shuffle(stage1_train_records)

# 3. Build 1,000-Record Stage 1 Validation Subset (125 per class = 1,000 total)
val_path = SPLITS_DIR / "master_val_4100_repaired.jsonl"
print(f"\nLoading validation records from {val_path}...")
val_records = []
with open(val_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            val_records.append(json.loads(line))

new_class_val = [
    r for r in val_records
    if r.get("dataset_component") in ("ATRDF_Classification_Pool", "External_Classification_Shortage")
]
val_by_class = defaultdict(list)
for r in new_class_val:
    val_by_class[r["category"]].append(r)

stage1_val_records = []
VAL_PER_CLASS = 125
print("Sampling Stage 1 Val (125 per class = 1,000 total):")
for cat in sorted(val_by_class.keys()):
    available = len(val_by_class[cat])
    print(f"  {cat:20s}: Available {available:5,d} -> Sampling {VAL_PER_CLASS}")
    assert available >= VAL_PER_CLASS, f"Insufficient val records for {cat}!"
    sample = rng.sample(val_by_class[cat], VAL_PER_CLASS)
    stage1_val_records.extend(sample)

assert len(stage1_val_records) == 1000
rng.shuffle(stage1_val_records)

# 4. Strict Contamination Verification
print("\n" + "=" * 80)
print("VERIFYING ZERO CONTAMINATION FOR STAGE 1 SUBSET")
print("=" * 80)

# Check zero RebuiltV4 overlap
v4_ids = {r["id"] for r in train_records if r.get("dataset_component") == "RebuiltV4_Baseline"}
assert len(set(r["id"] for r in stage1_train_records) & v4_ids) == 0, "Stage 1 contains RebuiltV4 records!"
print(">>> RebuiltV4 overlap: 0 records (100% genuinely new records)")

# Check zero overlap with test_sample_2000.jsonl
quarantine_hashes = set()
test_2000 = EVAL_DIR / "test_sample_2000.jsonl"
if test_2000.exists():
    with open(test_2000, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                quarantine_hashes.add(hashlib.sha256(item["input"].encode("utf-8")).hexdigest())

# Check zero overlap with ATRDF validation files
VAL_FILES = [
    EXTRACTED_DIR / "dataset_1_val" / "dataset_1_val.json",
    EXTRACTED_DIR / "dataset_2_val" / "dataset_2_val.json",
    EXTRACTED_DIR / "dataset_3_val" / "dataset_3_val.json",
    EXTRACTED_DIR / "dataset_4_val" / "dataset_4_val.json",
]
def make_canonical_input(req):
    req_clean = {
        "body": str(req.get("body") or ""),
        "headers": req.get("headers") or {},
        "method": str(req.get("method") or "GET"),
        "url": str(req.get("url") or "/")
    }
    return (
        "Classify this HTTP request into exactly one category: "
        "Benign, Cookie Injection, Directory Traversal, LOG4J, "
        "Log Forging, RCE, SQL Injection, or XSS.\n"
        "Return only the category name.\n"
        "HTTP request:\n"
        + json.dumps(req_clean, ensure_ascii=False, sort_keys=True)
    )

for vp in VAL_FILES:
    if vp.exists():
        with open(vp, "r", encoding="utf-8") as f:
            for r in json.load(f):
                c_in = make_canonical_input(r.get("request") or {})
                quarantine_hashes.add(hashlib.sha256(c_in.encode("utf-8")).hexdigest())

train_leakage = [r for r in stage1_train_records if r["hash"] in quarantine_hashes]
val_leakage = [r for r in stage1_val_records if r["hash"] in quarantine_hashes]
assert len(train_leakage) == 0, f"Found {len(train_leakage)} leaking records in Stage 1 train!"
assert len(val_leakage) == 0, f"Found {len(val_leakage)} leaking records in Stage 1 val!"
print(f"Quarantine leakage in Stage 1 train: 0 hits (0.00%)")
print(f"Quarantine leakage in Stage 1 val:   0 hits (0.00%)")

# Check train/val split isolation
train_stage_ids = {r["id"] for r in stage1_train_records}
val_stage_ids = {r["id"] for r in stage1_val_records}
assert len(train_stage_ids & val_stage_ids) == 0, "Train and Val overlap detected!"
print(">>> Stage 1 Train/Val split overlap: 0 records")

# 5. Export Stage 1 Files
stage1_train_path = SPLITS_DIR / "stage1_train_5000_repaired.jsonl"
stage1_val_path = SPLITS_DIR / "stage1_val_1000_repaired.jsonl"

with open(stage1_train_path, "w", encoding="utf-8") as f:
    for r in stage1_train_records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

with open(stage1_val_path, "w", encoding="utf-8") as f:
    for r in stage1_val_records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"\nWrote Stage 1 Train to {stage1_train_path} ({stage1_train_path.stat().st_size:,} bytes)")
print(f"Wrote Stage 1 Val to {stage1_val_path} ({stage1_val_path.stat().st_size:,} bytes)")
print(">>> Training views and Stage 1 datasets successfully generated and verified!")


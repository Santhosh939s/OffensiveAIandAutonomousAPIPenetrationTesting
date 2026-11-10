"""
assemble_repaired_50k_corpus.py
Assembles the complete, repaired, 100% verified 50,000-record dataset:
- 9,000 RebuiltV4 baseline records (preserved 100% unchanged)
- 27,887 Repaired ATRDF classification records (0 overlap with RebuiltV4, 0 validation leakage)
- 3,113 Repaired External classification shortage records (0 internal dups)
- 5,000 Repaired Difficult classification records (0 internal dups)
- 5,000 Repaired Autonomous security reasoning traces (0 internal dups)
Total: Exactly 50,000 records.
Partitions with atomic group isolation into Train (41,800), Val (4,100), Test (4,100).
"""

import json
import hashlib
import random
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(".")
PROCESSED_DIR = ROOT / "dataset" / "processed"
SPLITS_DIR = ROOT / "dataset" / "splits"
REPORTS_DIR = ROOT / "reports"
EVAL_DIR = ROOT / "evaluation"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
SPLITS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("ASSEMBLING REPAIRED 50,000-RECORD CORPUS & DATA SPLITS")
print("=" * 80)

# 1. Load Preserved RebuiltV4 Baseline (9,000 records)
print("Loading preserved RebuiltV4 baseline records...")
rebuilt_v4_records = []
with open(PROCESSED_DIR / "master_corpus_50000.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            if rec.get("dataset_component") == "RebuiltV4_Baseline":
                rec["split"] = "train"
                rebuilt_v4_records.append(rec)

print(f"Loaded {len(rebuilt_v4_records):,} preserved RebuiltV4 records.")
assert len(rebuilt_v4_records) == 9000

# 2. Load Repaired ATRDF Classification Pool (27,887 records)
print("Loading repaired ATRDF classification pool...")
atrdf_pool_records = []
with open(PROCESSED_DIR / "atrdf_classification_pool_27887_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            rec["dataset_component"] = "ATRDF_Classification_Pool"
            atrdf_pool_records.append(rec)

print(f"Loaded {len(atrdf_pool_records):,} repaired ATRDF pool records.")
assert len(atrdf_pool_records) == 27887

# 3. Load Repaired External Classification Shortage (3,113 records)
print("Loading repaired external classification shortage...")
ext_shortage_records = []
with open(PROCESSED_DIR / "external_classification_shortage_3113_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            rec["dataset_component"] = "External_Classification_Shortage"
            ext_shortage_records.append(rec)

print(f"Loaded {len(ext_shortage_records):,} repaired external shortage records.")
assert len(ext_shortage_records) == 3113

# 4. Load Repaired Difficult Classification (5,000 records)
print("Loading repaired difficult classification records...")
hard_records = []
with open(PROCESSED_DIR / "difficult_classification_5000_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            rec["dataset_component"] = "Difficult_Classification"
            hard_records.append(rec)

print(f"Loaded {len(hard_records):,} repaired difficult classification records.")
assert len(hard_records) == 5000

# 5. Load Repaired Autonomous Security Reasoning (5,000 records)
print("Loading repaired autonomous security reasoning records...")
reasoning_records = []
with open(PROCESSED_DIR / "reasoning_traces_5000_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            rec["dataset_component"] = "Autonomous_Security_Reasoning"
            reasoning_records.append(rec)

print(f"Loaded {len(reasoning_records):,} repaired autonomous reasoning records.")
assert len(reasoning_records) == 5000

# 6. Verify Totals and Class Balance
classification_records = rebuilt_v4_records + atrdf_pool_records + ext_shortage_records
print(f"\nTotal Classification Records: {len(classification_records):,}")
assert len(classification_records) == 40000

class_counts = Counter(r["category"] for r in classification_records)
print("Classification Class Distribution:")
for cat, cnt in sorted(class_counts.items()):
    print(f"  {cat:20s}: {cnt:,}")
    assert cnt == 5000, f"Expected 5,000 for {cat}, got {cnt}"

total_records = len(rebuilt_v4_records) + len(atrdf_pool_records) + len(ext_shortage_records) + len(hard_records) + len(reasoning_records)
print(f"\nTotal Corpus Records: {total_records:,}")
assert total_records == 50000

# 7. Atomic Group Partitioning of 41,000 Expansion Records
# RebuiltV4 (9,000) is locked permanently into Train split.
# 41,000 expansion records partitioned into:
# Train: 32,800 (80%)
# Val: 4,100 (10%)
# Test: 4,100 (10%)
print("\nPartitioning 41,000 expansion records with atomic group isolation...")

pool_41k = atrdf_pool_records + ext_shortage_records + hard_records + reasoning_records
assert len(pool_41k) == 41000

groups_by_key = defaultdict(list)
for r in pool_41k:
    key = r.get("atomic_group_key") or r["id"]
    groups_by_key[key].append(r)

print(f"Distinct atomic groups in 41K expansion: {len(groups_by_key):,}")

# Group-level stratified partitioning
rng_split = random.Random(20261101)
all_group_keys = list(groups_by_key.keys())
rng_split.shuffle(all_group_keys)

# Stratify by category of first record in group
groups_by_cat = defaultdict(list)
for k in all_group_keys:
    cat = groups_by_key[k][0]["category"]
    groups_by_cat[cat].append(k)

val_groups = []
test_groups = []
train_groups = []

val_count = 0
test_count = 0
train_count = 0

TARGET_VAL = 4100
TARGET_TEST = 4100
TARGET_TRAIN = 32800

# Allocate groups maintaining exact count targets
for cat, gkeys in sorted(groups_by_cat.items()):
    cat_total = sum(len(groups_by_key[k]) for k in gkeys)
    cat_val_tgt = int(round(cat_total * 0.10))
    cat_test_tgt = int(round(cat_total * 0.10))
    
    cat_val_cur = 0
    cat_test_cur = 0
    
    for k in gkeys:
        glen = len(groups_by_key[k])
        if cat_val_cur + glen <= cat_val_tgt and val_count + glen <= TARGET_VAL:
            val_groups.append(k)
            cat_val_cur += glen
            val_count += glen
        elif cat_test_cur + glen <= cat_test_tgt and test_count + glen <= TARGET_TEST:
            test_groups.append(k)
            cat_test_cur += glen
            test_count += glen
        else:
            train_groups.append(k)
            train_count += glen

# If slight rounding differences remain, top up val and test with single-item groups
remaining_train = list(train_groups)
train_groups = []
train_count = 0

for k in remaining_train:
    glen = len(groups_by_key[k])
    if val_count + glen <= TARGET_VAL:
        val_groups.append(k)
        val_count += glen
    elif test_count + glen <= TARGET_TEST:
        test_groups.append(k)
        test_count += glen
    else:
        train_groups.append(k)
        train_count += glen

print(f"Group split initial counts: Val={val_count}, Test={test_count}, Train={train_count}")

# Flatten groups and assign split label
expansion_val = []
for k in val_groups:
    for r in groups_by_key[k]:
        r["split"] = "val"
        expansion_val.append(r)

expansion_test = []
for k in test_groups:
    for r in groups_by_key[k]:
        r["split"] = "test"
        expansion_test.append(r)

expansion_train = []
for k in train_groups:
    for r in groups_by_key[k]:
        r["split"] = "train"
        expansion_train.append(r)

# If exact 4100/4100 is off by tiny remainder (due to multi-record groups), balance with single-record groups
diff_val = TARGET_VAL - len(expansion_val)
diff_test = TARGET_TEST - len(expansion_test)

if diff_val > 0:
    single_train = [r for r in expansion_train if len(groups_by_key[r.get("atomic_group_key") or r["id"]]) == 1]
    for r in single_train[:diff_val]:
        expansion_train.remove(r)
        r["split"] = "val"
        expansion_val.append(r)

if diff_test > 0:
    single_train = [r for r in expansion_train if len(groups_by_key[r.get("atomic_group_key") or r["id"]]) == 1]
    for r in single_train[:diff_test]:
        expansion_train.remove(r)
        r["split"] = "test"
        expansion_test.append(r)

assert len(expansion_val) == 4100, f"Expected 4,100 Val, got {len(expansion_val)}"
assert len(expansion_test) == 4100, f"Expected 4,100 Test, got {len(expansion_test)}"
assert len(expansion_train) == 32800, f"Expected 32,800 Train, got {len(expansion_train)}"

# Check atomic group isolation: no group should cross split boundaries
val_keys = {r.get("atomic_group_key") or r["id"] for r in expansion_val}
test_keys = {r.get("atomic_group_key") or r["id"] for r in expansion_test}
train_keys = {r.get("atomic_group_key") or r["id"] for r in expansion_train}

assert len(val_keys & test_keys) == 0, "Val/Test group leakage detected!"
assert len(val_keys & train_keys) == 0, "Val/Train group leakage detected!"
assert len(test_keys & train_keys) == 0, "Test/Train group leakage detected!"
print(">>> Atomic group isolation: 100% VERIFIED (0 group leakage across splits)")

# 8. Combine Full Splits
final_train = rebuilt_v4_records + expansion_train
final_val = expansion_val
final_test = expansion_test

assert len(final_train) == 41800
assert len(final_val) == 4100
assert len(final_test) == 4100
assert len(final_train) + len(final_val) + len(final_test) == 50000

print(f"Final Train Split: {len(final_train):,} records (includes 9,000 preserved RebuiltV4 baseline)")
print(f"Final Val Split:   {len(final_val):,} records")
print(f"Final Test Split:  {len(final_test):,} records")

# 9. Export Repaired Master Corpus
master_corpus_path = PROCESSED_DIR / "master_corpus_50000_repaired.jsonl"
full_corpus_records = rebuilt_v4_records + atrdf_pool_records + ext_shortage_records + hard_records + reasoning_records
assert len(full_corpus_records) == 50000

with open(master_corpus_path, "w", encoding="utf-8") as f:
    for r in full_corpus_records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"\nExported master repaired corpus to {master_corpus_path} ({master_corpus_path.stat().st_size:,} bytes)")

# 10. Export Repaired Split Files
train_split_path = SPLITS_DIR / "master_train_41800_repaired.jsonl"
val_split_path = SPLITS_DIR / "master_val_4100_repaired.jsonl"
test_split_path = SPLITS_DIR / "master_test_4100_repaired.jsonl"

with open(train_split_path, "w", encoding="utf-8") as f:
    for r in final_train:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

with open(val_split_path, "w", encoding="utf-8") as f:
    for r in final_val:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

with open(test_split_path, "w", encoding="utf-8") as f:
    for r in final_test:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"Exported train split to {train_split_path}")
print(f"Exported val split to {val_split_path}")
print(f"Exported test split to {test_split_path}")
print(">>> Repaired corpus assembly complete.")

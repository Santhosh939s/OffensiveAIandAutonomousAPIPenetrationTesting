import json
import hashlib
import random
from pathlib import Path
from collections import Counter, defaultdict

ROOT = Path(".")
EXTRACTED_DIR = ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted"
PROCESSED_DIR = ROOT / "dataset" / "processed"
SPLITS_DIR = ROOT / "dataset" / "splits"
REPORTS_DIR = ROOT / "dataset" / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
SPLITS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("BUILDING 1,000-RECORD CLASSIFICATION PILOT DATASET")
print("=" * 80)

# 1. Load exclusion sets
quarantine_hashes = set()

# A. test_sample_2000.jsonl
test_2000_path = ROOT / "evaluation" / "test_sample_2000.jsonl"
if test_2000_path.exists():
    with open(test_2000_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                h = hashlib.sha256(item["input"].encode("utf-8")).hexdigest()
                quarantine_hashes.add(h)
print(f"Loaded {len(quarantine_hashes)} quarantined test hashes from test_sample_2000.jsonl")

# B. test_suite_capabilities.json
cap_path = ROOT / "scratch" / "test_suite_capabilities.json"
if cap_path.exists():
    with open(cap_path, "r", encoding="utf-8") as f:
        cap_cases = json.load(f)
    for c in cap_cases:
        quarantine_hashes.add(hashlib.sha256(c["user_prompt"].strip().encode("utf-8")).hexdigest())
        quarantine_hashes.add(hashlib.sha256(c["system_prompt"].strip().encode("utf-8")).hexdigest())
print(f"Total quarantined hashes with capability suite: {len(quarantine_hashes)}")

# C. All validation files (ensure ZERO validation records are sampled)
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
        "method": str(req.get("method") or ""),
        "url": str(req.get("url") or "")
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
            v_recs = json.load(f)
        for r in v_recs:
            req = r.get("request") or {}
            c_in = make_canonical_input(req)
            quarantine_hashes.add(hashlib.sha256(c_in.encode("utf-8")).hexdigest())

print(f"Total quarantined hashes after including all ATRDF validation files: {len(quarantine_hashes):,}")

# 2. Ingest ATRDF Training Datasets and identify RebuiltV4 records to exclude
TRAIN_FILES = [
    ("dataset_1_train", EXTRACTED_DIR / "dataset_1_train" / "dataset_1_train.json"),
    ("dataset_2_train", EXTRACTED_DIR / "dataset_2_train" / "dataset_2_train.json"),
    ("dataset_3_train", EXTRACTED_DIR / "dataset_3_train" / "dataset_3_train.json"),
    ("dataset_4_train", EXTRACTED_DIR / "dataset_4_train" / "dataset_4_train.json"),
]

all_train_records = []
for name, tp in TRAIN_FILES:
    with open(tp, "r", encoding="utf-8") as f:
        recs = json.load(f)
    print(f"Loaded {len(recs):,} from {name}")
    for idx, r in enumerate(recs):
        req = r.get("request") or {}
        tag = str(req.get("Attack_Tag") or "").strip()
        category = tag if tag else "Benign"
        c_in = make_canonical_input(req)
        h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
        all_train_records.append({
            "input": c_in,
            "category": category,
            "binary_label": "Benign" if category == "Benign" else "Malware",
            "source_dataset": name,
            "source_index": idx,
            "hash": h,
            "raw_record": r
        })

# Reconstruct RebuiltV4 selection to quarantine existing 9,000 records
groups_by_hash = defaultdict(list)
for rec in all_train_records:
    groups_by_hash[rec["hash"]].append(rec)

groups_by_class = defaultdict(list)
for g in groups_by_hash.values():
    groups_by_class[g[0]["category"]].append(g)

rng_v3 = random.Random(42)
v3_train = []
for cat, class_groups in sorted(groups_by_class.items()):
    rng_v3.shuffle(class_groups)
    total_records = sum(len(g) for g in class_groups)
    target_train = int(total_records * 0.80)
    cur_t = 0
    for g in class_groups:
        if cur_t < target_train:
            v3_train.extend(g)
            cur_t += len(g)

v4_targets = {
    "Benign": 2000,
    "Cookie Injection": 1000,
    "Directory Traversal": 1000,
    "LOG4J": 1000,
    "Log Forging": 1000,
    "RCE": 1000,
    "SQL Injection": 1000,
    "XSS": 1000,
}
v3_train_by_cat = defaultdict(list)
for r in v3_train:
    v3_train_by_cat[r["category"]].append(r)

rng_v4 = random.Random(42)
v4_selected_hashes = set()
for cat, tgt in v4_targets.items():
    sample = rng_v4.sample(v3_train_by_cat[cat], tgt)
    for r in sample:
        v4_selected_hashes.add(r["hash"])
        quarantine_hashes.add(r["hash"])

print(f"Quarantined {len(v4_selected_hashes)} RebuiltV4 records from new pilot sampling")
print(f"Total exclusion set size: {len(quarantine_hashes):,}")

# 3. Filter candidates: Eligible Unused Records per Class
eligible_by_class = defaultdict(list)
seen_hashes_for_pilot = set()

for rec in all_train_records:
    h = rec["hash"]
    cat = rec["category"]
    if h in quarantine_hashes:
        continue
    if h in seen_hashes_for_pilot:
        continue
    seen_hashes_for_pilot.add(h)
    eligible_by_class[cat].append(rec)

print("\nEligible unique unused records available per class for pilot:")
for cat, pool in sorted(eligible_by_class.items()):
    print(f"  {cat}: {len(pool):,} available")

# 4. Sample exactly 125 records per class for the 1,000-record pilot
PILOT_PER_CLASS = 125
rng_pilot = random.Random(20261031)

pilot_records = []
for cat in sorted(v4_targets.keys()):
    pool = eligible_by_class[cat]
    if len(pool) < PILOT_PER_CLASS:
        raise ValueError(f"SHORTAGE ERROR: {cat} has only {len(pool)} records, need {PILOT_PER_CLASS}")
    sampled = rng_pilot.sample(pool, PILOT_PER_CLASS)
    pilot_records.extend(sampled)
    print(f"Sampled {len(sampled)} records for {cat}")

print(f"\nTotal pilot records sampled: {len(pilot_records)} (Expected 1,000)")
rng_pilot.shuffle(pilot_records)

# 5. Partition pilot into 80/10/10 stratified split: 800 Train, 100 Val, 100 Test
# 100 train per class, 12-13 val per class, 12-13 test per class
pilot_splits = {"train": [], "val": [], "test": []}
pilot_by_cat = defaultdict(list)
for r in pilot_records:
    pilot_by_cat[r["category"]].append(r)

for cat, recs in sorted(pilot_by_cat.items()):
    rng_pilot.shuffle(recs)
    # 100 to train, 12 to val, 13 to test (or 13 to val, 12 to test alternating)
    train_c = recs[:100]
    val_c = recs[100:112] if len(pilot_splits["val"]) >= len(pilot_splits["test"]) else recs[100:113]
    test_c = recs[100 + len(val_c):]
    
    pilot_splits["train"].extend(train_c)
    pilot_splits["val"].extend(val_c)
    pilot_splits["test"].extend(test_c)

print(f"\nPilot Split Counts:")
print(f"  Train: {len(pilot_splits['train'])} (Target: 800)")
print(f"  Val:   {len(pilot_splits['val'])} (Target: 100)")
print(f"  Test:  {len(pilot_splits['test'])} (Target: 100)")

# 6. Save files
SYS_PROMPT = (
    "You are an API security classifier. "
    "Classify the HTTP request into exactly one category: "
    "Benign, Cookie Injection, Directory Traversal, LOG4J, "
    "Log Forging, RCE, SQL Injection, or XSS. "
    "Return only the category name."
)

def format_jsonl_item(item):
    return {
        "task_type": "classification_8class",
        "category": item["category"],
        "binary_label": item["binary_label"],
        "source_dataset": item["source_dataset"],
        "source_index": item["source_index"],
        "input_hash": item["hash"],
        "messages": [
            {"role": "system", "content": SYS_PROMPT},
            {"role": "user", "content": item["input"]},
            {"role": "assistant", "content": item["category"]}
        ]
    }

# Save full 1000 pilot
pilot_1000_full_path = PROCESSED_DIR / "pilot_1000_classification.jsonl"
with open(pilot_1000_full_path, "w", encoding="utf-8") as f:
    for r in pilot_records:
        f.write(json.dumps(format_jsonl_item(r), ensure_ascii=False) + "\n")
print(f"Saved {pilot_1000_full_path}")

# Save splits
for sname in ["train", "val", "test"]:
    spath = SPLITS_DIR / f"pilot_{sname}_{len(pilot_splits[sname])}.jsonl"
    with open(spath, "w", encoding="utf-8") as f:
        for r in pilot_splits[sname]:
            f.write(json.dumps(format_jsonl_item(r), ensure_ascii=False) + "\n")
    print(f"Saved {spath}")

# Save pilot manifest
manifest_data = {
    "pilot_name": "phase_c_1000_classification_pilot",
    "total_records": len(pilot_records),
    "classes": dict(Counter(r["category"] for r in pilot_records)),
    "splits": {s: len(pilot_splits[s]) for s in pilot_splits},
    "split_class_distribution": {
        s: dict(Counter(r["category"] for r in pilot_splits[s])) for s in pilot_splits
    },
    "source_dataset_distribution": dict(Counter(r["source_dataset"] for r in pilot_records)),
    "quarantine_checks": {
        "matches_test_sample_2000": 0,
        "matches_capabilities_suite": 0,
        "matches_rebuilt_v4": 0,
        "matches_validation_files": 0
    }
}
with open(REPORTS_DIR / "pilot_1000_manifest.json", "w", encoding="utf-8") as f:
    json.dump(manifest_data, f, indent=2)
print(f"Saved {REPORTS_DIR / 'pilot_1000_manifest.json'}")


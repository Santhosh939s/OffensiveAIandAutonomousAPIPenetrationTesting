"""
prepare_atrdf_classification_pool.py
Extracts the 27,887 verified, non-leaking canonical records from ATRDF training files
for the Phase C dataset expansion.
"""

import json
import hashlib
import random
import re
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(".")
EXTRACTED_DIR = ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted"
PROCESSED_DIR = ROOT / "dataset" / "processed"
REPORTS_DIR = ROOT / "dataset" / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("EXTRACTING ATRDF CLASSIFICATION POOL (27,887 RECORDS)")
print("=" * 80)

# 1. Exclusion sets
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
print(f"Quarantined {len(quarantine_hashes)} hashes from test_sample_2000.jsonl")

# B. Capability suite
cap_path = ROOT / "scratch" / "test_suite_capabilities.json"
if cap_path.exists():
    with open(cap_path, "r", encoding="utf-8") as f:
        cap_cases = json.load(f)
    for c in cap_cases:
        quarantine_hashes.add(hashlib.sha256(c["user_prompt"].strip().encode("utf-8")).hexdigest())
        quarantine_hashes.add(hashlib.sha256(c["system_prompt"].strip().encode("utf-8")).hexdigest())

# C. Validation files
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

print(f"Quarantined hashes after ATRDF validation files: {len(quarantine_hashes):,}")

# 2. Ingest ATRDF Training Datasets
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
            "source_dataset": name,
            "source_index": idx,
            "hash": h,
            "raw_record": r
        })

# Exclude RebuiltV4 9,000 records
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

print(f"Quarantined {len(v4_selected_hashes)} RebuiltV4 records.")
print(f"Total exclusion set size: {len(quarantine_hashes):,}")

# Filter eligible unique records
eligible_by_class = defaultdict(list)
seen_hashes = set()

def extract_payload_root(req, category):
    method = str(req.get("method") or "GET").upper()
    url = str(req.get("url") or "")
    url_path = url.split("?")[0] if url else "/"
    body = str(req.get("body") or "")
    headers = req.get("headers") or {}
    
    # Extract salient signature
    text_to_scan = f"{url} {body} {headers.get('Cookie', '')}"
    # Normalize numbers and hex strings to reduce fragmentation
    signature = re.sub(r'\b[0-9a-fA-F]{8,}\b', '<HEX>', text_to_scan)
    signature = re.sub(r'\b\d+\b', '<NUM>', signature)
    
    key_str = f"{category}|{method}|{url_path}|{signature[:80]}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]

for rec in all_train_records:
    h = rec["hash"]
    cat = rec["category"]
    if h in quarantine_hashes:
        continue
    if h in seen_hashes:
        continue
    seen_hashes.add(h)
    
    req = rec["raw_record"].get("request") or {}
    group_key = extract_payload_root(req, cat)
    rec["atomic_group_key"] = group_key
    eligible_by_class[cat].append(rec)

print("\nEligible records available per class:")
for cat, pool in sorted(eligible_by_class.items()):
    print(f"  {cat}: {len(pool):,} available")

# Target numbers for the 27,887 ATRDF pool
ATRDF_TARGETS = {
    "Benign": 3000,
    "Cookie Injection": 2421,
    "Directory Traversal": 4000,
    "LOG4J": 4000,
    "Log Forging": 4000,
    "RCE": 2927,
    "SQL Injection": 4000,
    "XSS": 3539,
}

total_planned = sum(ATRDF_TARGETS.values())
assert total_planned == 27887, f"Expected 27,887, got {total_planned}"

rng_sample = random.Random(20261031)
selected_pool = []
system_prompt = (
    "You are an API security expert and vulnerability classification system. "
    "Your task is to analyze HTTP requests and accurately classify them into one of the "
    "following categories: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, "
    "RCE, SQL Injection, or XSS."
)

for cat, count in sorted(ATRDF_TARGETS.items()):
    available = eligible_by_class[cat]
    if len(available) < count:
        raise ValueError(f"Not enough eligible records for {cat}: needed {count}, available {len(available)}")
    # Deterministic sampling
    rng_sample.shuffle(available)
    sampled = available[:count]
    print(f"Sampled {len(sampled):,} / {count:,} for {cat}")
    selected_pool.extend(sampled)

# Shuffle the combined pool deterministically
rng_sample.shuffle(selected_pool)
print(f"\nTotal ATRDF classification records collected: {len(selected_pool):,}")

# Export to JSONL
out_jsonl = PROCESSED_DIR / "atrdf_classification_pool_27887.jsonl"
group_counter = Counter()

with open(out_jsonl, "w", encoding="utf-8") as f:
    for idx, r in enumerate(selected_pool, 1):
        group_key = r["atomic_group_key"]
        group_counter[group_key] += 1
        record_id = f"ATRDF_{idx:05d}"
        
        entry = {
            "id": record_id,
            "source": r["source_dataset"],
            "source_index": r["source_index"],
            "category": r["category"],
            "binary_label": "Benign" if r["category"] == "Benign" else "Malware",
            "atomic_group_key": group_key,
            "hash": r["hash"],
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": r["input"]},
                {"role": "assistant", "content": r["category"]}
            ]
        }
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

print(f"Exported to {out_jsonl} ({out_jsonl.stat().st_size:,} bytes)")

# Verification manifest
manifest = {
    "total_records": len(selected_pool),
    "target_records": 27887,
    "status": "PASSED" if len(selected_pool) == 27887 else "FAILED",
    "distribution": {cat: count for cat, count in Counter(r["category"] for r in selected_pool).items()},
    "unique_atomic_groups": len(group_counter),
    "quarantine_leakage_count": sum(1 for r in selected_pool if r["hash"] in quarantine_hashes),
    "output_file": str(out_jsonl)
}

manifest_path = REPORTS_DIR / "atrdf_classification_pool_manifest.json"
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(f"Wrote manifest to {manifest_path}")
print("Verification: Leakage count =", manifest["quarantine_leakage_count"])


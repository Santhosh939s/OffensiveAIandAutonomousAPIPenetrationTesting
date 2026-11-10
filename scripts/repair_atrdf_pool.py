"""
repair_atrdf_pool.py
Repairs the ATRDF classification pool (27,887 records):
- Identifies and discards the 2,714 records that duplicated RebuiltV4 or leaked into validation.
- Retains the 25,173 verified unique records.
- Samples exactly 2,714 fresh, eligible, globally unique replacement records from raw ATRDF training files.
- Ensures zero duplicate hashes, zero overlap with RebuiltV4, and zero quarantine leakage.
"""

import json
import hashlib
import random
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(".")
EXTRACTED_DIR = ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted"
PROCESSED_DIR = ROOT / "dataset" / "processed"
EVAL_DIR = ROOT / "evaluation"

print("=" * 80)
print("REPAIRING ATRDF CLASSIFICATION POOL (27,887 RECORDS)")
print("=" * 80)

# 1. Load All Quarantine Exclusion Hashes
quarantine_hashes = set()

# A. test_sample_2000.jsonl
test_2000 = EVAL_DIR / "test_sample_2000.jsonl"
if test_2000.exists():
    with open(test_2000, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                h = hashlib.sha256(item["input"].encode("utf-8")).hexdigest()
                quarantine_hashes.add(h)

# B. Capability Suite
cap_path = ROOT / "scratch" / "test_suite_capabilities.json"
if cap_path.exists():
    with open(cap_path, "r", encoding="utf-8") as f:
        for c in json.load(f):
            quarantine_hashes.add(hashlib.sha256(c["user_prompt"].strip().encode("utf-8")).hexdigest())
            quarantine_hashes.add(hashlib.sha256(c["system_prompt"].strip().encode("utf-8")).hexdigest())

# C. Validation Files
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
            v_recs = json.load(f)
        for r in v_recs:
            req = r.get("request") or {}
            c_in = make_canonical_input(req)
            quarantine_hashes.add(hashlib.sha256(c_in.encode("utf-8")).hexdigest())

print(f"Quarantined evaluation exclusion hashes: {len(quarantine_hashes):,}")

# 2. Extract RebuiltV4 Baseline Hashes (Locked 9,000 records)
v4_hashes = set()
with open(PROCESSED_DIR / "master_corpus_50000.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            if rec.get("dataset_component") == "RebuiltV4_Baseline":
                v4_hashes.add(rec["hash"])

print(f"Preserved RebuiltV4 Baseline Hashes: {len(v4_hashes):,}")

# 3. Load other components to avoid any cross-component overlap
external_hashes = set()
with open(PROCESSED_DIR / "external_classification_shortage_3113_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            external_hashes.add(json.loads(line)["hash"])

difficult_hashes = set()
with open(PROCESSED_DIR / "difficult_classification_5000_repaired.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            difficult_hashes.add(json.loads(line)["hash"])

# Full exclusion set for ATRDF pool
full_exclusion_hashes = quarantine_hashes | v4_hashes | external_hashes | difficult_hashes
print(f"Total exclusion set for pool: {len(full_exclusion_hashes):,}")

# 4. Filter existing ATRDF pool
existing_pool_file = PROCESSED_DIR / "atrdf_classification_pool_27887.jsonl"
retained_pool = []
discarded_pool = []
seen_pool_hashes = set()

with open(existing_pool_file, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            rec = json.loads(line)
            h = rec["hash"]
            if h in full_exclusion_hashes or h in seen_pool_hashes:
                discarded_pool.append(rec)
            else:
                retained_pool.append(rec)
                seen_pool_hashes.add(h)

print(f"Retained existing pool records: {len(retained_pool):,}")
print(f"Discarded duplicate/quarantine records: {len(discarded_pool):,}")
assert len(retained_pool) == 25173, f"Expected 25,173 retained, got {len(retained_pool)}"
assert len(discarded_pool) == 2714, f"Expected 2,714 discarded, got {len(discarded_pool)}"

# Required pool targets per class (Phase C approved allocation)
# ATRDF Pool Targets: Benign 1,000; Cookie 2,421; DT 4,000; LOG4J 4,000; LF 4,000; RCE 3,579; SQLi 4,000; XSS 3,439; Total 27,887
POOL_TARGETS = {
    "Benign": 3000,
    "Cookie Injection": 2421,
    "Directory Traversal": 4000,
    "LOG4J": 4000,
    "Log Forging": 4000,
    "RCE": 2927,
    "SQL Injection": 4000,
    "XSS": 3539
}

retained_by_cat = Counter(r["category"] for r in retained_pool)
shortages = {cat: POOL_TARGETS[cat] - retained_by_cat[cat] for cat in POOL_TARGETS}
print("\nReplacement Requirements per Class:")
for cat, short in shortages.items():
    print(f"  {cat:20s}: Need {short:4d} (Retained: {retained_by_cat[cat]:4d} / Target: {POOL_TARGETS[cat]:4d})")

total_needed = sum(shortages.values())
assert total_needed == 2714, f"Expected 2,714 replacements needed, got {total_needed}"

# 5. Ingest Raw ATRDF Training Files to Find Eligible Replacements
TRAIN_FILES = [
    ("dataset_1_train", EXTRACTED_DIR / "dataset_1_train" / "dataset_1_train.json"),
    ("dataset_2_train", EXTRACTED_DIR / "dataset_2_train" / "dataset_2_train.json"),
    ("dataset_3_train", EXTRACTED_DIR / "dataset_3_train" / "dataset_3_train.json"),
    ("dataset_4_train", EXTRACTED_DIR / "dataset_4_train" / "dataset_4_train.json"),
]

eligible_candidates = defaultdict(list)
candidate_seen_hashes = set()

print("\nScanning raw ATRDF training files for eligible replacements...")
for name, tp in TRAIN_FILES:
    with open(tp, "r", encoding="utf-8") as f:
        recs = json.load(f)
    print(f"Scanning {len(recs):,} records from {name}...")
    for idx, r in enumerate(recs):
        req = r.get("request") or {}
        tag = str(req.get("Attack_Tag") or "").strip()
        cat = tag if tag else "Benign"
        
        if shortages[cat] == 0:
            continue
            
        c_in = make_canonical_input(req)
        h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
        
        # Must not be in exclusion set, must not be in retained pool, must not be a duplicate candidate
        if h in full_exclusion_hashes or h in seen_pool_hashes or h in candidate_seen_hashes:
            continue
            
        candidate_seen_hashes.add(h)
        eligible_candidates[cat].append({
            "input": c_in,
            "category": cat,
            "source_dataset": name,
            "source_index": idx,
            "hash": h,
            "raw_record": r
        })

print("\nEligible Replacement Candidates Discovered:")
for cat, cands in eligible_candidates.items():
    print(f"  {cat:20s}: {len(cands):6,d} available (Needed: {shortages[cat]:4d})")
    assert len(cands) >= shortages[cat], f"Insufficient candidates for {cat}!"

# 6. Sample Exact Replacements
rng = random.Random(20261101)
replacement_records = []

def make_group_key(method, url, category):
    key_str = f"{category}|{method}|{url[:80]}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]

for cat, count in shortages.items():
    sample = rng.sample(eligible_candidates[cat], count)
    for item in sample:
        req = item["raw_record"].get("request") or {}
        method = str(req.get("method") or "GET")
        url = str(req.get("url") or "/")
        g_key = make_group_key(method, url, cat)
        rec = {
            "id": f"POOL_REP_{len(replacement_records)+1:05d}",
            "source": item["source_dataset"],
            "dataset_component": "ATRDF_Classification_Pool",
            "category": cat,
            "binary_label": "Benign" if cat == "Benign" else "Malware",
            "atomic_group_key": g_key,
            "hash": item["hash"],
            "messages": [
                {
                    "role": "system",
                    "content": "You are an API security expert and vulnerability classification system. Your task is to analyze HTTP requests and accurately classify them into one of the following categories: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, or XSS."
                },
                {"role": "user", "content": item["input"]},
                {"role": "assistant", "content": cat}
            ]
        }
        replacement_records.append(rec)

print(f"\nSampled exactly {len(replacement_records):,} replacement records.")
assert len(replacement_records) == 2714

# 7. Combine Retained Pool and Replacements
repaired_pool = retained_pool + replacement_records
print(f"Total Repaired Pool Size: {len(repaired_pool):,}")
assert len(repaired_pool) == 27887

# Verify category distribution
repaired_by_cat = Counter(r["category"] for r in repaired_pool)
print("\nFinal Repaired Pool Distribution:")
for cat, tgt in POOL_TARGETS.items():
    print(f"  {cat:20s}: {repaired_by_cat[cat]:5d} (Target: {tgt:5d})")
    assert repaired_by_cat[cat] == tgt, f"Mismatch in {cat}!"

# 8. Export to repaired pool jsonl
out_file = PROCESSED_DIR / "atrdf_classification_pool_27887_repaired.jsonl"
with open(out_file, "w", encoding="utf-8") as f:
    for idx, r in enumerate(repaired_pool, 1):
        r["id"] = f"ATRDF_POOL_{idx:05d}"
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"Exported repaired pool to {out_file} ({out_file.stat().st_size:,} bytes)")

# Uniqueness verification
hashes = [r["hash"] for r in repaired_pool]
print(f"Distinct hashes in repaired pool: {len(set(hashes)):,}")
assert len(hashes) == len(set(hashes)), "Must have 100% unique hashes!"

# Zero overlap verification
assert len(set(hashes) & v4_hashes) == 0, "Overlap with RebuiltV4 detected!"
assert len(set(hashes) & quarantine_hashes) == 0, "Quarantine leakage detected!"
print(">>> Repaired pool audit: 100% UNIQUE, 0 REBUILTV4 OVERLAP, 0 QUARANTINE LEAKAGE!")

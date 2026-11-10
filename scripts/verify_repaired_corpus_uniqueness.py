"""
verify_repaired_corpus_uniqueness.py
Performs a global, strict uniqueness audit across all 50,000 repaired records:
1. Exact duplicates using canonical full-record SHA-256 hashes.
2. Cross-component duplicate analysis.
3. Near-duplicate detection preserving security-relevant headers, cookies, params, body.
4. Overlap checking against all quarantined evaluation datasets.
5. Generates reports/REPAIRED_DUPLICATE_AUDIT.csv.
"""

import json
import csv
import hashlib
import re
import urllib.parse
from pathlib import Path
from collections import defaultdict, Counter

ROOT = Path(".")
PROCESSED_DIR = ROOT / "dataset" / "processed"
EVAL_DIR = ROOT / "evaluation"
EXTRACTED_DIR = ROOT / "kaggle_output" / "api_pentest_research" / "ATRDF" / "extracted"
REPORTS_DIR = ROOT / "reports"

CORPUS_JSONL = PROCESSED_DIR / "master_corpus_50000_repaired.jsonl"
DUPLICATE_CSV_OUT = REPORTS_DIR / "REPAIRED_DUPLICATE_AUDIT.csv"

print("=" * 80)
print("STRICT GLOBAL UNIQUENESS AUDIT ON REPAIRED 50,000 RECORDS")
print("=" * 80)

# 1. Load All 50,000 Repaired Records
print(f"Loading {CORPUS_JSONL}...")
records = []
with open(CORPUS_JSONL, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))

print(f"Loaded {len(records):,} records.")
assert len(records) == 50000

# Helper to extract request
def extract_request(rec):
    msgs = rec.get("messages", [])
    user_msg = next((m["content"] for m in msgs if m.get("role") == "user"), "")
    marker = "HTTP request:\n"
    if marker in user_msg:
        req_str = user_msg.split(marker, 1)[1].strip()
        try:
            return json.loads(req_str), False
        except Exception:
            return {"raw": req_str}, True
    return {"raw": user_msg}, True

# 2. Canonical Exact Hash
def make_exact_canonical(rec):
    req_d, is_raw = extract_request(rec)
    cat = rec.get("category", "")
    if is_raw:
        canon_obj = {
            "type": "raw",
            "content": req_d.get("raw", "").strip(),
            "category": cat
        }
    else:
        headers = req_d.get("headers") or {}
        sorted_headers = {k.lower().strip(): str(v).strip() for k, v in sorted(headers.items())}
        canon_obj = {
            "type": "http",
            "method": str(req_d.get("method") or "GET").strip().upper(),
            "url": str(req_d.get("url") or "/").strip(),
            "headers": sorted_headers,
            "body": str(req_d.get("body") or "").strip(),
            "category": cat
        }
    canon_bytes = json.dumps(canon_obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canon_bytes).hexdigest(), canon_obj

# 3. Near-Duplicate Canonicalization
def make_near_canonical(rec):
    req_d, is_raw = extract_request(rec)
    cat = rec.get("category", "")
    if is_raw:
        raw_norm = re.sub(r"\s+", " ", req_d.get("raw", "").strip())
        canon_obj = {"type": "raw", "content": raw_norm, "category": cat}
    else:
        method = str(req_d.get("method") or "GET").strip().upper()
        url = str(req_d.get("url") or "/").strip()
        body = str(req_d.get("body") or "").strip()
        headers = req_d.get("headers") or {}
        
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"
        
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urllib.parse.urlencode(sorted(query_pairs))
        norm_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, sorted_query, parsed.fragment))
        
        sec_headers = {}
        for k, v in headers.items():
            kl = k.lower().strip()
            sec_headers[kl] = re.sub(r"\s+", " ", str(v).strip())
        
        norm_body = re.sub(r"\s+", " ", body)
        
        canon_obj = {
            "type": "http",
            "method": method,
            "url": norm_url,
            "headers": dict(sorted(sec_headers.items())),
            "body": norm_body,
            "category": cat
        }
    canon_bytes = json.dumps(canon_obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canon_bytes).hexdigest(), canon_obj

# Execute Hashing
print("Computing exact and near-duplicate canonical hashes...")
exact_groups = defaultdict(list)
near_groups = defaultdict(list)

for rec in records:
    h_exact, _ = make_exact_canonical(rec)
    exact_groups[h_exact].append(rec)
    
    h_near, _ = make_near_canonical(rec)
    near_groups[h_near].append(rec)

# Analyze Exact Duplicates
exact_dups = {h: grp for h, grp in exact_groups.items() if len(grp) > 1}
unique_exact_hashes = len(exact_groups)
total_exact_dup_records = sum(len(grp) for grp in exact_dups.values())
redundant_exact_records = sum(len(grp) - 1 for grp in exact_dups.values())

print("\n--- REPAIRED EXACT DUPLICATE AUDIT SUMMARY ---")
print(f"Total Records: {len(records):,}")
print(f"Distinct Exact Canonical Hashes: {unique_exact_hashes:,}")
print(f"Exact Duplicate Groups: {len(exact_dups):,}")
print(f"Total Records Involved in Duplicate Groups: {total_exact_dup_records:,}")
print(f"Redundant Duplicate Records: {redundant_exact_records:,}")

# Component Breakdown of Duplicates
comp_dups = Counter()
rebuilt_v4_dups = 0
cross_component_dups = 0

for h, grp in exact_dups.items():
    comps = set(r.get("dataset_component") for r in grp)
    if len(comps) > 1:
        cross_component_dups += 1
    for r in grp:
        comp_dups[r.get("dataset_component")] += 1

print("\nDuplicate Records by Component:")
for comp, cnt in comp_dups.items():
    print(f"  {comp:35s}: {cnt:,} records")

print(f"\nCross-Component Duplicate Groups: {cross_component_dups}")
assert cross_component_dups == 0, f"Found {cross_component_dups} cross-component duplicate groups!"

# Newly collected duplicate check:
new_recs = [r for r in records if r.get("dataset_component") != "RebuiltV4_Baseline"]
new_exact_hashes = [make_exact_canonical(r)[0] for r in new_recs]
new_dups = len(new_exact_hashes) - len(set(new_exact_hashes))
print(f"Duplicates within Newly Collected Components (41,000 records): {new_dups}")
assert new_dups == 0, f"Expected 0 duplicates within newly collected components, got {new_dups}!"

# Overlap against Quarantined Evaluation Datasets
print("\n" + "=" * 80)
print("AUDITING OVERLAP AGAINST QUARANTINED EVALUATION DATASETS")
print("=" * 80)

quarantine_sources = {}
# A. test_sample_2000.jsonl
p_test2000 = EVAL_DIR / "test_sample_2000.jsonl"
if p_test2000.exists():
    with open(p_test2000, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = json.loads(line)
                inp = item.get("input", "").strip()
                h = hashlib.sha256(inp.encode("utf-8")).hexdigest()
                quarantine_sources[h] = "test_sample_2000.jsonl"

# B. ATRDF Validation Files
VAL_FILES = [
    ("dataset_1_val", EXTRACTED_DIR / "dataset_1_val" / "dataset_1_val.json"),
    ("dataset_2_val", EXTRACTED_DIR / "dataset_2_val" / "dataset_2_val.json"),
    ("dataset_3_val", EXTRACTED_DIR / "dataset_3_val" / "dataset_3_val.json"),
    ("dataset_4_val", EXTRACTED_DIR / "dataset_4_val" / "dataset_4_val.json"),
]

def make_val_canonical(req):
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

for vname, vp in VAL_FILES:
    if vp.exists():
        with open(vp, "r", encoding="utf-8") as f:
            v_recs = json.load(f)
        for r in v_recs:
            req = r.get("request") or {}
            c_in = make_val_canonical(req)
            h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
            quarantine_sources[h] = vname

print(f"Total Quarantined Evaluation Hashes Loaded: {len(quarantine_sources):,}")

# Check newly collected components for quarantine overlap
new_quarantine_hits = defaultdict(list)
all_quarantine_hits = defaultdict(list)

for r in records:
    user_msg = next((m["content"] for m in r.get("messages", []) if m.get("role") == "user"), "")
    h = hashlib.sha256(user_msg.encode("utf-8")).hexdigest()
    if h in quarantine_sources:
        src = quarantine_sources[h]
        all_quarantine_hits[src].append(r)
        if r.get("dataset_component") != "RebuiltV4_Baseline":
            new_quarantine_hits[src].append(r)

print(f"\nQuarantine Hits in Newly Collected Records (41,000): {sum(len(v) for v in new_quarantine_hits.values())}")
assert sum(len(v) for v in new_quarantine_hits.values()) == 0, "Quarantine leakage in newly collected records!"
print(">>> Zero contamination in newly collected components: 100% CLEAN")

print(f"Quarantine Hits in RebuiltV4 Baseline (Preserved Unchanged): {sum(len(v) for v in all_quarantine_hits.values())}")

# Near-Duplicate Analysis
near_dups = {h: grp for h, grp in near_groups.items() if len(grp) > 1}
unique_near_hashes = len(near_groups)
redundant_near_records = sum(len(grp) - 1 for grp in near_dups.values())

print("\n--- NEAR-DUPLICATE AUDIT SUMMARY ---")
print(f"Distinct Near-Canonical Hashes: {unique_near_hashes:,}")
print(f"Total Near-Duplicate Groups: {len(near_dups):,}")
print(f"Redundant Near-Duplicate Records: {redundant_near_records:,}")

pure_near_dups = {}
for h, grp in near_dups.items():
    exact_hashes_in_grp = {make_exact_canonical(r)[0] for r in grp}
    if len(exact_hashes_in_grp) > 1:
        pure_near_dups[h] = grp

print(f"Pure Near-Duplicate Groups (variance in query order/slashes only): {len(pure_near_dups):,}")
for h, grp in pure_near_dups.items():
    print("  Near group:", [r["id"] for r in grp], [r.get("dataset_component") for r in grp])

# Export REPAIRED_DUPLICATE_AUDIT.csv
print(f"\nExporting {DUPLICATE_CSV_OUT}...")
fieldnames = [
    "duplicate_group_id",
    "canonical_sha256",
    "category",
    "record_id",
    "dataset_component",
    "source",
    "split",
    "is_rebuilt_v4",
    "input_preview"
]

with open(DUPLICATE_CSV_OUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    
    group_idx = 0
    for h, grp in sorted(exact_dups.items(), key=lambda x: len(x[1]), reverse=True):
        group_idx += 1
        for r in grp:
            user_msg = next((m["content"] for m in r.get("messages", []) if m.get("role") == "user"), "")
            is_v4 = "YES" if r.get("dataset_component") == "RebuiltV4_Baseline" else "NO"
            writer.writerow({
                "duplicate_group_id": f"DUP_GRP_{group_idx:04d}",
                "canonical_sha256": h,
                "category": r.get("category", ""),
                "record_id": r.get("id", ""),
                "dataset_component": r.get("dataset_component", ""),
                "source": r.get("source", ""),
                "split": r.get("split", ""),
                "is_rebuilt_v4": is_v4,
                "input_preview": user_msg[:120].replace("\n", " ")
            })

print(f"Wrote {DUPLICATE_CSV_OUT} ({DUPLICATE_CSV_OUT.stat().st_size:,} bytes)")
print(">>> REPAIRED AUDIT VERIFICATION COMPLETE")


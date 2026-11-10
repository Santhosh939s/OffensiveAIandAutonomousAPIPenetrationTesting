"""
strict_uniqueness_audit.py
Performs a global, strict uniqueness audit across all 50,000 records:
1. Exact duplicates using canonical full-record SHA-256 hashes.
2. Cross-component duplicate analysis (specifically checking RebuiltV4 vs newly collected).
3. Near-duplicate detection preserving security-relevant headers, cookies, params, body.
4. Overlap checking against all quarantined evaluation datasets.
5. Generates duplicate report with IDs, sources, categories, and duplicate groups.
6. Proposes a safe removal and replacement plan preserving exact 5,000/class counts.
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

CORPUS_JSONL = PROCESSED_DIR / "master_corpus_50000.jsonl"
DUPLICATE_CSV_OUT = REPORTS_DIR / "DUPLICATE_GROUPS_AUDIT.csv"

print("=" * 80)
print("STRICT GLOBAL UNIQUENESS AUDIT (50,000 RECORDS)")
print("=" * 80)

# 1. Load All 50,000 Records
print("Loading master_corpus_50000.jsonl...")
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
# Canonicalizes: method, full url, sorted headers, body, and target category
def make_exact_canonical(rec):
    req_d, is_raw = extract_request(rec)
    cat = rec.get("category", "")
    comp = rec.get("dataset_component", "")
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
# Normalizes:
# - URL path trailing slashes
# - Query parameter order: ?b=2&a=1 -> ?a=1&b=2
# - Preserves security-critical headers: Cookie, Authorization, Content-Type, Host, Referer, X-*
# - Preserves full bodies and parameters
# - Strips insignificant whitespace
def make_near_canonical(rec):
    req_d, is_raw = extract_request(rec)
    cat = rec.get("category", "")
    if is_raw:
        # Normalize whitespace in raw content
        raw_norm = re.sub(r"\s+", " ", req_d.get("raw", "").strip())
        canon_obj = {"type": "raw", "content": raw_norm, "category": cat}
    else:
        method = str(req_d.get("method") or "GET").strip().upper()
        url = str(req_d.get("url") or "/").strip()
        body = str(req_d.get("body") or "").strip()
        headers = req_d.get("headers") or {}
        
        # Parse URL
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"
        
        # Sort query params
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urllib.parse.urlencode(sorted(query_pairs))
        norm_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, sorted_query, parsed.fragment))
        
        # Security relevant headers preserved with normalized whitespace
        sec_headers = {}
        for k, v in headers.items():
            kl = k.lower().strip()
            # preserve all headers, but normalize spaces
            sec_headers[kl] = re.sub(r"\s+", " ", str(v).strip())
        
        # Normalize body whitespace if JSON/text
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

print("\n--- EXACT DUPLICATE AUDIT SUMMARY ---")
print(f"Total Records: {len(records):,}")
print(f"Distinct Exact Canonical Hashes: {unique_exact_hashes:,}")
print(f"Exact Duplicate Groups: {len(exact_dups):,}")
print(f"Total Records Involved in Duplicate Groups: {total_exact_dup_records:,}")
print(f"Redundant Duplicate Records: {redundant_exact_records:,}")

# Analyze Cross-Component Duplicates
rebuilt_v4_ids = {r["id"] for r in records if r.get("dataset_component") == "RebuiltV4_Baseline"}
print(f"\nRebuiltV4 Baseline Records: {len(rebuilt_v4_ids):,}")

rebuilt_v4_dups = 0
rebuilt_in_pool = 0
rebuilt_in_ext = 0
rebuilt_in_hard = 0
rebuilt_in_reason = 0
intra_pool_dups = 0
intra_v4_dups = 0

cross_component_groups = 0

for h, grp in exact_dups.items():
    comps = set(r.get("dataset_component") for r in grp)
    if len(comps) > 1:
        cross_component_groups += 1
    
    v4_members = [r for r in grp if r.get("dataset_component") == "RebuiltV4_Baseline"]
    non_v4 = [r for r in grp if r.get("dataset_component") != "RebuiltV4_Baseline"]
    
    if v4_members and non_v4:
        rebuilt_v4_dups += len(v4_members)
        for r in non_v4:
            comp = r.get("dataset_component")
            if comp == "ATRDF_Classification_Pool":
                rebuilt_in_pool += 1
            elif comp == "External_Classification_Shortage":
                rebuilt_in_ext += 1
            elif comp == "Difficult_Classification":
                rebuilt_in_hard += 1
            elif comp == "Autonomous_Security_Reasoning":
                rebuilt_in_reason += 1

print(f"Cross-Component Duplicate Groups: {cross_component_groups:,}")
print(f"RebuiltV4 Records Duplicated in Other Components: {rebuilt_v4_dups:,}")
print(f"  - In ATRDF Classification Pool: {rebuilt_in_pool:,}")
print(f"  - In External Shortage:        {rebuilt_in_ext:,}")
print(f"  - In Difficult Classification:  {rebuilt_in_hard:,}")
print(f"  - In Autonomous Reasoning:      {rebuilt_in_reason:,}")

# Duplicate breakdown by Category
dup_by_category = Counter()
redundant_by_category = Counter()
for h, grp in exact_dups.items():
    cat = grp[0]["category"]
    dup_by_category[cat] += len(grp)
    redundant_by_category[cat] += len(grp) - 1

print("\nRedundant Exact Duplicates per Category:")
for cat, cnt in redundant_by_category.most_common():
    print(f"  {cat:25s}: {cnt:,} redundant copies")

# Analyze Near Duplicates
near_dups = {h: grp for h, grp in near_groups.items() if len(grp) > 1}
unique_near_hashes = len(near_groups)
total_near_dup_records = sum(len(grp) for grp in near_dups.values())
redundant_near_records = sum(len(grp) - 1 for grp in near_dups.values())

# Pure near duplicates (near duplicates that are NOT exact duplicates)
pure_near_dups = {}
for h, grp in near_dups.items():
    # check if all records in grp share the exact hash
    exact_hashes_in_grp = {make_exact_canonical(r)[0] for r in grp}
    if len(exact_hashes_in_grp) > 1:
        pure_near_dups[h] = grp

print("\n--- NEAR-DUPLICATE AUDIT SUMMARY ---")
print(f"Distinct Near-Canonical Hashes: {unique_near_hashes:,}")
print(f"Total Near-Duplicate Groups: {len(near_dups):,}")
print(f"Redundant Near-Duplicate Records: {redundant_near_records:,}")
print(f"Pure Near-Duplicate Groups (variance in query order/slashes only): {len(pure_near_dups):,}")

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

# Check corpus overlap
quarantine_hits = defaultdict(list)
for r in records:
    h = r.get("hash")
    if not h:
        user_msg = next((m["content"] for m in r.get("messages", []) if m.get("role") == "user"), "")
        h = hashlib.sha256(user_msg.encode("utf-8")).hexdigest()
    if h in quarantine_sources:
        quarantine_hits[quarantine_sources[h]].append(r["id"])

print(f"Total Contamination / Overlap with Quarantined Datasets: {sum(len(v) for v in quarantine_hits.values())}")
for src, hits in quarantine_hits.items():
    print(f"  - {src}: {len(hits)} hits")

# Export Detailed Duplicate CSV Report
print("\nExporting DUPLICATE_GROUPS_AUDIT.csv...")
with open(DUPLICATE_CSV_OUT, "w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "duplicate_group_id",
        "canonical_sha256",
        "category",
        "record_id",
        "dataset_component",
        "source",
        "split",
        "is_rebuilt_v4",
        "input_preview"
    ])
    
    group_idx = 1
    for h, grp in sorted(exact_dups.items(), key=lambda x: len(x[1]), reverse=True):
        cat = grp[0]["category"]
        for r in grp:
            user_msg = next((m["content"] for m in r.get("messages", []) if m.get("role") == "user"), "")
            snippet = user_msg.replace("\n", " ")[:120]
            is_v4 = "YES" if r.get("dataset_component") == "RebuiltV4_Baseline" else "NO"
            writer.writerow([
                f"DUP_GRP_{group_idx:05d}",
                h,
                cat,
                r["id"],
                r.get("dataset_component", ""),
                r.get("source", ""),
                r.get("split", ""),
                is_v4,
                snippet
            ])
        group_idx += 1

print(f"Exported duplicate details to: {DUPLICATE_CSV_OUT} ({DUPLICATE_CSV_OUT.stat().st_size:,} bytes)")

# 5. Feasibility of Removal and Replacement from Eligible ATRDF Records
print("\n" + "=" * 80)
print("FEASIBILITY OF REPLACEMENT FROM ELIGIBLE ATRDF POOL")
print("=" * 80)

# Check remaining raw records in ATRDF train files
TRAIN_FILES = [
    ("dataset_1_train", EXTRACTED_DIR / "dataset_1_train" / "dataset_1_train.json"),
    ("dataset_2_train", EXTRACTED_DIR / "dataset_2_train" / "dataset_2_train.json"),
    ("dataset_3_train", EXTRACTED_DIR / "dataset_3_train" / "dataset_3_train.json"),
    ("dataset_4_train", EXTRACTED_DIR / "dataset_4_train" / "dataset_4_train.json"),
]

# Track all existing hashes in 50k corpus
corpus_hashes = set(exact_groups.keys())
quarantine_all = set(quarantine_sources.keys())

available_replacements_by_class = Counter()

for name, tp in TRAIN_FILES:
    if not tp.exists():
        continue
    with open(tp, "r", encoding="utf-8") as f:
        raw_recs = json.load(f)
    for r in raw_recs:
        req = r.get("request") or {}
        tag = str(req.get("Attack_Tag") or "").strip()
        cat = tag if tag else "Benign"
        c_in = make_val_canonical(req)
        h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
        if h not in corpus_hashes and h not in quarantine_all:
            available_replacements_by_class[cat] += 1
            corpus_hashes.add(h) # unique count

print("Available Unused Eligible Unique ATRDF Records per Class:")
for cat, cnt in available_replacements_by_class.most_common():
    redundant = redundant_by_category[cat]
    surplus = cnt - redundant
    print(f"  {cat:22s}: {cnt:,} available (Needed to replace duplicates: {redundant:,} | Surplus: +{surplus:,})")

print("\nAUDIT EXECUTION COMPLETE!")


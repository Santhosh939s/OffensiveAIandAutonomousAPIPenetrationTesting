"""
export_repaired_csv.py
Exports the verified 50,000 repaired records into:
- dataset/processed/master_corpus_50000_repaired.csv
- dataset/processed/classification_40000_repaired.csv
- dataset/processed/difficult_classification_5000_repaired.csv
- dataset/processed/reasoning_traces_5000_repaired.csv
And mirrors to root:
- classification_40000_repaired.csv
- difficult_classification_5000_repaired.csv
- reasoning_traces_5000_repaired.csv
"""

import json
import csv
from pathlib import Path
from collections import Counter

ROOT = Path(".")
PROCESSED_DIR = ROOT / "dataset" / "processed"

JSONL_PATH = PROCESSED_DIR / "master_corpus_50000_repaired.jsonl"
CSV_MASTER_PATH = PROCESSED_DIR / "master_corpus_50000_repaired.csv"
CSV_CLASS_PATH = PROCESSED_DIR / "classification_40000_repaired.csv"
CSV_DIFF_PATH = PROCESSED_DIR / "difficult_classification_5000_repaired.csv"
CSV_REASON_PATH = PROCESSED_DIR / "reasoning_traces_5000_repaired.csv"

ROOT_CSV_CLASS = ROOT / "classification_40000_repaired.csv"
ROOT_CSV_DIFF = ROOT / "difficult_classification_5000_repaired.csv"
ROOT_CSV_REASON = ROOT / "reasoning_traces_5000_repaired.csv"

print("=" * 80)
print("EXPORTING REPAIRED DATASET TO CSV")
print("=" * 80)

records = []
with open(JSONL_PATH, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            records.append(json.loads(line))

print(f"Loaded {len(records):,} records from {JSONL_PATH}")
assert len(records) == 50000

CSV_COLUMNS = [
    "id",
    "dataset_component",
    "split",
    "category",
    "binary_label",
    "source",
    "source_index",
    "provenance",
    "pattern_id",
    "description",
    "final_verdict",
    "atomic_group_key",
    "hash",
    "system_prompt",
    "user_input",
    "assistant_response",
    "messages",
    "raw_trace"
]

def format_row(rec):
    rid = rec["id"]
    split = rec.get("split", "train")
    comp = rec.get("dataset_component", "")
    
    source = rec.get("source")
    if not source:
        if comp == "Difficult_Classification":
            source = f"Synthetic_Evasion_{rec.get('pattern_id', 'HARD')}"
        elif comp == "Autonomous_Security_Reasoning":
            source = "OWASP_API_Security_Top_10_2023_Lab"
        elif comp == "ATRDF_Classification_Pool":
            source = "ATRDF_Extracted_Train"
        else:
            source = "Unknown"

    msgs = rec.get("messages", [])
    sys_prompt = msgs[0]["content"] if len(msgs) > 0 else ""
    user_inp = msgs[1]["content"] if len(msgs) > 1 else ""
    asst_resp = msgs[2]["content"] if len(msgs) > 2 else ""

    return {
        "id": rid,
        "dataset_component": comp,
        "split": split,
        "category": rec.get("category", ""),
        "binary_label": rec.get("binary_label", ""),
        "source": source,
        "source_index": rec.get("source_index", ""),
        "provenance": rec.get("provenance", ""),
        "pattern_id": rec.get("pattern_id", ""),
        "description": rec.get("description", ""),
        "final_verdict": rec.get("final_verdict", ""),
        "atomic_group_key": rec.get("atomic_group_key", ""),
        "hash": rec.get("hash", ""),
        "system_prompt": sys_prompt,
        "user_input": user_inp,
        "assistant_response": asst_resp,
        "messages": json.dumps(msgs, ensure_ascii=False),
        "raw_trace": json.dumps(rec.get("raw_trace"), ensure_ascii=False) if rec.get("raw_trace") else ""
    }

def write_csv_file(path, subset_records):
    print(f"Writing {len(subset_records):,} records to {path}...")
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for r in subset_records:
            writer.writerow(format_row(r))
    print(f"Finished {path.name}: {path.stat().st_size:,} bytes")

class_40k_records = [
    r for r in records
    if r.get("dataset_component") in ("RebuiltV4_Baseline", "ATRDF_Classification_Pool", "External_Classification_Shortage")
]
diff_5k_records = [
    r for r in records
    if r.get("dataset_component") == "Difficult_Classification"
]
reason_5k_records = [
    r for r in records
    if r.get("dataset_component") == "Autonomous_Security_Reasoning"
]

assert len(records) == 50000
assert len(class_40k_records) == 40000
assert len(diff_5k_records) == 5000
assert len(reason_5k_records) == 5000

# Write dataset/processed/ CSVs
write_csv_file(CSV_MASTER_PATH, records)
write_csv_file(CSV_CLASS_PATH, class_40k_records)
write_csv_file(CSV_DIFF_PATH, diff_5k_records)
write_csv_file(CSV_REASON_PATH, reason_5k_records)

# Write root CSVs for exact path availability
write_csv_file(ROOT_CSV_CLASS, class_40k_records)
write_csv_file(ROOT_CSV_DIFF, diff_5k_records)
write_csv_file(ROOT_CSV_REASON, reason_5k_records)

print("\nValidating CSV row counts...")
for p, exp_rows in [
    (CSV_MASTER_PATH, 50000),
    (CSV_CLASS_PATH, 40000),
    (CSV_DIFF_PATH, 5000),
    (CSV_REASON_PATH, 5000),
    (ROOT_CSV_CLASS, 40000),
    (ROOT_CSV_DIFF, 5000),
    (ROOT_CSV_REASON, 5000)
]:
    with open(p, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        data_rows = sum(1 for _ in reader)
    print(f"  {p.name}: {data_rows:,} data rows (Expected: {exp_rows:,}) - {'MATCH' if data_rows == exp_rows else 'MISMATCH'}")
    assert data_rows == exp_rows

print(">>> ALL CSV EXPORTS COMPLETED AND VERIFIED!")


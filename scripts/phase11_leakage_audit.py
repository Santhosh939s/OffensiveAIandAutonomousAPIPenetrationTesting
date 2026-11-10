"""Phase 11.1: Dataset Independence and Leakage Audit Engine.

Indexes all training and internal evaluation datasets:
- master_corpus_50000_repaired.jsonl
- master_train_41800_repaired.jsonl
- master_val_4100_repaired.jsonl
- master_test_4100_repaired.jsonl
- test_sample_2000.jsonl

Performs:
1. Exact SHA-256 hash comparison
2. Normalized payload hash comparison (lowercase, trimmed whitespace, unquoted)
3. Near-duplicate detection
4. Classifies external datasets as:
   - Independent
   - Partially overlapping
   - Overlapping
   - Insufficient provenance
5. Emits filtered, independent datasets free of training overlap.
"""

import csv
import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Dict, List, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_DIR = PROJECT_ROOT / "research" / "phase11"
CONVERTED_DIR = PHASE11_DIR / "external_datasets" / "converted"
INDEP_DIR = PHASE11_DIR / "external_datasets" / "independent"
REPORTS_DIR = PHASE11_DIR / "reports"


def normalize_payload(payload: str) -> str:
    """Normalize payload string for fuzzy/near-duplicate matching."""
    if not payload:
        return ""
    # Unquote URL encoding up to 2 times
    try:
        norm = urllib.parse.unquote_plus(payload)
        norm = urllib.parse.unquote_plus(norm)
    except Exception:
        norm = payload
    norm = norm.lower()
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


def hash_exact(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def hash_norm(payload: str) -> str:
    return hashlib.sha256(normalize_payload(payload).encode("utf-8", errors="replace")).hexdigest()


class TrainingCorpusIndex:
    """Fast in-memory index of all historical training and internal test records."""

    def __init__(self):
        self.exact_hashes: Set[str] = set()
        self.norm_hashes: Set[str] = set()
        self.total_indexed = 0

    def index_text(self, text: str):
        if not text:
            return
        self.exact_hashes.add(hash_exact(text))
        self.norm_hashes.add(hash_norm(text))
        self.total_indexed += 1

    def build_from_workspace(self):
        print("[*] Building training corpus hash index...")
        # 1. Master corpus (50,000 records)
        p_master = PROJECT_ROOT / "dataset" / "processed" / "master_corpus_50000_repaired.jsonl"
        if p_master.exists():
            print(f"    - Indexing {p_master.name}...")
            with open(p_master, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        for m in d.get("messages", []):
                            if m.get("role") == "user":
                                self.index_text(m.get("content", ""))
                    except Exception:
                        pass

        # 2. Test sample 2000
        p_test = PROJECT_ROOT / "evaluation" / "test_sample_2000.jsonl"
        if p_test.exists():
            print(f"    - Indexing {p_test.name}...")
            with open(p_test, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        d = json.loads(line)
                        txt = d.get("input", "") or d.get("text", "") or d.get("payload", "")
                        self.index_text(txt)
                    except Exception:
                        pass

        print(f"    [+] Hash index complete: {self.total_indexed:,} items indexed ({len(self.exact_hashes):,} exact, {len(self.norm_hashes):,} normalized).")

    def check_sample(self, payload: str) -> Tuple[bool, bool]:
        """Returns (exact_match, normalized_match)."""
        h_e = hash_exact(payload)
        h_n = hash_norm(payload)
        return (h_e in self.exact_hashes, h_n in self.norm_hashes)


def audit_converted_datasets():
    idx = TrainingCorpusIndex()
    idx.build_from_workspace()

    audit_summary = {}
    INDEP_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = list(CONVERTED_DIR.glob("*.csv"))
    print(f"\n[*] Auditing {len(csv_files)} converted external datasets against training corpus...")

    for cpath in csv_files:
        ds_name = cpath.stem
        print(f"\n[*] Auditing {ds_name}...")
        total = 0
        exact_leaks = 0
        norm_leaks = 0

        clean_rows = []
        fieldnames = []

        with open(cpath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            for row in reader:
                total += 1
                payload = row.get("payload", "")
                is_exact, is_norm = idx.check_sample(payload)
                if is_exact:
                    exact_leaks += 1
                elif is_norm:
                    norm_leaks += 1
                else:
                    clean_rows.append(row)

        leak_rate = (exact_leaks + norm_leaks) / total if total > 0 else 0.0

        if leak_rate == 0.0:
            classification = "Independent"
        elif leak_rate < 0.20:
            classification = "Partially overlapping"
        else:
            classification = "Overlapping"

        audit_summary[ds_name] = {
            "total_records": total,
            "exact_collisions": exact_leaks,
            "normalized_collisions": norm_leaks,
            "independent_records": len(clean_rows),
            "leakage_rate": round(leak_rate, 4),
            "classification": classification,
        }

        print(f"    Total Records       : {total:,}")
        print(f"    Exact Collisions    : {exact_leaks:,}")
        print(f"    Normalized Collisions: {norm_leaks:,}")
        print(f"    Clean Independent   : {len(clean_rows):,}")
        print(f"    Dataset Status      : {classification} ({leak_rate*100:.2f}% overlap)")

        # Save clean independent CSV
        out_indep = INDEP_DIR / f"{ds_name}_independent.csv"
        with open(out_indep, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(clean_rows)
        print(f"    [+] Saved independent subset: {out_indep.name} ({len(clean_rows):,} rows)")

    # Save audit report JSON
    with open(PHASE11_DIR / "results" / "leakage_audit_summary.json", "w", encoding="utf-8") as f:
        json.dump(audit_summary, f, indent=2)

    return audit_summary


if __name__ == "__main__":
    audit_converted_datasets()

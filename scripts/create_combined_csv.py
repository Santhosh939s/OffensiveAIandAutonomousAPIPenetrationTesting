import csv
from pathlib import Path

indep_dir = Path("research/phase11/external_datasets/independent")
combined_path = indep_dir / "combined_external_independent.csv"

# Datasets eligible for combined textual classification
eligible_files = [
    indep_dir / "dataset_a_external_independent.csv",
    indep_dir / "dataset_b_external_independent.csv",
    indep_dir / "dataset_d_seclists_challenge_independent.csv",
    indep_dir / "dataset_e_atrdf_independent.csv",
]

total = 0
header = None

with open(combined_path, "w", encoding="utf-8", newline="") as out_f:
    writer = None
    for fpath in eligible_files:
        if not fpath.exists():
            continue
        with open(fpath, "r", encoding="utf-8", errors="ignore") as in_f:
            reader = csv.reader(in_f)
            h = next(reader, None)
            if writer is None:
                writer = csv.writer(out_f)
                writer.writerow(h)
            for row in reader:
                writer.writerow(row)
                total += 1

print(f"[+] Combined external independent dataset created: {combined_path.name} ({total:,} total records)")


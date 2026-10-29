import json
import os
import glob

# 1. Check baseline_model.ipynb
nb_path = 'kaggle_output/api_pentest_research/ATRDF/baseline_model.ipynb'
if os.path.exists(nb_path):
    with open(nb_path, 'r', encoding='utf-8') as f:
        nb = json.load(f)
    print(f"Total cells in baseline_model.ipynb: {len(nb['cells'])}")
    for idx, cell in enumerate(nb['cells']):
        src = "".join(cell.get('source', []))
        low = src.lower()
        if any(k in low for k in ['dataset', '9000', 'train', 'sample', 'load']):
            first_lines = [l.strip() for l in src.split('\n') if l.strip()][:3]
            print(f"Cell {idx} ({cell.get('cell_type')}): {first_lines}")

# 2. Check other notebooks
for nb_file in glob.glob("**/*.ipynb", recursive=True):
    if nb_file == nb_path: continue
    print(f"\nChecking {nb_file}:")
    with open(nb_file, 'r', encoding='utf-8') as f:
        nb = json.load(f)
    print(f"  Total cells: {len(nb['cells'])}")
    for idx, cell in enumerate(nb['cells']):
        src = "".join(cell.get('source', []))
        low = src.lower()
        if any(k in low for k in ['train.jsonl', 'rebuilt_v4', '9000', 'atrdf', 'dataset_1', 'dataset_2']):
            first_lines = [l.strip() for l in src.split('\n') if l.strip()][:3]
            print(f"  Cell {idx} ({cell.get('cell_type')}): {first_lines}")

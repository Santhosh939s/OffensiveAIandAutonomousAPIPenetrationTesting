import json
import re

nb = json.load(open('urop-offensive-ai.ipynb', encoding='utf-8'))
print(f'Total cells: {len(nb["cells"])}')

matches = []
for idx, cell in enumerate(nb['cells']):
    src = ''.join(cell.get('source', []))
    keywords = ['rebuilt_v4', 'train.jsonl', 'atrdf', 'dataset_1', 'dataset_2', 'dataset_3', 'dataset_4', '9000', '9,000', 'sampling', 'subsample', 'balanced']
    found = [k for k in keywords if k in src.lower()]
    if found:
        first_line = src.strip().split('\n')[0][:80] if src.strip() else ""
        matches.append((idx, cell.get('cell_type'), found, first_line))

print(f'Matching cells: {len(matches)}')
for idx, c_type, found, first_line in matches:
    print(f'Cell {idx:3d} [{c_type}]: found={found} | {first_line}')

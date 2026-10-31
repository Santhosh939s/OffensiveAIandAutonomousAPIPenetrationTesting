import json
from pathlib import Path

nb_path = Path("capability_eval_kaggle.ipynb")
nb = json.loads(nb_path.read_text(encoding="utf-8"))
for cell in nb["cells"]:
    src = cell.get("source", "")
    if isinstance(src, list):
        src = "".join(src)
    if "test_cases = [{" in src:
        start = src.find("test_cases = ") + len("test_cases = ")
        end = src.find("\nprint(f\"Loaded")
        cases_code = src[start:end].strip()
        test_cases = eval(cases_code)
        out_path = Path("scratch/test_suite_capabilities.json")
        out_path.write_text(json.dumps(test_cases, indent=2), encoding="utf-8")
        print(f"Successfully extracted {len(test_cases)} capability cases to {out_path}")
        break

import json
from pathlib import Path

p = Path("runs/run_20261028_rebuiltv4_capability_eval/capability_eval_results.json")
data = json.loads(p.read_text(encoding="utf-8"))

print("=== CAPABILITY EVAL RESULTS AUDIT ===")
print("Evaluation timestamp:", data.get("evaluation_timestamp"))
print("Model:", data.get("model"))
print("Adapter:", data.get("adapter"))
print("Reported composite score:", data.get("composite_score"))

cases = data["detailed_results"]
print(f"Total cases: {len(cases)}")

cap_groups = {}
for c in cases:
    cap = c["capability"]
    cap_groups.setdefault(cap, []).append(c)

recalculated_caps = {}
all_case_scores = []

for cap, group in sorted(cap_groups.items()):
    scores = []
    correctness_list = []
    schema_list = []
    evidence_list = []
    unsupported_list = []
    instruction_list = []
    collapse_count = 0
    cap_name = group[0]["capability_name"]
    
    print(f"\n--- Capability {cap} ({cap_name}) ---")
    for c in group:
        sc = c["scores"]
        # Expected formula: 0.35 * correctness + 0.15 * schema_validity + 0.20 * evidence_grounding + 0.15 * unsupported_claims + 0.15 * instruction_following
        calc_overall = round(
            0.35 * sc["correctness"] +
            0.15 * sc["schema_validity"] +
            0.20 * sc["evidence_grounding"] +
            0.15 * sc["unsupported_claims"] +
            0.15 * sc["instruction_following"],
            3
        )
        diff = abs(calc_overall - sc["overall_score"])
        print(f"Case {c['id']}: reported={sc['overall_score']:.3f}, calc={calc_overall:.3f}, diff={diff:.4f}, collapse={sc['is_mere_classification']}")
        scores.append(sc["overall_score"])
        all_case_scores.append(sc["overall_score"])
        correctness_list.append(sc["correctness"])
        schema_list.append(sc["schema_validity"])
        evidence_list.append(sc["evidence_grounding"])
        unsupported_list.append(sc["unsupported_claims"])
        instruction_list.append(sc["instruction_following"])
        if sc["is_mere_classification"]:
            collapse_count += 1
            
    n = len(group)
    recalculated_caps[cap] = {
        "name": cap_name,
        "avg_score": round(sum(scores) / n, 3),
        "correctness": round(sum(correctness_list) / n, 3),
        "schema_validity": round(sum(schema_list) / n, 3),
        "evidence_grounding": round(sum(evidence_list) / n, 3),
        "unsupported_claims": round(sum(unsupported_list) / n, 3),
        "instruction_following": round(sum(instruction_list) / n, 3),
        "collapses": collapse_count
    }

print("\n=== RECALCULATED VS REPORTED SUMMARY ===")
rep_summary = data["per_capability_summary"]
for cap in sorted(recalculated_caps.keys()):
    r = recalculated_caps[cap]
    rep = rep_summary[cap]
    print(f"Cap {cap} ({r['name']}):")
    print(f"  Score: calc={r['avg_score']:.3f} | rep={rep['average_score']:.3f}")
    print(f"  Correctness: calc={r['correctness']:.3f} | rep={rep['correctness']:.3f}")
    print(f"  Schema: calc={r['schema_validity']:.3f} | rep={rep['schema_validity']:.3f}")
    print(f"  Evidence: calc={r['evidence_grounding']:.3f} | rep={rep['evidence_grounding']:.3f}")
    print(f"  Unhallucinated: calc={r['unsupported_claims']:.3f} | rep={rep['unsupported_claims']:.3f}")
    print(f"  Instruction Follow: calc={r['instruction_following']:.3f} | rep={rep['instruction_following']:.3f}")

recalc_composite = round(sum(all_case_scores) / len(all_case_scores), 3)
print(f"\nRecalculated Overall Composite: {recalc_composite:.3f} (Reported in JSON: {data['composite_score']})")

print("\n=== SPECIFIC CASE DEEP-DIVES ===")

# Inspect C1-C4
print("\n--- Capability C (Tool Selection): C1 - C4 ---")
for c in cases:
    if c["capability"] == "C":
        print(f"\nCase: {c['id']} ({c['type']})")
        print("User Prompt:", c["user_prompt"].replace("\n", " ")[:120])
        print("Raw Output:\n", c["raw_output"])
        print("Parsed Output:", c["scores"]["parsed_output"])
        print("Scores:", c["scores"])

# Inspect D1-D4
print("\n--- Capability D (Evidence Analysis): D1 - D4 ---")
for c in cases:
    if c["capability"] == "D":
        print(f"\nCase: {c['id']} ({c['type']})")
        print("User Prompt:\n", c["user_prompt"])
        print("Raw Output:", repr(c["raw_output"]))
        print("Scores:", c["scores"])
        print("Rationale:", c["scores"]["rationale"])

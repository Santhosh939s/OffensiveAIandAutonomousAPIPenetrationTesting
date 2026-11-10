"""Phase 11.3: WAMM Ground-Truth Quality Review Table Generator.

Inspects all 90 WAMM evaluation samples in `dataset_b_phase11_2_predictions.csv`:
- Decodes URL-encoded parameters
- Extracts attack signatures
- Evaluates technical vulnerability category
- Generates markdown and JSON review tables
"""

import csv
import json
import urllib.parse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PHASE11_2_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_2"
PHASE11_3_DIR = PROJECT_ROOT / "research" / "phase11" / "results" / "phase11_3"
PHASE11_3_DIR.mkdir(parents=True, exist_ok=True)


def decode_payload(payload: str) -> str:
    """Recursively decode URL-encoded string up to 3 passes."""
    cur = payload
    for _ in range(3):
        nxt = urllib.parse.unquote(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def classify_technical_vulnerability(decoded: str, orig_label: str) -> tuple:
    """Determine true technical interpretation and evidence."""
    lower = decoded.lower()
    
    # Check SSI / Command execution
    if "<!--#exec" in lower or "cmd=" in lower or "exec(" in lower or "system(" in lower or "passthru(" in lower or "powershell" in lower or "/bin/bash" in lower or "/bin/sh" in lower:
        return ("Remote Code Execution (RCE) / SSI", "Contains server-side shell execution directive or SSI exec command", "HIGH")
        
    # Check Traversal / LFI
    if "/etc/passwd" in lower or "etc/passwd" in lower or "../" in lower or "..\\" in lower or "winnt" in lower or "system32" in lower or ".svn" in lower or ".git" in lower:
        return ("Directory Traversal / LFI", "Contains relative traversal sequences or targets sensitive operating system / repository files", "HIGH")
        
    # Check Template Injection (SSTI)
    if "{{" in decoded and "}}" in decoded:
        return ("Server-Side Template Injection (SSTI)", "Contains template expression delimiters (e.g. {{ data.model.url }})", "HIGH")
        
    # Check SQL Injection
    if "union select" in lower or "or 1=1" in lower or "' or '" in lower or "waitfor delay" in lower or "pg_sleep" in lower or "information_schema" in lower or "sysibm" in lower or "sysusers" in lower:
        return ("SQL Injection", "Contains SQL syntax, boolean operators, or database metadata query", "HIGH")
        
    # Check XSS
    if "<script" in lower or "<img" in lower or "<svg" in lower or "javascript:" in lower or "alert(" in lower or "confirm(" in lower:
        return ("Cross-Site Scripting (XSS)", "Contains HTML markup or JavaScript DOM execution vector", "HIGH")
        
    # Check SSRF / URL parameters
    if "http://" in lower or "https://" in lower or "gopher://" in lower or "dict://" in lower:
        if "google.com" in lower or "127.0.0.1" in lower or "localhost" in lower or "169.254." in lower:
            return ("Server-Side Request Forgery (SSRF) / URL Redirection", "Contains external or loopback URL scheme in parameter", "HIGH")
            
    # Check Admin scanning / probes
    if "admin" in lower or "login" in lower or "wp-login" in lower:
        return ("Administrative Endpoint Probe", "Standard probe against WordPress administrative or authentication endpoints", "MEDIUM")
        
    # Check Benign traffic
    if orig_label.lower() in ["normal", "benign"]:
        return ("Benign HTTP Request", "Normal web traffic without malicious payloads", "HIGH")
        
    return ("Unclassified Web Traffic", "Generic or obfuscated HTTP request", "LOW")


def generate_wamm_review():
    csv_path = PHASE11_2_DIR / "dataset_b_phase11_2_predictions.csv"
    assert csv_path.exists(), f"Missing file: {csv_path}"
    
    records = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            records.append(r)
            
    print(f"[*] Processing {len(records)} WAMM records for ground-truth review...")
    
    review_rows = []
    for r in records:
        sid = r["sample_id"]
        orig_lbl = r["ground_truth"]
        raw_pay = r["payload"]
        pred_lbl = r["predicted_label"]
        
        decoded = decode_payload(raw_pay)
        tech_cat, evidence, conf = classify_technical_vulnerability(decoded, orig_lbl)
        
        # Agreement check
        model_agrees_with_tech = (pred_lbl.lower() in tech_cat.lower()) or (tech_cat.startswith(pred_lbl))
        wamm_agrees_with_tech = (orig_lbl.lower() in tech_cat.lower())
        
        review_rows.append({
            "sample_id": sid,
            "original_wamm_label": orig_lbl,
            "raw_payload_snippet": raw_pay[:90].replace("\n", " "),
            "decoded_payload_snippet": decoded[:90].replace("\n", " "),
            "model_prediction": pred_lbl,
            "technical_interpretation": tech_cat,
            "evidence": evidence,
            "reviewer_confidence": conf,
            "model_matches_technical": model_agrees_with_tech,
            "wamm_matches_technical": wamm_agrees_with_tech,
        })
        
    # Save review JSON
    out_json = PHASE11_3_DIR / "wamm_ground_truth_audit.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(review_rows, f, indent=2)
    print(f"[+] Saved WAMM ground-truth audit to: {out_json}")
    
    # Print summary statistics
    n = len(review_rows)
    w_match = sum(1 for r in review_rows if r["wamm_matches_technical"])
    m_match = sum(1 for r in review_rows if r["model_matches_technical"])
    print(f"[*] Total samples analyzed: {n}")
    print(f"[*] WAMM Label matches technical payload: {w_match}/{n} ({w_match/n*100:.1f}%)")
    print(f"[*] Model Prediction matches technical payload: {m_match}/{n} ({m_match/n*100:.1f}%)")


if __name__ == "__main__":
    generate_wamm_review()


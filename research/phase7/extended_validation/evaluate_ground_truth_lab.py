"""Phase 7.1: Ground Truth Lab Verification & False Positive/Negative Audit.

Tests all 10 seeded vulnerability endpoints and 5 safe baseline endpoints in lab/app.py.
Computes ground truth detection accuracy, true positives, false positives,
true negatives, false negatives, specificity, sensitivity, and false positive rate.
"""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import requests
from werkzeug.serving import make_server

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from lab.app import create_app
from lab.database import LabDatabase


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_ground_truth_audit():
    print("=" * 78)
    print("   PHASE 7.1: GROUND TRUTH LAB EMPIRICAL AUDIT")
    print("=" * 78)

    db_path = PROJECT_ROOT / "research" / "phase7" / "extended_validation" / "lab_gt.db"
    if db_path.exists():
        db_path.unlink()

    port = find_free_port()
    db = LabDatabase(str(db_path))
    app = create_app(db=db)
    server = make_server("127.0.0.1", port, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(1.0)

    base_url = f"http://127.0.0.1:{port}"
    print(f"[*] Live Vulnerable Lab active on {base_url}")

    # Define test suite of ground truth endpoints
    test_cases = [
        # --- GROUND TRUTH VULNERABLE ENDPOINTS (Expected: VULNERABLE) ---
        {
            "id": "GT-VULN-01",
            "name": "BOLA / IDOR User PII Exposure",
            "owasp_category": "API1:2023 - Broken Object Level Authorization",
            "expected_ground_truth": "VULNERABLE",
            "method": "GET",
            "endpoint": "/api/users/2",
            "vuln_indicator": lambda r: r.status_code == 200 and "password_hash" in r.text and "api_token" in r.text,
            "evidence_desc": "Returns Bob's private password hash and API token without authorization",
        },
        {
            "id": "GT-VULN-02",
            "name": "BOLA / IDOR Cross-Account Orders",
            "owasp_category": "API1:2023 - Broken Object Level Authorization",
            "expected_ground_truth": "VULNERABLE",
            "method": "GET",
            "endpoint": "/api/orders/102",
            "vuln_indicator": lambda r: r.status_code == 200 and "shipping_address" in r.text and r.json().get("bola_exposed") is True,
            "evidence_desc": "Returns Order 102 shipping address without ownership check",
        },
        {
            "id": "GT-VULN-03",
            "name": "Broken Auth Empty Password Bypass",
            "owasp_category": "API2:2023 - Broken Authentication",
            "expected_ground_truth": "VULNERABLE",
            "method": "POST",
            "endpoint": "/api/login",
            "json": {"username": "admin", "password": ""},
            "vuln_indicator": lambda r: r.status_code == 200 and r.json().get("success") is True and "token" in r.json(),
            "evidence_desc": "Admin login succeeds with empty password and issues unsigned JWT",
        },
        {
            "id": "GT-VULN-04",
            "name": "BOPLA / Mass Assignment Role Elevation",
            "owasp_category": "API3:2023 - Broken Object Property Level Authorization",
            "expected_ground_truth": "VULNERABLE",
            "method": "PUT",
            "endpoint": "/api/users/2",
            "json": {"role": "admin", "is_admin": 1},
            "vuln_indicator": lambda r: r.status_code == 200 and r.json().get("user", {}).get("role") == "admin",
            "evidence_desc": "User 2 role elevated to admin via unrestricted property binding",
        },
        {
            "id": "GT-VULN-05",
            "name": "BFLA Unprivileged Role Modification",
            "owasp_category": "API5:2023 - Broken Function Level Authorization",
            "expected_ground_truth": "VULNERABLE",
            "method": "POST",
            "endpoint": "/api/admin/users/2/role",
            "json": {"role": "admin"},
            "vuln_indicator": lambda r: r.status_code == 200 and r.json().get("bfla_exposed") is True,
            "evidence_desc": "Unauthenticated caller modified user role via admin endpoint",
        },
        {
            "id": "GT-VULN-06",
            "name": "BFLA Administrative System Dump",
            "owasp_category": "API5:2023 - Broken Function Level Authorization",
            "expected_ground_truth": "VULNERABLE",
            "method": "GET",
            "endpoint": "/api/admin/export",
            "vuln_indicator": lambda r: r.status_code == 200 and "ADMIN_SYSTEM_DUMP" in r.text and "audit_logs" in r.text,
            "evidence_desc": "Unauthenticated caller retrieved full system dump with audit logs",
        },
        {
            "id": "GT-VULN-07",
            "name": "Business Flow Abuse Unlimited Coupons",
            "owasp_category": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
            "expected_ground_truth": "VULNERABLE",
            "method": "POST",
            "endpoint": "/api/coupons/apply",
            "json": {"coupon_code": "SAVE50", "order_id": 101},
            "vuln_indicator": lambda r: r.status_code == 200 and r.json().get("business_flow_abuse") is True,
            "evidence_desc": "Coupon code applied repeatedly without rate limits or quotas",
        },
        {
            "id": "GT-VULN-08",
            "name": "SQL Injection Raw Error Disclosure",
            "owasp_category": "API8:2023 - Security Misconfiguration / Injection",
            "expected_ground_truth": "VULNERABLE",
            "method": "GET",
            "endpoint": "/api/search?q='",
            "vuln_indicator": lambda r: r.status_code == 500 and ("syntax error" in r.text.lower() or "unrecognized token" in r.text.lower() or "database sql" in r.text.lower()),
            "evidence_desc": "Single quote triggers unhandled SQL syntax/token error in response",
        },
        {
            "id": "GT-VULN-09",
            "name": "Improper Inventory Shadow API Export",
            "owasp_category": "API9:2023 - Improper Inventory Management",
            "expected_ground_truth": "VULNERABLE",
            "method": "GET",
            "endpoint": "/api/v1/users/export",
            "vuln_indicator": lambda r: r.status_code == 200 and r.json().get("shadow_api") is True,
            "evidence_desc": "Unadvertised deprecated v1 endpoint accessible leaking user tokens",
        },
        {
            "id": "GT-VULN-10",
            "name": "GraphQL Unrestricted Introspection",
            "owasp_category": "GraphQL Misconfiguration",
            "expected_ground_truth": "VULNERABLE",
            "method": "POST",
            "endpoint": "/graphql",
            "json": {"query": "{ __schema { types { name } } }"},
            "vuln_indicator": lambda r: r.status_code == 200 and "__schema" in r.text and "User" in r.text,
            "evidence_desc": "Full schema introspection exposed without authentication",
        },
        # --- GROUND TRUTH SAFE / BASELINE ENDPOINTS (Expected: SAFE) ---
        {
            "id": "GT-SAFE-01",
            "name": "Health Check Service Status",
            "owasp_category": "Safe Baseline",
            "expected_ground_truth": "SAFE",
            "method": "GET",
            "endpoint": "/health",
            "vuln_indicator": lambda r: r.status_code != 200 or "password" in r.text.lower(),
            "evidence_desc": "Standard health check returns healthy status without sensitive data",
        },
        {
            "id": "GT-SAFE-02",
            "name": "Public User Directory (Safe Fields)",
            "owasp_category": "Safe Baseline",
            "expected_ground_truth": "SAFE",
            "method": "GET",
            "endpoint": "/api/users",
            "vuln_indicator": lambda r: "password_hash" in r.text or "api_token" in r.text or r.status_code != 200,
            "evidence_desc": "Public listing returns only public user attributes (id, username, full_name, role)",
        },
        {
            "id": "GT-SAFE-03",
            "name": "Item Catalog List",
            "owasp_category": "Safe Baseline",
            "expected_ground_truth": "SAFE",
            "method": "GET",
            "endpoint": "/api/items",
            "vuln_indicator": lambda r: r.status_code != 200 or "error" in r.text.lower(),
            "evidence_desc": "Standard catalog list returns public item details",
        },
        {
            "id": "GT-SAFE-04",
            "name": "Alphanumeric Benign Search Query",
            "owasp_category": "Safe Baseline",
            "expected_ground_truth": "SAFE",
            "method": "GET",
            "endpoint": "/api/search?q=laptop",
            "vuln_indicator": lambda r: r.status_code == 500 or "syntax error" in r.text.lower() or "unrecognized token" in r.text.lower(),
            "evidence_desc": "Benign search query succeeds normally without error or leak",
        },
        {
            "id": "GT-SAFE-05",
            "name": "Benign GraphQL Catalog Query",
            "owasp_category": "Safe Baseline",
            "expected_ground_truth": "SAFE",
            "method": "POST",
            "endpoint": "/graphql",
            "json": {"query": "{ items { id name price } }"},
            "vuln_indicator": lambda r: "__schema" in r.text or r.status_code != 200 or "errors" in r.json(),
            "evidence_desc": "Legitimate item catalog query succeeds without schema leakage",
        },
    ]

    tp, fp, tn, fn = 0, 0, 0, 0
    case_results = []

    for case in test_cases:
        url = base_url + case["endpoint"]
        try:
            if case["method"] == "GET":
                resp = requests.get(url, timeout=3.0)
            elif case["method"] == "POST":
                resp = requests.post(url, json=case.get("json"), timeout=3.0)
            elif case["method"] == "PUT":
                resp = requests.put(url, json=case.get("json"), timeout=3.0)
            else:
                resp = None

            detected_as_vuln = case["vuln_indicator"](resp) if resp is not None else False
        except Exception as e:
            print(f"Exception on {case['id']}: {type(e)} {e}")
            detected_as_vuln = False
            resp = None

        expected_vuln = (case["expected_ground_truth"] == "VULNERABLE")

        if expected_vuln and detected_as_vuln:
            outcome = "TRUE_POSITIVE"
            tp += 1
        elif not expected_vuln and not detected_as_vuln:
            outcome = "TRUE_NEGATIVE"
            tn += 1
        elif not expected_vuln and detected_as_vuln:
            outcome = "FALSE_POSITIVE"
            fp += 1
        else:
            outcome = "FALSE_NEGATIVE"
            fn += 1

        case_results.append({
            "test_id": case["id"],
            "name": case["name"],
            "category": case["owasp_category"],
            "endpoint": case["endpoint"],
            "method": case["method"],
            "expected_ground_truth": case["expected_ground_truth"],
            "detected_as_vulnerable": detected_as_vuln,
            "outcome": outcome,
            "evidence_description": case["evidence_desc"],
            "http_status": resp.status_code if resp else None,
        })
        status_symbol = "[PASS]" if outcome in ("TRUE_POSITIVE", "TRUE_NEGATIVE") else "[FAIL]"
        print(f" {status_symbol} {case['id']}: {case['name']:<42} -> {outcome}")

    server.shutdown()

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    sensitivity_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

    summary = {
        "timestamp": time.time(),
        "total_test_cases": total,
        "contingency_table": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "sensitivity_recall": round(sensitivity_recall, 4),
            "specificity": round(specificity, 4),
            "precision": round(precision, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        },
        "cases": case_results,
    }

    out_file = PROJECT_ROOT / "research" / "phase7" / "extended_validation" / "ground_truth_lab_validation.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 78)
    print("   GROUND TRUTH AUDIT SUMMARY")
    print("=" * 78)
    print(f" Total Endpoints Tested  : {total} (10 Vulnerable, 5 Safe Baseline)")
    print(f" True Positives (TP)     : {tp} / 10")
    print(f" True Negatives (TN)     : {tn} / 5")
    print(f" False Positives (FP)    : {fp} (FPR: {fpr * 100:.2f}%)")
    print(f" False Negatives (FN)    : {fn} (FNR: {fnr * 100:.2f}%)")
    print(f" Overall Accuracy        : {accuracy * 100:.2f}%")
    print(f" Sensitivity (Recall)    : {sensitivity_recall * 100:.2f}%")
    print(f" Specificity             : {specificity * 100:.2f}%")
    print(f" Saved Results To        : {out_file}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_ground_truth_audit()

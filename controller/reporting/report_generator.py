"""Multi-Format Security Report Generator for Autonomous API Penetration Testing.

Produces structured, audit-ready security assessment reports in:
1. GitHub-Flavored Markdown (.md)
2. Machine-Readable Structured JSON (.json)
3. Self-Contained Styled HTML (.html)

Enriched with CVSS v3.1 base scores, CWE identifiers, OWASP API Top 10 (2023)
mappings, executive risk ratings, and actionable developer remediation guidance.
"""

import json
import time
from typing import Any, Dict, List, Optional

from controller.storage.evidence_store import EvidenceStore
from controller.reporting.risk_engine import RiskAssessmentEngine, Severity


class ReportGenerator:
    """Generates structured Markdown, JSON, and HTML reports from evidence database records."""

    def __init__(self, evidence_store: Optional[EvidenceStore] = None):
        self.store = evidence_store

    def generate_report(self, session_id: str) -> str:
        """Construct full Markdown report for a given session ID."""
        if not self.store:
            raise ValueError("EvidenceStore must be provided to fetch session records")

        session = self.store.get_session(session_id)
        if not session:
            return f"# Report Generation Error\nSession `{session_id}` not found in evidence store."

        findings = self.store.get_findings(session_id)
        traffic_logs = self.store.get_traffic_logs(session_id)
        tool_executions = self.store.get_tool_executions(session_id)
        plans = self.store.get_plans(session_id)
        specs = self.store.get_specifications(session_id)

        # Risk scoring
        risk_summary = RiskAssessmentEngine.calculate_session_risk_summary(findings)

        target = session.get("target", "Unknown")
        created_at_str = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime(session.get("created_at", time.time())),
        )
        turns_taken = session.get("turns_taken", 0)
        requests_sent = session.get("requests_sent", 0)
        status = session.get("status", "COMPLETED")
        notes = session.get("notes", "")

        lines = [
            "# API Security Penetration Testing Assessment Report",
            "",
            "## Session Metadata",
            f"- **Session ID:** `{session_id}`",
            f"- **Target URL:** `{target}`",
            f"- **Timestamp:** {created_at_str}",
            f"- **Session Status:** {status}",
            f"- **Agent Turns Taken:** {turns_taken}",
            f"- **HTTP Requests Dispatched:** {requests_sent}",
            f"- **Termination / Exit Note:** {notes}",
            "",
            "## 1. Scope & Authorization Verification",
            "> [!NOTE]",
            "> All testing operations were restricted strictly to authorized localhost boundaries (127.0.0.1 / localhost).",
            "> Arbitrary shell execution and destructive actions were blocked by deterministic guardrails.",
            "",
            "## 2. Executive Risk Summary",
            f"An autonomous, model-orchestrated security assessment was performed against `{target}`.",
            "",
            f"| Overall Risk Score | Overall Risk Rating | Total Findings | Confirmed Flaws | Suspected Anomalies |",
            f"| :---: | :---: | :---: | :---: | :---: |",
            f"| **{risk_summary.overall_risk_score} / 10.0** | **{risk_summary.overall_risk_rating.value}** | **{risk_summary.total_findings}** | **{risk_summary.confirmed_count}** | **{risk_summary.suspected_count}** |",
            "",
            "### Vulnerability Severity Breakdown",
            f"- 🔴 **Critical:** {risk_summary.critical_count}",
            f"- 🟠 **High:** {risk_summary.high_count}",
            f"- 🟡 **Medium:** {risk_summary.medium_count}",
            f"- 🔵 **Low:** {risk_summary.low_count}",
            f"- ⚪ **Informational:** {risk_summary.info_count}",
            "",
            "## 3. Security Findings Table",
            "| ID | Endpoint | Vulnerability Category | Severity | CVSS | CWE | Status | Verification Rule |",
            "|---|---|---|:---:|:---:|:---:|:---:|---|",
        ]

        if not findings:
            lines.append("| - | - | None identified | INFO | 0.0 | - | CLEAN | All probes produced expected baseline behavior |")
        else:
            for f in findings:
                f_id = f.get("id", "-")
                ep = f.get("endpoint", "/")
                cat = f.get("category", "N/A")
                stat = f.get("status", "UNTESTED")
                rule = f.get("verification_rule") or "None (Unverified)"
                sev = f.get("severity") or "INFORMATIONAL"
                cvss = f.get("cvss_score", 0.0)
                cwe = f.get("cwe_id", "CWE-699")
                lines.append(f"| {f_id} | `{ep}` | {cat} | **{sev}** | {cvss} | `{cwe}` | **{stat}** | `{rule}` |")

        lines.extend([
            "",
            "## 4. Detailed Technical Findings & Remediation",
        ])

        if not findings:
            lines.append("No security anomalies or confirmed flaws observed.")
        else:
            for f in findings:
                f_id = f.get("id", "-")
                ep = f.get("endpoint", "/")
                cat = f.get("category", "Finding")
                stat = f.get("status", "UNTESTED")
                sev = f.get("severity", "INFORMATIONAL")
                cvss = f.get("cvss_score", 0.0)
                cwe = f.get("cwe_id", "CWE-699")
                rule = f.get("verification_rule", "None")
                notes = f.get("evidence_notes", "No notes recorded.")
                rem = f.get("remediation", "Apply defensive validation controls.")

                # Enrich with risk profile details if not stored directly
                profile = RiskAssessmentEngine.get_finding_risk_profile(cat, status=stat, evidence_notes=notes, endpoint=ep)
                impact = f.get("technical_impact") or profile.technical_impact
                repro = f.get("reproduction_steps") or profile.reproduction_steps

                lines.extend([
                    f"### Finding #{f_id}: {cat} ({stat})",
                    f"- **Target Endpoint:** `{ep}`",
                    f"- **Severity:** `{sev}` (CVSS Base: {cvss})",
                    f"- **Weakness Enumeration:** `{cwe}`",
                    f"- **Verification Rule:** `{rule}`",
                    f"- **Technical Analysis:** {notes}",
                    f"- **Technical Impact:** {impact}",
                    f"- **Safe Reproduction Steps:** `{repro}`",
                    f"- **Actionable Remediation:** {rem}",
                ])
                raw_ev = f.get("raw_evidence")
                if raw_ev:
                    lines.append(f"- **Evidence Artifact:** `{raw_ev.get('tool', 'Tool')}` execution logged.")
                lines.append("")

        lines.extend([
            "## 5. Discovered Specifications & Reconnaissance",
        ])
        if specs:
            for sp in specs:
                lines.append(f"- **Spec Source:** `{sp.get('spec_source')}` | **Title:** {sp.get('title')} (v{sp.get('spec_version')}) | **Endpoints:** {sp.get('endpoints_count')}")
        else:
            lines.append("No external API specifications ingested.")

        lines.extend([
            "",
            "## 6. Test Plans and Methodology",
        ])
        if plans:
            for p in plans:
                plan_obj = p.get("plan", {})
                title = plan_obj.get("plan_title", "Assessment Plan")
                rationale = plan_obj.get("rationale", "")
                steps = plan_obj.get("steps", [])
                lines.append(f"### {title}")
                lines.append(f"*{rationale}*")
                for s in steps:
                    lines.append(f"- Step {s.get('step_number')}: `{s.get('tool')}` - {s.get('purpose')}")
                lines.append("")
        else:
            lines.append("No formal test plan was registered.")

        lines.extend([
            "## 7. Tool Activity & Execution Audit Trail",
            "| # | Tool Name | Approved | Policy Decision / Reason | Duration (ms) |",
            "|---|---|:---:|---|:---:|",
        ])
        if not tool_executions:
            lines.append("| - | None | - | No tool calls attempted | - |")
        else:
            for idx, te in enumerate(tool_executions, 1):
                appr_str = "YES" if te.get("approved") else "DENIED"
                lines.append(
                    f"| {idx} | `{te.get('tool_name')}` | {appr_str} | "
                    f"{te.get('policy_reason')} | {te.get('duration_ms', 0)} |"
                )

        lines.extend([
            "",
            "## 8. HTTP Traffic Summary",
            f"Total recorded HTTP interactions: {len(traffic_logs)}.",
        ])
        for t in traffic_logs[:15]:
            lines.append(f"- `[{t.get('method')}]` `{t.get('url')}` -> Status: {t.get('response_status')} ({t.get('elapsed_ms')} ms)")

        if len(traffic_logs) > 15:
            lines.append(f"- *... and {len(traffic_logs) - 15} additional HTTP interaction(s) logged in database.*")

        lines.extend([
            "",
            "## 9. Operational Safety and Limitations",
            "- Findings marked `CONFIRMED` represent deterministic verification against recorded traffic proof.",
            "- Findings marked `SUSPECTED` require further manual verification or extended authorization before concluding vulnerability presence.",
            "- No destructive commands, file modifications, or denial-of-service tests were dispatched.",
            "",
            "---",
            "*Report generated autonomously by Qwen2.5-1.5B API Security Brain and Python Controller.*",
        ])

        return "\n".join(lines)

    def generate_json_report(self, session_id: str) -> Dict[str, Any]:
        """Construct structured machine-readable JSON report for a given session ID."""
        if not self.store:
            raise ValueError("EvidenceStore must be provided to fetch session records")

        session = self.store.get_session(session_id)
        if not session:
            return {"error": f"Session '{session_id}' not found"}

        findings = self.store.get_findings(session_id)
        traffic_logs = self.store.get_traffic_logs(session_id)
        tool_executions = self.store.get_tool_executions(session_id)
        plans = self.store.get_plans(session_id)
        specs = self.store.get_specifications(session_id)

        risk_summary = RiskAssessmentEngine.calculate_session_risk_summary(findings)

        return {
            "report_version": "2.0.0",
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session": {
                "session_id": session_id,
                "target_url": session.get("target"),
                "created_at": session.get("created_at"),
                "status": session.get("status"),
                "turns_taken": session.get("turns_taken", 0),
                "requests_sent": session.get("requests_sent", 0),
                "notes": session.get("notes"),
            },
            "risk_summary": risk_summary.to_dict(),
            "findings": [
                {
                    "id": f.get("id"),
                    "endpoint": f.get("endpoint"),
                    "category": f.get("category"),
                    "status": f.get("status"),
                    "severity": f.get("severity"),
                    "cvss_score": f.get("cvss_score"),
                    "cwe_id": f.get("cwe_id"),
                    "verification_rule": f.get("verification_rule"),
                    "evidence_notes": f.get("evidence_notes"),
                    "technical_impact": f.get("technical_impact") or RiskAssessmentEngine.get_finding_risk_profile(f.get("category", ""), status=f.get("status", "CONFIRMED"), endpoint=f.get("endpoint", "/")).technical_impact,
                    "reproduction_steps": f.get("reproduction_steps") or RiskAssessmentEngine.get_finding_risk_profile(f.get("category", ""), status=f.get("status", "CONFIRMED"), endpoint=f.get("endpoint", "/")).reproduction_steps,
                    "remediation": f.get("remediation"),
                    "raw_evidence": f.get("raw_evidence"),
                }
                for f in findings
            ],
            "specifications": specs,
            "test_plans": [p.get("plan") for p in plans],
            "tool_executions": [
                {
                    "id": te.get("id"),
                    "tool_name": te.get("tool_name"),
                    "approved": te.get("approved"),
                    "policy_reason": te.get("policy_reason"),
                    "duration_ms": te.get("duration_ms"),
                }
                for te in tool_executions
            ],
            "traffic_sample": [
                {
                    "method": t.get("method"),
                    "url": t.get("url"),
                    "response_status": t.get("response_status"),
                    "elapsed_ms": t.get("elapsed_ms"),
                }
                for t in traffic_logs[:20]
            ],
            "total_traffic_count": len(traffic_logs),
        }

    def generate_html_report(self, session_id: str) -> str:
        """Construct standalone styled HTML report for a given session ID."""
        json_data = self.generate_json_report(session_id)
        if "error" in json_data:
            return f"<html><body><h1>Error</h1><p>{json_data['error']}</p></body></html>"

        sess = json_data["session"]
        risk = json_data["risk_summary"]
        findings = json_data["findings"]

        severity_badge_class = {
            "CRITICAL": "badge-critical",
            "HIGH": "badge-high",
            "MEDIUM": "badge-medium",
            "LOW": "badge-low",
            "INFORMATIONAL": "badge-info",
        }

        findings_rows = ""
        for f in findings:
            s_class = severity_badge_class.get(f.get("severity", "INFORMATIONAL"), "badge-info")
            rule = f.get("verification_rule") or "None"
            findings_rows += f"""
            <tr>
                <td>#{f.get('id')}</td>
                <td><code>{f.get('endpoint')}</code></td>
                <td><strong>{f.get('category')}</strong></td>
                <td><span class="badge {s_class}">{f.get('severity')}</span></td>
                <td>{f.get('cvss_score')}</td>
                <td><code>{f.get('cwe_id')}</code></td>
                <td><span class="badge badge-status">{f.get('status')}</span></td>
                <td><code>{rule}</code></td>
            </tr>
            <tr>
                <td colspan="8" class="finding-detail-row">
                    <p><strong>Technical Impact:</strong> {f.get('technical_impact', 'N/A')}</p>
                    <p><strong>Safe Reproduction:</strong> <code>{f.get('reproduction_steps', 'N/A')}</code></p>
                    <p><strong>Evidence & Analysis:</strong> {f.get('evidence_notes')}</p>
                    <p><strong>Remediation:</strong> {f.get('remediation')}</p>
                </td>
            </tr>
            """

        if not findings:
            findings_rows = "<tr><td colspan='8' style='text-align:center;'>No vulnerabilities identified during assessment.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Assessment Report - {sess['session_id']}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --blue: #3b82f6;
            --green: #22c55e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--surface-border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: var(--accent-cyan);
            margin: 0 0 10px 0;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 16px;
        }}
        .card h4 {{
            margin: 0 0 8px 0;
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        .card p {{
            margin: 0;
            font-size: 1.25rem;
            font-weight: 700;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .badge-critical {{ background: var(--red); color: #fff; }}
        .badge-high {{ background: var(--orange); color: #fff; }}
        .badge-medium {{ background: var(--yellow); color: #000; }}
        .badge-low {{ background: var(--blue); color: #fff; }}
        .badge-info {{ background: #64748b; color: #fff; }}
        .badge-status {{ background: var(--surface-border); color: var(--accent-cyan); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: var(--surface);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--surface-border);
        }}
        th {{
            background: #090d16;
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
        }}
        .finding-detail-row {{
            background: #141d2d;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        .finding-detail-row strong {{
            color: var(--text-primary);
        }}
        code {{
            background: #090d16;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--surface-border);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Security Penetration Testing Report</h1>
            <p>Target: <code>{sess['target_url']}</code> | Session: <code>{sess['session_id']}</code> | Status: <strong>{sess['status']}</strong></p>
        </div>

        <div class="meta-grid">
            <div class="card">
                <h4>Overall Risk Score</h4>
                <p style="color: var(--accent-cyan);">{risk['overall_risk_score']} / 10.0</p>
            </div>
            <div class="card">
                <h4>Risk Rating</h4>
                <p>{risk['overall_risk_rating']}</p>
            </div>
            <div class="card">
                <h4>Total Findings</h4>
                <p>{risk['total_findings']}</p>
            </div>
            <div class="card">
                <h4>Requests Sent</h4>
                <p>{sess['requests_sent']}</p>
            </div>
        </div>

        <h2>Security Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Endpoint</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>CWE</th>
                    <th>Status</th>
                    <th>Verification Rule</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated autonomously by Offensive AI Penetration Testing Agent & Qwen 2.5 1.5B.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

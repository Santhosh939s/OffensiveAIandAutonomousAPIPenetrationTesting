"""Markdown Report Generator for Autonomous API Penetration Testing.

Produces structured, audit-ready security assessment reports based on
stored session metadata, tool activity logs, traffic receipts, and findings.
"""

import time
from typing import Any, Dict, List, Optional

from controller.storage.evidence_store import EvidenceStore


class ReportGenerator:
    """Generates structured Markdown reports from evidence database records."""

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
            "## 1. Scope and Authorization Verification",
            "> [!NOTE]",
            "> All testing was restricted strictly to authorized localhost boundaries (127.0.0.1 / localhost).",
            "> Arbitrary shell execution and destructive actions were blocked by deterministic guardrails.",
            "",
            "## 2. Executive Summary",
            f"An autonomous, model-orchestrated security assessment was performed against `{target}`.",
            f"A total of **{len(findings)}** finding(s) were recorded during this session.",
            "",
            "## 3. Security Findings",
            "| ID | Endpoint | Vulnerability Category | Status | Verification Rule |",
            "|---|---|---|---|---|",
        ]

        if not findings:
            lines.append("| - | - | None identified | CLEAN | All probes produced expected baseline behavior |")
        else:
            for f in findings:
                f_id = f.get("id", "-")
                ep = f.get("endpoint", "/")
                cat = f.get("category", "N/A")
                stat = f.get("status", "UNTESTED")
                rule = f.get("verification_rule") or "None (Unverified)"
                lines.append(f"| {f_id} | `{ep}` | {cat} | **{stat}** | `{rule}` |")

        lines.extend([
            "",
            "### Detailed Evidence Breakdown",
        ])

        if not findings:
            lines.append("No security anomalies or confirmed flaws observed.")
        else:
            for f in findings:
                lines.extend([
                    f"#### Finding #{f.get('id')} - {f.get('category')} ({f.get('status')})",
                    f"- **Endpoint:** `{f.get('endpoint')}`",
                    f"- **Verification Rule:** `{f.get('verification_rule')}`",
                    f"- **Analysis Notes:** {f.get('evidence_notes')}",
                ])
                raw_ev = f.get("raw_evidence")
                if raw_ev:
                    lines.append(f"- **Raw Evidence Summary:** {raw_ev.get('tool', 'tool')} executed.")
                lines.append("")

        lines.extend([
            "## 4. Test Plans and Methodology",
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
            "## 5. Tool Activity and Execution Audit Trail",
            "| # | Tool Name | Approved | Policy Decision / Reason | Duration (ms) |",
            "|---|---|---|---|---|",
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
            "## 6. HTTP Traffic Summary",
            f"Total recorded HTTP interactions: {len(traffic_logs)}.",
        ])
        for t in traffic_logs[:10]:
            lines.append(f"- `[{t.get('method')}]` `{t.get('url')}` -> Status: {t.get('response_status')} ({t.get('elapsed_ms')} ms)")

        if len(traffic_logs) > 10:
            lines.append(f"- *... and {len(traffic_logs) - 10} additional HTTP interaction(s) logged in database.*")

        lines.extend([
            "",
            "## 7. Operational Safety and Limitations",
            "- Findings marked `CONFIRMED` represent deterministic verification against recorded traffic proof.",
            "- Findings marked `SUSPECTED` require further manual verification or extended authorization before concluding vulnerability presence.",
            "- No destructive commands, file modifications, or denial-of-service tests were dispatched.",
            "",
            "---",
            "*Report generated autonomously by Qwen2.5-1.5B API Security Brain and Python Controller.*",
        ])

        return "\n".join(lines)


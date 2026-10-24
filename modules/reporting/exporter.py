import json
from pathlib import Path
from typing import Union

from modules.reporting.generator import AssessmentReport


class ReportExporter:
    """Exports AssessmentReport instances into Markdown, JSON, or standalone HTML."""

    @staticmethod
    def to_markdown(report: AssessmentReport) -> str:
        md = []
        md.append(f"# Security Assessment Report: {report.assessment_name}\n")
        md.append(f"- **Target:** `{report.target}`")
        md.append(f"- **Assessment ID:** `{report.assessment_id}`")
        md.append(f"- **Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append(f"- **Policy:** `{report.scope_policy}`\n")

        md.append("## 1. Executive Summary\n")
        md.append(report.executive_summary + "\n")

        md.append("## 2. Risk Metrics & Breakdown\n")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        for sev, count in report.severity_breakdown.items():
            md.append(f"| {sev.upper()} | {count} |")
        md.append(f"| **Verified Confirmed** | **{report.verified_findings_count}** |\n")

        md.append("## 3. Technical Findings Breakdown\n")
        for idx, f in enumerate(report.findings, start=1):
            md.append(f"### {idx}. [{f.severity.value.upper()}] {f.title}")
            md.append(f"- **Verification:** `{f.verification_status.value}`")
            if f.cwe:
                md.append(f"- **CWE:** {f.cwe}")
            if f.cve:
                md.append(f"- **CVE:** {f.cve}")
            md.append(f"- **Evidence Records:** {', '.join(f.evidence_ids) or 'None'}")
            md.append(f"\n**Description:**\n{f.description}\n")

            if f.ai_reasoning:
                md.append(f"**Grounded AI Analysis:**\n{f.ai_reasoning}\n")

            md.append(f"**Remediation:**\n{f.remediation}\n")
            md.append("---\n")

        md.append("## 4. Prioritized Remediation Roadmap\n")
        for item in report.remediation_roadmap:
            md.append(f"- {item}")

        return "\n".join(md)

    @staticmethod
    def to_json(report: AssessmentReport, indent: int = 2) -> str:
        return report.model_dump_json(indent=indent)

    @staticmethod
    def to_html(report: AssessmentReport) -> str:
        """Generate a clean, standalone, printable HTML document."""
        md_content = ReportExporter.to_markdown(report)
        # Wrap in clean, modern typography
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Assessment Report - {report.assessment_name}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.6;
      max-width: 900px;
      margin: 2rem auto;
      padding: 0 1.5rem;
      color: #1a1e24;
      background: #ffffff;
    }}
    h1 {{ border-bottom: 2px solid #b45309; padding-bottom: 0.5rem; color: #11141a; }}
    h2 {{ border-bottom: 1px solid #e2e8f0; padding-bottom: 0.3rem; margin-top: 2rem; color: #1e293b; }}
    h3 {{ margin-top: 1.5rem; color: #0f172a; }}
    code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 3px; font-family: monospace; font-size: 0.9em; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #f8fafc; font-weight: 600; }}
    blockquote {{ border-left: 3px solid #b45309; margin: 1rem 0; padding-left: 1rem; color: #475569; }}
    @media print {{ body {{ margin: 0; padding: 0; }} }}
  </style>
</head>
<body>
  <pre style="white-space: pre-wrap; font-family: inherit;">{md_content}</pre>
</body>
</html>"""
        return html

    @classmethod
    def save_to_file(cls, report: AssessmentReport, output_path: Union[str, Path]) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.suffix == ".json":
            content = cls.to_json(report)
        elif path.suffix == ".html":
            content = cls.to_html(report)
        else:
            content = cls.to_markdown(report)

        path.write_text(content, encoding="utf-8")
        return path

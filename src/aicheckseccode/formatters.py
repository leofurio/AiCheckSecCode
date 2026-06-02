"""Output formatters for audit reports."""

from __future__ import annotations

import json

from .models import AuditReport


def format_json(report: AuditReport) -> str:
    """Serialize a report as stable, pretty JSON."""

    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def format_text(report: AuditReport) -> str:
    """Render a compact human-readable report."""

    lines = [
        f"Repository: {report.repository}",
        f"Source: {report.source}",
        f"Score: {report.score}/100",
        f"Files scanned: {report.stats.files_scanned}",
        f"Directories scanned: {report.stats.directories_scanned}",
        "",
        "Findings:",
    ]
    if not report.findings:
        lines.append("  No findings detected.")
        return "\n".join(lines)

    for finding in report.findings:
        location = ""
        if finding.path:
            location = f" ({finding.path}"
            if finding.line:
                location += f":{finding.line}"
            location += ")"
        lines.append(f"  [{finding.severity.value.upper()}] {finding.rule_id} {finding.title}{location}")
        if finding.message:
            lines.append(f"    {finding.message}")
    return "\n".join(lines)

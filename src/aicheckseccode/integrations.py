"""Optional integrations with external security tools (Semgrep, Trivy)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Finding, Severity

# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_SEMGREP_SEVERITY: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_TRIVY_SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,
}


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

def run_semgrep(root: Path) -> list[Finding]:
    """Run semgrep on *root* and return findings. Returns [] if semgrep is not installed."""
    if not shutil.which("semgrep"):
        return []
    result = subprocess.run(
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(root)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for hit in data.get("results", []):
        extra = hit.get("extra", {})
        raw_sev = extra.get("severity", "WARNING").upper()
        severity = _SEMGREP_SEVERITY.get(raw_sev, Severity.MEDIUM)

        rule_id = hit.get("check_id", "SEMGREP")
        # shorten to last segment: "python.lang.security.eval.eval" → "eval"
        rule_short = rule_id.split(".")[-1].upper() if "." in rule_id else rule_id

        cwe = ""
        metadata = extra.get("metadata", {})
        if isinstance(metadata.get("cwe"), list) and metadata["cwe"]:
            cwe = f" ({metadata['cwe'][0]})"
        elif isinstance(metadata.get("cwe"), str):
            cwe = f" ({metadata['cwe']})"

        findings.append(
            Finding(
                rule_id=f"SEMGREP-{rule_short}",
                title=f"Semgrep: {extra.get('message', rule_id)[:120]}{cwe}",
                severity=severity,
                category="security",
                path=str(Path(hit.get("path", "")).relative_to(root) if hit.get("path") else ""),
                line=hit.get("start", {}).get("line"),
                message=extra.get("message", ""),
                recommendation=metadata.get("fix", metadata.get("references", [""])[0] if metadata.get("references") else ""),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

def run_trivy(root: Path) -> list[Finding]:
    """Run trivy fs on *root* and return findings. Returns [] if trivy is not installed."""
    if not shutil.which("trivy"):
        return []
    result = subprocess.run(
        [
            "trivy", "fs",
            "--scanners", "vuln,secret,misconfig",
            "--format", "json",
            "--quiet",
            str(root),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for result_entry in data.get("Results", []):
        target = result_entry.get("Target", "")

        # --- Vulnerabilities (CVEs in dependencies) ---
        for vuln in result_entry.get("Vulnerabilities") or []:
            sev_raw = vuln.get("Severity", "UNKNOWN").upper()
            severity = _TRIVY_SEVERITY.get(sev_raw, Severity.LOW)
            cve_id = vuln.get("VulnerabilityID", "CVE-?")
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "?")
            fixed = vuln.get("FixedVersion", "no fix available")
            findings.append(
                Finding(
                    rule_id=f"TRIVY-{cve_id}",
                    title=f"Trivy: {cve_id} in {pkg}@{installed}",
                    severity=severity,
                    category="security",
                    path=target,
                    message=vuln.get("Description", vuln.get("Title", ""))[:300],
                    recommendation=f"Upgrade {pkg} to {fixed}." if fixed != "no fix available" else "No fix available yet; monitor the advisory.",
                )
            )

        # --- Secrets ---
        for secret in result_entry.get("Secrets") or []:
            findings.append(
                Finding(
                    rule_id="TRIVY-SECRET",
                    title=f"Trivy secret: {secret.get('Title', 'Potential secret')}",
                    severity=Severity.CRITICAL,
                    category="security",
                    path=target,
                    line=secret.get("StartLine"),
                    message=f"Secret pattern matched: {secret.get('RuleID', '')}",
                    recommendation="Rotate the credential and load secrets from a secret manager.",
                )
            )

        # --- Misconfigurations ---
        for mis in result_entry.get("Misconfigurations") or []:
            sev_raw = mis.get("Severity", "UNKNOWN").upper()
            severity = _TRIVY_SEVERITY.get(sev_raw, Severity.LOW)
            findings.append(
                Finding(
                    rule_id=f"TRIVY-MISCONF-{mis.get('ID', 'MISC')}",
                    title=f"Trivy misconfig: {mis.get('Title', '')}",
                    severity=severity,
                    category="security",
                    path=target,
                    message=mis.get("Description", ""),
                    recommendation=mis.get("Resolution", ""),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Unified runner
# ---------------------------------------------------------------------------

def run_external_tools(root: Path) -> tuple[list[Finding], list[str]]:
    """Run all available external tools and return (findings, tool_names_used)."""
    findings: list[Finding] = []
    tools_used: list[str] = []

    semgrep = run_semgrep(root)
    if semgrep or shutil.which("semgrep"):
        findings.extend(semgrep)
        tools_used.append("Semgrep")

    trivy = run_trivy(root)
    if trivy or shutil.which("trivy"):
        findings.extend(trivy)
        tools_used.append("Trivy")

    return findings, tools_used

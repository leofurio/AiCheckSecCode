"""Optional integrations with external security tools (Semgrep, Trivy)."""

from __future__ import annotations

import gzip
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
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

# Pinned release — update periodically
_TRIVY_VERSION = "0.51.4"

# Cache dir: ~/.cache/aicheckseccode/trivy or /tmp on read-only filesystems
_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "aicheckseccode"


# ---------------------------------------------------------------------------
# Trivy auto-download
# ---------------------------------------------------------------------------

def _trivy_asset_url() -> str:
    """Return the GitHub release download URL for the current OS/arch."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "Linux", "darwin": "macOS", "windows": "Windows"}
    arch_map = {
        "x86_64": "64bit",
        "amd64": "64bit",
        "aarch64": "ARM64",
        "arm64": "ARM64",
        "armv7l": "ARM",
    }
    os_name = os_map.get(system, "Linux")
    arch = arch_map.get(machine, "64bit")
    ext = "zip" if system == "windows" else "tar.gz"
    filename = f"trivy_{_TRIVY_VERSION}_{os_name}-{arch}.{ext}"
    return (
        f"https://github.com/aquasecurity/trivy/releases/download/"
        f"v{_TRIVY_VERSION}/{filename}"
    )


def _download_trivy(dest_dir: Path) -> Path:
    """Download and extract the Trivy binary into *dest_dir*. Returns binary path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    url = _trivy_asset_url()
    suffix = ".zip" if url.endswith(".zip") else ".tar.gz"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        urllib.request.urlretrieve(url, tmp_path)
        if suffix == ".tar.gz":
            with tarfile.open(tmp_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("trivy") or member.name.endswith("trivy.exe"):
                        member.name = Path(member.name).name
                        tar.extract(member, dest_dir)
        else:
            import zipfile
            with zipfile.ZipFile(tmp_path) as zf:
                for name in zf.namelist():
                    if name.endswith("trivy.exe") or name == "trivy":
                        zf.extract(name, dest_dir)
    finally:
        tmp_path.unlink(missing_ok=True)

    binary = dest_dir / ("trivy.exe" if platform.system() == "Windows" else "trivy")
    if not binary.exists():
        raise FileNotFoundError(f"Trivy binary not found after extraction in {dest_dir}")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def _ensure_trivy() -> str | None:
    """Return path to trivy binary, downloading it if necessary. Returns None on failure."""
    # 1. already in PATH
    system_trivy = shutil.which("trivy")
    if system_trivy:
        return system_trivy

    # 2. previously downloaded
    cached = _CACHE_DIR / "trivy" / ("trivy.exe" if platform.system() == "Windows" else "trivy")
    if cached.exists():
        return str(cached)

    # 3. download
    try:
        binary = _download_trivy(_CACHE_DIR / "trivy")
        return str(binary)
    except Exception:
        # try /tmp as fallback (useful on read-only filesystems like Vercel)
        try:
            tmp_dir = Path(tempfile.gettempdir()) / "aicheckseccode-trivy"
            binary = _download_trivy(tmp_dir)
            return str(binary)
        except Exception:
            return None


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
                source="semgrep",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

def run_trivy(root: Path) -> list[Finding]:
    """Run trivy fs on *root*, auto-downloading the binary if needed."""
    trivy_bin = _ensure_trivy()
    if not trivy_bin:
        return []

    result = subprocess.run(
        [
            trivy_bin, "fs",
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
                    source="trivy",
                )
            )

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
                    source="trivy",
                )
            )

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
                    source="trivy",
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
    if trivy or _ensure_trivy():
        findings.extend(trivy)
        tools_used.append("Trivy")

    return findings, tools_used

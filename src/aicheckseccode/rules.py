"""Rule implementations for security and repository hygiene checks."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from .crawler import CrawledFile
from .models import ControlResult, Finding, Severity

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    (
        "Likely hard-coded secret",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"
        ),
    ),
)

_DANGEROUS_CODE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("PY001", "Python dynamic code execution", re.compile(r"\b(eval|exec)\s*\(")),
    ("PY002", "Python shell command execution", re.compile(r"subprocess\.(Popen|call|run)\([^\n]*shell\s*=\s*True")),
    ("JS001", "JavaScript dynamic code execution", re.compile(r"\b(eval|Function)\s*\(")),
    ("SQL001", "Possible string-built SQL query", re.compile(r"(?i)(select|insert|update|delete).*(\+|%|\.format\(|f['\"])")),
)

_DEPENDENCY_MANIFESTS = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
}

_PACKAGE_MANIFESTS = {
    "package.json": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
    "pyproject.toml": {"poetry.lock", "Pipfile.lock", "uv.lock"},
    "Pipfile": {"Pipfile.lock"},
    "Cargo.toml": {"Cargo.lock"},
    "go.mod": {"go.sum"},
    "Gemfile": {"Gemfile.lock"},
}

_SECURITY_DOC_NAMES = {"security.md", "security.txt"}
_README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}
_LICENSE_NAMES = {"license", "license.md", "license.txt", "copying"}
_TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__"}
_CI_HINTS = {".github/workflows", ".gitlab-ci.yml", "circle.yml", ".circleci", "azure-pipelines.yml"}
_SAFE_HTTP_HOSTS = {"localhost", "127.0.0.1", "schemas.openxmlformats.org"}

RULE_CATALOG: tuple[ControlResult, ...] = (
    ControlResult("SEC001", "Potential secret committed", Severity.CRITICAL, "security", "passed", recommendation="Rotate committed credentials and load secrets from a secret manager or environment variables."),
    ControlResult("SEC002", "Security policy present", Severity.MEDIUM, "security", "passed", recommendation="Add SECURITY.md with vulnerability reporting and supported versions."),
    ControlResult("SEC003", "Dependency scanner configured", Severity.MEDIUM, "security", "passed", recommendation="Enable Dependabot, Renovate, pip-audit, npm audit, or an equivalent dependency scanner."),
    ControlResult("SEC004", "External URLs use HTTPS", Severity.MEDIUM, "security", "passed", recommendation="Use HTTPS for external endpoints whenever possible."),
    ControlResult("PY001", "Python dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval/exec or strictly validate inputs before dynamic execution."),
    ControlResult("PY002", "Python shell command execution", Severity.HIGH, "security", "passed", recommendation="Avoid shell=True and pass command arguments as a sequence."),
    ControlResult("JS001", "JavaScript dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval/Function constructors or strictly validate inputs."),
    ControlResult("SQL001", "Possible string-built SQL query", Severity.HIGH, "security", "passed", recommendation="Use parameterized queries or ORM-safe APIs."),
    ControlResult("HYG001", "README present", Severity.MEDIUM, "hygiene", "passed", recommendation="Add a README with setup, usage, testing, and security notes."),
    ControlResult("HYG002", "License present", Severity.LOW, "hygiene", "passed", recommendation="Add a license file so reuse terms are explicit."),
    ControlResult("HYG003", ".gitignore present", Severity.LOW, "hygiene", "passed", recommendation="Add a .gitignore tailored to the project stack."),
    ControlResult("HYG004", "Tests detected", Severity.MEDIUM, "hygiene", "passed", recommendation="Add automated tests and include the test command in documentation."),
    ControlResult("HYG005", "No unresolved maintenance markers", Severity.INFO, "hygiene", "passed", recommendation="Track maintenance debt in issues or resolve markers before release."),
    ControlResult("HYG006", "No large source files skipped", Severity.LOW, "hygiene", "passed", recommendation="Keep large generated artifacts out of source control or raise the scan limit deliberately."),
    ControlResult("HYG007", "CI configuration detected", Severity.LOW, "hygiene", "passed", recommendation="Add CI to run tests, linting, and security checks on every change."),
    ControlResult("HYG008", "Dependency lock files present", Severity.MEDIUM, "hygiene", "passed", recommendation="Commit lock files for applications so builds are reproducible."),
    ControlResult("HYG009", "Repository history clone mode reviewed", Severity.INFO, "hygiene", "info", recommendation="Use --depth 1 for large repositories when history is not needed."),
)


class RuleEngine:
    """Runs security and hygiene rules over crawled files."""

    def run(self, root: Path, files: Iterable[CrawledFile]) -> list[Finding]:
        file_list = list(files)
        findings: list[Finding] = []
        findings.extend(self._scan_file_content(file_list))
        findings.extend(self._scan_repo_shape(root, file_list))
        return findings

    def _scan_file_content(self, files: list[CrawledFile]) -> list[Finding]:
        findings: list[Finding] = []
        for crawled in files:
            path = crawled.relative_path.as_posix()
            if crawled.skipped_reason:
                if crawled.skipped_reason == "file-too-large":
                    findings.append(
                        Finding(
                            rule_id="HYG006",
                            title="Large file skipped",
                            severity=Severity.LOW,
                            category="hygiene",
                            path=path,
                            message=f"File is {crawled.size} bytes and was not scanned.",
                            recommendation="Keep large generated artifacts out of source control or raise the scan limit deliberately.",
                        )
                    )
                continue
            if crawled.text is None:
                continue

            lines = crawled.text.splitlines()
            findings.extend(self._find_secrets(path, lines))
            findings.extend(self._find_dangerous_code(path, lines))
            findings.extend(self._find_todos(path, lines))
            findings.extend(self._find_insecure_urls(path, lines))
        return findings

    def _find_secrets(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for secret_name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id="SEC001",
                            title=f"Potential secret committed: {secret_name}",
                            severity=Severity.CRITICAL,
                            category="security",
                            path=path,
                            line=line_number,
                            message="A value matching a secret pattern was found in source control.",
                            recommendation="Rotate the credential, remove it from history, and load secrets from a secret manager or environment variables.",
                        )
                    )
        return findings

    def _find_dangerous_code(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule_id, title, pattern in _DANGEROUS_CODE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=Severity.HIGH,
                            category="security",
                            path=path,
                            line=line_number,
                            message="Dangerous construct detected by a lightweight static rule.",
                            recommendation="Validate inputs, avoid dynamic execution, and prefer safe library APIs.",
                        )
                    )
        return findings

    def _find_todos(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            if re.search(r"(?i)\b(TODO|FIXME|HACK)\b", line):
                findings.append(
                    Finding(
                        rule_id="HYG005",
                        title="Unresolved maintenance marker",
                        severity=Severity.INFO,
                        category="hygiene",
                        path=path,
                        line=line_number,
                        message="A TODO/FIXME/HACK marker was found.",
                        recommendation="Track maintenance debt in issues or resolve the marker before release.",
                    )
                )
        return findings

    def _find_insecure_urls(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for url in re.findall(r"http://[^\s'\"<>()]+", line):
                host = re.sub(r"^http://", "", url).split("/", 1)[0].lower()
                if host not in _SAFE_HTTP_HOSTS:
                    findings.append(
                        Finding(
                            rule_id="SEC004",
                            title="Plain HTTP URL",
                            severity=Severity.MEDIUM,
                            category="security",
                            path=path,
                            line=line_number,
                            message="Plain HTTP can expose traffic to interception or tampering.",
                            recommendation="Use HTTPS for external endpoints whenever possible.",
                        )
                    )
        return findings

    def _scan_repo_shape(self, root: Path, files: list[CrawledFile]) -> list[Finding]:
        paths = {file.relative_path.as_posix() for file in files}
        names = {file.relative_path.name.lower() for file in files}
        lower_paths = {path.lower() for path in paths}
        findings: list[Finding] = []

        if not names.intersection(_README_NAMES):
            findings.append(_repo_finding("HYG001", "Missing README", Severity.MEDIUM, "Add a README with setup, usage, testing, and security notes."))
        if not names.intersection(_LICENSE_NAMES):
            findings.append(_repo_finding("HYG002", "Missing license", Severity.LOW, "Add a license file so reuse terms are explicit."))
        if ".gitignore" not in names:
            findings.append(_repo_finding("HYG003", "Missing .gitignore", Severity.LOW, "Add a .gitignore tailored to the project stack."))
        if not any(_has_path_hint(path, _TEST_HINTS) for path in lower_paths):
            findings.append(_repo_finding("HYG004", "No tests detected", Severity.MEDIUM, "Add automated tests and include the test command in documentation."))
        if not any(path.startswith(tuple(_CI_HINTS)) or path in _CI_HINTS for path in lower_paths):
            findings.append(_repo_finding("HYG007", "No CI configuration detected", Severity.LOW, "Add CI to run tests, linting, and security checks on every change."))
        if not names.intersection(_SECURITY_DOC_NAMES):
            findings.append(_repo_finding("SEC002", "Missing security policy", Severity.MEDIUM, "Add SECURITY.md with vulnerability reporting and supported versions."))

        manifests = {Path(path).name for path in paths}
        if manifests.intersection(_DEPENDENCY_MANIFESTS) and not _has_dependency_scanner(paths):
            findings.append(_repo_finding("SEC003", "Dependency manifest without scanner configuration", Severity.MEDIUM, "Enable Dependabot, Renovate, pip-audit, npm audit, or an equivalent dependency scanner."))
        for manifest, lock_candidates in _PACKAGE_MANIFESTS.items():
            if manifest in manifests and not manifests.intersection(lock_candidates):
                findings.append(
                    _repo_finding(
                        "HYG008",
                        f"Dependency manifest {manifest} has no lock file",
                        Severity.MEDIUM,
                        "Commit lock files for applications so builds are reproducible.",
                    )
                )

        if (root / ".git").exists() and not (root / ".git" / "shallow").exists():
            findings.append(
                Finding(
                    rule_id="HYG009",
                    title="Repository cloned with full history",
                    severity=Severity.INFO,
                    category="hygiene",
                    message="The audit ran on a full clone.",
                    recommendation="Use --depth 1 for large repositories when history is not needed.",
                )
            )
        return findings


def _repo_finding(rule_id: str, title: str, severity: Severity, recommendation: str) -> Finding:
    category = "security" if rule_id.startswith("SEC") else "hygiene"
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, recommendation=recommendation)


def _has_path_hint(path: str, hints: set[str]) -> bool:
    parts = set(Path(path).parts)
    return bool(parts.intersection(hints)) or any(part.startswith("test_") or part.endswith("_test.py") for part in parts)


def _has_dependency_scanner(paths: set[str]) -> bool:
    lower_paths = {path.lower() for path in paths}
    scanner_hints = (
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        "renovate.json",
        ".renovaterc",
        ".github/workflows/dependency-review.yml",
        ".github/workflows/dependency-review.yaml",
    )
    return any(hint in lower_paths for hint in scanner_hints)

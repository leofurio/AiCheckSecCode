from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from zipfile import ZipFile

from aicheckseccode.auditor import RepoAuditor
from aicheckseccode.cli import main
from aicheckseccode.excel import write_excel_report
from aicheckseccode.formatters import format_json
from aicheckseccode.git import clone_repository
from aicheckseccode.web import AuditRequestHandler, AuditWebApp


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_auditor_detects_security_and_hygiene_findings(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "# Demo\n")
    write_file(tmp_path / ".gitignore", "*.pyc\n")
    write_file(tmp_path / "app.py", "password = 'super-secret-value'\neval(user_input)\n# TODO fix\n")
    write_file(tmp_path / "requirements.txt", "flask==3.0.0\n")

    report = RepoAuditor().audit(str(tmp_path))

    rule_ids = {finding.rule_id for finding in report.findings}
    assert "SEC001" in rule_ids
    assert "PY001" in rule_ids
    assert "HYG005" in rule_ids
    assert "SEC003" in rule_ids
    assert report.score < 100


def test_json_formatter_outputs_report_dictionary(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "# Demo\n")
    write_file(tmp_path / "LICENSE", "MIT\n")
    write_file(tmp_path / ".gitignore", "*.pyc\n")
    write_file(tmp_path / "SECURITY.md", "Report issues by email.\n")
    write_file(tmp_path / "tests" / "test_demo.py", "def test_demo():\n    assert True\n")
    write_file(tmp_path / ".github" / "workflows" / "ci.yml", "name: ci\n")

    report = RepoAuditor().audit(str(tmp_path))
    payload = json.loads(format_json(report))

    assert payload["source"] == str(tmp_path)
    assert payload["stats"]["files_scanned"] == 6
    assert isinstance(payload["findings"], list)
    assert any(control["rule_id"] == "HYG001" for control in payload["controls"])


def test_cli_fail_under_returns_status_two_for_low_score(tmp_path: Path, capsys) -> None:
    write_file(tmp_path / "app.py", "token = '12345678901234567890'\n")

    status = main([str(tmp_path), "--format", "json", "--fail-under", "99"])

    captured = capsys.readouterr()
    assert status == 2
    assert '"score"' in captured.out


def test_excel_report_contains_controls_and_findings_sheets(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "# Demo\n")
    write_file(tmp_path / ".gitignore", "*.pyc\n")
    write_file(tmp_path / "app.py", "eval(user_input)\n")

    report = RepoAuditor().audit(str(tmp_path))
    destination = tmp_path / "audit-report.xlsx"

    write_excel_report(report, destination)

    assert destination.exists()
    with ZipFile(destination) as archive:
        workbook = archive.read("xl/workbook.xml").decode("utf-8")
        controls = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
        findings = archive.read("xl/worksheets/sheet3.xml").decode("utf-8")

    assert "Controls" in workbook
    assert "Findings" in workbook
    assert "PY001" in controls
    assert "failed" in controls
    assert "Python dynamic code execution" in findings


def test_cli_writes_excel_report(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "# Demo\n")
    destination = tmp_path / "cli-report.xlsx"

    status = main([str(tmp_path), "--excel", str(destination)])

    assert status == 0
    assert destination.exists()


def test_hyg009_does_not_fail_controls_or_score_local_repo(tmp_path: Path) -> None:
    write_file(tmp_path / "README.md", "# Demo\n")
    write_file(tmp_path / "LICENSE", "MIT\n")
    write_file(tmp_path / ".gitignore", "*.pyc\n")
    write_file(tmp_path / "SECURITY.md", "Report issues by email.\n")
    write_file(tmp_path / "tests" / "test_demo.py", "def test_demo():\n    assert True\n")
    write_file(tmp_path / ".github" / "workflows" / "ci.yml", "name: ci\n")

    report = RepoAuditor().audit(str(tmp_path))

    hyg009 = next(control for control in report.controls if control.rule_id == "HYG009")
    assert hyg009.status == "info"
    assert report.score == 100


def test_http_openxml_namespace_does_not_trigger_insecure_url_finding(tmp_path: Path) -> None:
    write_file(tmp_path / "styles.xml", '<x xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></x>\n')

    report = RepoAuditor().audit(str(tmp_path))

    assert not any(finding.rule_id == "SEC004" for finding in report.findings)


def test_pyproject_without_lock_file_fails_hyg008(tmp_path: Path) -> None:
    write_file(tmp_path / "pyproject.toml", "[project]\nname='demo'\nversion='0.1.0'\n")

    report = RepoAuditor().audit(str(tmp_path))

    assert any(finding.rule_id == "HYG008" for finding in report.findings)


def test_web_app_generates_downloadable_reports(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_file(repo / "README.md", "# Demo\n")
    reports_dir = tmp_path / "reports"

    app = AuditWebApp(reports_dir)
    result = app.audit(str(repo))

    excel_path = app.resolve_download(result["id"], "audit-report.xlsx")
    json_path = app.resolve_download(result["id"], "audit-report.json")

    assert "Download Excel" in result["html"]
    assert excel_path is not None and excel_path.exists()
    assert json_path is not None and json_path.exists()


def test_clone_repository_falls_back_when_system_temp_is_denied(tmp_path: Path, monkeypatch) -> None:
    calls: list[Path | None] = []
    original = tempfile.TemporaryDirectory
    cloned_destinations: list[Path] = []

    def fake_temporary_directory(*args, **kwargs):
        calls.append(Path(kwargs["dir"]) if "dir" in kwargs else None)
        if "dir" not in kwargs:
            raise PermissionError("denied")
        return original(*args, **kwargs)

    def fake_run(command, check, capture_output, text, timeout):
        destination = Path(command[-1])
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "README.md").write_text("# Cloned\n", encoding="utf-8")
        cloned_destinations.append(destination)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    monkeypatch.setattr("aicheckseccode.git.TemporaryDirectory", fake_temporary_directory)
    monkeypatch.setattr("aicheckseccode.git.subprocess.run", fake_run)

    with clone_repository("https://example.com/repo.git") as repo_path:
        assert repo_path.name == "repo"
        assert (repo_path / "README.md").exists()

    fallback_root = Path.cwd() / ".aicheckseccode-tmp"
    assert calls[0] is None
    assert calls[1] == fallback_root
    assert cloned_destinations


def test_enterprise_security_controls_detect_risky_code_and_container_config(tmp_path: Path) -> None:
    write_file(
        tmp_path / "app.py",
        """import hashlib
import os
import yaml

requests.get('https://example.com', verify=False)
yaml.load(payload)
hashlib.md5(payload).hexdigest()
headers = {'Access-Control-Allow-Origin': '*'}
os.system(user_command)
""",
    )
    write_file(tmp_path / "Dockerfile", "FROM python:latest\nRUN curl https://example.com/install.sh | bash\n")

    report = RepoAuditor().audit(str(tmp_path))

    rule_ids = {finding.rule_id for finding in report.findings}
    assert {"SEC007", "SEC008", "SEC009", "SEC010", "SEC011", "SEC012", "SEC013", "SEC014"}.issubset(rule_ids)


def test_dependency_version_controls_detect_unpinned_and_legacy_dependencies(tmp_path: Path) -> None:
    write_file(tmp_path / "requirements.txt", "requests==2.31.0\nflask>=2\n")
    write_file(tmp_path / "package.json", '{"dependencies":{"lodash":"4.17.20","express":"^4.17.0"}}')

    report = RepoAuditor().audit(str(tmp_path))

    findings_by_rule = {finding.rule_id: finding for finding in report.findings}
    assert "SEC005" in findings_by_rule
    assert "SEC006" in findings_by_rule
    assert any(finding.rule_id == "SEC006" and "requests" in finding.message for finding in report.findings)
    assert any(finding.rule_id == "SEC006" and "lodash" in finding.message for finding in report.findings)


def test_vercel_entrypoint_exposes_aicheckseccode_handler() -> None:
    from api.index import handler

    assert issubclass(handler, AuditRequestHandler)
    assert isinstance(handler.app, AuditWebApp)


def test_clone_repository_falls_back_to_github_archive_when_git_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            return None

        def read(self) -> bytes:
            return self.payload

    archive_buffer = io.BytesIO()
    with ZipFile(archive_buffer, "w") as archive:
        archive.writestr("repo-main/README.md", "# Archive fallback\n")

    def fake_run(command, check, capture_output, text, timeout):
        raise FileNotFoundError("git")

    def fake_urlopen(request, timeout):
        url = request.full_url
        if url == "https://api.github.com/repos/example/repo":
            return FakeResponse(b'{"default_branch":"main"}')
        if url == "https://codeload.github.com/example/repo/zip/refs/heads/main":
            return FakeResponse(archive_buffer.getvalue())
        raise AssertionError(url)

    monkeypatch.setattr("aicheckseccode.git.subprocess.run", fake_run)
    monkeypatch.setattr("aicheckseccode.git.urllib.request.urlopen", fake_urlopen)

    with clone_repository("https://github.com/example/repo.git") as repo_path:
        assert repo_path.name == "repo"
        assert (repo_path / "README.md").read_text(encoding="utf-8") == "# Archive fallback\n"

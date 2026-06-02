from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZipFile

from aicheckseccode.auditor import RepoAuditor
from aicheckseccode.cli import main
from aicheckseccode.excel import write_excel_report
from aicheckseccode.formatters import format_json


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

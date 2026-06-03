"""Vercel WSGI entrypoint — wraps the existing AuditWebApp logic in Flask."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Make the src/ package importable without an installed wheel
_src = Path(__file__).parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from flask import Flask, Response, request, send_file  # noqa: E402

from aicheckseccode.auditor import AuditConfig, RepoAuditor  # noqa: E402
from aicheckseccode.excel import write_excel_report  # noqa: E402
from aicheckseccode.git import GitCloneError  # noqa: E402
from aicheckseccode.web import render_index, render_report_page  # noqa: E402

app = Flask(__name__)

_REPORTS_DIR = Path(tempfile.gettempdir()) / "aicheckseccode-reports"
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _run_audit(source: str, max_file_bytes: int) -> tuple[str, dict]:
    """Clone, audit, write reports to /tmp, return (report_id, paths_dict)."""
    import secrets

    report_id = secrets.token_urlsafe(8)
    report_dir = _REPORTS_DIR / report_id
    report_dir.mkdir(parents=True, exist_ok=True)

    clone_dir = report_dir / "repo"
    auditor = RepoAuditor(AuditConfig(max_file_bytes=max_file_bytes, keep_clone_path=clone_dir))
    report = auditor.audit(source)

    excel_path = report_dir / "audit-report.xlsx"
    json_path = report_dir / "audit-report.json"
    write_excel_report(report, excel_path)
    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    return report_id, report


@app.route("/", methods=["GET"])
def index():
    return Response(render_index(), mimetype="text/html")


@app.route("/audit", methods=["POST"])
def audit():
    source = request.form.get("source", "").strip()
    max_file_bytes_raw = request.form.get("max_file_bytes", "1000000").strip()

    if not source:
        return Response(
            render_index("Repository URL or local path is required."),
            status=400,
            mimetype="text/html",
        )
    try:
        max_file_bytes = int(max_file_bytes_raw)
    except ValueError:
        return Response(
            render_index("Max file size must be an integer."),
            status=400,
            mimetype="text/html",
        )

    try:
        report_id, report = _run_audit(source, max_file_bytes)
    except GitCloneError as exc:
        return Response(
            render_index(f"Clone failed: {exc}"),
            status=400,
            mimetype="text/html",
        )
    except Exception as exc:
        return Response(
            render_index(f"Audit failed: {exc}"),
            status=500,
            mimetype="text/html",
        )

    return Response(render_report_page(report_id, source, report), mimetype="text/html")


@app.route("/download/<report_id>/<filename>", methods=["GET"])
def download(report_id: str, filename: str):
    candidate = (_REPORTS_DIR / report_id / filename).resolve()
    if _REPORTS_DIR.resolve() not in candidate.parents:
        return Response("Not found", status=404)
    if not candidate.exists() or not candidate.is_file():
        return Response(
            render_index(
                "Report file not found. On serverless deployments the file may have expired — "
                "re-run the audit and download immediately."
            ),
            status=404,
            mimetype="text/html",
        )
    mimetype = "application/octet-stream"
    if candidate.suffix == ".json":
        mimetype = "application/json"
    elif candidate.suffix == ".xlsx":
        mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return send_file(candidate, mimetype=mimetype, as_attachment=True, download_name=filename)

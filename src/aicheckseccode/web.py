"""Local web UI for repository audits."""

from __future__ import annotations

import argparse
import html
import io
import json
import secrets
import shutil
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auditor import AuditConfig, RepoAuditor
from .excel import write_excel_report
from .git import GitCloneError
from .rules import RULE_CATALOG

RULE_COUNT = len(RULE_CATALOG)


class AuditWebApp:
    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def audit(self, source: str, max_file_bytes: int = 1_000_000) -> dict[str, str]:
        report_id = secrets.token_urlsafe(8)
        report_dir = self.reports_dir / report_id
        report_dir.mkdir(parents=True, exist_ok=True)

        clone_dir = report_dir / "repo"
        auditor = RepoAuditor(AuditConfig(max_file_bytes=max_file_bytes, keep_clone_path=clone_dir))
        report = auditor.audit(source)

        excel_path = report_dir / "audit-report.xlsx"
        json_path = report_dir / "audit-report.json"
        write_excel_report(report, excel_path)
        json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        return {
            "id": report_id,
            "html": render_report_page(report_id, source, report),
        }

    def resolve_download(self, report_id: str, filename: str) -> Path | None:
        candidate = (self.reports_dir / report_id / filename).resolve()
        if self.reports_dir.resolve() not in candidate.parents:
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        return candidate


def _findings_table(findings: list, empty_msg: str = "No findings detected.") -> str:
    """Render a findings list as an HTML table body."""
    rows = "\n".join(
        f"<tr>"
        f"<td><code>{html.escape(f.rule_id)}</code></td>"
        f"<td><span class='sev sev-{html.escape(f.severity.value)}'>{html.escape(f.severity.value)}</span></td>"
        f"<td>{html.escape(f.path or '')}</td>"
        f"<td>{f.line or ''}</td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.message)}</td>"
        f"</tr>"
        for f in findings
    ) or f'<tr><td colspan="6">{html.escape(empty_msg)}</td></tr>'
    return rows


def _tool_status_badge(status: str) -> str:
    """Render a small status badge for a tool's run status."""
    if status == "ok":
        return '<span class="status status-passed">ran</span>'
    if status == "not_found":
        return '<span class="status status-info">not installed</span>'
    return f'<span class="status status-failed" title="{html.escape(status[6:])}">error</span>'


def _findings_panel(title: str, subtitle: str, findings: list, tool_status: str = "") -> str:
    rows = _findings_table(findings)
    count = len(findings)
    count_badge = f'<span class="count-badge">{count}</span>' if count else '<span class="count-badge count-zero">0</span>'
    status_badge = f" {_tool_status_badge(tool_status)}" if tool_status else ""
    not_installed_note = ""
    if tool_status == "not_found":
        install_cmd = "pip install semgrep" if "emgrep" in title else "see https://aquasecurity.github.io/trivy"
        not_installed_note = f'<p class="panel-note">Tool not available — install with: <code>{html.escape(install_cmd)}</code></p>'
    elif tool_status.startswith("error:"):
        not_installed_note = f'<p class="panel-note panel-note-error">Scan error: {html.escape(tool_status[6:])}</p>'
    return f"""
    <section class="panel{' panel-disabled' if tool_status == 'not_found' else ''}">
      <div class="panel-header">
        <h2>{html.escape(title)} {count_badge}{status_badge}</h2>
        <p class="panel-sub">{html.escape(subtitle)}</p>
        {not_installed_note}
      </div>
      <table>
        <thead>
          <tr><th>Rule</th><th>Severity</th><th>Path</th><th>Line</th><th>Title</th><th>Message</th></tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


def render_report_page(report_id: str, source: str, report) -> str:
    tools_html = ""
    if report.tools_used:
        badges = " ".join(f'<span class="pill pill-tool">{html.escape(t)}</span>' for t in report.tools_used)
        tools_html = f'<p class="tools-used">External scanners used: {badges}</p>'

    internal = [f for f in report.findings if f.source == "internal"]
    semgrep  = [f for f in report.findings if f.source == "semgrep"]
    trivy    = [f for f in report.findings if f.source == "trivy"]

    controls_rows = "\n".join(
        f"<tr>"
        f"<td><code>{html.escape(c.rule_id)}</code></td>"
        f"<td>{html.escape(c.category)}</td>"
        f"<td><span class='sev sev-{html.escape(c.severity.value)}'>{html.escape(c.severity.value)}</span></td>"
        f"<td>{html.escape(c.title)}</td>"
        f"<td><span class='status status-{html.escape(c.status)}'>{html.escape(c.status)}</span></td>"
        f"<td>{c.findings_count}</td>"
        f"</tr>"
        for c in report.controls
    )

    tool_status = getattr(report, "tool_status", {})
    internal_panel = _findings_panel(
        "Internal rules", f"{RULE_COUNT} built-in security & hygiene rules", internal
    )
    semgrep_panel = _findings_panel(
        "Semgrep", "Static analysis via Semgrep auto config",
        semgrep,
        tool_status.get("semgrep", ""),
    )
    trivy_panel = _findings_panel(
        "Trivy", "CVE, secrets and IaC misconfigurations via Trivy fs",
        trivy,
        tool_status.get("trivy", ""),
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AiCheckSecCode Report</title>
  <style>
    :root {{
      --bg: #f4f1e8;
      --panel: #fffaf0;
      --ink: #1b1d1f;
      --muted: #5e5a54;
      --line: #d7cdb9;
      --accent: #0f766e;
      --danger: #b42318;
      --semgrep: #1d4ed8;
      --trivy: #7c3aed;
      --shadow: 0 20px 50px rgba(54, 48, 38, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.14), transparent 32%),
        linear-gradient(180deg, #f7f2e7 0%, var(--bg) 100%);
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 64px; }}
    .hero, .panel {{
      background: rgba(255, 250, 240, 0.9);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(6px);
    }}
    .hero {{ padding: 28px; margin-bottom: 24px; }}
    h1 {{ margin: 0 0 8px; font-weight: 700; }}
    h2 {{ margin: 0; font-weight: 700; font-size: 1.2rem; }}
    p {{ margin: 0; color: var(--muted); line-height: 1.5; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 14px;
      margin-top: 22px;
    }}
    .stat {{
      padding: 16px;
      background: white;
      border-radius: 18px;
      border: 1px solid var(--line);
    }}
    .stat strong {{ display: block; font-size: 2rem; color: var(--accent); }}
    .stat small {{ color: var(--muted); font-size: 0.85rem; }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 22px;
    }}
    .btn {{
      display: inline-block;
      padding: 11px 18px;
      border-radius: 999px;
      border: 1px solid var(--accent);
      color: white;
      text-decoration: none;
      background: var(--accent);
      font-size: 0.95rem;
    }}
    .btn.secondary {{ background: transparent; color: var(--accent); }}
    /* panels */
    .panel {{ padding: 24px; margin-top: 20px; overflow: hidden; }}
    .panel-disabled {{ opacity: 0.6; }}
    .panel-header {{ margin-bottom: 14px; }}
    .panel-sub {{ font-size: 0.88rem; margin-top: 4px; }}
    /* section accent strips */
    .panel:nth-of-type(2) {{ border-left: 4px solid var(--accent); }}
    .panel:nth-of-type(3) {{ border-left: 4px solid var(--semgrep); }}
    .panel:nth-of-type(4) {{ border-left: 4px solid var(--trivy); }}
    .panel:nth-of-type(5) {{ border-left: 4px solid #b45309; }}
    /* table */
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 0.93rem;
      background: white;
      border-radius: 14px;
      overflow: hidden;
    }}
    th, td {{
      text-align: left;
      padding: 10px 10px;
      border-bottom: 1px solid #eee5d5;
      vertical-align: top;
    }}
    th {{
      background: #f2ecdf;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #57524a;
    }}
    code {{ font-size: 0.85rem; background: #f3f0e8; padding: 2px 5px; border-radius: 5px; }}
    /* severity pills */
    .sev {{
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .sev-critical {{ background:#fee2e2; color:#991b1b; }}
    .sev-high     {{ background:#fef3c7; color:#92400e; }}
    .sev-medium   {{ background:#e0f2fe; color:#075985; }}
    .sev-low      {{ background:#f0fdf4; color:#166534; }}
    .sev-info     {{ background:#f1f5f9; color:#475569; }}
    /* status pills */
    .status {{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:0.78rem; font-weight:700; }}
    .status-passed {{ background:#dcfce7; color:#166534; }}
    .status-failed {{ background:#fee2e2; color:#991b1b; }}
    .status-info   {{ background:#f1f5f9; color:#475569; }}
    /* count badge */
    .count-badge {{
      display: inline-block;
      padding: 2px 10px;
      border-radius: 999px;
      background: #fee2e2;
      color: #991b1b;
      font-size: 0.8rem;
      font-weight: 700;
      vertical-align: middle;
    }}
    .count-zero {{ background: #f0fdf4; color: #166534; }}
    /* misc */
    .pill {{
      display: inline-block;
      padding: 5px 12px;
      border-radius: 999px;
      background: #e7f7f5;
      color: var(--accent);
      font-size: 0.82rem;
    }}
    .pill-tool {{ background: #f0e8ff; color: #6d28d9; }}
    .tools-used {{ margin-top: 10px; font-size: 0.9rem; color: var(--muted); }}
    .panel-note {{ margin-top: 8px; font-size: 0.88rem; color: #92400e; background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 8px 12px; }}
    .panel-note-error {{ color: #991b1b; background: #fff1f2; border-color: #fca5a5; }}
    @media (max-width: 720px) {{
      .wrap {{ padding: 20px 14px 48px; }}
      .hero, .panel {{ border-radius: 18px; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <span class="pill">v{html.escape(__version__)} &middot; {RULE_COUNT} built-in rules</span>
      <h1>Repository audit completed</h1>
      <p>Source: {html.escape(source)}</p>
      {tools_html}
      <div class="stats">
        <div class="stat"><strong>{report.score}</strong><small>Score</small></div>
        <div class="stat"><strong>{report.stats.files_scanned}</strong><small>Files scanned</small></div>
        <div class="stat"><strong>{report.stats.directories_scanned}</strong><small>Directories</small></div>
        <div class="stat"><strong>{len(internal)}</strong><small>Internal findings</small></div>
        <div class="stat"><strong>{len(semgrep)}</strong><small>Semgrep findings</small></div>
        <div class="stat"><strong>{len(trivy)}</strong><small>Trivy findings</small></div>
      </div>
      <div class="actions">
        <a class="btn" href="/download/{report_id}/audit-report.xlsx">Download Excel</a>
        <a class="btn secondary" href="/download/{report_id}/audit-report.json">Download JSON</a>
        <a class="btn secondary" href="/">Run another audit</a>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2>Controls <span class="count-badge" style="background:#e0f2fe;color:#075985">{len(report.controls)}</span></h2>
        <p class="panel-sub">Status of all {RULE_COUNT} built-in controls</p>
      </div>
      <table>
        <thead>
          <tr><th>Rule</th><th>Category</th><th>Severity</th><th>Control</th><th>Status</th><th>Findings</th></tr>
        </thead>
        <tbody>{controls_rows}</tbody>
      </table>
    </section>

    {internal_panel}
    {semgrep_panel}
    {trivy_panel}
  </div>
</body>
</html>"""


def render_index(error: str | None = None) -> str:
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AiCheckSecCode Web</title>
  <style>
    :root {{
      --bg: #f1eee7;
      --panel: #fffdf7;
      --ink: #1f2933;
      --accent: #14532d;
      --line: #d9d2c0;
      --error: #b42318;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top, rgba(20, 83, 45, 0.16), transparent 28%),
        linear-gradient(135deg, #f6f2e8 0%, var(--bg) 100%);
      padding: 20px;
    }}
    .card {{
      width: min(760px, 100%);
      background: rgba(255, 253, 247, 0.94);
      border: 1px solid var(--line);
      border-radius: 26px;
      padding: 30px;
      box-shadow: 0 28px 60px rgba(49, 43, 34, 0.12);
    }}
    h1 {{ margin: 0 0 12px; font-size: clamp(2rem, 5vw, 3.2rem); }}
    p {{ color: #5f6358; line-height: 1.5; }}
    .meta {{
      display: inline-block;
      margin: 0 0 8px;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(20, 83, 45, 0.1);
      color: var(--accent);
      font-size: 0.85rem;
    }}
    form {{ display: grid; gap: 14px; margin-top: 22px; }}
    label {{ font-size: 0.95rem; }}
    input {{
      width: 100%;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid var(--line);
      font: inherit;
      background: white;
    }}
    button {{
      padding: 14px 18px;
      border-radius: 999px;
      border: 0;
      font: inherit;
      background: var(--accent);
      color: white;
      cursor: pointer;
      width: fit-content;
    }}
    .error {{
      color: var(--error);
      margin-top: 12px;
    }}
  </style>
</head>
<body>
  <main class="card">
    <h1>AiCheckSecCode Web</h1>
    <p class="meta">Versione {html.escape(__version__)} &middot; {RULE_COUNT} regole di sicurezza e hygiene</p>
    <p>Audit di repository Git o path locali dal browser, con report HTML immediato e file Excel scaricabile.</p>
    {error_html}
    <form method="post" action="/audit">
      <label for="source">Repository URL o path locale</label>
      <input id="source" name="source" placeholder="https://github.com/owner/repo.git oppure C:\\repo" required>
      <label for="max_file_bytes">Dimensione massima file scansionato</label>
      <input id="max_file_bytes" name="max_file_bytes" type="number" min="1" value="1000000" required>
      <button type="submit">Genera report</button>
    </form>
  </main>
</body>
</html>"""


class AuditRequestHandler(BaseHTTPRequestHandler):
    app: AuditWebApp

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._write_html(HTTPStatus.OK, render_index())
            return
        if parsed.path.startswith("/download/"):
            parts = parsed.path.split("/")
            if len(parts) != 4:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            _, _, report_id, filename = parts
            file_path = self.app.resolve_download(report_id, filename)
            if file_path is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._send_file(file_path)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/audit":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        form = self._read_form()
        source = form.get("source", [""])[0].strip()
        max_file_bytes_raw = form.get("max_file_bytes", ["1000000"])[0].strip()

        if not source:
            self._write_html(HTTPStatus.BAD_REQUEST, render_index("Repository URL or local path is required."))
            return

        try:
            max_file_bytes = int(max_file_bytes_raw)
        except ValueError:
            self._write_html(HTTPStatus.BAD_REQUEST, render_index("Max file size must be an integer."))
            return

        try:
            result = self.app.audit(source, max_file_bytes=max_file_bytes)
        except GitCloneError as exc:
            self._write_html(HTTPStatus.BAD_REQUEST, render_index(f"Clone failed: {exc}"))
            return
        except Exception as exc:  # pragma: no cover - defensive response path
            self._write_html(HTTPStatus.INTERNAL_SERVER_ERROR, render_index(f"Audit failed: {exc}"))
            return

        self._write_html(HTTPStatus.OK, result["html"])

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length).decode("utf-8")
        return parse_qs(payload, keep_blank_values=True)

    def _write_html(self, status: HTTPStatus, html_body: str) -> None:
        body = html_body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        content_type = "application/octet-stream"
        if path.suffix == ".json":
            content_type = "application/json"
        elif path.suffix == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        payload = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aicheckseccode-web",
        description="Run the local web UI for AiCheckSecCode.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", default=8000, type=int, help="Port to bind (default: 8000)")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Directory used to store downloadable reports",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = type("AuditHandler", (AuditRequestHandler,), {})
    handler.app = AuditWebApp(args.reports_dir)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"AiCheckSecCode Web running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

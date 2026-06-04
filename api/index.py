"""Vercel serverless entrypoint for the AiCheckSecCode web UI.

Render can run ``aicheckseccode-web`` as a long-lived process, but Vercel
expects a Python file under ``api/`` exposing a ``handler`` class based on
``BaseHTTPRequestHandler``. This module adapts the existing web request handler
without starting a listening socket.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aicheckseccode.web import AuditRequestHandler, AuditWebApp  # noqa: E402


class handler(AuditRequestHandler):  # noqa: N801 - Vercel requires this class name.
    """Vercel Python Runtime request handler."""


_reports_dir = Path(os.environ.get("AICHECKSECCODE_REPORTS_DIR", "/tmp/aicheckseccode-reports"))
handler.app = AuditWebApp(_reports_dir)

"""Git repository acquisition helpers."""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


class GitCloneError(RuntimeError):
    """Raised when a repository cannot be cloned."""


@contextmanager
def clone_repository(source: str, keep_path: Path | None = None):
    """Clone a Git repository or reuse a local path.

    Args:
        source: Git URL or local repository path.
        keep_path: Optional destination directory. When omitted, a temporary clone is removed automatically.
    """

    local = Path(source).expanduser()
    if local.exists():
        yield local.resolve()
        return

    if keep_path:
        keep_path.mkdir(parents=True, exist_ok=True)
        destination = keep_path
        temp_dir: TemporaryDirectory[str] | None = None
    else:
        temp_dir = TemporaryDirectory(prefix="aicheckseccode-")
        destination = Path(temp_dir.name) / "repo"

    try:
        command = ["git", "clone", "--depth", "1", source, str(destination)]
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise GitCloneError(result.stderr.strip() or f"git clone failed with exit code {result.returncode}")
        yield destination.resolve()
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()

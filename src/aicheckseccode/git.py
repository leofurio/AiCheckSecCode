"""Git repository acquisition helpers."""

from __future__ import annotations

import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


class GitCloneError(RuntimeError):
    """Raised when a repository cannot be cloned."""


def _temporary_clone_directory() -> TemporaryDirectory[str]:
    try:
        return TemporaryDirectory(prefix="aicheckseccode-")
    except PermissionError:
        fallback_root = Path.cwd() / ".aicheckseccode-tmp"
        fallback_root.mkdir(parents=True, exist_ok=True)
        return TemporaryDirectory(prefix="aicheckseccode-", dir=fallback_root)


def _clone_with_git(source: str, destination: Path) -> None:
    command = ["git", "clone", "--depth", "1", source, str(destination)]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise GitCloneError(result.stderr.strip() or f"git clone failed with exit code {result.returncode}")


def _clone_with_dulwich(source: str, destination: Path) -> None:
    try:
        from dulwich import porcelain
    except ImportError as exc:
        raise GitCloneError(
            "git binary not found and dulwich is not installed. "
            "Install dulwich or ensure git is available in PATH."
        ) from exc
    try:
        porcelain.clone(source, str(destination), depth=1, errstream=open("/dev/null", "wb"))
    except Exception as exc:
        raise GitCloneError(str(exc)) from exc


def _clone(source: str, destination: Path) -> None:
    if shutil.which("git"):
        _clone_with_git(source, destination)
    else:
        _clone_with_dulwich(source, destination)


@contextmanager
def clone_repository(source: str, keep_path: Path | None = None):
    """Clone a Git repository or reuse a local path.

    Uses the system git binary when available, dulwich otherwise (serverless envs).
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
        temp_dir = _temporary_clone_directory()
        destination = Path(temp_dir.name) / "repo"

    try:
        _clone(source, destination)
        yield destination.resolve()
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()

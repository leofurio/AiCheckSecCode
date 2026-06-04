"""Git repository acquisition helpers."""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile


class GitCloneError(RuntimeError):
    """Raised when a repository cannot be cloned."""


def _temporary_clone_directory() -> TemporaryDirectory[str]:
    try:
        return TemporaryDirectory(prefix="aicheckseccode-")
    except PermissionError:
        fallback_root = Path.cwd() / ".aicheckseccode-tmp"
        fallback_root.mkdir(parents=True, exist_ok=True)
        return TemporaryDirectory(prefix="aicheckseccode-", dir=fallback_root)


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
        keep_path.parent.mkdir(parents=True, exist_ok=True)
        if keep_path.exists():
            shutil.rmtree(keep_path)
        destination = keep_path
        temp_dir: TemporaryDirectory[str] | None = None
    else:
        temp_dir = _temporary_clone_directory()
        destination = Path(temp_dir.name) / "repo"

    try:
        try:
            _clone_with_git(source, destination)
        except GitCloneError as git_error:
            if not _can_download_github_archive(source):
                raise
            try:
                _download_github_archive(source, destination)
            except GitCloneError as archive_error:
                raise GitCloneError(f"{git_error}; GitHub archive fallback also failed: {archive_error}") from archive_error
        yield destination.resolve()
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def _clone_with_git(source: str, destination: Path) -> None:
    command = ["git", "clone", "--depth", "1", source, str(destination)]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as exc:
        raise GitCloneError("git executable is not available in this runtime") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitCloneError("git clone timed out after 300 seconds") from exc
    if result.returncode != 0:
        raise GitCloneError(result.stderr.strip() or f"git clone failed with exit code {result.returncode}")


def _can_download_github_archive(source: str) -> bool:
    return _parse_github_repo(source) is not None


def _download_github_archive(source: str, destination: Path) -> None:
    repo = _parse_github_repo(source)
    if repo is None:
        raise GitCloneError("archive fallback only supports GitHub repository URLs")

    owner, name = repo
    branch = _github_default_branch(owner, name)
    errors: list[str] = []
    for candidate_branch in dict.fromkeys([branch, "main", "master"]):
        if not candidate_branch:
            continue
        try:
            _download_and_extract_archive(owner, name, candidate_branch, destination)
            return
        except GitCloneError as exc:
            errors.append(str(exc))
    raise GitCloneError("; ".join(errors) or "unable to download GitHub archive")


def _parse_github_repo(source: str) -> tuple[str, str] | None:
    scp_match = None
    if source.startswith("git@github.com:"):
        scp_match = source.removeprefix("git@github.com:")
    elif source.startswith("ssh://git@github.com/"):
        scp_match = source.removeprefix("ssh://git@github.com/")
    if scp_match:
        parts = scp_match.removesuffix(".git").strip("/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None

    parsed = urllib.parse.urlparse(source)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = parsed.path.removesuffix(".git").strip("/").split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def _github_default_branch(owner: str, name: str) -> str | None:
    url = f"https://api.github.com/repos/{owner}/{name}"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "AiCheckSecCode"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None
    default_branch = payload.get("default_branch")
    return default_branch if isinstance(default_branch, str) else None


def _download_and_extract_archive(owner: str, name: str, branch: str, destination: Path) -> None:
    quoted_branch = urllib.parse.quote(branch, safe="")
    url = f"https://codeload.github.com/{owner}/{name}/zip/refs/heads/{quoted_branch}"
    request = urllib.request.Request(url, headers={"User-Agent": "AiCheckSecCode"})
    archive_parent = destination.parent
    archive_parent.mkdir(parents=True, exist_ok=True)
    archive_path = archive_parent / f"{name}-{branch}.zip"
    extract_root = archive_parent / f"{name}-{branch}-archive"
    if destination.exists():
        shutil.rmtree(destination)
    if extract_root.exists():
        shutil.rmtree(extract_root)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            archive_path.write_bytes(response.read())
        with ZipFile(archive_path) as archive:
            _safe_extract_archive(archive, extract_root)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise GitCloneError(f"unable to download GitHub archive for branch {branch}: {exc}") from exc
    finally:
        archive_path.unlink(missing_ok=True)

    extracted_roots = [path for path in extract_root.iterdir() if path.is_dir()]
    if len(extracted_roots) != 1:
        shutil.rmtree(extract_root, ignore_errors=True)
        raise GitCloneError(f"unexpected GitHub archive layout for branch {branch}")
    shutil.move(str(extracted_roots[0]), destination)
    shutil.rmtree(extract_root, ignore_errors=True)


def _safe_extract_archive(archive: ZipFile, destination: Path) -> None:
    destination_resolved = destination.resolve()
    for member in archive.infolist():
        member_path = (destination / member.filename).resolve()
        if destination_resolved != member_path and destination_resolved not in member_path.parents:
            raise GitCloneError(f"unsafe path in GitHub archive: {member.filename}")
    archive.extractall(destination)

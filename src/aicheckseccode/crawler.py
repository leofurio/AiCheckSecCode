"""Filesystem crawler for cloned Git repositories."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path


DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}

DEFAULT_BINARY_EXTENSIONS = {
    ".7z",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".exe",
    ".gif",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".tar",
    ".webp",
    ".zip",
}


@dataclass(frozen=True)
class CrawledFile:
    """A file discovered by the crawler."""

    absolute_path: Path
    relative_path: Path
    size: int
    text: str | None
    skipped_reason: str | None = None


@dataclass
class CrawlOptions:
    """Configuration for repository crawling."""

    ignored_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORED_DIRS))
    max_file_bytes: int = 1_000_000
    binary_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_BINARY_EXTENSIONS))


class RepositoryCrawler:
    """Depth-first crawler that yields text files and tracks skipped content."""

    def __init__(self, root: Path, options: CrawlOptions | None = None) -> None:
        self.root = root.resolve()
        self.options = options or CrawlOptions()

    def crawl(self) -> Iterator[CrawledFile]:
        for path in sorted(self.root.rglob("*")):
            relative_path = path.relative_to(self.root)
            if self._is_ignored(relative_path):
                continue
            if not path.is_file():
                continue

            size = path.stat().st_size
            if size > self.options.max_file_bytes:
                yield CrawledFile(path, relative_path, size, None, "file-too-large")
                continue
            if path.suffix.lower() in self.options.binary_extensions:
                yield CrawledFile(path, relative_path, size, None, "binary-extension")
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                yield CrawledFile(path, relative_path, size, None, "non-utf8")
                continue
            yield CrawledFile(path, relative_path, size, text)

    def count_directories(self) -> int:
        return sum(
            1
            for path in self.root.rglob("*")
            if path.is_dir() and not self._is_ignored(path.relative_to(self.root))
        )

    def _is_ignored(self, relative_path: Path) -> bool:
        return any(part in self.options.ignored_dirs for part in relative_path.parts)

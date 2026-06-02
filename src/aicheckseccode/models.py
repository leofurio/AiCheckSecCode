"""Data models for repository audit findings and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """A single repository quality or security finding."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    path: str | None = None
    line: int | None = None
    message: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class RepoStats:
    """Summary statistics gathered while crawling a repository."""

    files_scanned: int = 0
    directories_scanned: int = 0
    total_bytes: int = 0
    files_by_extension: dict[str, int] = field(default_factory=dict)
    skipped_paths: list[str] = field(default_factory=list)

    def add_file(self, path: Path, size: int) -> None:
        self.files_scanned += 1
        self.total_bytes += size
        extension = path.suffix.lower() or "<no-extension>"
        self.files_by_extension[extension] = self.files_by_extension.get(extension, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Complete audit output."""

    repository: str
    source: str
    score: int
    stats: RepoStats
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "source": self.source,
            "score": self.score,
            "stats": self.stats.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }

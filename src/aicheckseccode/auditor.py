"""High-level repository auditor orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .crawler import CrawlOptions, RepositoryCrawler
from .git import clone_repository
from .models import AuditReport, RepoStats, Severity
from .rules import RuleEngine


@dataclass(frozen=True)
class AuditConfig:
    """Configuration for a repository audit."""

    max_file_bytes: int = 1_000_000
    keep_clone_path: Path | None = None


class RepoAuditor:
    """Clones/crawls a repository and evaluates security and hygiene rules."""

    def __init__(self, config: AuditConfig | None = None) -> None:
        self.config = config or AuditConfig()
        self.rule_engine = RuleEngine()

    def audit(self, source: str) -> AuditReport:
        with clone_repository(source, self.config.keep_clone_path) as repo_path:
            crawler = RepositoryCrawler(repo_path, CrawlOptions(max_file_bytes=self.config.max_file_bytes))
            crawled_files = list(crawler.crawl())
            stats = RepoStats(directories_scanned=crawler.count_directories())
            for crawled_file in crawled_files:
                if crawled_file.skipped_reason:
                    stats.skipped_paths.append(f"{crawled_file.relative_path.as_posix()}:{crawled_file.skipped_reason}")
                else:
                    stats.add_file(crawled_file.relative_path, crawled_file.size)

            findings = self.rule_engine.run(repo_path, crawled_files)
            score = _score(findings)
            return AuditReport(
                repository=repo_path.name,
                source=source,
                score=score,
                stats=stats,
                findings=sorted(findings, key=lambda item: (_severity_rank(item.severity), item.rule_id, item.path or ""), reverse=True),
            )


def _score(findings) -> int:
    penalties = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }
    score = 100 - sum(penalties[finding.severity] for finding in findings)
    return max(0, min(100, score))


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }[severity]

"""Command-line entry point for AiCheckSecCode."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .auditor import AuditConfig, RepoAuditor
from .formatters import format_json, format_text
from .git import GitCloneError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aicheckseccode",
        description="Clone/crawl a Git repository and audit security plus hygiene quality signals.",
    )
    parser.add_argument("repo", help="Git URL or local repository path to audit")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="Maximum text file size to scan (default: 1000000)",
    )
    parser.add_argument(
        "--keep-clone-path",
        type=Path,
        help="Optional destination path where the cloned repository should be kept",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        metavar="SCORE",
        help="Exit with status 2 when the repository score is below SCORE",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    auditor = RepoAuditor(AuditConfig(max_file_bytes=args.max_file_bytes, keep_clone_path=args.keep_clone_path))
    try:
        report = auditor.audit(args.repo)
    except GitCloneError as exc:
        print(f"Unable to clone repository: {exc}", file=sys.stderr)
        return 1

    output = format_json(report) if args.format == "json" else format_text(report)
    print(output)

    if args.fail_under is not None and report.score < args.fail_under:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

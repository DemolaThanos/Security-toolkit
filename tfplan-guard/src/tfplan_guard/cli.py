from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from tfplan_guard import __version__
from tfplan_guard.logsetup import configure_logging
from tfplan_guard.models import parse_severity
from tfplan_guard.paths import resolve_cli_path
from tfplan_guard.report import render
from tfplan_guard.scan import scan_path
from tfplan_guard.suppress import ConfigError, load_suppressions

_DEFAULT_MAX_BYTES = 20_000_000
_MAX_BYTES_LIMIT = 50_000_000


class LintError(Exception):
    """The arguments could not be used."""


def cli() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    verbosity = int(args.verbose)
    try:
        configure_logging(verbosity, _log_format())
        if args.command != "check":
            parser.print_help(sys.stderr)
            return 2
        root = Path(_cli_path(args.path))
        if not root.exists():
            raise LintError(f"path does not exist: {args.path}")
        max_bytes = _DEFAULT_MAX_BYTES if args.max_bytes is None else args.max_bytes
        if max_bytes <= 0 or max_bytes > _MAX_BYTES_LIMIT:
            raise LintError(f"--max-bytes must be between 1 and {_MAX_BYTES_LIMIT}")
        suppressions = load_suppressions(Path(args.suppressions)) if args.suppressions else ()
        destination = _cli_path(args.output) if args.output else None
        report = scan_path(root, max_bytes=max_bytes, suppressions=suppressions)
        body = render(report, args.format)
        if destination:
            Path(destination).write_text(body, encoding="utf-8")
        else:
            sys.stdout.write(body)
        if report.files_checked == 0 and not report.errors:
            print("tfplan-guard: no terraform plans found", file=sys.stderr)
            return 2
        if report.errors:
            for error in report.errors:
                print(f"tfplan-guard: {error}", file=sys.stderr)
            return 2
        return 1 if report.failing(parse_severity(args.fail_on)) else 0
    except ConfigError as exc:
        for problem in exc.problems:
            print(f"tfplan-guard: {problem}", file=sys.stderr)
        return 2
    except LintError as exc:
        print(f"tfplan-guard: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"tfplan-guard: {exc}", file=sys.stderr)
        return 2


def _cli_path(raw: str) -> str:
    try:
        return resolve_cli_path(raw)
    except ValueError as exc:
        raise LintError(str(exc)) from exc


def _log_format() -> str:
    value = os.environ.get("TFPLAN_GUARD_LOG_FORMAT", "text").strip().lower()
    if not value:
        return "text"
    if value not in {"text", "json"}:
        raise LintError("TFPLAN_GUARD_LOG_FORMAT must be text or json")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfplan-guard",
        description="Check AWS Terraform plan or state JSON for security misconfigurations.",
    )
    parser.add_argument("--version", action="version", version=f"tfplan-guard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check a plan or state JSON file, or a directory of them")
    check.add_argument("path", nargs="?", default=".")
    check.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"])
    check.add_argument("--format", default="text", choices=["text", "json", "sarif"])
    check.add_argument("--output")
    check.add_argument("--suppressions", help="TOML file of suppressions; each one needs a justification")
    check.add_argument("--max-bytes", type=int)
    check.add_argument("-v", "--verbose", action="count", default=0)
    return parser

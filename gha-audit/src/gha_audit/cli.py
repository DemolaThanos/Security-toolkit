from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from gha_audit import __version__
from gha_audit.ignore import ConfigError, Ignore, load_config
from gha_audit.logsetup import configure_logging
from gha_audit.models import Options, parse_severity
from gha_audit.paths import contained_file, resolve_cli_path
from gha_audit.report import render
from gha_audit.scan import scan

_CONFIG_NAME = ".gha-audit.toml"


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
        options, ignores = _configuration(args.config, allow_flag=bool(args.allow_actions_refs))
        roots = [Path(_cli_path(raw)) for raw in args.paths] or [Path(_cli_path(".github/workflows"))]
        destination = _cli_path(args.output) if args.output else None
        report = scan(roots, options=options, ignores=ignores)
        body = render(report, args.format)
        if destination:
            # Join the cwd with the relative path so the write cannot leave it.
            contained_file(destination).write_text(body, encoding="utf-8")
        else:
            sys.stdout.write(body)
        if report.errors:
            for error in report.errors:
                print(f"gha-audit: {error}", file=sys.stderr)
            return 2
        if report.files_checked == 0:
            print("gha-audit: no workflows found", file=sys.stderr)
            return 2
        return 1 if report.failing(parse_severity(args.fail_on)) else 0
    except ConfigError as exc:
        for problem in exc.problems:
            print(f"gha-audit: {problem}", file=sys.stderr)
        return 2
    except LintError as exc:
        print(f"gha-audit: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"gha-audit: {exc}", file=sys.stderr)
        return 2


def _configuration(config: str | None, *, allow_flag: bool) -> tuple[Options, tuple[Ignore, ...]]:
    if config:
        options, ignores = load_config(Path(_cli_path(config)))
    else:
        discovered = Path.cwd() / _CONFIG_NAME
        if discovered.is_file():
            options, ignores = load_config(discovered)
        else:
            options, ignores = Options(), ()
    if allow_flag:
        options = Options(allow_actions_refs=True)
    return options, ignores


def _cli_path(raw: str) -> str:
    try:
        return resolve_cli_path(raw)
    except ValueError as exc:
        raise LintError(str(exc)) from exc


def _log_format() -> str:
    value = os.environ.get("GHA_AUDIT_LOG_FORMAT", "text").strip().lower()
    if not value:
        return "text"
    if value not in {"text", "json"}:
        raise LintError("GHA_AUDIT_LOG_FORMAT must be text or json")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gha-audit",
        description="Check GitHub Actions workflows and composite actions for unsafe patterns.",
    )
    parser.add_argument("--version", action="version", version=f"gha-audit {__version__}")
    parser.add_argument("paths", nargs="*", help="workflow files or directories (default: .github/workflows)")
    parser.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"])
    parser.add_argument("--format", default="table", choices=["table", "json", "sarif"])
    parser.add_argument("--output", help="write the report to this file instead of stdout")
    parser.add_argument("--config", help="TOML config; defaults to .gha-audit.toml in the working directory")
    parser.add_argument(
        "--allow-actions-refs",
        action="store_true",
        help="accept any ref for actions/*, including tags and branches",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    return parser

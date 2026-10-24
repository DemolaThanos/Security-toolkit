from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from k8s_harden import __version__
from k8s_harden.lint import lint_path
from k8s_harden.logsetup import configure_logging
from k8s_harden.models import parse_severity
from k8s_harden.report import render


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
        root = Path(args.path)
        if not root.exists():
            raise LintError(f"path does not exist: {root}")
        if args.max_bytes is not None and (args.max_bytes <= 0 or args.max_bytes > 20_000_000):
            raise LintError("--max-bytes must be between 1 and 20000000")
        report = lint_path(
            root,
            max_bytes=args.max_bytes or 1_000_000,
            exclude=tuple(args.exclude or []),
        )
        body = render(report, args.format)
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
        else:
            sys.stdout.write(body)
        if report.files_checked == 0 and not report.errors:
            print("k8s-harden: no manifests found", file=sys.stderr)
            return 2
        if report.errors:
            for error in report.errors:
                print(f"k8s-harden: {error}", file=sys.stderr)
            return 2
        threshold = parse_severity(args.fail_on)
        return 1 if report.failing(threshold) else 0
    except (LintError, ValueError) as exc:
        print(f"k8s-harden: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"k8s-harden: {exc}", file=sys.stderr)
        return 2


def _log_format() -> str:
    value = os.environ.get("K8S_HARDEN_LOG_FORMAT", "text").strip().lower()
    if not value:
        return "text"
    if value not in {"text", "json"}:
        raise LintError("K8S_HARDEN_LOG_FORMAT must be text or json")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s-harden",
        description="Check Kubernetes manifests for weak RBAC, committed secrets, and missing isolation.",
    )
    parser.add_argument("--version", action="version", version=f"k8s-harden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check a file or directory of manifests")
    check.add_argument("path", nargs="?", default=".")
    check.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"])
    check.add_argument("--format", default="text", choices=["text", "json", "sarif"])
    check.add_argument("--output")
    check.add_argument("--exclude", action="append", default=[])
    check.add_argument("--max-bytes", type=int)
    check.add_argument("-v", "--verbose", action="count", default=0)
    return parser

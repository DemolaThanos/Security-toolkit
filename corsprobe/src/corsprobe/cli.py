from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

from corsprobe import __version__
from corsprobe.errors import CorsprobeError, InputError
from corsprobe.logsetup import configure_logging
from corsprobe.models import parse_severity
from corsprobe.paths import resolve_cli_path
from corsprobe.probe import scan
from corsprobe.report import render
from corsprobe.targets import load_targets

_DISCLAIMER = (
    "corsprobe sends a few requests with a crafted Origin header. "
    "Use it only on systems you own or have written permission to test."
)


def cli() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    verbosity = int(args.verbose)
    try:
        configure_logging(verbosity, _log_format())
        if args.command != "scan":
            parser.print_help(sys.stderr)
            return 2
        print(_DISCLAIMER, file=sys.stderr)
        if not args.i_am_authorized and not _env_flag("CORSPROBE_AUTHORIZED"):
            raise InputError(
                "refusing to run without --i-am-authorized. "
                "corsprobe is for hosts you own or have written permission to test."
            )
        output = _prepare_output(args.output)
        targets = load_targets(args.targets, args.urls, limit=args.max_urls)
        report = scan(
            targets,
            trusted=args.trusted,
            timeout=float(args.timeout),
            concurrency=args.concurrency,
            rate=float(args.rate),
            preflight=not args.no_preflight,
            follow_off_host=bool(args.follow_off_host),
        )
        body = render(report, args.format)
        if output is None:
            sys.stdout.write(body)
        else:
            Path(output).write_text(body, encoding="utf-8")
        if report.errors:
            for failure in report.errors:
                print(f"corsprobe: {failure.target}: {failure.message}", file=sys.stderr)
            return 2
        return 1 if report.failing(parse_severity(args.fail_on)) else 0
    except CorsprobeError as exc:
        print(f"corsprobe: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        with contextlib.suppress(BrokenPipeError):
            sys.stdout.close()
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"corsprobe: {exc}", file=sys.stderr)
        return 2


def _prepare_output(raw: str | None) -> str | None:
    if not raw or raw == "-":
        return None
    cleaned = resolve_cli_path(raw)
    if os.path.isdir(cleaned):
        raise InputError(f"not a file: {raw}")
    parent = os.path.dirname(cleaned)
    if parent and not os.path.isdir(parent):
        raise InputError(f"output directory does not exist: {parent}")
    return cleaned


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _log_format() -> str:
    value = os.environ.get("CORSPROBE_LOG_FORMAT", "text").strip().lower()
    if not value:
        return "text"
    if value not in {"text", "json"}:
        raise InputError("CORSPROBE_LOG_FORMAT must be text or json")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="corsprobe", description=_DISCLAIMER)
    parser.add_argument("--version", action="version", version=f"corsprobe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("scan", help="probe URLs for CORS misconfigurations")
    command.add_argument("targets", nargs="*", help="http(s) URLs you are allowed to test")
    command.add_argument("--urls", help="file with one URL per line, or - for stdin")
    command.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you are allowed to test these URLs",
    )
    command.add_argument("--trusted", help="hostname the application intends to allow, such as example.com")
    command.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "info"])
    command.add_argument("--format", default="table", choices=["table", "json", "sarif"])
    command.add_argument("--output", help="write the report to this path instead of stdout")
    command.add_argument("--timeout", type=float, default=5.0, help="seconds for each connection")
    command.add_argument("--concurrency", type=int, default=4)
    command.add_argument(
        "--rate",
        type=float,
        default=4.0,
        help="maximum request starts per second; 0 disables the pause",
    )
    command.add_argument("--max-urls", type=int, default=100)
    command.add_argument("--no-preflight", action="store_true", help="skip the OPTIONS request")
    command.add_argument(
        "--follow-off-host",
        action="store_true",
        help="follow redirects to a different host",
    )
    command.add_argument("-v", "--verbose", action="count", default=0)
    return parser

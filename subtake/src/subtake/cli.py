from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from subtake import __version__
from subtake.check import check_hosts
from subtake.dns import SystemLookup
from subtake.errors import SubtakeError
from subtake.fingerprints import load_fingerprints
from subtake.hosts import read_host_list
from subtake.http_client import HttpProber
from subtake.logsetup import configure_logging
from subtake.paths import resolve_cli_path
from subtake.report import render

_DISCLAIMER = (
    "subtake resolves names and requests them. Use it only on systems you own or have written permission to test."
)


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
        print(_DISCLAIMER, file=sys.stderr)
        if not args.i_am_authorized and not _env_flag("SUBTAKE_AUTHORIZED"):
            raise SubtakeError(
                "refusing to run without --i-am-authorized. "
                "subtake is for hosts you own or have written permission to test."
            )
        output = _prepare_output(args.output)
        hosts = read_host_list(args.hosts, limit=args.max_hosts)
        services = load_fingerprints(args.fingerprints)
        report = check_hosts(
            hosts,
            lookup=SystemLookup(float(args.timeout)),
            prober=HttpProber(),
            services=services,
            timeout=float(args.timeout),
            concurrency=args.concurrency,
            rate=float(args.rate),
        )
        body = render(report, args.format)
        if output is None:
            sys.stdout.write(body)
        else:
            Path(output).write_text(body, encoding="utf-8")
        if report.broken:
            print(_broken(report.broken), file=sys.stderr)
            return 2
        return 1 if report.failing(args.fail_on) else 0
    except SubtakeError as exc:
        print(f"subtake: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"subtake: {exc}", file=sys.stderr)
        return 2


def _prepare_output(raw: str | None) -> str | None:
    if not raw or raw == "-":
        return None
    cleaned = resolve_cli_path(raw)
    if os.path.isdir(cleaned):
        raise SubtakeError(f"not a file: {raw}")
    parent = os.path.dirname(cleaned)
    if parent and not os.path.isdir(parent):
        raise SubtakeError(f"output directory does not exist: {parent}")
    return cleaned


def _broken(hosts: tuple[str, ...]) -> str:
    shown = ", ".join(hosts[:5])
    extra = "" if len(hosts) <= 5 else f" and {len(hosts) - 5} more"
    return f"subtake: check failed for {shown}{extra}"


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _log_format() -> str:
    value = os.environ.get("SUBTAKE_LOG_FORMAT", "text").strip().lower()
    if not value:
        return "text"
    if value not in {"text", "json"}:
        raise SubtakeError("SUBTAKE_LOG_FORMAT must be text or json")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="subtake", description=_DISCLAIMER)
    parser.add_argument("--version", action="version", version=f"subtake {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="check hostnames for dangling CNAMEs")
    check.add_argument("hosts", help="file with one hostname per line, or - for stdin")
    check.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you are allowed to test these hosts",
    )
    check.add_argument("--fail-on", default="likely", choices=["likely", "edge"])
    check.add_argument("--format", default="table", choices=["table", "json", "sarif"])
    check.add_argument("--output", help="write the report to this path instead of stdout")
    check.add_argument("--timeout", type=float, default=5.0, help="seconds for each DNS query and HTTP connection")
    check.add_argument("--concurrency", type=int, default=8)
    check.add_argument(
        "--rate",
        type=float,
        default=5.0,
        help="maximum DNS and HTTP starts per second; 0 disables the pause",
    )
    check.add_argument("--max-hosts", type=int, default=2000)
    check.add_argument("--fingerprints", help="JSON fingerprint file; replaces the bundled set")
    check.add_argument("-v", "--verbose", action="count", default=0)
    return parser

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from authrecon import __version__
from authrecon.audit import inspect, render
from authrecon.errors import ReconError
from authrecon.logsetup import configure_logging
from authrecon.models import parse_severity
from authrecon.ports import parse_ports

_DISCLAIMER = (
    "authrecon opens connections to one host you name. "
    "Use it only on systems you own or have written permission to test."
)


def cli() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    verbosity = int(args.verbose)
    try:
        configure_logging(verbosity)
        if args.command != "inspect":
            parser.print_help(sys.stderr)
            return 2
        print(_DISCLAIMER, file=sys.stderr)
        authorized = bool(args.i_am_authorized) or _env_flag("AUTHRECON_AUTHORIZED")
        if not authorized:
            raise ReconError(
                "refusing to run without --i-am-authorized. "
                "authrecon is for hosts you own or have written permission to test."
            )
        ports = parse_ports(args.ports) if args.ports else ()
        report = inspect(
            args.url,
            authorized=True,
            timeout=float(args.timeout),
            ports=ports,
        )
        body = render(report, args.format)
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
        else:
            sys.stdout.write(body)
        return 1 if report.failing(parse_severity(args.fail_on)) else 0
    except ReconError as exc:
        print(f"authrecon: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"authrecon: {exc}", file=sys.stderr)
        return 2


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authrecon",
        description=_DISCLAIMER,
    )
    parser.add_argument("--version", action="version", version=f"authrecon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect_cmd = sub.add_parser("inspect", help="inspect one http(s) URL")
    inspect_cmd.add_argument("url")
    inspect_cmd.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you are allowed to test this host",
    )
    inspect_cmd.add_argument(
        "--ports",
        help=f"optional comma-separated TCP ports on the same host (max {32})",
    )
    inspect_cmd.add_argument("--fail-on", default="medium", choices=["critical", "high", "medium", "low", "info"])
    inspect_cmd.add_argument("--format", default="text", choices=["text", "json"])
    inspect_cmd.add_argument("--output")
    inspect_cmd.add_argument("--timeout", type=float, default=10.0)
    inspect_cmd.add_argument("-v", "--verbose", action="count", default=0)
    return parser

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from devsecops_scan import __version__
from devsecops_scan.config import resolve_settings
from devsecops_scan.errors import ScanError
from devsecops_scan.logsetup import configure_logging
from devsecops_scan.publish import post_webhook, publish_s3
from devsecops_scan.report import render
from devsecops_scan.scan import run_scan

logger = logging.getLogger("devsecops_scan")


def cli() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    verbosity = int(args.verbose)
    try:
        configure_logging(verbosity)
        if args.command != "scan":
            parser.print_help(sys.stderr)
            return 2
        root = Path(args.path).expanduser()
        settings = resolve_settings(
            root=root,
            config_path=Path(args.config) if args.config else None,
            fail_on=args.fail_on,
            exclude=tuple(args.exclude or []),
            max_bytes=args.max_bytes,
            no_secrets=bool(args.no_secrets),
            no_sast=bool(args.no_sast),
            no_sca=bool(args.no_sca),
            require_pins=True if args.require_pins else None,
            advisories=args.advisories,
            dast_url=args.dast_url,
            dast_authorized=bool(args.i_am_authorized) or _env_flag("DEVSECOPS_SCAN_DAST_AUTHORIZED"),
            s3_bucket=args.s3_bucket,
            s3_key=args.s3_key,
            s3_kms_key_id=args.s3_kms_key_id,
            webhook_url=args.webhook_url,
            report_format=args.format,
            output=args.output,
            timeout=float(args.timeout),
        )
        report = run_scan(settings)
        body = render(report, settings.report_format).encode("utf-8")
        if settings.output:
            settings.output.write_bytes(body)
            logger.info("wrote %s", settings.output)
        else:
            sys.stdout.buffer.write(body)
        extension = "sarif" if settings.report_format == "sarif" else "json"
        if settings.s3_bucket:
            publish_s3(
                body,
                bucket=settings.s3_bucket,
                key=settings.s3_key or _default_key(extension),
                kms_key_id=settings.s3_kms_key_id,
            )
        if settings.webhook_url:
            post_webhook(body, settings.webhook_url, settings.webhook_token, settings.timeout)
        return 1 if report.failing(settings.fail_on) else 0
    except ScanError as exc:
        print(f"devsecops-scan: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"devsecops-scan: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsecops-scan",
        description="Scan a tree for secrets, risky patterns, and known-vulnerable dependencies.",
    )
    parser.add_argument("--version", action="version", version=f"devsecops-scan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--config", help="TOML config path")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"])
    scan.add_argument("--format", choices=["text", "json", "sarif"])
    scan.add_argument("--output")
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--max-bytes", type=int)
    scan.add_argument("--no-secrets", action="store_true")
    scan.add_argument("--no-sast", action="store_true")
    scan.add_argument("--no-sca", action="store_true")
    scan.add_argument("--require-pins", action="store_true")
    scan.add_argument("--advisories", help="OSV JSON feed; defaults to the small starter file")
    scan.add_argument("--dast-url", help="authorized passive header check of one URL")
    scan.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you are allowed to request --dast-url",
    )
    scan.add_argument("--s3-bucket")
    scan.add_argument("--s3-key")
    scan.add_argument("--s3-kms-key-id")
    scan.add_argument("--webhook-url")
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("-v", "--verbose", action="count", default=0)
    return parser


def _env_flag(name: str) -> bool:
    import os

    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def _default_key(extension: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"devsecops-scan/{stamp[:8]}/{stamp}.{extension}"

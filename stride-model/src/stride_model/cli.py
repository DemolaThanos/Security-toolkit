from __future__ import annotations

import argparse
import sys
from pathlib import Path

from stride_model import __version__
from stride_model.catalog import generate
from stride_model.logsetup import configure_logging
from stride_model.models import parse_severity
from stride_model.parse import ModelError, parse_model
from stride_model.render import failing, render_json, render_markdown


def cli() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    verbosity = int(args.verbose)
    try:
        configure_logging(verbosity)
        if args.command != "render":
            parser.print_help(sys.stderr)
            return 2
        text = Path(args.path).read_text(encoding="utf-8")
        model = parse_model(text)
        threats = generate(model)
        body = render_json(model, threats) if args.format == "json" else render_markdown(model, threats)
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
        else:
            sys.stdout.write(body)
        if args.fail_on:
            return 1 if failing(threats, parse_severity(args.fail_on)) else 0
        return 0
    except ModelError as exc:
        for problem in exc.problems:
            print(f"stride-model: {problem}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"stride-model: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if verbosity >= 2:
            raise
        print(f"stride-model: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stride-model",
        description="Turn a YAML system model into a STRIDE threat review.",
    )
    parser.add_argument("--version", action="version", version=f"stride-model {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    render = sub.add_parser("render", help="render a model")
    render.add_argument("path")
    render.add_argument("--format", default="markdown", choices=["markdown", "json"])
    render.add_argument("--output")
    render.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="exit 1 when a threat is at or above this severity",
    )
    render.add_argument("-v", "--verbose", action="count", default=0)
    return parser

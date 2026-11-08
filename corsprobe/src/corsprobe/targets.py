from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from corsprobe.errors import InputError
from corsprobe.models import Target
from corsprobe.net import parse_target
from corsprobe.paths import resolve_cli_path

_MAX_BYTES = 1_000_000
_MAX_URLS = 500


def load_targets(positional: Sequence[str], url_file: str | None, *, limit: int) -> tuple[Target, ...]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_URLS:
        raise InputError(f"max-urls must be an integer between 1 and {_MAX_URLS}")
    raws = [item.strip() for item in positional]
    if url_file:
        raws.extend(read_url_lines(url_file))
    unique: list[str] = []
    seen: set[str] = set()
    for item in raws:
        if item in seen:
            continue
        if not item:
            raise InputError("URL is empty or too long")
        seen.add(item)
        unique.append(item)
    if not unique:
        raise InputError("no URLs to scan")
    if len(unique) > limit:
        raise InputError(f"more than {limit} URLs")
    return tuple(parse_target(item) for item in unique)


def read_url_lines(path: str) -> tuple[str, ...]:
    text = _read(path)
    if "\x00" in text:
        raise InputError("URL list is not text")
    found: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if any(char.isspace() for char in line):
            raise InputError(f"line {number}: expected one URL")
        try:
            parse_target(line)
        except InputError as exc:
            raise InputError(f"line {number}: {exc}") from exc
        found.append(line)
    return tuple(found)


def _read(path: str) -> str:
    if path == "-":
        data = sys.stdin.buffer.read(_MAX_BYTES + 1)
    else:
        file = Path(resolve_cli_path(path))
        try:
            info = file.stat()
        except OSError as exc:
            raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
        if not file.is_file():
            raise InputError(f"not a file: {path}")
        if info.st_size > _MAX_BYTES:
            raise InputError(f"URL list is larger than {_MAX_BYTES} bytes")
        try:
            data = file.read_bytes()
        except OSError as exc:
            raise InputError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > _MAX_BYTES:
        raise InputError(f"URL list is larger than {_MAX_BYTES} bytes")
    try:
        return data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise InputError("URL list is not valid UTF-8") from exc

from __future__ import annotations

import sys
from pathlib import Path

from subtake.errors import SubtakeError
from subtake.net import normalize_hostname
from subtake.paths import resolve_cli_path

_MAX_BYTES = 1_000_000
_MAX_HOSTS = 10_000


def read_host_list(path: str, *, limit: int) -> tuple[str, ...]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_HOSTS:
        raise SubtakeError(f"max-hosts must be an integer between 1 and {_MAX_HOSTS}")
    return parse_hosts(_read(path), limit=limit)


def parse_hosts(text: str, *, limit: int) -> tuple[str, ...]:
    if "\x00" in text:
        raise SubtakeError("host list is not text")
    found: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        token = raw.split("#", 1)[0].strip()
        if not token:
            continue
        parts = token.split()
        if len(parts) != 1:
            raise SubtakeError(f"line {number}: expected one hostname")
        try:
            name = normalize_hostname(parts[0])
        except SubtakeError as exc:
            raise SubtakeError(f"line {number}: {exc}") from exc
        if name in seen:
            continue
        if len(found) >= limit:
            raise SubtakeError(f"more than {limit} hostnames")
        seen.add(name)
        found.append(name)
    if not found:
        raise SubtakeError("no hostnames in input")
    return tuple(found)


def _read(path: str) -> str:
    if path == "-":
        data = sys.stdin.buffer.read(_MAX_BYTES + 1)
    else:
        file = Path(resolve_cli_path(path))
        try:
            info = file.stat()
        except OSError as exc:
            raise SubtakeError(f"cannot read {path}: {exc.strerror or exc}") from exc
        if not file.is_file():
            raise SubtakeError(f"not a file: {path}")
        if info.st_size > _MAX_BYTES:
            raise SubtakeError(f"host list is larger than {_MAX_BYTES} bytes")
        try:
            data = file.read_bytes()
        except OSError as exc:
            raise SubtakeError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(data) > _MAX_BYTES:
        raise SubtakeError(f"host list is larger than {_MAX_BYTES} bytes")
    try:
        return data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise SubtakeError("host list is not valid UTF-8") from exc

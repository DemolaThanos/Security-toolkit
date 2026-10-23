from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterable

from authrecon.errors import TargetError
from authrecon.models import PortResult
from authrecon.net import classify_host

MAX_PORTS = 32
_DELAY_SECONDS = 0.2


class PortSpecError(TargetError):
    """The port list is empty, too wide, or not numeric."""


def parse_ports(spec: str) -> tuple[int, ...]:
    ports: list[int] = []
    seen: set[int] = set()
    for part in spec.split(","):
        item = part.strip()
        if not item:
            continue
        values: Iterable[int]
        try:
            if "-" in item:
                start_text, end_text = item.split("-", 1)
                start, end = int(start_text), int(end_text)
                if end < start:
                    raise PortSpecError(f"invalid port range {item}")
                values = range(start, end + 1)
            else:
                values = (int(item),)
        except ValueError as exc:
            raise PortSpecError(f"invalid port {item!r}") from exc
        for port in values:
            if port < 1 or port > 65535:
                raise PortSpecError(f"port {port} is out of range")
            if port not in seen:
                seen.add(port)
                ports.append(port)
    if not ports:
        raise PortSpecError("port list is empty")
    if len(ports) > MAX_PORTS:
        raise PortSpecError(f"port list has {len(ports)} ports; the limit is {MAX_PORTS}")
    return tuple(ports)


def probe_ports(
    host: str,
    ports: tuple[int, ...],
    timeout: float,
    *,
    sleeper: Callable[[float], None] | None = None,
) -> tuple[PortResult, ...]:
    classify_host(host)
    pause = sleeper or time.sleep
    results: list[PortResult] = []
    for index, port in enumerate(ports):
        if index:
            pause(_DELAY_SECONDS)
        results.append(_one(host, port, timeout))
    return tuple(results)


def _one(host: str, port: int, timeout: float) -> PortResult:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (TimeoutError, OSError):
        return PortResult(port=port, open=False, banner="")
    try:
        sock.settimeout(0.4)
        try:
            data = sock.recv(256)
        except (TimeoutError, OSError):
            data = b""
    finally:
        sock.close()
    return PortResult(port=port, open=True, banner=_banner(data))


def _banner(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    cleaned = "".join(char if char.isprintable() else " " for char in text)
    return cleaned.strip()[:120]

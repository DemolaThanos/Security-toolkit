from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from collections.abc import Callable

from subtake import __version__
from subtake.net import public_addresses, usable_address

USER_AGENT = f"subtake/{__version__}"
_MAX_BODY = 65_536
_MAX_ADDRESSES = 4

Opener = Callable[[str, str, str, float], http.client.HTTPConnection]


class RefusedAddress(Exception):
    """The address is not a public unicast target."""


class HttpSnapshot:
    def __init__(self, status: int | None, body: str, error: str | None) -> None:
        self.status = status
        self.body = body
        self.error = error


class HttpProber:
    def __init__(self, opener: Opener | None = None) -> None:
        self._open = opener or open_connection

    def probe(self, host: str, sni: str, addresses: tuple[str, ...], timeout: float) -> HttpSnapshot:
        targets = public_addresses(addresses)
        if targets is None:
            return HttpSnapshot(None, "", "refusing non-public address")
        if not targets:
            return HttpSnapshot(None, "", "connection failed")
        errors: list[str] = []
        try:
            for scheme in _schemes(sni):
                found, reason = self._first(scheme, host, sni, targets, timeout)
                if found is not None:
                    return found
                errors.append(f"{scheme} {reason}")
        except RefusedAddress as exc:
            return HttpSnapshot(None, "", str(exc))
        return HttpSnapshot(None, "", "; ".join(errors) or "connection failed")

    def _first(
        self,
        scheme: str,
        host: str,
        sni: str,
        addresses: tuple[str, ...],
        timeout: float,
    ) -> tuple[HttpSnapshot | None, str]:
        reason = "connection failed"
        for ip in addresses[:_MAX_ADDRESSES]:
            try:
                conn = self._open(scheme, ip, sni, timeout)
                return _exchange(conn, host), reason
            except RefusedAddress:
                raise
            except (TimeoutError, OSError, ssl.SSLError, http.client.HTTPException, ValueError, TypeError) as exc:
                reason = _error_text(exc)
        return None, reason


def open_connection(scheme: str, ip: str, sni: str, timeout: float) -> http.client.HTTPConnection:
    checked = usable_address(ip)
    if checked is None:
        raise RefusedAddress("refusing non-public address")
    if scheme == "https":
        return _open_tls(checked, sni, timeout)
    if scheme == "http":
        return _open_plain(checked, timeout)
    raise RefusedAddress("unsupported URL scheme")


def _open_tls(ip: str, sni: str, timeout: float) -> http.client.HTTPSConnection:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection((ip, 443), timeout)
    try:
        # SNI is the provider name on the certificate. The Host header stays
        # the name under test, which is what the provider routes on.
        wrapped = context.wrap_socket(raw, server_hostname=sni)
    except (TimeoutError, OSError, ssl.SSLError):
        raw.close()
        raise
    conn = http.client.HTTPSConnection(sni, 443, timeout=timeout, context=context)
    conn.sock = wrapped
    return conn


def _open_plain(ip: str, timeout: float) -> http.client.HTTPConnection:
    raw = socket.create_connection((ip, 80), timeout)
    conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
    conn.sock = raw
    return conn


def _exchange(conn: http.client.HTTPConnection, host: str) -> HttpSnapshot:
    try:
        conn.request(
            "GET",
            "/",
            headers={
                "Host": host,
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        raw = response.read(_MAX_BODY)
        status = int(response.status)
    finally:
        conn.close()
    return HttpSnapshot(status, raw.decode("utf-8", "replace"), None)


def _schemes(sni: str) -> list[str]:
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        return ["https", "http"]
    return ["http"]


def _error_text(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls failed"
    if isinstance(exc, (http.client.HTTPException, ValueError, TypeError)):
        return "http failed"
    return "connection failed"

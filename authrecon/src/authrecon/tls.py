from __future__ import annotations

import contextlib
import socket
import ssl
from datetime import UTC, datetime

from authrecon.models import TlsInfo
from authrecon.net import classify_host

_LEGACY = (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1))


def probe_tls(host: str, port: int, timeout: float) -> TlsInfo:
    classify_host(host)
    legacy_timeout = min(timeout, 5.0)
    try:
        sock = _handshake(host, port, timeout, minimum=ssl.TLSVersion.TLSv1_2, verify=True)
        verified = True
        verify_error = None
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verify_error = getattr(exc, "verify_message", None) or exc.strerror or "certificate verification failed"
        try:
            sock = _handshake(host, port, timeout, minimum=ssl.TLSVersion.TLSv1_2, verify=False)
        except (ssl.SSLError, TimeoutError, OSError) as inner:
            return _failed(str(inner), verify_error)
    except (ssl.SSLError, TimeoutError, OSError):
        accepted, unknown = _legacy(host, port, legacy_timeout)
        return TlsInfo(
            protocol=None,
            cipher=None,
            verified=False,
            verify_error=None,
            not_after=None,
            subject=None,
            legacy_accepted=accepted,
            legacy_unknown=unknown,
            handshake_error=f"TLS 1.2+ handshake failed for {host}:{port}",
        )
    try:
        protocol = sock.version()
        cipher_bits = sock.cipher()
        cipher = cipher_bits[0] if cipher_bits else None
        subject, not_after = _certificate(sock, verified)
    finally:
        sock.close()
    accepted, unknown = _legacy(host, port, legacy_timeout)
    return TlsInfo(
        protocol=protocol,
        cipher=cipher,
        verified=verified,
        verify_error=None if verified else verify_error,
        not_after=not_after,
        subject=subject,
        legacy_accepted=accepted,
        legacy_unknown=unknown,
        handshake_error=None,
    )


def _failed(handshake_error: str, verify_error: str | None) -> TlsInfo:
    return TlsInfo(
        protocol=None,
        cipher=None,
        verified=False,
        verify_error=verify_error,
        not_after=None,
        subject=None,
        legacy_accepted=(),
        legacy_unknown=(),
        handshake_error=handshake_error,
    )


def _handshake(
    host: str,
    port: int,
    timeout: float,
    *,
    minimum: ssl.TLSVersion,
    maximum: ssl.TLSVersion | None = None,
    verify: bool,
) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = minimum
    if maximum is not None:
        context.maximum_version = maximum
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def _certificate(sock: ssl.SSLSocket, verified: bool) -> tuple[str | None, datetime | None]:
    if not verified:
        # getpeercert() is empty unless the handshake verified the chain.
        return None, None
    cert = sock.getpeercert()
    if not isinstance(cert, dict):
        return None, None
    subject = _common_name(cert.get("subject"))
    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return subject, None
    try:
        parsed = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)
    except ValueError:
        return subject, None
    return subject, parsed


def _common_name(subject: object) -> str | None:
    if not isinstance(subject, tuple):
        return None
    for rdn in subject:
        if not isinstance(rdn, tuple):
            continue
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2 and item[0] == "commonName":
                return str(item[1])
    return None


def _legacy(host: str, port: int, timeout: float) -> tuple[tuple[str, ...], tuple[str, ...]]:
    accepted: list[str] = []
    unknown: list[str] = []
    for label, version in _LEGACY:
        result = _legacy_one(host, port, timeout, version)
        if result is True:
            accepted.append(label)
        elif result is None:
            unknown.append(label)
    return tuple(accepted), tuple(unknown)


def _legacy_one(host: str, port: int, timeout: float, version: ssl.TLSVersion) -> bool | None:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
    except ValueError:
        return None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (TimeoutError, OSError):
        return None
    try:
        wrapped = context.wrap_socket(raw, server_hostname=host)
        wrapped.close()
        return True
    except ssl.SSLError:
        return False
    except (TimeoutError, OSError):
        return None
    finally:
        with contextlib.suppress(OSError):
            raw.close()

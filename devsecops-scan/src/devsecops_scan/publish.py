from __future__ import annotations

import http.client
import importlib
import logging
import re
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit

from devsecops_scan import __version__
from devsecops_scan.errors import PublishError, TargetError
from devsecops_scan.net import open_http, resolve_host

logger = logging.getLogger("devsecops_scan.publish")

OpenFn = Callable[[Any, float], Any]
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def publish_s3(
    body: bytes,
    *,
    bucket: str,
    key: str,
    kms_key_id: str | None,
    content_type: str = "application/json",
    client: Any | None = None,
) -> None:
    bucket = _bucket(bucket)
    key = _key(key)
    if kms_key_id is not None:
        kms_key_id = _kms(kms_key_id)
    s3 = client or _s3_client()
    arguments: dict[str, object] = {
        "Bucket": bucket,
        "Key": key,
        "Body": body,
        "ContentType": content_type,
        "ServerSideEncryption": "AES256",
    }
    if kms_key_id:
        arguments["ServerSideEncryption"] = "aws:kms"
        arguments["SSEKMSKeyId"] = kms_key_id
    try:
        s3.put_object(**arguments)
    except Exception as exc:
        raise PublishError(f"S3 upload failed: {exc.__class__.__name__}") from exc
    logger.info("uploaded s3://%s/%s", bucket, key)


def post_webhook(
    body: bytes,
    url: str,
    token: str | None,
    timeout: float,
    opener: OpenFn | None = None,
) -> None:
    parts = _webhook_parts(url)
    try:
        resolved = resolve_host(parts.hostname or "")
    except TargetError as exc:
        raise PublishError(str(exc)) from exc
    if opener is not None:
        _via_opener(opener, url, body, token, timeout, parts)
        return
    port = parts.port or 443
    try:
        conn = open_http("https", resolved, port, timeout, True)
        try:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"devsecops-scan/{__version__}",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"
            conn.request("POST", _path(parts), body=body, headers=headers)
            response = conn.getresponse()
            response.read(1024)
            status = int(response.status)
        finally:
            conn.close()
    except PublishError:
        raise
    except (TimeoutError, OSError, ssl.SSLError, http.client.HTTPException, TargetError) as exc:
        detail = _scrub(str(exc), token)
        detail = _scrub(detail, parts.query)
        raise PublishError(f"webhook request to {parts.netloc} failed: {detail}") from exc
    if status in {301, 302, 303, 307, 308}:
        refuse_redirect(status)
    if status >= 300:
        raise PublishError(f"webhook on {parts.netloc} returned HTTP {status}")
    logger.info("delivered report to webhook host %s", parts.hostname)


def refuse_redirect(code: int) -> None:
    raise PublishError(f"webhook returned HTTP {code}; not following redirects")


def _webhook_parts(url: str) -> SplitResult:
    if len(url) > 2048:
        raise PublishError("webhook URL is too long")
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname is None:
        raise PublishError("webhook URL must be https and include a host")
    if parts.username or parts.password:
        raise PublishError("webhook URL must not contain credentials")
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise PublishError("webhook URL port is out of range")
    return parts


def _via_opener(
    opener: OpenFn,
    url: str,
    body: bytes,
    token: str | None,
    timeout: float,
    parts: SplitResult,
) -> None:
    from urllib.request import Request

    # The URL is already constrained to https. This hook exists so tests can
    # observe the request without opening a socket.
    request = Request(url, data=body, method="POST")  # noqa: S310
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", f"devsecops-scan/{__version__}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with opener(request, timeout) as response:
            status = getattr(response, "status", 200)
            if status in {301, 302, 303, 307, 308}:
                refuse_redirect(int(status))
            if isinstance(status, int) and status >= 300:
                raise PublishError(f"webhook on {parts.netloc} returned HTTP {status}")
    except PublishError:
        raise
    except Exception as exc:
        detail = _scrub(str(exc), token)
        detail = _scrub(detail, parts.query)
        raise PublishError(f"webhook request to {parts.netloc} failed: {detail}") from exc


def _path(parts: SplitResult) -> str:
    path = parts.path or "/"
    target = f"{path}?{parts.query}" if parts.query else path
    if any(char in target for char in "\r\n\x00"):
        raise PublishError("webhook URL path is not usable")
    return target


def _bucket(value: str) -> str:
    name = value.strip()
    if not _BUCKET.fullmatch(name) or ".." in name:
        raise PublishError("S3 bucket name is invalid")
    return name


def _key(value: str) -> str:
    if not value or len(value) > 1024 or "\\" in value or _CONTROL.search(value):
        raise PublishError("S3 key is invalid")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise PublishError("S3 key is invalid")
    return value


def _kms(value: str) -> str:
    if not value.strip() or len(value) > 2048 or _CONTROL.search(value) or any(char.isspace() for char in value):
        raise PublishError("KMS key id is invalid")
    return value.strip()


def _s3_client() -> Any:
    try:
        module = importlib.import_module("boto3")
    except ImportError as exc:
        raise PublishError("S3 publishing requires boto3; install devsecops-scan[s3]") from exc
    client_factory = getattr(module, "client", None)
    if not callable(client_factory):
        raise PublishError("boto3.client is not available")
    return client_factory("s3")


def _scrub(text: str, secret: str | None) -> str:
    if secret and secret in text:
        return text.replace(secret, "***")
    return text

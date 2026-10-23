from __future__ import annotations

import importlib
import logging
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request

from devsecops_scan.errors import PublishError, TargetError
from devsecops_scan.net import classify_host

logger = logging.getLogger("devsecops_scan.publish")

OpenFn = Callable[[Request, float], Any]


def publish_s3(
    body: bytes,
    *,
    bucket: str,
    key: str,
    kms_key_id: str | None,
    content_type: str = "application/json",
    client: Any | None = None,
) -> None:
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
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise PublishError("webhook URL must be http or https and include a host")
    if parts.username or parts.password:
        raise PublishError("webhook URL must not contain credentials")
    try:
        classify_host(parts.hostname)
    except TargetError as exc:
        raise PublishError(str(exc)) from exc
    request = Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "devsecops-scan/0.1.0")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    open_request = opener or _open
    try:
        with open_request(request, timeout) as response:
            status = getattr(response, "status", 200)
            if isinstance(status, int) and status >= 300:
                raise PublishError(f"webhook on {parts.netloc} returned HTTP {status}")
    except PublishError:
        raise
    except Exception as exc:
        detail = _scrub(str(exc), token)
        detail = _scrub(detail, parts.query)
        raise PublishError(f"webhook request to {parts.netloc} failed: {detail}") from exc
    logger.info("delivered report to webhook host %s", parts.netloc)


def refuse_redirect(code: int) -> None:
    raise PublishError(f"webhook returned HTTP {code}; not following redirects")


def _open(request: Request, timeout: float) -> Any:
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            req: object,
            fp: object,
            code: int,
            msg: object,
            headers: object,
            newurl: str,
        ) -> None:
            del req, fp, msg, headers, newurl
            refuse_redirect(code)

    opener = urllib.request.build_opener(_NoRedirect)
    return opener.open(request, timeout=timeout)


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

from __future__ import annotations

import math
import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from devsecops_scan.errors import ConfigError
from devsecops_scan.models import Severity, parse_severity

_MAX_BYTES = 20_000_000

_KEYS = frozenset(
    {
        "advisories",
        "exclude",
        "fail_on",
        "format",
        "max_bytes",
        "require_pins",
        "sast",
        "sca",
        "secrets",
    }
)

# Destinations and credentials stay in the environment or on the CLI.
_SINK_KEYS = frozenset(
    {
        "aws_role_arn",
        "password",
        "s3_bucket",
        "s3_key",
        "s3_kms_key_id",
        "token",
        "webhook_token",
        "webhook_url",
    }
)


@dataclass(frozen=True)
class Settings:
    root: Path
    fail_on: Severity
    exclude: tuple[str, ...]
    max_bytes: int
    secrets: bool
    sast: bool
    sca: bool
    require_pins: bool
    advisories: Path | None
    dast_url: str | None
    dast_authorized: bool
    s3_bucket: str | None
    s3_key: str | None
    s3_kms_key_id: str | None
    webhook_url: str | None
    webhook_token: str | None
    report_format: str
    output: Path | None
    timeout: float


def resolve_settings(
    *,
    root: Path,
    config_path: Path | None,
    fail_on: str | None,
    exclude: tuple[str, ...],
    max_bytes: int | None,
    no_secrets: bool,
    no_sast: bool,
    no_sca: bool,
    require_pins: bool | None,
    advisories: str | None,
    dast_url: str | None,
    dast_authorized: bool,
    s3_bucket: str | None,
    s3_key: str | None,
    s3_kms_key_id: str | None,
    webhook_url: str | None,
    report_format: str | None,
    output: str | None,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> Settings:
    if not root.exists():
        raise ConfigError(f"path does not exist: {root}")
    environment = env if env is not None else os.environ
    config_file = config_path or _default_config(root)
    data: dict[str, object] = {}
    config_dir = root if root.is_dir() else root.parent
    if config_file is not None:
        data = _load_toml(config_file)
        config_dir = config_file.parent
    try:
        fail = parse_severity(_pick_str(fail_on, data.get("fail_on"), "high", "fail_on"))
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    report_fmt = _pick_str(report_format, data.get("format"), "text", "format")
    if report_fmt not in {"text", "json", "sarif"}:
        raise ConfigError("format must be text, json, or sarif")
    return Settings(
        root=root,
        fail_on=fail,
        exclude=_excludes(data.get("exclude"), exclude),
        max_bytes=_positive_int(
            _first(max_bytes, data.get("max_bytes"), 1_000_000),
            "max_bytes",
            upper=_MAX_BYTES,
        ),
        secrets=_flag(data.get("secrets"), True) and not no_secrets,
        sast=_flag(data.get("sast"), True) and not no_sast,
        sca=_flag(data.get("sca"), True) and not no_sca,
        require_pins=_flag(data.get("require_pins"), True) if require_pins is None else require_pins,
        advisories=_advisories(advisories, data.get("advisories"), config_dir, root),
        dast_url=dast_url,
        dast_authorized=dast_authorized,
        # Bucket and webhook destinations use ambient credentials. A file in the
        # tree is untrusted, so those values come only from the CLI or the environment.
        s3_bucket=_blank_to_none(_pick_optional(s3_bucket, environment.get("DEVSECOPS_SCAN_S3_BUCKET"), None)),
        s3_key=_blank_to_none(_pick_optional(s3_key, environment.get("DEVSECOPS_SCAN_S3_KEY"), None)),
        s3_kms_key_id=_blank_to_none(
            _pick_optional(s3_kms_key_id, environment.get("DEVSECOPS_SCAN_S3_KMS_KEY_ID"), None)
        ),
        webhook_url=_blank_to_none(_pick_optional(webhook_url, environment.get("DEVSECOPS_SCAN_WEBHOOK_URL"), None)),
        webhook_token=_blank_to_none(environment.get("DEVSECOPS_SCAN_WEBHOOK_TOKEN")),
        report_format=report_fmt,
        output=Path(output) if output else None,
        timeout=_timeout(timeout),
    )


def _default_config(root: Path) -> Path | None:
    base = root if root.is_dir() else root.parent
    candidate = base / ".devsecops-scan.toml"
    return candidate if candidate.is_file() else None


def _load_toml(path: Path) -> dict[str, object]:
    try:
        info = path.stat()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if info.st_size > 1_000_000:
        raise ConfigError(f"{path} is larger than 1000000 bytes")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not raw.strip():
        return {}
    try:
        loaded = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    sinks = set(loaded) & _SINK_KEYS
    if sinks:
        names = ", ".join(sorted(sinks))
        raise ConfigError(
            f"credential sink in config ({names}); "
            "use DEVSECOPS_SCAN_S3_BUCKET, DEVSECOPS_SCAN_S3_KEY, DEVSECOPS_SCAN_S3_KMS_KEY_ID, "
            "DEVSECOPS_SCAN_WEBHOOK_URL, or the matching CLI flag. "
            "The bearer token is only DEVSECOPS_SCAN_WEBHOOK_TOKEN. "
            "An AWS role ARN belongs in the Actions secret AWS_ROLE_ARN"
        )
    extra = set(loaded) - _KEYS
    if extra:
        names = ", ".join(sorted(extra))
        raise ConfigError(f"unknown config keys: {names}")
    return loaded


def _excludes(configured: object, extra: tuple[str, ...]) -> tuple[str, ...]:
    values: list[str] = []
    if configured is not None:
        if not isinstance(configured, list) or not all(isinstance(item, str) for item in configured):
            raise ConfigError("exclude must be a list of strings")
        values.extend(configured)
    values.extend(extra)
    return tuple(values)


def _advisories(cli: str | None, configured: object, config_dir: Path, root: Path) -> Path | None:
    if cli:
        return Path(cli).expanduser()
    if configured is None:
        return None
    if not isinstance(configured, str):
        raise ConfigError("advisories must be a path")
    path = Path(configured).expanduser()
    if not path.is_absolute():
        path = config_dir / path
    scan_root = (root if root.is_dir() else root.parent).resolve()
    try:
        resolved = path.resolve()
        resolved.relative_to(scan_root)
    except (OSError, ValueError) as exc:
        raise ConfigError("advisories path must stay inside the scan root") from exc
    return resolved


def _pick_str(cli: str | None, configured: object, default: str, name: str) -> str:
    if cli is not None:
        return cli
    if configured is None:
        return default
    if not isinstance(configured, str):
        raise ConfigError(f"{name} must be a string")
    return configured


def _pick_optional(cli: str | None, env: str | None, configured: object) -> str | None:
    if cli:
        return cli
    if env:
        return env
    if configured is None:
        return None
    if not isinstance(configured, str):
        raise ConfigError("expected a string")
    return configured


def _flag(configured: object, default: bool) -> bool:
    if configured is None:
        return default
    if not isinstance(configured, bool):
        raise ConfigError("expected a boolean")
    return configured


def _first(cli: int | None, configured: object, default: int) -> object:
    if cli is not None:
        return cli
    if configured is not None:
        return configured
    return default


def _positive_int(value: object, name: str, *, upper: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    if upper is not None and value > upper:
        raise ConfigError(f"{name} must be <= {upper}")
    return value


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ConfigError("timeout must be between 0.1 and 30 seconds")
    if value < 0.1 or value > 30:
        raise ConfigError("timeout must be between 0.1 and 30 seconds")
    return float(value)


def _blank_to_none(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return value.strip()

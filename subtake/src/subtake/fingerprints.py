from __future__ import annotations

import json
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from subtake.errors import SubtakeError
from subtake.models import Verdict
from subtake.paths import resolve_cli_path

_MAX_BYTES = 1_000_000
_MAX_SERVICES = 200
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_LITERAL_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_VERDICTS = {
    "likely-vulnerable": Verdict.LIKELY,
    "edge-case": Verdict.EDGE,
    "not-vulnerable": Verdict.SAFE,
}


@dataclass(frozen=True)
class HttpRule:
    body: str
    status: tuple[int, ...] | None
    verdict: Verdict


@dataclass(frozen=True)
class Service:
    id: str
    service: str
    cname: tuple[str, ...]
    nxdomain: Verdict
    on_miss: Verdict
    http: tuple[HttpRule, ...]


def load_fingerprints(path: str | None = None) -> tuple[Service, ...]:
    return _parse(_read(path))


def match_name(host: str, services: tuple[Service, ...]) -> Service | None:
    best: tuple[tuple[int, int], Service] | None = None
    for index, service in enumerate(services):
        for pattern in service.cname:
            if not _matches(host, pattern):
                continue
            key = (_specificity(pattern), -index)
            if best is None or key > best[0]:
                best = (key, service)
    return None if best is None else best[1]


def matching_rule(service: Service, status: int, body: str) -> HttpRule | None:
    folded = body.casefold()
    found: HttpRule | None = None
    for rule in service.http:
        needle = rule.body.casefold()
        if len(needle) < 8 or needle not in folded:
            continue
        if rule.status is not None and status not in rule.status:
            continue
        if rule.verdict is Verdict.LIKELY:
            return rule
        if found is None:
            found = rule
    return found


def _matches(host: str, pattern: str) -> bool:
    if "*" not in pattern:
        return host == pattern or host.endswith("." + pattern)
    return fnmatchcase(host, pattern)


def _specificity(pattern: str) -> int:
    return sum(1 for char in pattern if char != "*")


def _read(path: str | None) -> str:
    if path is None:
        bundled = Path(__file__).resolve().parent / "data" / "fingerprints.json"
        try:
            return bundled.read_text(encoding="utf-8")
        except OSError as exc:
            raise SubtakeError("bundled fingerprints are missing") from exc
    file = Path(resolve_cli_path(path))
    try:
        info = file.stat()
    except OSError as exc:
        raise SubtakeError(f"cannot read fingerprints: {exc.strerror or exc}") from exc
    if not file.is_file():
        raise SubtakeError(f"not a file: {path}")
    if info.st_size > _MAX_BYTES:
        raise SubtakeError(f"fingerprint file is larger than {_MAX_BYTES} bytes")
    try:
        return file.read_text(encoding="utf-8")
    except OSError as exc:
        raise SubtakeError(f"cannot read fingerprints: {exc.strerror or exc}") from exc


def _parse(text: str) -> tuple[Service, ...]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SubtakeError(f"fingerprint file is not JSON: {exc.msg}") from exc
    if not isinstance(payload, dict) or set(payload) != {"services"}:
        raise SubtakeError("fingerprint file must contain a services array")
    raw_services = payload.get("services")
    if not isinstance(raw_services, list) or not raw_services:
        raise SubtakeError("fingerprint file has no services")
    if len(raw_services) > _MAX_SERVICES:
        raise SubtakeError(f"fingerprint file has more than {_MAX_SERVICES} services")
    services: list[Service] = []
    seen_ids: set[str] = set()
    seen_patterns: set[str] = set()
    for index, raw in enumerate(raw_services, start=1):
        services.append(_service(raw, index, seen_ids, seen_patterns))
    return tuple(services)


def _service(raw: object, index: int, seen_ids: set[str], seen_patterns: set[str]) -> Service:
    label = f"service {index}"
    body = _object(raw, label)
    extra = set(body) - {"id", "service", "cname", "nxdomain", "on_miss", "http"}
    missing = {"id", "service", "cname", "nxdomain", "on_miss", "http"} - set(body)
    if extra or missing:
        detail = ", ".join(sorted(extra or missing))
        raise SubtakeError(f"{label} has invalid fields: {detail}")
    service_id = _identifier(body["id"], label)
    if service_id in seen_ids:
        raise SubtakeError(f"duplicate fingerprint id {service_id}")
    seen_ids.add(service_id)
    patterns = _patterns(body["cname"], service_id, seen_patterns)
    rules = _rules(body["http"], service_id)
    return Service(
        id=service_id,
        service=_title(body["service"], service_id),
        cname=patterns,
        nxdomain=_choice(body["nxdomain"], service_id, "nxdomain", {Verdict.LIKELY, Verdict.EDGE}),
        on_miss=_choice(body["on_miss"], service_id, "on_miss", {Verdict.SAFE, Verdict.EDGE}),
        http=rules,
    )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise SubtakeError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None or len(value) > 40:
        raise SubtakeError(f"{label} id must be a short lowercase slug")
    return value


def _title(value: object, service_id: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 80:
        raise SubtakeError(f"{service_id} service name is missing")
    if any(ord(char) < 32 for char in value):
        raise SubtakeError(f"{service_id} service name is not text")
    return value.strip()


def _patterns(value: object, service_id: str, seen: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise SubtakeError(f"{service_id} needs between 1 and 32 CNAME patterns")
    patterns: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _valid_pattern(item):
            raise SubtakeError(f"{service_id} has an invalid CNAME pattern")
        if item in seen:
            raise SubtakeError(f"duplicate CNAME pattern {item}")
        seen.add(item)
        patterns.append(item)
    return tuple(patterns)


def _valid_pattern(pattern: str) -> bool:
    if not pattern or len(pattern) > 253 or any(char in pattern for char in " ?[]/\\"):
        return False
    labels = pattern.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    fixed = 0
    for label in reversed(labels):
        if "*" in label:
            break
        if _LITERAL_LABEL.fullmatch(label) is None:
            return False
        fixed += 1
    if fixed < 2:
        return False
    return all("*" not in label or re.fullmatch(r"[a-z0-9*-]+", label) for label in labels)


def _rules(value: object, service_id: str) -> tuple[HttpRule, ...]:
    if not isinstance(value, list) or len(value) > 16:
        raise SubtakeError(f"{service_id} http rules must be a list of at most 16")
    rules: list[HttpRule] = []
    for item in value:
        body = _object(item, f"{service_id} http rule")
        extra = set(body) - {"body", "status", "verdict"}
        if extra or "body" not in body or "verdict" not in body:
            raise SubtakeError(f"{service_id} http rule has invalid fields")
        needle = body["body"]
        if not isinstance(needle, str) or not 8 <= len(needle.strip()) <= 200:
            raise SubtakeError(f"{service_id} http body must be 8 to 200 characters")
        if any(ord(char) < 32 for char in needle):
            raise SubtakeError(f"{service_id} http body is not text")
        rules.append(
            HttpRule(
                body=needle.strip(),
                status=_statuses(body.get("status"), service_id) if "status" in body else None,
                verdict=_choice(body["verdict"], service_id, "http verdict", {Verdict.LIKELY, Verdict.EDGE}),
            )
        )
    return tuple(rules)


def _statuses(value: object, service_id: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise SubtakeError(f"{service_id} http status must be a short list of codes")
    codes: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 100 <= item <= 599:
            raise SubtakeError(f"{service_id} http status is not a code")
        if item not in codes:
            codes.append(item)
    return tuple(codes)


def _choice(value: object, service_id: str, field: str, allowed: set[Verdict]) -> Verdict:
    if not isinstance(value, str):
        raise SubtakeError(f"{service_id} {field} is invalid")
    verdict = _VERDICTS.get(value)
    if verdict is None or verdict not in allowed:
        raise SubtakeError(f"{service_id} {field} is invalid")
    return verdict

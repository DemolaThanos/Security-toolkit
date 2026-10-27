from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from tfplan_guard.models import Finding, Resource
from tfplan_guard.paths import resolve_cli_path
from tfplan_guard.rules import RULE_INDEX
from tfplan_guard.values import lookup

_MIN_JUSTIFICATION = 12
_MAX_ADDRESS = 1_024
MAX_SUPPRESSION_BYTES = 1_000_000
_TAG = "tfplan-guard/ignore"
_TAG_PREFIX = "tfplan-guard/ignore:"
_PLACEHOLDER = re.compile(r"(?i)^(todo|fixme|later|wip|n/?a|none|ignore|false|tbd|xxx+|test|ok|no)$")


class ConfigError(Exception):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Suppression:
    rule: str
    address: str
    justification: str
    literal: bool = False


def load_suppressions(path: Path) -> tuple[Suppression, ...]:
    display = path.as_posix()
    try:
        opened = resolve_cli_path(os.fspath(path))
    except (OSError, ValueError) as exc:
        raise ConfigError([str(exc)]) from exc
    file_path = Path(opened)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise ConfigError([f"cannot read {display}: {exc}"]) from exc
    if size > MAX_SUPPRESSION_BYTES:
        raise ConfigError([f"{display} is larger than {MAX_SUPPRESSION_BYTES} bytes"])
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError([f"cannot read {display}: {exc}"]) from exc
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"{display} is not valid TOML: {exc}"]) from exc
    if not isinstance(raw, dict):
        raise ConfigError([f"{display} must be a TOML table"])
    if not raw:
        return ()
    if "suppress" not in raw:
        raise ConfigError([f"{display} has no [[suppress]] entries"])
    entries = raw.get("suppress")
    if not isinstance(entries, list):
        raise ConfigError([f"{display} suppress must be an array of tables"])
    found: list[Suppression] = []
    problems: list[str] = []
    for index, entry in enumerate(entries, start=1):
        item, problem = _entry(f"{display} suppress entry {index}", entry)
        if problem:
            problems.append(problem)
        elif item is not None:
            found.append(item)
    if problems:
        raise ConfigError(problems)
    return tuple(found)


def inline_suppressions(resources: list[Resource]) -> tuple[tuple[Suppression, ...], tuple[str, ...]]:
    found: list[Suppression] = []
    errors: list[str] = []
    for resource in resources:
        for key, value in _tags(resource).items():
            if key == _TAG:
                errors.append(f"{resource.address} tag {_TAG} must be {_TAG}:<rule-id>")
                continue
            if not key.startswith(_TAG_PREFIX):
                continue
            rule_id = key.removeprefix(_TAG_PREFIX).strip()
            where = f"{resource.address} tag {key}"
            if not rule_id:
                errors.append(f"{where} is missing a rule id")
                continue
            if rule_id != "*" and rule_id not in RULE_INDEX:
                errors.append(f"{where} uses unknown rule {rule_id!r}")
                continue
            if not isinstance(value, str):
                errors.append(f"{where} justification must be a string")
                continue
            reason = justification_error(value)
            if reason:
                errors.append(f"{where} {reason}")
                continue
            found.append(Suppression(rule_id, resource.address, value.strip(), literal=True))
    return tuple(found), tuple(errors)


def suppressed(finding: Finding, items: tuple[Suppression, ...]) -> bool:
    return any(
        item.rule in {finding.rule_id, "*"} and _address_match(finding.address, item.address, literal=item.literal)
        for item in items
    )


def justification_error(text: str) -> str | None:
    cleaned = text.strip()
    if _PLACEHOLDER.fullmatch(cleaned):
        return "justification is a placeholder"
    if len(cleaned) < _MIN_JUSTIFICATION:
        return f"justification must be at least {_MIN_JUSTIFICATION} characters"
    return None


def _entry(where: str, entry: object) -> tuple[Suppression | None, str | None]:
    if not isinstance(entry, dict):
        return None, f"{where} must be a table"
    rule = entry.get("rule")
    address = entry.get("address")
    justification = entry.get("justification")
    if not isinstance(rule, str) or not rule.strip():
        return None, f"{where} is missing rule"
    if not isinstance(address, str) or not address.strip():
        return None, f"{where} is missing address"
    rule_id = rule.strip()
    address_text = address.strip()
    if len(address_text) > _MAX_ADDRESS:
        return None, f"{where} address is too long"
    if rule_id != "*" and rule_id not in RULE_INDEX:
        return None, f"{where} uses unknown rule {rule_id!r}"
    if not isinstance(justification, str):
        return None, f"{where} is missing a justification"
    reason = justification_error(justification)
    if reason:
        return None, f"{where} {reason}"
    return Suppression(rule_id, address_text, justification.strip()), None


def _tags(resource: Resource) -> dict[str, object]:
    merged: dict[str, object] = {}
    for name in ("tags_all", "tags"):
        attr = lookup(resource, name)
        if not attr.known or not isinstance(attr.value, dict):
            continue
        for raw_key, raw_value in attr.value.items():
            if isinstance(raw_key, str):
                merged[raw_key] = raw_value
    return merged


def _address_match(address: str, pattern: str, *, literal: bool) -> bool:
    # Inline tags come from the plan, so they match one address.
    # In a file, only * and ? are wildcards. Brackets stay literal so
    # aws_instance.web[0] does not also match aws_instance.web0.
    if literal or ("*" not in pattern and "?" not in pattern):
        return address == pattern
    escaped = "".join("[[]" if char == "[" else char for char in pattern)
    return fnmatch(address, escaped)

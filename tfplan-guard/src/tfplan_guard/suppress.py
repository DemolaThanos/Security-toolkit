from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from tfplan_guard.models import Finding, Resource
from tfplan_guard.rules import RULE_INDEX
from tfplan_guard.values import lookup

_MIN_JUSTIFICATION = 12
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


def load_suppressions(path: Path) -> tuple[Suppression, ...]:
    display = path.as_posix()
    try:
        text = path.read_text(encoding="utf-8")
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
            found.append(Suppression(rule_id, resource.address, value.strip()))
    return tuple(found), tuple(errors)


def suppressed(finding: Finding, items: tuple[Suppression, ...]) -> bool:
    return any(item.rule in {finding.rule_id, "*"} and _address_match(finding.address, item.address) for item in items)


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
    if rule_id != "*" and rule_id not in RULE_INDEX:
        return None, f"{where} uses unknown rule {rule_id!r}"
    if not isinstance(justification, str):
        return None, f"{where} is missing a justification"
    reason = justification_error(justification)
    if reason:
        return None, f"{where} {reason}"
    return Suppression(rule_id, address.strip(), justification.strip()), None


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


def _address_match(address: str, pattern: str) -> bool:
    if any(char in pattern for char in "*?["):
        return fnmatch(address, pattern)
    return address == pattern

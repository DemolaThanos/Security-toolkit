"""Helpers for resolved Terraform values and the after_unknown mask.

A mask of True means Terraform has not chosen the value yet. Those attributes
are skipped: a missing encryption flag is a finding, an unknown one is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfplan_guard.models import Resource


@dataclass(frozen=True)
class Attr:
    known: bool
    value: Any
    unknown: Any = None


def lookup(resource: Resource, *keys: str) -> Attr:
    current: Any = resource.values
    unknown: Any = resource.unknown
    for key in keys:
        if unknown is True:
            return Attr(False, None, True)
        if not isinstance(current, dict):
            return Attr(True, None, None)
        child_unknown = unknown.get(key) if isinstance(unknown, dict) else None
        if child_unknown is True:
            return Attr(False, None, True)
        if key not in current:
            return Attr(True, None, None)
        current = current[key]
        unknown = child_unknown
    if unknown is True:
        return Attr(False, None, True)
    return Attr(True, current, unknown)


def field(block: dict[str, Any], unknown: object, key: str) -> Attr:
    if unknown is True:
        return Attr(False, None, True)
    child_unknown = unknown.get(key) if isinstance(unknown, dict) else None
    if child_unknown is True:
        return Attr(False, None, True)
    if key not in block:
        return Attr(True, None, None)
    return Attr(True, block[key], child_unknown)


def block_pairs(value: object, unknown: object) -> list[tuple[dict[str, Any], object]]:
    if unknown is True:
        return [(item, True) for item in _dicts(value)]
    if isinstance(value, dict):
        return [(value, unknown if isinstance(unknown, dict) else {})]
    if isinstance(value, list):
        if isinstance(unknown, list):
            masks: list[object] = list(unknown)
        elif isinstance(unknown, dict) and len(value) == 1:
            masks = [unknown]
        else:
            masks = []
        pairs: list[tuple[dict[str, Any], object]] = []
        for index, item in enumerate(value):
            if isinstance(item, dict):
                mask = masks[index] if index < len(masks) else {}
                pairs.append((item, mask))
        return pairs
    return []


def explicitly_true(attr: Attr) -> bool:
    if not attr.known:
        return False
    if attr.value is True:
        return True
    return isinstance(attr.value, str) and attr.value.strip().lower() == "true"


def known_false(attr: Attr) -> bool:
    if not attr.known:
        return False
    if attr.value is False:
        return True
    return isinstance(attr.value, str) and attr.value.strip().lower() == "false"


def require_true(attr: Attr) -> bool:
    """The value is present and is not true. Unknown values are not failures."""
    if not attr.known:
        return False
    return not explicitly_true(attr)


def as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            return None
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        digits = text[1:] if text.startswith(("+", "-")) else text
        if digits.isdigit() and len(digits) <= 6:
            return int(text)
    return None


def as_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def as_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _dicts(value: object) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

from tfplan_guard.models import Resource
from tfplan_guard.paths import contained

logger = logging.getLogger("tfplan_guard.load")

_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".tox", ".nox"})
MAX_FILES = 1_000
_MAX_MODULE_DEPTH = 50


def terraform_files(root: Path) -> tuple[list[Path], bool]:
    if root.is_file():
        return [root], False
    found: list[Path] = []
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            if Path(name).suffix.lower() != ".json":
                continue
            path = Path(dirpath) / name
            if not _contained_file(root, path):
                logger.warning("skip %s", path.relative_to(root).as_posix())
                continue
            found.append(path)
            if len(found) > MAX_FILES:
                truncated = True
                return found, truncated
    return sorted(found), truncated


def display_path(root: Path, path: Path) -> str:
    """Path shown in a report. Prefer a path relative to the working directory."""
    target = path if root.is_dir() else root
    try:
        relative = target.resolve().relative_to(Path.cwd().resolve())
    except (OSError, ValueError):
        if root.is_dir():
            return path.relative_to(root).as_posix()
        return root.as_posix()
    text = relative.as_posix()
    return "." if text == "" else text


def load_document(
    path: Path,
    display: str,
    *,
    max_bytes: int,
    strict: bool,
    root: Path,
) -> tuple[list[Resource] | None, str | None]:
    """Return resources, or (None, None) when a directory entry is not a plan."""
    text, error = _read(path, display, max_bytes, root)
    if error or text is None:
        return None, error
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"{display} is not valid JSON: {exc}"
    except RecursionError:
        return None, f"{display} is too deeply nested"
    if not isinstance(payload, dict):
        if strict:
            return None, f"{display} is not a Terraform plan or state"
        logger.info("skip %s: not a Terraform plan or state", display)
        return None, None
    try:
        resources = _resources(payload, text, display)
    except ValueError as exc:
        return None, f"{display}: {exc}"
    if resources is None:
        if strict:
            return None, f"{display} is not a Terraform plan or state"
        logger.info("skip %s: not a Terraform plan or state", display)
        return None, None
    return resources, None


def _read(path: Path, display: str, max_bytes: int, root: Path) -> tuple[str | None, str | None]:
    try:
        opened = contained(os.fspath(path), os.fspath(root))
    except (OSError, ValueError) as exc:
        return None, f"refusing to read {display}: {exc}"
    file_path = Path(opened)
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return None, f"cannot stat {display}: {exc}"
    if size > max_bytes:
        return None, f"{display} is larger than {max_bytes} bytes"
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return None, f"cannot read {display}: {exc}"
    if text.startswith("\ufeff"):
        text = text[1:]
    return text, None


def _resources(payload: dict[str, Any], text: str, display: str) -> list[Resource] | None:
    if "resource_changes" in payload:
        changes = payload.get("resource_changes")
        if not isinstance(changes, list):
            raise ValueError("resource_changes is not a list")
        resources: list[Resource] = []
        for item in changes:
            if not isinstance(item, dict):
                continue
            resource = _from_change(item, text, display)
            if resource is not None:
                resources.append(resource)
        return resources
    values = payload.get("values")
    if isinstance(values, dict) and isinstance(values.get("root_module"), dict):
        found: list[Resource] = []
        _from_module(values["root_module"], text, display, found)
        return [item for item in found if item is not None]
    planned = payload.get("planned_values")
    if isinstance(planned, dict) and isinstance(planned.get("root_module"), dict):
        planned_resources: list[Resource] = []
        _from_module(planned["root_module"], text, display, planned_resources)
        return planned_resources
    return None


def _from_change(item: dict[str, Any], text: str, display: str) -> Resource | None:
    if not _aws_managed(item):
        return None
    change = item.get("change")
    if not isinstance(change, dict):
        return None
    actions = change.get("actions")
    if isinstance(actions, list) and actions and all(item == "delete" for item in actions):
        return None
    after = change.get("after")
    if not isinstance(after, dict):
        return None
    return _resource(item, after, _unknown(change.get("after_unknown")), text, display)


def _from_module(module: dict[str, Any], text: str, display: str, into: list[Resource], depth: int = 0) -> None:
    if depth > _MAX_MODULE_DEPTH:
        raise ValueError(f"module nesting exceeds {_MAX_MODULE_DEPTH}")
    raw = module.get("resources")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            resource = _from_state(item, text, display)
            if resource is not None:
                into.append(resource)
    children = module.get("child_modules")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                _from_module(child, text, display, into, depth + 1)


def _from_state(item: dict[str, Any], text: str, display: str) -> Resource | None:
    if not _aws_managed(item):
        return None
    values = item.get("values")
    if not isinstance(values, dict):
        return None
    return _resource(item, values, {}, text, display)


def _resource(
    item: dict[str, Any],
    values: dict[str, Any],
    unknown: Any,
    text: str,
    display: str,
) -> Resource | None:
    address = item.get("address")
    type_name = item.get("type")
    if not isinstance(address, str) or not address or not isinstance(type_name, str):
        return None
    return Resource(
        address=address,
        type=type_name,
        values=values,
        unknown=unknown,
        path=display,
        line=_line(text, address),
    )


def _aws_managed(item: dict[str, Any]) -> bool:
    if item.get("mode") != "managed":
        return False
    type_name = item.get("type")
    if not isinstance(type_name, str) or not type_name.startswith("aws_"):
        return False
    provider = item.get("provider_name")
    if isinstance(provider, str) and provider:
        return provider.rsplit("/", 1)[-1] == "aws"
    return True


def _unknown(value: object) -> Any:
    if value is True or isinstance(value, dict):
        return value
    return {}


def _line(text: str, address: str) -> int:
    needles = (f'"address": "{address}"', f'"address":"{address}"')
    for index, line in enumerate(text.splitlines(), start=1):
        if any(needle in line for needle in needles):
            return index
    return 1


def _contained_file(root: Path, path: Path) -> bool:
    try:
        opened = contained(os.fspath(path), os.fspath(root))
    except (OSError, ValueError):
        return False
    try:
        info = os.stat(opened)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("k8s_harden.load")

_MAX_NODES = 100_000
_MAX_ALIASES = 1_000


class _BoundedLoader(yaml.SafeLoader):  # type: ignore[misc]
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            count = getattr(self, "_alias_count", 0) + 1
            self._alias_count = count
            if count > _MAX_ALIASES:
                raise yaml.YAMLError("YAML document exceeds the alias limit")
        nodes = getattr(self, "_node_count", 0) + 1
        self._node_count = nodes
        if nodes > _MAX_NODES:
            raise yaml.YAMLError("YAML document exceeds the node limit")
        return super().compose_node(parent, index)


def load_file(path: Path, *, max_bytes: int) -> tuple[list[dict[str, Any]], str | None]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], f"cannot stat {path}: {exc}"
    if size > max_bytes:
        return [], f"{path} is larger than {max_bytes} bytes"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [], f"cannot read {path}: {exc}"
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        documents = list(yaml.load_all(text, Loader=_BoundedLoader))
    except yaml.YAMLError as exc:
        message = str(exc)
        if "limit" in message:
            return [], f"{path} is not valid YAML: {message}"
        if "{{" in text or "{%" in text:
            logger.warning("skipping template %s", path)
            return [], None
        return [], f"{path} is not valid YAML: {exc}"
    loaded: list[dict[str, Any]] = []
    for document in documents:
        if isinstance(document, list):
            for item in document:
                loaded.extend(_resources(item))
            continue
        loaded.extend(_resources(document))
    return loaded, None


def _resources(document: object) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    kind = document.get("kind")
    if kind == "List" and isinstance(document.get("items"), list):
        resources: list[dict[str, Any]] = []
        items = document["items"]
        if isinstance(items, list):
            for item in items:
                resources.extend(_resources(item))
        return resources
    if isinstance(kind, str):
        return [document]
    return []

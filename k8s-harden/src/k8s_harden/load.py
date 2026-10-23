from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("k8s_harden.load")


def load_file(path: Path, *, max_bytes: int) -> tuple[list[dict[str, Any]], str | None]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], f"cannot stat {path}: {exc}"
    if size > max_bytes:
        return [], f"{path} is larger than {max_bytes} bytes"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [], f"cannot read {path}: {exc}"
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        if "{{" in text or "{%" in text:
            logger.warning("skipping template %s", path)
            return [], None
        return [], f"{path} is not valid YAML: {exc}"
    loaded: list[dict[str, Any]] = []
    for document in documents:
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

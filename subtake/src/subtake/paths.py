"""Resolve command-line paths before they are opened.

The string that reaches open() is the validated text, not a value derived from
realpath. realpath is used only to decide whether a relative path or a symlink
stays inside its directory.
"""

from __future__ import annotations

import os
import re

from subtake.errors import SubtakeError

# A segment may start with one dot (.hosts) but ".." does not match.
_SEGMENT = r"\.?[A-Za-z0-9_~-][A-Za-z0-9_~ .-]*"
_SAFE_PATH = re.compile(rf"^(?:{_SEGMENT})(?:/{_SEGMENT})*$|^(?:/(?:{_SEGMENT}))+$")


def resolve_cli_path(raw: str) -> str:
    """Validate a CLI path. Relative paths that leave the working directory fail."""
    cleaned = _safe(raw)
    if cleaned == ".":
        return "."
    if not os.path.isabs(cleaned) and not _inside(cleaned, os.getcwd()):
        raise SubtakeError(f"path must stay inside the working directory: {cleaned}")
    return cleaned


def _safe(raw: str) -> str:
    if "\x00" in raw:
        raise SubtakeError("path contains unsupported characters")
    while raw.startswith("./"):
        raw = raw[2:]
    if raw == ".":
        return "."
    if ".." in raw.split("/"):
        raise SubtakeError(f"path must stay inside the working directory: {raw}")
    match = _SAFE_PATH.fullmatch(raw)
    if match is None:
        raise SubtakeError("path contains unsupported characters")
    return match.group(0)


def _inside(path: str, root: str) -> bool:
    try:
        resolved = os.path.realpath(path)
        base = os.path.realpath(root)
    except (OSError, ValueError):
        return False
    if resolved == base:
        return True
    prefix = base if base.endswith(os.sep) else base + os.sep
    return resolved.startswith(prefix)

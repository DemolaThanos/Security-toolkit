"""Resolve command-line paths before they are opened.

Relative paths have to stay inside the working directory after symlinks are
resolved. Absolute paths are explicit and are returned with symlinks resolved.
"""

from __future__ import annotations

import os


def resolve_cli_path(raw: str) -> str:
    """Resolve one CLI path. Relative paths that leave the working directory fail."""
    if "\x00" in raw:
        raise ValueError("path contains a null byte")
    try:
        resolved = os.path.realpath(raw)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot resolve {raw}: {exc}") from exc
    if not os.path.isabs(raw):
        base = os.path.realpath(os.getcwd())
        if not _within(resolved, base):
            raise ValueError(f"path must stay inside the working directory: {raw}")
    return resolved


def contained(path: str, root: str) -> str:
    """Resolve path and require the result to stay inside root."""
    if "\x00" in path or "\x00" in root:
        raise ValueError("path contains a null byte")
    try:
        resolved = os.path.realpath(path)
        base = os.path.realpath(root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot resolve path: {exc}") from exc
    if not _within(resolved, base):
        raise ValueError("path escapes the directory being scanned")
    return resolved


def _within(resolved: str, base: str) -> bool:
    if resolved == base:
        return True
    prefix = base if base.endswith(os.sep) else base + os.sep
    return resolved.startswith(prefix)

from __future__ import annotations

from pathlib import Path, PurePosixPath


def resolve_cli_path(raw: str) -> str:
    """Validate a CLI path. Relative paths that leave the working directory fail."""
    if not raw or not raw.strip():
        raise ValueError("path is empty")
    if raw != raw.strip() or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError("path contains unsupported characters")
    if ".." in PurePosixPath(raw.replace("\\", "/")).parts:
        raise ValueError(f"path must stay inside the working directory: {raw}")
    path = Path(raw)
    if path.is_absolute():
        return raw
    cwd = Path.cwd().resolve()
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise ValueError(f"path could not be resolved: {raw}") from exc
    if resolved != cwd and cwd not in resolved.parents:
        raise ValueError(f"path must stay inside the working directory: {raw}")
    return raw

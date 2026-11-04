from __future__ import annotations

from pathlib import Path, PurePosixPath


def resolve_cli_path(raw: str) -> str:
    """Validate a path typed on the command line.

    Relative paths have to stay inside the working directory once symlinks are
    resolved. An absolute path is returned as given so a workflow file can be
    named by its full path. Files this tool writes, and the config it reads,
    go through :func:`contained_file` instead.
    """
    if not raw or not raw.strip():
        raise ValueError("path is empty")
    if raw != raw.strip() or "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError("path contains unsupported characters")
    if ".." in PurePosixPath(raw.replace("\\", "/")).parts:
        raise ValueError(f"path must stay inside the working directory: {raw}")
    path = Path(raw)
    if path.is_absolute():
        return raw
    root = Path.cwd().resolve()
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise ValueError(f"path could not be resolved: {raw}") from exc
    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError(f"path must stay inside the working directory: {raw}")
    return raw


def contained_file(raw: str | Path) -> Path:
    """Resolve a path and keep the result inside the working directory.

    The returned path is the working directory joined with the relative path
    from :meth:`Path.relative_to`. A symlink that points outside fails here.
    """
    root = Path.cwd().resolve()
    if isinstance(raw, Path):
        if ".." in PurePosixPath(raw.as_posix()).parts:
            raise ValueError(f"path must stay inside the working directory: {raw.as_posix()}")
        candidate = raw
        label: object = raw.as_posix()
    else:
        candidate = Path(resolve_cli_path(raw))
        label = raw
    try:
        resolved = candidate.resolve()
    except OSError as exc:
        raise ValueError(f"path could not be resolved: {label}") from exc
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path must stay inside the working directory: {label}") from exc
    return root / relative

from __future__ import annotations

import logging
import os
import stat
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger("devsecops_scan.discover")

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "vendor",
        "venv",
    }
)

LOCK_NAMES = frozenset(
    {
        "Cargo.lock",
        "Pipfile.lock",
        "composer.lock",
        "go.sum",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "packages.lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "yarn.lock",
    }
)

BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".a",
        ".bin",
        ".bz2",
        ".class",
        ".dll",
        ".dylib",
        ".eot",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".mp3",
        ".mp4",
        ".o",
        ".pdf",
        ".png",
        ".pyc",
        ".pyo",
        ".so",
        ".tgz",
        ".ttf",
        ".war",
        ".wasm",
        ".webp",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)


def iter_files(root: Path, *, exclude: tuple[str, ...]) -> Iterator[Path]:
    """Yield files under root. Hidden files are included; hidden directories are not."""
    if root.is_file():
        if not _excluded(root.name, exclude):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS and not name.startswith(".")]
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if _excluded(relative, exclude):
                logger.debug("excluded %s", relative)
                continue
            if not _contained_file(root, path):
                logger.warning("skip %s", relative)
                continue
            yield path


def _excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    from fnmatch import fnmatch

    for pattern in patterns:
        cleaned = pattern.replace("\\", "/").rstrip("/")
        if not cleaned:
            continue
        if (
            fnmatch(relative, cleaned)
            or fnmatch(relative, cleaned + "/**")
            or relative == cleaned
            or relative.startswith(cleaned + "/")
            or fnmatch(Path(relative).name, cleaned)
        ):
            return True
    return False


def _contained_file(root: Path, path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            return False
    try:
        info = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)


def read_text(path: Path, *, max_bytes: int) -> str | None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        logger.warning("cannot stat %s: %s", path, exc)
        return None
    if size > max_bytes:
        logger.debug("skip large file %s", path)
        return None
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        data = path.read_bytes()
    except OSError as exc:
        logger.warning("cannot read %s: %s", path, exc)
        return None
    if b"\0" in data:
        logger.debug("skip binary %s", path)
        return None
    text = data.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text

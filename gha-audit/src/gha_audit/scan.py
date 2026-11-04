from __future__ import annotations

import logging
import os
from pathlib import Path

from gha_audit.ignore import Ignore, parse_inline
from gha_audit.load import MAX_BYTES, load_document, read_text
from gha_audit.models import Finding, Options, ScanReport
from gha_audit.rules import check
from gha_audit.workflow import classify, parse_document

logger = logging.getLogger("gha_audit.scan")

_MAX_FILES = 1_000
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
        "vendor",
    }
)


def scan(
    paths: list[Path],
    *,
    options: Options | None = None,
    ignores: tuple[Ignore, ...] = (),
    max_bytes: int = MAX_BYTES,
) -> ScanReport:
    chosen = options or Options()
    files, errors = _discover(paths)
    if len(files) > _MAX_FILES:
        return ScanReport((), (f"refusing to scan more than {_MAX_FILES} files",), 0, 0)
    findings: list[Finding] = []
    ignored = 0
    checked = 0
    for path, explicit in files:
        found, file_errors, file_ignored, did_check = _audit(
            path,
            explicit=explicit,
            options=chosen,
            ignores=ignores,
            max_bytes=max_bytes,
        )
        findings.extend(found)
        errors.extend(file_errors)
        ignored += file_ignored
        checked += int(did_check)
    unique = _dedupe(findings)
    return ScanReport(tuple(unique), tuple(errors), checked, ignored)


def display_path(path: Path) -> str:
    try:
        resolved = path.resolve()
        cwd = Path.cwd().resolve()
        return resolved.relative_to(cwd).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _audit(
    path: Path,
    *,
    explicit: bool,
    options: Options,
    ignores: tuple[Ignore, ...],
    max_bytes: int,
) -> tuple[list[Finding], list[str], int, bool]:
    display = display_path(path)
    if explicit and path.suffix.lower() not in {".yml", ".yaml"}:
        return [], [f"{display} is not a workflow or action file"], 0, False
    text, error = read_text(path, max_bytes=max_bytes)
    if error or text is None:
        return [], [error or f"cannot read {display}"], 0, False
    document, error = load_document(text)
    if error:
        return [], [f"{display} is {error}"], 0, False
    if classify(document) is None or not isinstance(document, dict):
        if explicit:
            return [], [f"{display} is not a GitHub Actions workflow or action"], 0, False
        logger.info("skipping %s", display)
        return [], [], 0, False
    parsed = parse_document(document, display)
    if parsed is None:
        return [], [f"{display} is not a GitHub Actions workflow or action"], 0, False
    logger.info("checking %s", display)
    inline, inline_errors = parse_inline(text, display)
    kept: list[Finding] = []
    ignored = 0
    for finding in _dedupe(check(parsed, options)):
        if any(item.matches(finding) for item in (*ignores, *inline)):
            ignored += 1
        else:
            kept.append(finding)
    return kept, list(inline_errors), ignored, True


def _discover(paths: list[Path]) -> tuple[list[tuple[Path, bool]], list[str]]:
    found: list[tuple[Path, bool]] = []
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"path does not exist: {path}")
            continue
        if path.is_file():
            found.append((path, True))
            continue
        if path.is_dir():
            found.extend((item, False) for item in _dir_files(path))
            continue
        errors.append(f"path does not exist: {path}")
    unique: list[tuple[Path, bool]] = []
    seen: set[Path] = set()
    for path, explicit in found:
        try:
            key = path.resolve()
        except OSError:
            key = path
        if key in seen:
            continue
        seen.add(key)
        unique.append((path, explicit))
    unique.sort(key=lambda item: item[0].as_posix())
    return unique, errors


def _dir_files(root: Path) -> list[Path]:
    files: list[Path] = []
    workflow_dir = _workflow_dir(root)
    if workflow_dir is not None:
        files.extend(_yaml_in(workflow_dir, root))
        files.extend(_actions_under(root))
        return files
    files.extend(_yaml_in(root, root))
    files.extend(_actions_under(root))
    return files


def _workflow_dir(root: Path) -> Path | None:
    if root.name == "workflows" and root.is_dir():
        return root
    direct = root / ".github" / "workflows"
    if direct.is_dir():
        return direct
    nested = root / "workflows"
    if root.name == ".github" and nested.is_dir():
        return nested
    return None


def _yaml_in(directory: Path, root: Path) -> list[Path]:
    try:
        children = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        logger.warning("cannot list %s: %s", directory, exc)
        return []
    found: list[Path] = []
    for child in children:
        if not child.is_file() or child.suffix.lower() not in {".yml", ".yaml"}:
            continue
        if child.name in {"action.yml", "action.yaml"}:
            continue
        if _inside(child, root):
            found.append(child)
    return found


def _actions_under(root: Path) -> list[Path]:
    found: list[Path] = []
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if not _inside(current, base):
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            name for name in dirnames if name not in _SKIP_DIRS and (name == ".github" or not name.startswith("."))
        )
        for name in sorted(filenames):
            if name not in {"action.yml", "action.yaml"}:
                continue
            candidate = current / name
            if candidate.is_file() and _inside(candidate, base):
                found.append(candidate)
    return found


def _inside(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        base = root.resolve()
    except OSError:
        return False
    return resolved == base or base in resolved.parents


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique: list[Finding] = []
    seen: set[tuple[str, str, int, str]] = set()
    for item in sorted(findings, key=lambda finding: (finding.path, finding.line, finding.rule_id, finding.message)):
        key = (item.rule_id, item.path, item.line, item.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique

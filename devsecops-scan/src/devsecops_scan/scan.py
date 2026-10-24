from __future__ import annotations

import logging
from importlib.resources import files
from pathlib import Path

from devsecops_scan.config import Settings
from devsecops_scan.dast import scan_dast
from devsecops_scan.discover import LOCK_NAMES, iter_files, read_text
from devsecops_scan.errors import ScanError
from devsecops_scan.models import Finding, ScanReport
from devsecops_scan.sast import scan_sast
from devsecops_scan.sca import (
    Dependency,
    load_advisories,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
    scan_dependencies,
)
from devsecops_scan.secrets import scan_secrets

logger = logging.getLogger("devsecops_scan")

_MAX_FILES = 50_000


def run_scan(settings: Settings) -> ScanReport:
    findings: list[Finding] = []
    files_scanned = 0
    manifests: list[Dependency] = []
    lock_dirs: set[Path] = set()
    root = settings.root
    manifest_names = {"requirements.txt", "package-lock.json", "package.json", "go.mod"}
    seen_files = 0

    for path in iter_files(root, exclude=settings.exclude):
        seen_files += 1
        if seen_files > _MAX_FILES:
            raise ScanError(f"refusing to scan more than {_MAX_FILES} files")
        relative = _relative(root, path)
        if path.name in LOCK_NAMES and not settings.sca:
            continue
        text = read_text(path, max_bytes=settings.max_bytes)
        if text is None:
            continue
        files_scanned += 1
        if settings.sca and path.name in manifest_names:
            if path.name == "package-lock.json":
                lock_dirs.add(path.parent)
            manifests.extend(_dependencies(path.name, text, relative, root))
        if path.name in LOCK_NAMES:
            continue
        if settings.secrets:
            findings.extend(scan_secrets(text, relative))
        if settings.sast:
            findings.extend(scan_sast(text, relative))

    if settings.sca:
        dependencies = _dedupe(
            [
                dep
                for dep in manifests
                if not (dep.path.endswith("package.json") and _parent(root, dep.path) in lock_dirs)
            ]
        )
        findings.extend(
            scan_dependencies(
                dependencies,
                load_advisories(_advisory_path(settings)),
                require_pins=settings.require_pins,
            )
        )
    if settings.dast_url:
        findings.extend(
            scan_dast(
                settings.dast_url,
                authorized=settings.dast_authorized,
                timeout=settings.timeout,
            )
        )
    findings.sort(key=lambda item: (item.path or "", item.line or 0, item.rule_id))
    logger.info("scanned %s files, %s findings", files_scanned, len(findings))
    return ScanReport(findings=tuple(findings), files_scanned=files_scanned)


def _dependencies(name: str, text: str, relative: str, root: Path) -> list[Dependency]:
    if name == "requirements.txt":
        base = root if root.is_dir() else root.parent
        return parse_requirements(text, relative, root=base)
    if name == "package-lock.json":
        return parse_package_lock(text, relative)
    if name == "package.json":
        return parse_package_json(text, relative)
    if name == "go.mod":
        return parse_go_mod(text, relative)
    return []


def _advisory_path(settings: Settings) -> Path:
    if settings.advisories is not None:
        return settings.advisories
    resource = files("devsecops_scan").joinpath("advisories/starter.json")
    return Path(str(resource))


def _relative(root: Path, path: Path) -> str:
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def _dedupe(dependencies: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str, str | None, str, int | None]] = set()
    unique: list[Dependency] = []
    for dep in dependencies:
        key = (dep.ecosystem, dep.name, dep.version, dep.path, dep.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dep)
    return unique


def _parent(root: Path, relative: str) -> Path:
    base = root if root.is_dir() else root.parent
    return (base / relative).parent

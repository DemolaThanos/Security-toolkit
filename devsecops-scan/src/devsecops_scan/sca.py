from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from devsecops_scan.errors import ScanError
from devsecops_scan.models import Finding, Severity, parse_severity

logger = logging.getLogger("devsecops_scan.sca")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    path: str
    line: int | None


@dataclass(frozen=True)
class VersionRange:
    introduced: str | None
    fixed: str | None
    last_affected: str | None


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    severity: Severity
    ecosystem: str
    package: str
    ranges: tuple[VersionRange, ...]
    versions: tuple[str, ...]


def scan_dependencies(
    dependencies: list[Dependency],
    advisories: tuple[Advisory, ...],
    *,
    require_pins: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    index: dict[tuple[str, str], list[Advisory]] = {}
    for advisory in advisories:
        index.setdefault((advisory.ecosystem.lower(), _key(advisory.ecosystem, advisory.package)), []).append(advisory)
    for dep in dependencies:
        if dep.version is None:
            if require_pins:
                findings.append(
                    Finding(
                        rule_id="unpinned-dependency",
                        severity=Severity.MEDIUM,
                        message=f"{dep.name} has no exact version",
                        tool="sca",
                        path=dep.path,
                        line=dep.line,
                    )
                )
            continue
        matched = index.get((dep.ecosystem.lower(), _key(dep.ecosystem, dep.name)), [])
        parsed = _parse_version(dep.version)
        if parsed is None:
            continue
        for advisory in matched:
            if _affected(parsed, dep.version, advisory):
                findings.append(
                    Finding(
                        rule_id=advisory.id,
                        severity=advisory.severity,
                        message=f"{advisory.id}: {advisory.summary} ({dep.name} {dep.version})",
                        tool="sca",
                        path=dep.path,
                        line=dep.line,
                    )
                )
    return findings


def parse_requirements(text: str, relative_path: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        pinned = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9.*+!_-]+)",
            line,
        )
        if pinned:
            matched_version = pinned.group(2)
            if not isinstance(matched_version, str):
                continue
            version = None if "*" in matched_version else matched_version
            dependencies.append(Dependency("PyPI", canonicalize_name(pinned.group(1)), version, relative_path, lineno))
            continue
        named = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if named:
            dependencies.append(Dependency("PyPI", canonicalize_name(named.group(1)), None, relative_path, lineno))
    return dependencies


def parse_package_lock(text: str, relative_path: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{relative_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScanError(f"{relative_path} is not a package-lock object")
    dependencies: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if path == "" or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            if not isinstance(name, str):
                name = str(path).split("node_modules/")[-1]
            version = meta.get("version")
            if isinstance(name, str) and isinstance(version, str):
                dependencies.append(Dependency("npm", name, version, relative_path, None))
        return dependencies
    raw_deps = data.get("dependencies")
    if isinstance(raw_deps, dict):
        _walk_npm_v1(raw_deps, relative_path, dependencies)
    return dependencies


def parse_package_json(text: str, relative_path: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{relative_path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        return []
    dependencies: list[Dependency] = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(name, str):
                continue
            dependencies.append(Dependency("npm", name, _exact_npm(spec), relative_path, None))
    return dependencies


def parse_go_mod(text: str, relative_path: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    mode: str | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if mode == "skip":
            if line == ")":
                mode = None
            continue
        if mode == "require":
            if line == ")":
                mode = None
                continue
            dep = _go_dep(line, relative_path, lineno)
            if dep is not None:
                dependencies.append(dep)
            continue
        if line.startswith(("exclude (", "replace (")):
            mode = "skip"
            continue
        if line.startswith("require ("):
            mode = "require"
            continue
        if line.startswith("require "):
            dep = _go_dep(line[len("require ") :], relative_path, lineno)
            if dep is not None:
                dependencies.append(dep)
    return dependencies


def load_advisories(path: Path) -> tuple[Advisory, ...]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"cannot read advisories {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScanError(f"{path} is not valid advisory JSON: {exc}") from exc
    records = _records(data, path)
    advisories: list[Advisory] = []
    for record in records:
        advisories.extend(_advisory_from_osv(record))
    return tuple(advisories)


def _records(data: object, path: Path) -> list[dict[str, object]]:
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        items = data["vulnerabilities"]
    elif isinstance(data, dict) and "affected" in data:
        items = [data]
    else:
        raise ScanError(f"{path} is not an OSV object, array, or vulnerabilities bundle")
    records: list[dict[str, object]] = []
    for item in items:
        if isinstance(item, dict):
            records.append(item)
    return records


def _advisory_from_osv(record: dict[str, object]) -> list[Advisory]:
    identifier = record.get("id")
    if not isinstance(identifier, str) or not identifier:
        return []
    summary = record.get("summary")
    if not isinstance(summary, str) or not summary:
        summary = identifier
    severity = _severity(record)
    affected = record.get("affected")
    if not isinstance(affected, list):
        return []
    advisories: list[Advisory] = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package")
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            continue
        ranges = tuple(_ranges(item.get("ranges")))
        versions = (
            tuple(version for version in item.get("versions", []) if isinstance(version, str))
            if isinstance(item.get("versions"), list)
            else ()
        )
        advisories.append(
            Advisory(
                id=identifier,
                summary=summary,
                severity=severity,
                ecosystem=ecosystem,
                package=canonicalize_name(name) if ecosystem.lower() == "pypi" else name,
                ranges=ranges,
                versions=versions,
            )
        )
    return advisories


def _severity(record: dict[str, object]) -> Severity:
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        label = specific.get("severity")
        if isinstance(label, str):
            try:
                return parse_severity(label)
            except ValueError:
                logger.debug("unknown advisory severity %s", label)
    return Severity.MEDIUM


def _ranges(raw: object) -> list[VersionRange]:
    if not isinstance(raw, list):
        return []
    parsed: list[VersionRange] = []
    for item in raw:
        if not isinstance(item, dict) or item.get("type") == "GIT":
            continue
        events = item.get("events")
        if not isinstance(events, list):
            continue
        introduced: str | None = None
        fixed: str | None = None
        last_affected: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if isinstance(event.get("introduced"), str):
                introduced = event["introduced"]
            if isinstance(event.get("fixed"), str):
                fixed = event["fixed"]
            if isinstance(event.get("last_affected"), str):
                last_affected = event["last_affected"]
        parsed.append(VersionRange(introduced, fixed, last_affected))
    return parsed


def _affected(version: Version, raw_version: str, advisory: Advisory) -> bool:
    if any(_same(raw_version, listed) for listed in advisory.versions):
        return True
    return any(_in_range(version, bounds) for bounds in advisory.ranges)


def _in_range(version: Version, bounds: VersionRange) -> bool:
    # OSV uses "0" for the start of a package's history.
    vulnerable = False
    if bounds.introduced is None and bounds.fixed is None and bounds.last_affected is None:
        return False
    introduced = bounds.introduced
    if introduced is not None and (introduced in {"0", "0.0.0"} or _at_least(version, introduced)):
        vulnerable = True
    if bounds.fixed is not None and _at_least(version, bounds.fixed):
        vulnerable = False
    if bounds.last_affected is not None and _newer_than(version, bounds.last_affected):
        vulnerable = False
    return vulnerable


def _at_least(version: Version, raw: str) -> bool:
    other = _parse_version(raw)
    if other is None:
        return False
    return version >= other


def _newer_than(version: Version, raw: str) -> bool:
    other = _parse_version(raw)
    if other is None:
        return False
    return version > other


def _parse_version(raw: str) -> Version | None:
    text = raw.strip()
    if text[:1] in {"v", "V"}:
        text = text[1:]
    text = re.sub(r"\+incompatible$", "", text)
    try:
        return Version(text)
    except InvalidVersion:
        logger.debug("unparsable version %s", raw)
        return None


def _same(left: str, right: str) -> bool:
    return _parse_version(left) == _parse_version(right) and _parse_version(left) is not None


def _key(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "pypi":
        return canonicalize_name(name)
    return name


def _exact_npm(spec: object) -> str | None:
    if not isinstance(spec, str):
        return None
    if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec):
        return spec
    if re.fullmatch(r"[=vV]\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", spec):
        return spec[1:]
    return None


def _walk_npm_v1(block: dict[str, object], path: str, dependencies: list[Dependency]) -> None:
    for name, meta in block.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str):
            dependencies.append(Dependency("npm", name, version, path, None))
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1(nested, path, dependencies)


def _go_dep(line: str, path: str, lineno: int) -> Dependency | None:
    parts = line.split()
    if len(parts) < 2:
        return None
    version = parts[1][1:] if parts[1].startswith("v") else parts[1]
    return Dependency("Go", parts[0], version, path, lineno)

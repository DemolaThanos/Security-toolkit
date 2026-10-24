from __future__ import annotations

import json
import logging
import math
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from devsecops_scan.errors import ScanError
from devsecops_scan.models import Finding, Severity, parse_severity

logger = logging.getLogger("devsecops_scan.sca")

_INCLUDE = re.compile(r"^(?:-r|--requirement|-c|--constraint)(?:\s+|=)(\S+)$")
_MAX_INCLUDE_BYTES = 1_000_000
_MAX_INCLUDE_DEPTH = 5


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    path: str
    line: int | None


@dataclass(frozen=True)
class RangeEvent:
    kind: str
    value: str


@dataclass(frozen=True)
class Advisory:
    id: str
    summary: str
    severity: Severity
    ecosystem: str
    package: str
    ranges: tuple[tuple[RangeEvent, ...], ...]
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
        for advisory in matched:
            if _matches(dep.version, parsed, advisory):
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


def parse_requirements(
    text: str,
    relative_path: str,
    *,
    root: Path | None = None,
    _seen: set[Path] | None = None,
    _depth: int = 0,
) -> list[Dependency]:
    seen = _seen
    if root is not None:
        current = (root.resolve() / relative_path).resolve()
        seen = _seen if _seen is not None else set()
        if current in seen:
            return []
        seen.add(current)
    dependencies: list[Dependency] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        included = _INCLUDE.match(line)
        if included:
            if root is None or seen is None:
                raise ScanError(f"{relative_path}:{lineno} includes another file, but no scan root was set")
            if _depth >= _MAX_INCLUDE_DEPTH:
                raise ScanError(f"{relative_path}:{lineno} includes are nested too deeply")
            spec = included.group(1)
            target = _include_path(root, relative_path, spec)
            try:
                info = target.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_INCLUDE_BYTES:
                    raise ScanError(f"requirement include {spec} is too large")
                body = target.read_text(encoding="utf-8")
            except ScanError:
                raise
            except (OSError, UnicodeError) as exc:
                raise ScanError(f"cannot read requirement include {spec}: {exc}") from exc
            rel = target.resolve().relative_to(root.resolve()).as_posix()
            dependencies.extend(parse_requirements(body, rel, root=root, _seen=seen, _depth=_depth + 1))
            continue
        if line.startswith("-"):
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
            if isinstance(name, str) and name and isinstance(version, str):
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
    replaces: dict[str, tuple[str, str | None]] = {}
    mode: str | None = None
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if mode in {"require", "replace", "skip"}:
            if line == ")":
                mode = None
                continue
            if mode == "require":
                dep = _go_dep(line, relative_path, lineno)
                if dep is not None:
                    dependencies.append(dep)
            elif mode == "replace":
                parsed = _go_replace(line)
                if parsed is not None:
                    replaces[parsed[0]] = (parsed[1], parsed[2])
            continue
        if line.startswith("replace ("):
            mode = "replace"
            continue
        if line.startswith(("exclude (", "retract (")):
            mode = "skip"
            continue
        if line.startswith("require ("):
            mode = "require"
            continue
        if line.startswith("require "):
            dep = _go_dep(line[len("require ") :], relative_path, lineno)
            if dep is not None:
                dependencies.append(dep)
            continue
        if line.startswith("replace "):
            parsed = _go_replace(line[len("replace ") :])
            if parsed is not None:
                replaces[parsed[0]] = (parsed[1], parsed[2])
    if not replaces:
        return dependencies
    adjusted: list[Dependency] = []
    for dep in dependencies:
        replacement = replaces.get(dep.name)
        if replacement is None or replacement[1] is None:
            adjusted.append(dep)
            continue
        module, version = replacement
        adjusted.append(Dependency("Go", module, version, dep.path, dep.line))
    return adjusted


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


def _include_path(root: Path, relative_path: str, spec: str) -> Path:
    if spec.startswith(("/", "\\")) or any(char in spec for char in "\r\n\x00"):
        raise ScanError(f"requirement include {spec} is not a relative path")
    root_resolved = root.resolve()
    base = (root_resolved / relative_path).parent
    try:
        target = (base / spec).resolve()
        target.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise ScanError(f"requirement include {spec} escapes the scan root") from exc
    if not target.is_file():
        raise ScanError(f"requirement include {spec} is not a file")
    return target


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
                logger.warning("unknown advisory severity %s", label)
    scored = _cvss_severity(record.get("severity"))
    if scored is not None:
        return scored
    logger.warning("advisory %s has no usable severity; treating it as high", record.get("id"))
    return Severity.HIGH


_CVSS_V3 = re.compile(r"^CVSS:3\.[01]/(.+)$")
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _cvss_severity(raw: object) -> Severity | None:
    if not isinstance(raw, list):
        return None
    scores: list[float] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if not isinstance(score, str):
            continue
        parsed = _cvss_score(score)
        if parsed is not None:
            scores.append(parsed)
    if not scores:
        return None
    return _score_to_severity(max(scores))


def _cvss_score(score: str) -> float | None:
    text = score.strip()
    matched = _CVSS_V3.match(text)
    if matched:
        return _cvss_v3_base(matched.group(1))
    if text.startswith("CVSS:"):
        return None
    return _numeric_score(text)


def _cvss_v3_base(vector: str) -> float | None:
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        attack = _AV[metrics["AV"]]
        complexity = _AC[metrics["AC"]]
        interaction = _UI[metrics["UI"]]
        scope = metrics["S"]
        confidentiality = _CIA[metrics["C"]]
        integrity = _CIA[metrics["I"]]
        availability = _CIA[metrics["A"]]
    except KeyError:
        return None
    privileges = _PR_CHANGED if scope == "C" else _PR_UNCHANGED if scope == "U" else None
    if privileges is None or metrics["PR"] not in privileges:
        return None
    privilege = privileges[metrics["PR"]]
    impact_sub = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    # The two CVSS impact formulas stay on separate lines; a ternary is harder to check.
    if scope == "U":  # noqa: SIM108
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * attack * complexity * privilege * interaction
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return min(10.0, _roundup(raw))


def _roundup(value: float) -> float:
    """Smallest one-decimal value greater than or equal to `value` (CVSS v3.1)."""
    if value <= 0:
        return 0.0
    scaled = math.ceil(value * 10 - 1e-9)
    return scaled / 10


def _numeric_score(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    if 0 <= value <= 10:
        return value
    return None


def _score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _ranges(raw: object) -> list[tuple[RangeEvent, ...]]:
    if not isinstance(raw, list):
        return []
    parsed: list[tuple[RangeEvent, ...]] = []
    for item in raw:
        if not isinstance(item, dict) or item.get("type") == "GIT":
            continue
        events = item.get("events")
        if not isinstance(events, list):
            continue
        collected: list[RangeEvent] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            for kind in ("introduced", "fixed", "last_affected", "limit"):
                value = event.get(kind)
                if isinstance(value, str):
                    collected.append(RangeEvent(kind, value))
        if collected:
            parsed.append(tuple(collected))
    return parsed


def _matches(raw_version: str, version: Version | None, advisory: Advisory) -> bool:
    if any(_same(raw_version, listed) for listed in advisory.versions):
        return True
    if version is None:
        return False
    return any(_in_events(version, events) for events in advisory.ranges)


def _in_events(version: Version, events: tuple[RangeEvent, ...]) -> bool:
    # Walk OSV events in order. A later introduced event can mark a version
    # vulnerable again after an earlier fix.
    affected = False
    for event in events:
        if event.kind == "introduced":
            if event.value in {"0", "0.0.0"} or _at_least(version, event.value):
                affected = True
        elif event.kind in {"fixed", "limit"}:
            if _at_least(version, event.value):
                affected = False
        elif event.kind == "last_affected" and _newer_than(version, event.value):
            affected = False
    return affected


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
    text = _strip_v(raw)
    text = re.sub(r"\+incompatible$", "", text)
    try:
        return Version(text)
    except InvalidVersion:
        logger.debug("unparsable version %s", raw)
        return None


def _strip_v(raw: str) -> str:
    text = raw.strip()
    if len(text) > 1 and text[0] in {"v", "V"} and text[1].isdigit():
        return text[1:]
    return text


def _same(left: str, right: str) -> bool:
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is not None or parsed_right is not None:
        return parsed_left == parsed_right and parsed_left is not None
    return _strip_v(left) == _strip_v(right)


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
    return Dependency("Go", parts[0], _strip_v(parts[1]), path, lineno)


def _go_replace(line: str) -> tuple[str, str, str | None] | None:
    if "=>" not in line:
        return None
    left, right = line.split("=>", 1)
    left_parts = left.split()
    right_parts = right.split()
    if not left_parts or not right_parts:
        return None
    target = right_parts[0]
    if target.startswith((".", "/")) or len(right_parts) < 2:
        return left_parts[0], target, None
    return left_parts[0], target, _strip_v(right_parts[1])

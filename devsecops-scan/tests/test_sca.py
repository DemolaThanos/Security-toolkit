import json
from pathlib import Path

from devsecops_scan.models import Severity
from devsecops_scan.sca import (
    Advisory,
    Dependency,
    RangeEvent,
    load_advisories,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
    scan_dependencies,
)

STARTER = Path(__file__).resolve().parents[1] / "src" / "devsecops_scan" / "advisories" / "starter.json"


def test_requirements_and_ranges() -> None:
    advisories = load_advisories(STARTER)
    deps = parse_requirements("Requests==2.31.0\nflask\n", "requirements.txt")
    findings = scan_dependencies(deps, advisories, require_pins=True)
    ids = {item.rule_id for item in findings}
    assert ids == {
        "GHSA-9hjg-9r4m-mvj7",
        "GHSA-9wx4-h78v-vm56",
        "GHSA-gc5v-m9x4-r6x2",
        "unpinned-dependency",
    }
    clean = parse_requirements("requests==2.33.0\n", "requirements.txt")
    assert scan_dependencies(clean, advisories, require_pins=False) == []


def test_package_lock_beats_ranges() -> None:
    text = json.dumps({"packages": {"": {"name": "app"}, "node_modules/left-pad": {"version": "1.2.3"}}})
    deps = parse_package_lock(text, "package-lock.json")
    assert [(item.name, item.version) for item in deps] == [("left-pad", "1.2.3")]


def test_package_json_exact_only() -> None:
    text = json.dumps({"dependencies": {"left-pad": "1.2.3", "other": "^1.0.0"}})
    deps = parse_package_json(text, "package.json")
    versions = {item.name: item.version for item in deps}
    assert versions == {"left-pad": "1.2.3", "other": None}


def test_go_mod() -> None:
    text = """
module example.com/app

go 1.22

require (
    golang.org/x/net v0.24.0 // indirect
)

require golang.org/x/text v0.14.0
exclude golang.org/x/crypto v0.1.0
"""
    deps = parse_go_mod(text, "go.mod")
    assert [(item.name, item.version, item.line) for item in deps] == [
        ("golang.org/x/net", "0.24.0", 7),
        ("golang.org/x/text", "0.14.0", 10),
    ]


def test_go_replace_selects_the_module_that_is_built() -> None:
    text = """
module example.com/app

go 1.22

require golang.org/x/net v0.24.0

replace golang.org/x/net => example.com/net v0.1.0
"""
    deps = parse_go_mod(text, "go.mod")
    assert [(item.name, item.version) for item in deps] == [("example.com/net", "0.1.0")]


def test_scoped_lock_package_without_name() -> None:
    text = json.dumps({"packages": {"node_modules/@scope/left-pad": {"version": "1.2.3"}}})
    deps = parse_package_lock(text, "package-lock.json")
    assert [(item.name, item.version) for item in deps] == [("@scope/left-pad", "1.2.3")]


def test_reintroduced_and_last_affected_ranges() -> None:
    advisory = Advisory(
        id="TEST-1",
        summary="gap",
        severity=Severity.HIGH,
        ecosystem="PyPI",
        package="demo",
        ranges=(
            (
                RangeEvent("introduced", "0"),
                RangeEvent("fixed", "1.0.0"),
                RangeEvent("introduced", "2.0.0"),
                RangeEvent("fixed", "2.1.0"),
            ),
            (RangeEvent("introduced", "1.0.0"), RangeEvent("last_affected", "1.2.0")),
        ),
        versions=(),
    )

    def flagged(version: str) -> bool:
        dep = Dependency("PyPI", "demo", version, "requirements.txt", 1)
        return any(item.rule_id == "TEST-1" for item in scan_dependencies([dep], (advisory,), require_pins=False))

    assert flagged("0.9.0")
    assert not flagged("1.5.0")
    assert flagged("1.2.0")
    assert not flagged("1.2.1")
    assert flagged("2.0.5")
    assert not flagged("2.1.0")


def test_cvss_v3_score_is_used_when_the_feed_has_no_label() -> None:
    record = {
        "id": "OSV-1",
        "summary": "remote code execution",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "versions": ["1.0.0"],
            }
        ],
    }
    loaded = load_advisories_from(record)
    assert loaded[0].severity is Severity.CRITICAL
    medium = {
        "id": "OSV-2",
        "summary": "info leak",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "versions": ["1.0.0"]}],
    }
    assert load_advisories_from(medium)[0].severity is Severity.HIGH
    unlabeled = {
        "id": "OSV-3",
        "summary": "unspecified",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "versions": ["1.0.0"]}],
    }
    assert load_advisories_from(unlabeled)[0].severity is Severity.HIGH


def load_advisories_from(record: dict[str, object]) -> tuple[Advisory, ...]:
    from devsecops_scan.sca import _advisory_from_osv

    return tuple(_advisory_from_osv(record))


def test_limit_event_is_exclusive() -> None:
    advisory = Advisory(
        id="TEST-2",
        summary="limit",
        severity=Severity.HIGH,
        ecosystem="PyPI",
        package="demo",
        ranges=((RangeEvent("introduced", "0"), RangeEvent("limit", "2.0.0")),),
        versions=(),
    )

    def flagged(version: str) -> bool:
        dep = Dependency("PyPI", "demo", version, "requirements.txt", 1)
        return any(item.rule_id == "TEST-2" for item in scan_dependencies([dep], (advisory,), require_pins=False))

    assert flagged("1.9.0")
    assert not flagged("2.0.0")

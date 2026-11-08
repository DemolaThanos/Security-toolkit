from __future__ import annotations

import json

import pytest

from corsprobe.models import Failure, Finding, Report, Severity
from corsprobe.report import render


def _finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        "origin-reflection",
        severity,
        "https://app.example/api",
        "https://corsprobe.invalid",
        "reflected https://corsprobe.invalid",
        False,
        "https://app.example/api",
    )


def test_table_lists_findings_and_probe_errors() -> None:
    report = Report((_finding(),), (Failure("https://down.example/", "timed out"),), 2)
    text = render(report, "table")
    assert "severity" in text
    assert "origin-reflection" in text
    assert "https://app.example/api" in text
    assert "1 finding" in text
    assert "----" in text
    assert "1 target could not be probed" in text


def test_empty_table() -> None:
    text = render(Report((), (), 0), "table")
    assert text == "no findings\n"


def test_json_shape() -> None:
    payload = json.loads(render(Report((_finding(Severity.LOW),), (), 1), "json"))
    assert payload["targets_checked"] == 1
    assert payload["errors"] == []
    assert payload["findings"][0]["rule_id"] == "origin-reflection"
    assert payload["findings"][0]["severity"] == "low"
    assert payload["findings"][0]["credentials"] is False


def test_sarif_uses_the_finding_severity() -> None:
    sarif = json.loads(render(Report((_finding(Severity.CRITICAL),), (), 1), "sarif"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "corsprobe"
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert rules["origin-reflection"]["properties"]["security-severity"] == "9.0"
    assert rules["origin-reflection"]["defaultConfiguration"]["level"] == "error"
    assert rules["wildcard"]["properties"]["security-severity"] == "3.0"
    result = run["results"][0]
    assert result["ruleId"] == "origin-reflection"
    assert result["level"] == "error"
    assert len(result["partialFingerprints"]["primaryLocationLineHash"]) == 64
    assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == "https://app.example/api"
    assert run["properties"]["targetsChecked"] == 1


def test_unknown_format() -> None:
    with pytest.raises(ValueError, match="unknown format"):
        render(Report((), (), 0), "html")

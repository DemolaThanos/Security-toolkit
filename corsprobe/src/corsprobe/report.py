from __future__ import annotations

import hashlib
import json

from corsprobe import __version__
from corsprobe.checks import RULES, Rule
from corsprobe.models import Finding, Report, Severity, meets_threshold

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORE = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render(report: Report, report_format: str) -> str:
    if report_format == "json":
        return _json(report)
    if report_format == "sarif":
        return json.dumps(_sarif(report), indent=2) + "\n"
    if report_format == "table":
        return _table(report)
    raise ValueError(f"unknown format {report_format!r}")


def _json(report: Report) -> str:
    payload = {
        "targets_checked": report.targets_checked,
        "findings": [item.to_dict() for item in report.findings],
        "errors": [item.to_dict() for item in report.errors],
    }
    return json.dumps(payload, indent=2) + "\n"


def _table(report: Report) -> str:
    lines: list[str] = []
    if report.findings:
        header = ("severity", "rule", "target", "message")
        rows = [
            (item.severity.value, item.rule_id, item.target, " ".join(item.message.split())) for item in report.findings
        ]
        widths = [len(cell) for cell in header]
        for row in rows:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))

        def format_row(row: tuple[str, ...]) -> str:
            return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()

        lines.append(format_row(header))
        lines.append(format_row(tuple("-" * width for width in widths)))
        lines.extend(format_row(row) for row in rows)
        noun = "finding" if len(rows) == 1 else "findings"
        lines.append(f"{len(rows)} {noun}")
    else:
        lines.append("no findings")
    if report.errors:
        noun = "target" if len(report.errors) == 1 else "targets"
        lines.append(f"{len(report.errors)} {noun} could not be probed")
    return "\n".join(lines) + "\n"


def _sarif(report: Report) -> dict[str, object]:
    highest: dict[str, Severity] = {}
    for finding in report.findings:
        current = highest.get(finding.rule_id)
        if current is None or _higher(finding.severity, current):
            highest[finding.rule_id] = finding.severity
    rules: list[dict[str, object]] = []
    seen: set[str] = set()
    for rule in RULES:
        rules.append(_rule(rule, highest.get(rule.id, rule.severity)))
        seen.add(rule.id)
    for finding in report.findings:
        if finding.rule_id in seen:
            continue
        rules.append(_rule(Rule(finding.rule_id, finding.severity, finding.message, finding.message), finding.severity))
        seen.add(finding.rule_id)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "corsprobe",
                        "version": __version__,
                        "informationUri": "https://github.com/DemolaThanos/Security-toolkit",
                        "rules": rules,
                    }
                },
                "results": [_result(finding) for finding in report.findings],
                "properties": {
                    "targetsChecked": report.targets_checked,
                    "errors": [item.to_dict() for item in report.errors],
                },
            }
        ],
    }


def _rule(rule: Rule, severity: Severity) -> dict[str, object]:
    return {
        "id": rule.id,
        "shortDescription": {"text": rule.description},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _LEVEL[severity]},
        "properties": {"security-severity": _SCORE[severity], "tags": ["security", "cors"]},
    }


def _result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {"logicalLocations": [{"name": finding.target, "fullyQualifiedName": finding.target, "kind": "resource"}]}
        ],
        "partialFingerprints": {"primaryLocationLineHash": _fingerprint(finding)},
        "properties": {
            "origin": finding.origin,
            "credentials": finding.credentials,
            "finalUrl": finding.final_url,
        },
    }


def _fingerprint(finding: Finding) -> str:
    raw = "\n".join((finding.rule_id, finding.target, finding.origin, finding.message))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _higher(left: Severity, right: Severity) -> bool:
    return left is not right and meets_threshold(left, right)

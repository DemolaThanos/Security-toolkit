from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

from gha_audit import __version__
from gha_audit.models import Finding, ScanReport, Severity
from gha_audit.rules import RULES

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(report: ScanReport, report_format: str) -> str:
    if report_format == "json":
        payload = {
            "files_checked": report.files_checked,
            "ignored": report.ignored,
            "findings": [item.to_dict() for item in report.findings],
            "errors": list(report.errors),
        }
        return json.dumps(payload, indent=2) + "\n"
    if report_format == "sarif":
        return json.dumps(_sarif(report), indent=2) + "\n"
    return _table(report)


def _table(report: ScanReport) -> str:
    ignored = f", {report.ignored} ignored" if report.ignored else ""
    if not report.findings:
        return f"no findings{ignored}\n"
    header = ("severity", "rule", "location", "message")
    rows = [(item.severity.value, item.rule_id, f"{item.path}:{item.line}", item.message) for item in report.findings]
    widths = [len(cell) for cell in header]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def format_row(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()

    lines = [format_row(header), format_row(tuple("-" * width for width in widths))]
    lines.extend(format_row(row) for row in rows)
    lines.append(f"{len(rows)} findings{ignored}")
    return "\n".join(lines) + "\n"


def _sarif(report: ScanReport) -> dict[str, object]:
    rules = {rule.id: _rule(rule.id, rule.description, rule.remediation, rule.severity) for rule in RULES}
    results = [_result(finding) for finding in report.findings]
    if report.errors:
        rules["parse-error"] = _rule(
            "parse-error",
            "The workflow file could not be read.",
            "Fix the YAML, or pass a workflow or composite action file.",
            Severity.HIGH,
        )
        results.extend(_error_result(error) for error in report.errors)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gha-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/DemolaThanos/Security-toolkit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"filesChecked": report.files_checked, "ignored": report.ignored},
            }
        ],
    }


def _rule(rule_id: str, description: str, remediation: str, severity: Severity) -> dict[str, object]:
    return {
        "id": rule_id,
        "shortDescription": {"text": description},
        "fullDescription": {"text": description},
        "help": {"text": remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[severity]},
        "properties": {"security-severity": _score(severity), "tags": ["security", "github-actions"]},
    }


def _result(finding: Finding) -> dict[str, object]:
    line = finding.line if finding.line > 0 else 1
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path, safe="/:")},
                    "region": {"startLine": line},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(
                f"{finding.rule_id}\n{finding.path}\n{line}\n{finding.message}".encode()
            ).hexdigest()
        },
    }


def _error_result(message: str) -> dict[str, object]:
    return {
        "ruleId": "parse-error",
        "level": "error",
        "message": {"text": message},
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"parse-error\n{message}".encode()).hexdigest()
        },
    }


def _score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]

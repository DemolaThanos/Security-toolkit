from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

from tfplan_guard import __version__
from tfplan_guard.models import Finding, Rule, ScanReport, Severity
from tfplan_guard.rules import RULES

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
            "findings": [item.to_dict() for item in report.findings],
            "errors": list(report.errors),
        }
        return json.dumps(payload, indent=2) + "\n"
    if report_format == "sarif":
        return json.dumps(_sarif(report), indent=2) + "\n"
    if not report.findings:
        return "no findings\n"
    lines = [
        "\t".join(
            (
                item.severity.value,
                item.rule_id,
                _cell(item.path),
                _cell(item.address),
                _cell(item.message),
                _cell(item.remediation),
            )
        )
        for item in report.findings
    ]
    lines.append(f"{len(report.findings)} findings")
    return "\n".join(lines) + "\n"


def _sarif(report: ScanReport) -> dict[str, object]:
    rules = {rule.id: _rule(rule) for rule in RULES}
    results: list[dict[str, object]] = []
    for finding in report.findings:
        results.append(_result(finding))
    if report.errors:
        rules["parse-error"] = {
            "id": "parse-error",
            "shortDescription": {"text": "The plan or state JSON could not be read."},
            "help": {"text": "Pass the JSON from terraform show -json."},
            "defaultConfiguration": {"level": "error"},
            "properties": {"security-severity": "8.0", "tags": ["security"]},
        }
        for error in report.errors:
            results.append(_error_result(error))
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tfplan-guard",
                        "version": __version__,
                        "informationUri": "https://github.com/DemolaThanos/Security-toolkit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"filesChecked": report.files_checked},
            }
        ],
    }


def _rule(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "shortDescription": {"text": rule.description},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        "properties": {"security-severity": _score(rule.severity), "tags": ["security"]},
    }


def _result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(finding.path)},
                    "region": {"startLine": finding.line if finding.line > 0 else 1},
                },
                "logicalLocations": [{"name": finding.address, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(
                f"{finding.rule_id}\n{finding.path}\n{finding.address}\n{finding.message}".encode()
            ).hexdigest()
        },
    }


def _error_result(message: str) -> dict[str, object]:
    result: dict[str, object] = {
        "ruleId": "parse-error",
        "level": "error",
        "message": {"text": message},
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"parse-error\n{message}".encode()).hexdigest()
        },
    }
    path = _error_path(message)
    if path:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(path)},
                    "region": {"startLine": 1},
                }
            }
        ]
    return result


def _error_path(message: str) -> str | None:
    """Best-effort path from a load error. Absolute paths are left off the SARIF URI."""
    for prefix in ("refusing to read ", "cannot stat ", "cannot read "):
        if message.startswith(prefix):
            path, separator, _rest = message[len(prefix) :].partition(": ")
            if separator and path and not path.startswith(("/", "\\")):
                return path
            return None
    for marker in (" is ", ": "):
        if marker not in message:
            continue
        path = message.split(marker, 1)[0].strip()
        if path and not path.startswith(("/", "\\")) and "\n" not in path and len(path) <= 240:
            return path
    return None


def _artifact_uri(path: str) -> str:
    """Percent-encode a relative path so a space survives as a SARIF URI."""
    return quote(path.replace("\\", "/"), safe="/")


def _score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]


def _cell(text: str) -> str:
    return " ".join(text.split())

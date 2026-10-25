from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

from k8s_harden import __version__
from k8s_harden.models import LintReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(report: LintReport, report_format: str) -> str:
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
        f"{item.severity.value}\t{item.rule_id}\t{item.path}\t{item.location}\t{item.message}"
        for item in report.findings
    ]
    lines.append(f"{len(report.findings)} findings")
    return "\n".join(lines) + "\n"


def _sarif(report: LintReport) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in report.findings:
        results.append(_result(rules, finding.rule_id, finding.severity, finding.message, finding.path))
    for error in report.errors:
        results.append(_result(rules, "parse-error", Severity.HIGH, error, None))
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "k8s-harden",
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


def _result(
    rules: dict[str, dict[str, object]],
    rule_id: str,
    severity: Severity,
    message: str,
    path: str | None,
) -> dict[str, object]:
    rules.setdefault(
        rule_id,
        {
            "id": rule_id,
            "shortDescription": {"text": message},
            "properties": {"security-severity": _score(severity)},
        },
    )
    result: dict[str, object] = {
        "ruleId": rule_id,
        "level": _SARIF_LEVEL[severity],
        "message": {"text": message},
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"{rule_id}\n{path or ''}\n{message}".encode()).hexdigest()
        },
    }
    if path is not None:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/:")}}}]
    return result


def _score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]

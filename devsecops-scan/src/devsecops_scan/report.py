from __future__ import annotations

import json
from urllib.parse import quote

from devsecops_scan import __version__
from devsecops_scan.models import ScanReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(report: ScanReport, report_format: str) -> str:
    if report_format == "json":
        return json.dumps(_json_body(report), indent=2) + "\n"
    if report_format == "sarif":
        return json.dumps(_sarif(report), indent=2) + "\n"
    if report_format == "text":
        return _text(report)
    raise ValueError(f"unknown format {report_format!r}")


def _json_body(report: ScanReport) -> dict[str, object]:
    return {
        "files_scanned": report.files_scanned,
        "findings": [finding.to_dict() for finding in report.findings],
    }


def _text(report: ScanReport) -> str:
    if not report.findings:
        return f"no findings in {report.files_scanned} files\n"
    lines = []
    for finding in report.findings:
        where = finding.path or "-"
        if finding.line is not None:
            where = f"{where}:{finding.line}"
        lines.append(f"{finding.severity.value}\t{finding.tool}\t{finding.rule_id}\t{where}\t{finding.message}")
    lines.append(f"{len(report.findings)} findings in {report.files_scanned} files")
    return "\n".join(lines) + "\n"


def _sarif(report: ScanReport) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "properties": {
                    "tags": [finding.tool],
                    "security-severity": _score(finding.severity),
                },
            },
        )
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message},
        }
        if finding.path is not None:
            location: dict[str, object] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path, safe="/:")},
                }
            }
            if finding.line is not None:
                physical = location["physicalLocation"]
                assert isinstance(physical, dict)
                physical["region"] = {"startLine": finding.line}
            result["locations"] = [location]
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "devsecops-scan",
                        "version": __version__,
                        "informationUri": "https://github.com/DemolaThanos/Security-toolkit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"filesScanned": report.files_scanned},
            }
        ],
    }


def _score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]

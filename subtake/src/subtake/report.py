from __future__ import annotations

import hashlib
import json

from subtake import __version__
from subtake.models import Report, Result, Verdict

_LEVEL = {
    Verdict.LIKELY: "error",
    Verdict.EDGE: "note",
}
_SCORE = {
    Verdict.LIKELY: "8.0",
    Verdict.EDGE: "3.0",
}
_RANK = {
    Verdict.LIKELY: 2,
    Verdict.EDGE: 1,
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
    likely, edge, safe = report.counts()
    payload = {
        "hosts_checked": len(report.results),
        "likely_vulnerable": likely,
        "edge_case": edge,
        "not_vulnerable": safe,
        "results": [item.to_dict() for item in report.results],
    }
    return json.dumps(payload, indent=2) + "\n"


def _table(report: Report) -> str:
    if not report.results:
        return "no hosts\n"
    rows = [("verdict", "host", "service", "evidence")]
    for item in report.results:
        rows.append((item.verdict.value, item.host, item.service or "-", " ".join(item.evidence.split())))
    widths = [max(len(row[index]) for row in rows) for index in range(3)]
    lines = []
    for row in rows:
        cells = [cell.ljust(widths[index]) for index, cell in enumerate(row[:3])]
        lines.append("  ".join(cells) + "  " + row[3])
    likely, edge, safe = report.counts()
    lines.append("")
    lines.append(f"{likely} likely-vulnerable, {edge} edge-case, {safe} not-vulnerable")
    return "\n".join(lines) + "\n"


def _sarif(report: Report) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    ranks: dict[str, int] = {}
    results = []
    likely, edge, safe = report.counts()
    for item in report.issues():
        rule_id = _rule_id(item)
        rank = _RANK[item.verdict]
        if rule_id not in rules or rank > ranks[rule_id]:
            rules[rule_id] = _rule(rule_id, item)
            ranks[rule_id] = rank
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL[item.verdict],
                "message": {"text": f"{item.host}: {item.evidence}"},
                "locations": [
                    {"logicalLocations": [{"name": item.host, "fullyQualifiedName": item.host, "kind": "resource"}]}
                ],
                "partialFingerprints": {"primaryLocationLineHash": _fingerprint(item)},
                "properties": {
                    "verdict": item.verdict.value,
                    "service": item.service,
                    "cnameChain": list(item.cname_chain),
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "subtake",
                        "version": __version__,
                        "informationUri": "https://github.com/DemolaThanos/Security-toolkit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "hostsChecked": len(report.results),
                    "likelyVulnerable": likely,
                    "edgeCase": edge,
                    "notVulnerable": safe,
                },
            }
        ],
    }


def _rule(rule_id: str, item: Result) -> dict[str, object]:
    text = f"Dangling CNAME at {item.service}" if item.service else "Unconfirmed dangling CNAME"
    return {
        "id": rule_id,
        "shortDescription": {"text": text},
        "help": {"text": "Remove the CNAME, or point it at a resource you control."},
        "properties": {"security-severity": _SCORE[item.verdict]},
    }


def _rule_id(item: Result) -> str:
    if item.fingerprint:
        return f"subtake/{item.fingerprint}"
    return "subtake/unconfirmed"


def _fingerprint(item: Result) -> str:
    raw = "\n".join((item.fingerprint or "", item.host, item.verdict.value, item.evidence))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

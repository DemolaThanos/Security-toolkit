from __future__ import annotations

import logging
from pathlib import Path

from tfplan_guard import load as load_mod
from tfplan_guard.models import Finding, ScanReport
from tfplan_guard.rules import evaluate
from tfplan_guard.suppress import Suppression, inline_suppressions, suppressed

logger = logging.getLogger("tfplan_guard.scan")


def scan_path(root: Path, *, max_bytes: int, suppressions: tuple[Suppression, ...]) -> ScanReport:
    files, truncated = load_mod.terraform_files(root)
    if truncated:
        return ScanReport(
            findings=(),
            errors=(f"refusing to scan more than {load_mod.MAX_FILES} JSON files",),
            files_checked=len(files),
        )
    findings: list[Finding] = []
    errors: list[str] = []
    checked = 0
    strict = root.is_file()
    for path in files:
        display = load_mod.display_path(root, path)
        resources, error = load_mod.load_document(path, display, max_bytes=max_bytes, strict=strict)
        if error:
            errors.append(error)
            continue
        if resources is None:
            continue
        checked += 1
        inline, inline_errors = inline_suppressions(resources)
        errors.extend(inline_errors)
        active = suppressions + inline
        logger.info("checked %s resources in %s", len(resources), display)
        for finding in evaluate(resources):
            if suppressed(finding, active):
                logger.info("suppressed %s on %s", finding.rule_id, finding.address)
                continue
            findings.append(finding)
    findings.sort(key=lambda item: (item.path, item.address, item.rule_id, item.message))
    return ScanReport(findings=tuple(findings), errors=tuple(errors), files_checked=checked)

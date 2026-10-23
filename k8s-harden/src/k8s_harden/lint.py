from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from k8s_harden.load import load_file
from k8s_harden.models import Finding, LintReport, Severity
from k8s_harden.rules import ignores, lint_document, network_policy_namespace, workload_namespace

_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "__pycache__"})


def lint_path(root: Path, *, max_bytes: int, exclude: tuple[str, ...]) -> LintReport:
    files = list(_manifests(root, exclude))
    errors: list[str] = []
    documents: list[tuple[str, dict[str, Any]]] = []
    for path in files:
        loaded, error = load_file(path, max_bytes=max_bytes)
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        if error:
            errors.append(error)
        for document in loaded:
            documents.append((relative, document))
    findings: list[Finding] = []
    workloads: dict[str, list[tuple[str, set[str]]]] = {}
    policies: set[str] = set()
    for relative, document in documents:
        findings.extend(lint_document(document, relative))
        namespace = workload_namespace(document)
        if namespace is not None:
            workloads.setdefault(namespace, []).append((relative, ignores(document)))
        policy_namespace = network_policy_namespace(document)
        if policy_namespace is not None:
            policies.add(policy_namespace)
    for namespace, entries in sorted(workloads.items()):
        if namespace in policies:
            continue
        if entries and all("netpol-missing" in ignored or "*" in ignored for _, ignored in entries):
            continue
        manifest = entries[0][0]
        findings.append(
            Finding(
                "netpol-missing",
                Severity.MEDIUM,
                f"namespace {namespace} has workloads and no NetworkPolicy in this scan",
                manifest,
                f"namespace/{namespace}",
            )
        )
    findings.sort(key=lambda item: (item.path, item.location, item.rule_id))
    return LintReport(findings=tuple(findings), errors=tuple(errors))


def _manifests(root: Path, exclude: tuple[str, ...]) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.startswith(".")]
        for name in filenames:
            if Path(name).suffix.lower() not in {".yaml", ".yml", ".json"}:
                continue
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            if any(pattern and (pattern in relative or relative.endswith(pattern)) for pattern in exclude):
                continue
            found.append(path)
    return sorted(found)

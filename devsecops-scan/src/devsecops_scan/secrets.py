from __future__ import annotations

import re

from devsecops_scan.models import Finding, Severity

_IGNORE = "devsecops-scan: ignore"

# AWS documents these two values. They are not live credentials.
_IGNORED_VALUES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

_PLACEHOLDER = re.compile(
    r"(?i)^("
    r"changeme|changeit|password|secret|example|placeholder|todo|xxx+|test|dummy|"
    r"sample|redacted|insert[-_ ]?here|your[-_ ]?(key|secret|password)|none|null|"
    r"<.*>|\$\{.*\}|\{\{.*\}\}"
    r")$"
)


def _rule(
    rule_id: str,
    severity: Severity,
    pattern: str,
    description: str,
) -> tuple[str, Severity, re.Pattern[str], str]:
    return rule_id, severity, re.compile(pattern), description


_RULES = (
    _rule(
        "aws-access-key-id",
        Severity.HIGH,
        r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "AWS access key id",
    ),
    _rule(
        "github-token",
        Severity.HIGH,
        r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
        "GitHub token",
    ),
    _rule(
        "github-fine-grained-token",
        Severity.HIGH,
        r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        "GitHub fine-grained token",
    ),
    _rule(
        "slack-token",
        Severity.HIGH,
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b",
        "Slack token",
    ),
    _rule(
        "slack-webhook",
        Severity.HIGH,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "Slack incoming webhook",
    ),
    _rule(
        "stripe-live-key",
        Severity.HIGH,
        r"\bsk_live_[0-9a-zA-Z]{24,}\b",
        "Stripe live secret key",
    ),
    _rule(
        "pypi-token",
        Severity.HIGH,
        r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{20,}",
        "PyPI API token",
    ),
    _rule(
        "gitlab-pat",
        Severity.HIGH,
        r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        "GitLab personal access token",
    ),
    _rule(
        "npm-token",
        Severity.HIGH,
        r"\bnpm_[A-Za-z0-9]{36}\b",
        "npm access token",
    ),
    _rule(
        "private-key",
        Severity.HIGH,
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
        "private key material",
    ),
    _rule(
        "aws-secret-access-key",
        Severity.HIGH,
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "AWS secret access key assignment",
    ),
    _rule(
        "password-assignment",
        Severity.MEDIUM,
        r"(?i)\b(?:password|passwd|secret|api_key|apikey|api_secret|private_key)\b"
        r"\s*[=:]\s*['\"]([^'\"]{12,})['\"]",
        "credential assigned in source",
    ),
)


def scan_secrets(text: str, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _IGNORE in line:
            continue
        for rule_id, severity, pattern, description in _RULES:
            matched = False
            for match in pattern.finditer(line):
                value = match.group(1) if match.lastindex else match.group(0)
                if value in _IGNORED_VALUES or _PLACEHOLDER.match(value.strip()):
                    continue
                matched = True
                break
            if matched:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=description,
                        tool="secrets",
                        path=relative_path,
                        line=lineno,
                    )
                )
    return findings

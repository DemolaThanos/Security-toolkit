from __future__ import annotations

import re

from devsecops_scan.models import Finding, Severity

_IGNORE = "devsecops-scan: ignore"

_PY = frozenset({".py"})
_JS = frozenset({".js", ".jsx", ".mjs", ".ts", ".tsx"})
_BOTH = _PY | _JS


def _rule(
    rule_id: str,
    severity: Severity,
    extensions: frozenset[str],
    pattern: str,
    description: str,
    suppress: str | None = None,
) -> tuple[str, Severity, frozenset[str], re.Pattern[str], str, re.Pattern[str] | None]:
    return (
        rule_id,
        severity,
        extensions,
        re.compile(pattern),
        description,
        re.compile(suppress) if suppress else None,
    )


# Attribute calls such as model.eval( are left alone; builtin eval( is the target.
# literal_eval is excluded by the word-boundary lookbehind.
_RULES = (
    _rule(
        "python-eval",
        Severity.HIGH,
        _PY,
        r"(?<![\w.])eval\s*\(",
        "eval() runs attacker-controlled text as code",
    ),
    _rule(
        "python-exec",
        Severity.HIGH,
        _PY,
        r"(?<![\w.])exec\s*\(",
        "exec() runs attacker-controlled text as code",
    ),
    _rule(
        "subprocess-shell",
        Severity.HIGH,
        _PY,
        r"\bshell\s*=\s*True\b",
        "shell=True passes the command through a shell",
    ),
    _rule(
        "os-system",
        Severity.HIGH,
        _PY,
        r"(?<![\w.])os\.(?:system|popen)\s*\(",
        "os.system or os.popen runs a command through a shell",
    ),
    _rule(
        "yaml-unsafe-load",
        Severity.HIGH,
        _PY,
        r"\byaml\.(?:unsafe_load|load)\s*\(",
        "yaml.load can instantiate arbitrary objects; use yaml.safe_load",
        suppress=r"SafeLoader|safe_load",
    ),
    _rule(
        "insecure-pickle",
        Severity.MEDIUM,
        _PY,
        r"\bpickle\.loads?\s*\(",
        "pickle deserialises arbitrary objects",
    ),
    _rule(
        "tls-verify-disabled",
        Severity.HIGH,
        _PY,
        r"\bverify\s*=\s*False\b",
        "TLS certificate verification is disabled",
    ),
    _rule(
        "sql-string-execute",
        Severity.HIGH,
        _PY,
        r"""\.(?:execute|executemany)\(\s*(?:f(?:\"\"\"|'''|["'])|(?:[A-Za-z_][\w.]*|["'][^"']*["'])\s*%)""",
        "SQL is built with an f-string or percent formatting",
    ),
    _rule(
        "sql-string-concat",
        Severity.MEDIUM,
        _PY,
        r"""\.(?:execute|executemany)\(\s*["'][^"']*["']\s*\+\s*(?!["'])""",
        "SQL is built by concatenating a non-literal value",
    ),
    _rule(
        "js-eval",
        Severity.HIGH,
        _JS,
        r"(?<![\w.])eval\s*\(",
        "eval() runs attacker-controlled text as code",
    ),
    _rule(
        "innerhtml-assign",
        Severity.MEDIUM,
        _JS,
        r"\.innerHTML\s*=",
        "assigning to innerHTML parses HTML",
    ),
    _rule(
        "react-dangerous-html",
        Severity.MEDIUM,
        _JS,
        r"\bdangerouslySetInnerHTML\b",
        "dangerouslySetInnerHTML parses HTML",
    ),
    _rule(
        "jwt-algorithm-none",
        Severity.HIGH,
        _BOTH,
        r"""(?i)algorithms?\s*[=:]\s*\[?\s*["']none["']""",
        "JWT algorithm is none",
    ),
)


def scan_sast(text: str, relative_path: str) -> list[Finding]:
    suffix = _suffix(relative_path)
    if suffix is None:
        return []
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _IGNORE in line:
            continue
        for rule_id, severity, extensions, pattern, description, suppress in _RULES:
            if suffix not in extensions:
                continue
            if suppress and suppress.search(line):
                continue
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=description,
                        tool="sast",
                        path=relative_path,
                        line=lineno,
                    )
                )
    return findings


def _suffix(relative_path: str) -> str | None:
    name = relative_path.rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return "." + name.rsplit(".", 1)[-1].lower()

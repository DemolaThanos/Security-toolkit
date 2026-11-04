from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from gha_audit.load import MAX_BYTES
from gha_audit.models import Finding, Options
from gha_audit.paths import contained_file
from gha_audit.rules import RULE_INDEX

_MIN_JUSTIFICATION = 12
_PLACEHOLDER = re.compile(r"(?i)^(todo|fixme|later|wip|n/?a|none|ignore|false|tbd|xxx+|test|ok|no)$")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
# Spaces are written out so the rule id and the justification do not overlap.
_DIRECTIVE = re.compile(r"gha-audit:[ \t]*ignore\[([^\]\n]+)\](.*)\Z")
_CONFIG_KEYS = frozenset({"allow_actions_refs", "ignore"})
_ENTRY_KEYS = frozenset({"rule", "path", "justification"})


class ConfigError(Exception):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Ignore:
    rule: str
    path: str | None
    line: int | None
    justification: str
    literal: bool = False

    def matches(self, finding: Finding) -> bool:
        if self.rule not in {finding.rule_id, "*"}:
            return False
        if self.line is not None and finding.line != self.line:
            return False
        if self.path is None:
            return True
        if self.literal:
            return _posix(finding.path) == _posix(self.path)
        return path_matches(self.path, finding.path)


def load_config(path: Path) -> tuple[Options, tuple[Ignore, ...]]:
    try:
        target = contained_file(path)
    except ValueError as exc:
        raise ConfigError([str(exc)]) from exc
    display = target.as_posix()
    if not target.is_file():
        raise ConfigError([f"{display} is not a file"])
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise ConfigError([f"cannot read {display}: {exc}"]) from exc
    if size > MAX_BYTES:
        raise ConfigError([f"{display} is larger than {MAX_BYTES} bytes"])
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError([f"cannot read {display}: {exc}"]) from exc
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError([f"{display} is not valid TOML: {exc}"]) from exc
    if not isinstance(raw, dict):
        raise ConfigError([f"{display} must be a TOML table"])
    unknown = sorted(set(raw) - _CONFIG_KEYS)
    if unknown:
        raise ConfigError([f"{display} has unknown key {unknown[0]!r}"])
    allow = raw.get("allow_actions_refs", False)
    if not isinstance(allow, bool):
        raise ConfigError([f"{display} allow_actions_refs must be a boolean"])
    entries = raw.get("ignore", [])
    if not isinstance(entries, list):
        raise ConfigError([f"{display} ignore must be an array of tables"])
    found: list[Ignore] = []
    problems: list[str] = []
    for index, entry in enumerate(entries, start=1):
        item, problem = _config_entry(f"{display} ignore entry {index}", entry)
        if problem:
            problems.append(problem)
        elif item is not None:
            found.append(item)
    if problems:
        raise ConfigError(problems)
    return Options(allow_actions_refs=allow), tuple(found)


def parse_inline(text: str, path: str) -> tuple[tuple[Ignore, ...], tuple[str, ...]]:
    lines = text.splitlines()
    ignores: list[Ignore] = []
    errors: list[str] = []
    for index, line in enumerate(lines):
        code, comment = _split_comment(line)
        if comment is None:
            continue
        match = _DIRECTIVE.search(comment)
        if match is None:
            continue
        rules, problem = _rules(match.group(1), f"{path}:{index + 1}")
        if problem or rules is None:
            errors.append(problem or f"{path}:{index + 1} ignore comment is missing a rule id")
            continue
        justification = (match.group(2) or "").strip()
        reason = justification_error(justification)
        if reason:
            errors.append(f"{path}:{index + 1} {reason}")
            continue
        if code.strip():
            targets = {index + 1}
        else:
            targets = _block_targets(lines, index)
            if not targets:
                errors.append(f"{path}:{index + 1} ignore comment does not apply to a line")
                continue
        for rule in rules:
            for target in targets:
                ignores.append(Ignore(rule, path, target, justification, literal=True))
    return tuple(ignores), tuple(errors)


def path_matches(pattern: str, report_path: str) -> bool:
    pat = pattern.strip().replace("\\", "/")
    candidate = _posix(report_path)
    if not pat or pat == "*":
        return True
    if fnmatch(candidate, pat):
        return True
    if "/" not in pat and fnmatch(PurePosixPath(candidate).name, pat):
        return True
    return candidate.endswith("/" + pat.lstrip("/"))


def justification_error(text: str) -> str | None:
    cleaned = text.strip()
    if _PLACEHOLDER.fullmatch(cleaned):
        return "justification is a placeholder"
    if len(cleaned) < _MIN_JUSTIFICATION:
        return f"justification must be at least {_MIN_JUSTIFICATION} characters"
    return None


def _config_entry(where: str, entry: object) -> tuple[Ignore | None, str | None]:
    if not isinstance(entry, dict):
        return None, f"{where} must be a table"
    unknown = sorted(set(entry) - _ENTRY_KEYS)
    if unknown:
        return None, f"{where} has unknown key {unknown[0]!r}"
    rule = entry.get("rule")
    pattern = entry.get("path")
    justification = entry.get("justification")
    if not isinstance(rule, str) or not rule.strip():
        return None, f"{where} is missing rule"
    rule_id = rule.strip()
    if rule_id != "*" and rule_id not in RULE_INDEX:
        return None, f"{where} uses unknown rule {rule_id!r}"
    if pattern is not None and (not isinstance(pattern, str) or not pattern.strip()):
        return None, f"{where} path must be a non-empty string"
    if not isinstance(justification, str):
        return None, f"{where} is missing a justification"
    reason = justification_error(justification)
    if reason:
        return None, f"{where} {reason}"
    path = pattern.strip() if isinstance(pattern, str) else None
    return Ignore(rule_id, path, None, justification.strip()), None


def _rules(raw: str, where: str) -> tuple[tuple[str, ...] | None, str | None]:
    rules = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not rules:
        return None, f"{where} ignore comment is missing a rule id"
    for rule in rules:
        if rule != "*" and (not _RULE_ID.fullmatch(rule) or rule not in RULE_INDEX):
            return None, f"{where} uses unknown rule {rule!r}"
    return rules, None


def _block_targets(lines: list[str], comment_index: int) -> set[int]:
    start = comment_index + 1
    while start < len(lines) and not _split_comment(lines[start])[0].strip():
        start += 1
    if start >= len(lines):
        return set()
    base = _indent(lines[start])
    targets = {start + 1}
    for index in range(start + 1, len(lines)):
        code, _comment = _split_comment(lines[index])
        if not code.strip():
            continue
        if _indent(lines[index]) <= base:
            break
        targets.add(index + 1)
    return targets


def _split_comment(line: str) -> tuple[str, str | None]:
    in_single = False
    in_double = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index], line[index + 1 :]
        elif char == "\\" and in_double and index + 1 < len(line):
            index += 1
        index += 1
    return line, None


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _posix(path: str) -> str:
    return path.replace("\\", "/")

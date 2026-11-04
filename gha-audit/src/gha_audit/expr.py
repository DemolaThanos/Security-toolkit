"""GitHub Actions expression helpers.

The parser only answers one question: can an attacker-controlled context be
the value that gets spliced into a shell script? Boolean functions and
comparisons are treated as safe. ``&&`` and ``||`` are not, because they can
return one of their operands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_UNTRUSTED: tuple[tuple[str, ...], ...] = (
    ("github", "head_ref"),
    ("github", "event", "issue", "title"),
    ("github", "event", "issue", "body"),
    ("github", "event", "pull_request", "title"),
    ("github", "event", "pull_request", "body"),
    ("github", "event", "pull_request", "head", "ref"),
    ("github", "event", "pull_request", "head", "label"),
    ("github", "event", "comment", "body"),
    ("github", "event", "review", "body"),
    ("github", "event", "review_comment", "body"),
    ("github", "event", "discussion", "title"),
    ("github", "event", "discussion", "body"),
    ("github", "event", "head_commit", "message"),
    ("github", "event", "head_commit", "author", "email"),
    ("github", "event", "head_commit", "author", "name"),
    ("github", "event", "head_commit", "committer", "email"),
    ("github", "event", "head_commit", "committer", "name"),
    ("github", "event", "commits"),
    ("github", "event", "pull_request", "head", "repo", "default_branch"),
    ("github", "event", "pages"),
    ("github", "event", "workflow_run", "head_branch"),
    ("github", "event", "workflow_run", "display_title"),
    ("github", "event", "workflow_run", "head_commit"),
    ("github", "event", "workflow_run", "pull_requests"),
)

_BOOL_CALLS = frozenset(
    {
        "contains",
        "startsWith",
        "endsWith",
        "success",
        "failure",
        "always",
        "cancelled",
        "hashFiles",
    }
)

_LABELS = tuple(sorted({".".join(item) for item in _UNTRUSTED}, key=len, reverse=True))
# `secrets` is the secrets context. `github.token` is the automatic token.
# A dot or identifier character before either name means some other field.
_SECRET = re.compile(r"(?<![\w.])secrets\b|(?<![\w.])github\.token\b")
_CMP = ("==", "!=", "<=", ">=", "<", ">")


class ParseError(Exception):
    """The expression is not one this checker understands."""


@dataclass(frozen=True)
class _Value:
    leaks: bool
    path: tuple[str, ...] | None = None
    literal: str | None = None
    label: str | None = None


def iter_expressions(script: str) -> list[str]:
    found: list[str] = []
    cursor = 0
    while True:
        start = script.find("${{", cursor)
        if start < 0:
            break
        body, end = _read_expression(script, start + 3)
        if end < 0:
            break
        found.append(body)
        cursor = end
    return found


def leaking_contexts(script: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for body in iter_expressions(script):
        for label in _labels_in(body):
            if label not in seen:
                seen.add(label)
                found.append(label)
    return found


def contains_secret(text: str) -> bool:
    return any(_SECRET.search(_without_strings(body)) for body in iter_expressions(text))


def _without_strings(body: str) -> str:
    """Drop single-quoted GitHub expression strings so a literal cannot match."""
    out: list[str] = []
    index = 0
    limit = len(body)
    while index < limit:
        if body[index] != "'":
            out.append(body[index])
            index += 1
            continue
        index += 1
        while index < limit:
            if body[index] == "'" and index + 1 < limit and body[index + 1] == "'":
                index += 2
                continue
            if body[index] == "'":
                index += 1
                break
            index += 1
        out.append("''")
    return "".join(out)


def _labels_in(body: str) -> list[str]:
    try:
        value = _Parser(body).parse()
    except ParseError:
        return _fallback(body)
    if not value.leaks:
        return []
    if value.label:
        return [value.label]
    return _fallback(body)


def _fallback(body: str) -> list[str]:
    compact = "".join(body.split())
    found: list[str] = []
    for label in _LABELS:
        if label in compact and not any(label in earlier and label != earlier for earlier in found):
            found.append(label)
    return found


def _is_untrusted(path: tuple[str, ...]) -> bool:
    return any(path[: len(item)] == item for item in _UNTRUSTED)


def _label(path: tuple[str, ...]) -> str | None:
    best: tuple[str, ...] | None = None
    for item in _UNTRUSTED:
        if path[: len(item)] == item and (best is None or len(item) > len(best)):
            best = item
    if best is None:
        return None
    return ".".join(best)


def _extend(value: _Value, segment: str) -> _Value:
    if value.path is None:
        return value
    path = (*value.path, segment)
    label = _label(path)
    if label is not None:
        return _Value(True, path, None, label)
    return _Value(value.leaks, path, None, value.label)


def _combine(left: _Value, right: _Value) -> _Value:
    if not left.leaks and not right.leaks:
        return _Value(False)
    label = left.label if left.leaks and left.label else right.label or left.label
    return _Value(True, None, None, label)


def _call(name: str, args: list[_Value]) -> _Value:
    if name in _BOOL_CALLS:
        return _Value(False)
    for arg in args:
        if arg.leaks:
            return _Value(True, None, None, arg.label)
    return _Value(False)


def _read_expression(script: str, start: int) -> tuple[str, int]:
    i = start
    in_string = False
    while i < len(script):
        char = script[i]
        if in_string:
            if char == "'" and i + 1 < len(script) and script[i + 1] == "'":
                i += 2
                continue
            if char == "'":
                in_string = False
            i += 1
            continue
        if char == "'":
            in_string = True
            i += 1
            continue
        if char == "}" and i + 1 < len(script) and script[i + 1] == "}":
            return script[start:i], i + 2
        i += 1
    return "", -1


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.i = 0

    def parse(self) -> _Value:
        value = self._parse_or()
        self._skip()
        if self.i != self.n:
            raise ParseError
        return value

    def _parse_or(self) -> _Value:
        left = self._parse_and()
        while self._eat("||"):
            left = _combine(left, self._parse_and())
        return left

    def _parse_and(self) -> _Value:
        left = self._parse_equality()
        while self._eat("&&"):
            left = _combine(left, self._parse_equality())
        return left

    def _parse_equality(self) -> _Value:
        left = self._parse_unary()
        matched = False
        while self._comparison():
            matched = True
            self._parse_unary()
        return _Value(False) if matched else left

    def _parse_unary(self) -> _Value:
        if self._starts("!") and not self._starts("!="):
            self._eat("!")
            self._parse_unary()
            return _Value(False)
        return self._parse_primary()

    def _parse_primary(self) -> _Value:
        if self._eat("("):
            value = self._parse_or()
            self._expect(")")
            return self._postfix(value)
        if self._starts("'"):
            return self._postfix(_Value(False, None, self._string()))
        if self._looks_like_number():
            self._number()
            return self._postfix(_Value(False))
        word = self._ident()
        if self._eat("("):
            return self._postfix(_call(word, self._args()))
        if word in {"true", "false", "null"}:
            return self._postfix(_Value(False))
        path = (word,)
        label = _label(path)
        return self._postfix(_Value(label is not None, path, None, label))

    def _postfix(self, value: _Value) -> _Value:
        while True:
            if self._eat("."):
                if self._eat("*"):
                    value = _extend(value, "*")
                    continue
                value = _extend(value, self._ident())
                continue
            if self._eat("["):
                if self._eat("*"):
                    self._expect("]")
                    value = _extend(value, "*")
                    continue
                inner = self._parse_or()
                self._expect("]")
                value = _extend(value, inner.literal if inner.literal is not None else "*")
                continue
            return value

    def _args(self) -> list[_Value]:
        if self._eat(")"):
            return []
        args = [self._parse_or()]
        while self._eat(","):
            if self._starts(")"):
                break
            args.append(self._parse_or())
        self._expect(")")
        return args

    def _string(self) -> str:
        self._expect("'")
        chars: list[str] = []
        while self.i < self.n:
            char = self.text[self.i]
            if char == "'" and self.i + 1 < self.n and self.text[self.i + 1] == "'":
                chars.append("'")
                self.i += 2
                continue
            if char == "'":
                self.i += 1
                return "".join(chars)
            chars.append(char)
            self.i += 1
        raise ParseError

    def _number(self) -> None:
        self._skip()
        if self.i < self.n and self.text[self.i] == "-":
            self.i += 1
        if self.i >= self.n or not self.text[self.i].isdigit():
            raise ParseError
        while self.i < self.n and self.text[self.i].isdigit():
            self.i += 1
        if self.i + 1 < self.n and self.text[self.i] == "." and self.text[self.i + 1].isdigit():
            self.i += 1
            while self.i < self.n and self.text[self.i].isdigit():
                self.i += 1

    def _ident(self) -> str:
        self._skip()
        if self.i >= self.n or not (self.text[self.i].isalpha() or self.text[self.i] == "_"):
            raise ParseError
        start = self.i
        self.i += 1
        while self.i < self.n and (self.text[self.i].isalnum() or self.text[self.i] in {"_", "-"}):
            self.i += 1
        return self.text[start : self.i]

    def _comparison(self) -> bool:
        return any(self._eat(op) for op in _CMP)

    def _looks_like_number(self) -> bool:
        self._skip()
        if self.i >= self.n:
            return False
        if self.text[self.i].isdigit():
            return True
        return self.text[self.i] == "-" and self.i + 1 < self.n and self.text[self.i + 1].isdigit()

    def _starts(self, token: str) -> bool:
        self._skip()
        return self.text.startswith(token, self.i)

    def _eat(self, token: str) -> bool:
        if self._starts(token):
            self.i += len(token)
            return True
        return False

    def _expect(self, token: str) -> None:
        if not self._eat(token):
            raise ParseError

    def _skip(self) -> None:
        while self.i < self.n and self.text[self.i].isspace():
            self.i += 1

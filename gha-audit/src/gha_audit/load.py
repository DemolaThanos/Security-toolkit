from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

MAX_BYTES = 1_000_000
_MAX_ALIASES = 1_000
_MAX_NODES = 100_000
_MAX_DEPTH = 64

# PyYAML's YAML 1.1 rules treat `on`, `off`, `yes`, and `no` as booleans.
# Workflow files use an unquoted `on:` key, so those spellings stay strings.
_BOOL = "tag:yaml.org,2002:bool"
_BOOL_RE = re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$")


class MarkedDict(dict[str, Any]):
    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line
        self.key_lines: dict[str, int] = {}


class MarkedList(list[Any]):
    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line


class LineLoader(yaml.SafeLoader):  # type: ignore[misc]
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            count = getattr(self, "_alias_count", 0) + 1
            self._alias_count = count
            if count > _MAX_ALIASES:
                raise yaml.YAMLError("YAML document exceeds the alias limit")
        nodes = getattr(self, "_node_count", 0) + 1
        self._node_count = nodes
        if nodes > _MAX_NODES:
            raise yaml.YAMLError("YAML document exceeds the node limit")
        # Depth is counted here because construction defers nested values.
        depth = getattr(self, "_depth", 0) + 1
        if depth > _MAX_DEPTH:
            raise yaml.YAMLError("YAML document exceeds the depth limit")
        self._depth = depth
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth = depth - 1

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        expanded = getattr(self, "_expanded", 0) + 1
        self._expanded = expanded
        if expanded > _MAX_NODES:
            raise yaml.YAMLError("YAML document exceeds the expansion limit")
        return super().construct_object(node, deep)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> MarkedDict:
        # Reject a repeated key in the file itself, then expand `<<` merges.
        # A merge reuses keys on purpose; the later explicit key wins.
        self._reject_duplicate_keys(node)
        self.flatten_mapping(node)
        mapping = MarkedDict(node.start_mark.line + 1)
        for key_node, value_node in node.value:
            key = self._string_key(key_node, deep)
            mapping[key] = self.construct_object(value_node, deep=deep)
            mapping.key_lines[key] = key_node.start_mark.line + 1
        return mapping

    def _reject_duplicate_keys(self, node: yaml.MappingNode) -> None:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self._string_key(key_node, deep=False)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)

    def _string_key(self, key_node: yaml.Node, deep: bool) -> str:
        key = self.construct_object(key_node, deep=deep)
        if isinstance(key, str):
            return key
        raise yaml.constructor.ConstructorError(
            None,
            None,
            f"mapping key {key!r} is not a string",
            key_node.start_mark,
        )

    def construct_sequence(self, node: yaml.SequenceNode, deep: bool = False) -> MarkedList:
        seq = MarkedList(node.start_mark.line + 1)
        for item in node.value:
            seq.append(self.construct_object(item, deep=deep))
        return seq

    def construct_yaml_map(self, node: yaml.MappingNode) -> Any:
        # PyYAML registers SafeConstructor.construct_yaml_map, which copies into a plain dict.
        data = MarkedDict(node.start_mark.line + 1)
        yield data
        value = self.construct_mapping(node)
        data.update(value)
        if isinstance(value, MarkedDict):
            data.key_lines.update(value.key_lines)

    def construct_yaml_seq(self, node: yaml.SequenceNode) -> Any:
        data = MarkedList(node.start_mark.line + 1)
        yield data
        data.extend(self.construct_sequence(node))


def _install_bool_resolver(loader: type[LineLoader]) -> None:
    copied: dict[str, list[tuple[str, re.Pattern[str]]]] = {}
    for key, entries in loader.yaml_implicit_resolvers.items():
        copied[key] = [(tag, regexp) for tag, regexp in entries if tag != _BOOL]
    loader.yaml_implicit_resolvers = copied
    loader.add_implicit_resolver(_BOOL, _BOOL_RE, list("tTfF"))


_install_bool_resolver(LineLoader)
LineLoader.add_constructor("tag:yaml.org,2002:map", LineLoader.construct_yaml_map)
LineLoader.add_constructor("tag:yaml.org,2002:seq", LineLoader.construct_yaml_seq)


def read_text(path: Path, *, max_bytes: int) -> tuple[str | None, str | None]:
    display = path.as_posix()
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"cannot stat {display}: {exc}"
    if size > max_bytes:
        return None, f"{display} is larger than {max_bytes} bytes"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return None, f"cannot read {display}: {exc}"
    if text.startswith("\ufeff"):
        text = text[1:]
    return text, None


def load_document(text: str) -> tuple[Any, str | None]:
    try:
        loader = LineLoader(text)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
    except RecursionError:
        return None, "not valid YAML: document is too deeply nested"
    except yaml.YAMLError as exc:
        message = " ".join(str(exc).split())
        return None, f"not valid YAML: {message}"
    return document, None


def node_line(node: object, default: int = 1) -> int:
    found = getattr(node, "line", None)
    if isinstance(found, int) and found > 0:
        return found
    return default


def key_line(node: object, key: str, default: int) -> int:
    lines = getattr(node, "key_lines", None)
    if isinstance(lines, dict):
        found = lines.get(key)
        if isinstance(found, int) and found > 0:
            return found
    return default

from __future__ import annotations

from typing import Any

import yaml

from stride_model.models import SENSITIVE, Component, Flow, Model, Zone

_INFERRED_EXTERNAL = frozenset({"external", "internet", "public", "untrusted"})
_ZONE_KEYS = frozenset({"description", "external", "id"})
_COMPONENT_KEYS = frozenset(
    {
        "data_classes",
        "description",
        "encrypted_at_rest",
        "id",
        "logs_actions",
        "rate_limited",
        "type",
        "zone",
    }
)
_FLOW_KEYS = frozenset({"authenticated", "data_classes", "destination", "id", "protocol", "source"})
_TOP_KEYS = frozenset({"components", "description", "flows", "name", "trust_zones"})
_TYPES = frozenset({"data-store", "external", "process"})
_MAX_TEXT = 1_000_000
_MAX_NODES = 100_000
_MAX_ALIASES = 1_000
_MAX_ZONES = 100
_MAX_COMPONENTS = 200
_MAX_FLOWS = 500
_MAX_FIELD = 2_000


class ModelError(Exception):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


class _BoundedLoader(yaml.SafeLoader):  # type: ignore[misc]
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
        return super().compose_node(parent, index)


def parse_model(text: str) -> Model:
    if len(text) > _MAX_TEXT:
        raise ModelError(["model is larger than 1000000 bytes"])
    try:
        loaded = yaml.load(text, Loader=_BoundedLoader)
    except yaml.YAMLError as exc:
        raise ModelError([f"model is not valid YAML: {exc}"]) from exc
    if not isinstance(loaded, dict):
        raise ModelError(["model must be a mapping"])
    problems: list[str] = []
    _unknown(loaded, _TOP_KEYS, "model", problems)
    name = _string(loaded.get("name"), "name", problems)
    description = _string(loaded.get("description"), "description", problems)
    zones = _zones(loaded.get("trust_zones"), problems)
    components = _components(loaded.get("components"), {zone.id for zone in zones}, problems)
    flows = _flows(loaded.get("flows"), {item.id for item in components}, problems)
    if not components and not any(item.startswith("components") for item in problems):
        problems.append("components must contain at least one component")
    if problems:
        raise ModelError(problems)
    return Model(name, description, tuple(zones), tuple(components), tuple(flows))


def is_sensitive(data_classes: tuple[str, ...]) -> bool:
    return any(item.lower() in SENSITIVE for item in data_classes)


def _zones(raw: object, problems: list[str]) -> list[Zone]:
    if not isinstance(raw, list):
        problems.append("trust_zones must be a list")
        return []
    if len(raw) > _MAX_ZONES:
        problems.append(f"trust_zones has more than {_MAX_ZONES} entries")
        return []
    zones: list[Zone] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        label = f"trust_zones[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{label} must be a mapping")
            continue
        _unknown(item, _ZONE_KEYS, label, problems)
        identifier = _string(item.get("id"), f"{label}.id", problems)
        description = _string(item.get("description"), f"{label}.description", problems)
        if "external" in item:
            external = _bool(item.get("external"), f"{label}.external", problems)
        else:
            external = identifier.lower() in _INFERRED_EXTERNAL
        if identifier and identifier in seen:
            problems.append(f"duplicate trust zone {identifier}")
        seen.add(identifier)
        zones.append(Zone(identifier, description, external))
    return zones


def _components(raw: object, zone_ids: set[str], problems: list[str]) -> list[Component]:
    if not isinstance(raw, list):
        problems.append("components must be a list")
        return []
    if len(raw) > _MAX_COMPONENTS:
        problems.append(f"components has more than {_MAX_COMPONENTS} entries")
        return []
    components: list[Component] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        label = f"components[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{label} must be a mapping")
            continue
        _unknown(item, _COMPONENT_KEYS, label, problems)
        identifier = _string(item.get("id"), f"{label}.id", problems)
        kind = _string(item.get("type"), f"{label}.type", problems)
        zone = _string(item.get("zone"), f"{label}.zone", problems)
        description = _string(item.get("description"), f"{label}.description", problems)
        if kind and kind not in _TYPES:
            problems.append(f"{label}.type must be external, process, or data-store")
        if zone and zone not in zone_ids:
            problems.append(f"{label}.zone {zone!r} is not a trust zone")
        if identifier and identifier in seen:
            problems.append(f"duplicate component {identifier}")
        seen.add(identifier)
        components.append(
            Component(
                identifier,
                kind,
                zone,
                description,
                _optional_bool(item, "logs_actions", label, problems),
                _optional_bool(item, "rate_limited", label, problems),
                _optional_bool(item, "encrypted_at_rest", label, problems),
                tuple(_classes(item.get("data_classes"), f"{label}.data_classes", problems)),
            )
        )
    return components


def _flows(raw: object, component_ids: set[str], problems: list[str]) -> list[Flow]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append("flows must be a list")
        return []
    if len(raw) > _MAX_FLOWS:
        problems.append(f"flows has more than {_MAX_FLOWS} entries")
        return []
    flows: list[Flow] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        label = f"flows[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{label} must be a mapping")
            continue
        _unknown(item, _FLOW_KEYS, label, problems)
        identifier = _string(item.get("id"), f"{label}.id", problems)
        source = _string(item.get("source"), f"{label}.source", problems)
        destination = _string(item.get("destination"), f"{label}.destination", problems)
        protocol = _string(item.get("protocol"), f"{label}.protocol", problems).lower()
        if "authenticated" not in item:
            problems.append(f"{label}.authenticated is required")
            authenticated = False
        else:
            authenticated = _bool(item.get("authenticated"), f"{label}.authenticated", problems)
        for endpoint, value in (("source", source), ("destination", destination)):
            if value and value not in component_ids:
                problems.append(f"{label}.{endpoint} {value!r} is not a component")
        if identifier and identifier in seen:
            problems.append(f"duplicate flow {identifier}")
        seen.add(identifier)
        flows.append(
            Flow(
                identifier,
                source,
                destination,
                protocol,
                authenticated,
                tuple(_classes(item.get("data_classes"), f"{label}.data_classes", problems)),
            )
        )
    return flows


def _classes(raw: object, label: str, problems: list[str]) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        problems.append(f"{label} must be a list of strings")
        return []
    return [str(item) for item in raw]


def _optional_bool(item: dict[str, Any], key: str, label: str, problems: list[str]) -> bool | None:
    if key not in item:
        return None
    return _bool(item.get(key), f"{label}.{key}", problems)


def _unknown(item: dict[str, Any], allowed: frozenset[str], label: str, problems: list[str]) -> None:
    extra = sorted(set(item) - allowed)
    if extra:
        problems.append(f"{label} has unknown keys: {', '.join(extra)}")


def _string(value: object, label: str, problems: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{label} must be a non-empty string")
        return ""
    text = value.strip()
    if len(text) > _MAX_FIELD:
        problems.append(f"{label} is too long")
        return ""
    if any(char in text for char in "\r\n\x00"):
        problems.append(f"{label} must be a single line")
        return ""
    return text


def _bool(value: object, label: str, problems: list[str]) -> bool:
    if not isinstance(value, bool):
        problems.append(f"{label} must be a boolean")
        return False
    return value

from __future__ import annotations

import json

from stride_model.models import Model, Severity, Threat


def _plain(value: str) -> str:
    """One line, with backticks turned into apostrophes so they cannot close a code span."""
    return " ".join(value.replace("`", "'").split())


def _cell(value: str) -> str:
    return _plain(value).replace("|", "\\|")


def render_markdown(model: Model, threats: tuple[Threat, ...]) -> str:
    lines = [
        f"# {_plain(model.name)}",
        "",
        "STRIDE review generated from one YAML system model.",
        "",
        _plain(model.description),
        "",
        "## Trust zones",
        "",
    ]
    for zone in model.zones:
        marker = " (external)" if zone.external else ""
        lines.append(f"- `{_plain(zone.id)}`{marker} — {_plain(zone.description)}")
    lines.extend(["", "## Components", ""])
    for component in model.components:
        lines.append(
            f"- `{_plain(component.id)}` {component.type} in `{_plain(component.zone)}`"
            f" — {_plain(component.description)}"
        )
    lines.extend(["", "## Flows", ""])
    if not model.flows:
        lines.append("No flows declared.")
    for flow in model.flows:
        data = ", ".join(_plain(item) for item in flow.data_classes) if flow.data_classes else "none declared"
        auth = "authenticated" if flow.authenticated else "not authenticated"
        lines.append(
            f"- `{_plain(flow.id)}` `{_plain(flow.source)}` → `{_plain(flow.destination)}` "
            f"via {_plain(flow.protocol)}, {auth}, data: {data}"
        )
    lines.extend(["", "## Threats", ""])
    if not threats:
        lines.append("No threats raised from the declared controls.")
    else:
        lines.append("| ID | Severity | Category | Element | Detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for threat in threats:
            lines.append(
                f"| `{_cell(threat.id)}` | {threat.severity.value} | {threat.category} "
                f"| `{_cell(threat.element)}` | {_cell(threat.detail)} |"
            )
        lines.extend(["", "## Mitigations", ""])
        for threat in threats:
            lines.append(f"### `{_plain(threat.id)}`")
            lines.append("")
            lines.append(_plain(threat.mitigation))
            lines.append("")
    lines.append("Threats are raised only where a control is missing or weak. Absence of a row is not an approval.")
    lines.append(
        "Generated from the YAML model. No diagram interchange, no authorization model, and no threat-model lifecycle."
    )
    lines.append("")
    return "\n".join(lines)


def render_json(model: Model, threats: tuple[Threat, ...]) -> str:
    payload = {
        "kind": "stride-review",
        "scope": (
            "STRIDE review generated from one YAML system model. "
            "No diagram interchange, no authorization model, and no threat-model lifecycle."
        ),
        "name": model.name,
        "description": model.description,
        "trust_zones": [
            {"id": zone.id, "description": zone.description, "external": zone.external} for zone in model.zones
        ],
        "components": [
            {
                "id": item.id,
                "type": item.type,
                "zone": item.zone,
                "description": item.description,
                "logs_actions": item.logs_actions,
                "rate_limited": item.rate_limited,
                "encrypted_at_rest": item.encrypted_at_rest,
                "data_classes": list(item.data_classes),
            }
            for item in model.components
        ],
        "flows": [
            {
                "id": item.id,
                "source": item.source,
                "destination": item.destination,
                "protocol": item.protocol,
                "authenticated": item.authenticated,
                "data_classes": list(item.data_classes),
            }
            for item in model.flows
        ],
        "threats": [threat.to_dict() for threat in threats],
    }
    return json.dumps(payload, indent=2) + "\n"


def failing(threats: tuple[Threat, ...], threshold: Severity) -> tuple[Threat, ...]:
    from stride_model.models import meets_threshold

    return tuple(threat for threat in threats if meets_threshold(threat.severity, threshold))

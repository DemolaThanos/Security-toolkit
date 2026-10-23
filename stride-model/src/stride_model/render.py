from __future__ import annotations

import json

from stride_model.models import Model, Severity, Threat


def render_markdown(model: Model, threats: tuple[Threat, ...]) -> str:
    lines = [f"# {model.name}", "", model.description, "", "## Trust zones", ""]
    for zone in model.zones:
        marker = " (external)" if zone.external else ""
        lines.append(f"- `{zone.id}`{marker} — {zone.description}")
    lines.extend(["", "## Components", ""])
    for component in model.components:
        lines.append(f"- `{component.id}` {component.type} in `{component.zone}` — {component.description}")
    lines.extend(["", "## Flows", ""])
    if not model.flows:
        lines.append("No flows declared.")
    for flow in model.flows:
        data = ", ".join(flow.data_classes) if flow.data_classes else "none declared"
        auth = "authenticated" if flow.authenticated else "not authenticated"
        lines.append(f"- `{flow.id}` `{flow.source}` → `{flow.destination}` via {flow.protocol}, {auth}, data: {data}")
    lines.extend(["", "## Threats", ""])
    if not threats:
        lines.append("No threats raised from the declared controls.")
    else:
        lines.append("| ID | Severity | Category | Element | Detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for threat in threats:
            lines.append(
                f"| `{threat.id}` | {threat.severity.value} | {threat.category} "
                f"| `{threat.element}` | {threat.detail} |"
            )
        lines.extend(["", "## Mitigations", ""])
        for threat in threats:
            lines.append(f"### `{threat.id}`")
            lines.append("")
            lines.append(threat.mitigation)
            lines.append("")
    lines.append("Threats are raised only where a control is missing or weak. Absence of a row is not an approval.")
    lines.append("")
    return "\n".join(lines)


def render_json(model: Model, threats: tuple[Threat, ...]) -> str:
    payload = {
        "name": model.name,
        "description": model.description,
        "threats": [threat.to_dict() for threat in threats],
    }
    return json.dumps(payload, indent=2) + "\n"


def failing(threats: tuple[Threat, ...], threshold: Severity) -> tuple[Threat, ...]:
    from stride_model.models import meets_threshold

    return tuple(threat for threat in threats if meets_threshold(threat.severity, threshold))

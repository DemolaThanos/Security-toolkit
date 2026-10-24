from __future__ import annotations

from stride_model.models import PROTECTED, Flow, Model, Severity, Threat
from stride_model.parse import is_sensitive

_MITIGATION = {
    "spoofing": "Authenticate the caller before the request is acted on.",
    "tampering": "Protect the hop with TLS and reject unexpected writers.",
    "disclosure": "Encrypt the data in transit and at rest, and limit who can read it.",
    "repudiation": "Audit the actor, object, and time, and keep those logs away from the workload.",
    "dos": "Rate limit at the trust boundary and set resource limits on the process.",
    "elevation": "Authorise every action. Do not let an unauthenticated caller write stored data.",
}


def generate(model: Model) -> tuple[Threat, ...]:
    threats: dict[tuple[str, str, str], Threat] = {}
    components = {item.id: item for item in model.components}
    for flow in model.flows:
        source = components[flow.source]
        dest = components[flow.destination]
        sensitive = is_sensitive(flow.data_classes)
        protected = flow.protocol in PROTECTED
        crosses = source.zone != dest.zone
        if dest.type in {"process", "data-store"} and not flow.authenticated:
            severity = Severity.CRITICAL if sensitive else Severity.HIGH
            _put(
                threats,
                Threat(
                    id=f"spoofing:{flow.id}",
                    category="spoofing",
                    element=flow.id,
                    severity=severity,
                    detail=(
                        f"Flow {flow.id} does not authenticate the caller"
                        + (" and carries sensitive data." if sensitive else ".")
                    ),
                    mitigation=_MITIGATION["spoofing"],
                ),
                "flow",
            )
        if not protected:
            detail = f"Flow {flow.id} uses {flow.protocol}, which this review does not treat as protected" + (
                " and it crosses trust zones." if crosses else "."
            )
            _put(
                threats,
                Threat(
                    id=f"tampering:{flow.id}",
                    category="tampering",
                    element=flow.id,
                    severity=Severity.HIGH if flow.data_classes else Severity.MEDIUM,
                    detail=detail,
                    mitigation=_MITIGATION["tampering"],
                ),
                "flow",
            )
            _put(
                threats,
                Threat(
                    id=f"disclosure:{flow.id}",
                    category="disclosure",
                    element=flow.id,
                    severity=Severity.HIGH if sensitive else Severity.MEDIUM,
                    detail=f"Flow {flow.id} can expose its payload on an unprotected hop.",
                    mitigation=_MITIGATION["disclosure"],
                ),
                "flow",
            )
        if dest.type == "process" and _internet_facing(model, flow):
            residual = dest.rate_limited is True
            _put(
                threats,
                Threat(
                    id=f"dos:{dest.id}",
                    category="dos",
                    element=dest.id,
                    severity=Severity.LOW if residual else Severity.MEDIUM,
                    detail=(
                        f"{dest.id} accepts traffic from an external zone. "
                        + (
                            "Rate limiting is declared; confirm it sits on this boundary."
                            if residual
                            else "No rate limit is declared."
                        )
                    ),
                    mitigation=_MITIGATION["dos"],
                ),
                "component",
            )
    for component in model.components:
        if component.type == "process":
            if component.logs_actions is False:
                _put(
                    threats,
                    _control(
                        f"repudiation:{component.id}",
                        "repudiation",
                        component.id,
                        Severity.MEDIUM,
                        f"{component.id} declares logs_actions false.",
                    ),
                    "component",
                )
            elif component.logs_actions is None:
                _put(
                    threats,
                    _control(
                        f"repudiation:{component.id}",
                        "repudiation",
                        component.id,
                        Severity.LOW,
                        f"{component.id} does not declare whether actions are logged.",
                    ),
                    "component",
                )
            inbound = [flow for flow in model.flows if flow.destination == component.id]
            outbound = [flow for flow in model.flows if flow.source == component.id]
            writes_store = any(components[flow.destination].type == "data-store" for flow in outbound)
            if writes_store and any(not flow.authenticated for flow in inbound):
                _put(
                    threats,
                    _control(
                        f"elevation:{component.id}",
                        "elevation",
                        component.id,
                        Severity.HIGH,
                        f"{component.id} can be called without authentication and it writes to a data store.",
                    ),
                    "component",
                )
        if component.type == "data-store":
            inbound_sensitive = is_sensitive(component.data_classes) or any(
                is_sensitive(flow.data_classes) for flow in model.flows if flow.destination == component.id
            )
            if component.encrypted_at_rest is not True:
                _put(
                    threats,
                    _control(
                        f"disclosure:{component.id}",
                        "disclosure",
                        component.id,
                        Severity.HIGH if inbound_sensitive else Severity.MEDIUM,
                        f"{component.id} does not declare encryption at rest.",
                    ),
                    "component",
                )
            if component.logs_actions is False:
                _put(
                    threats,
                    _control(
                        f"repudiation:{component.id}",
                        "repudiation",
                        component.id,
                        Severity.MEDIUM,
                        f"{component.id} declares logs_actions false.",
                    ),
                    "component",
                )
            elif component.logs_actions is None:
                _put(
                    threats,
                    _control(
                        f"repudiation:{component.id}",
                        "repudiation",
                        component.id,
                        Severity.LOW,
                        f"{component.id} does not declare whether access is logged.",
                    ),
                    "component",
                )
    ordered = sorted(threats.values(), key=lambda item: (-_rank(item.severity), item.id))
    return tuple(ordered)


def _internet_facing(model: Model, flow: Flow) -> bool:
    source = model.component(flow.source)
    if source.type == "external":
        return True
    return model.zone(source.zone).external


def _control(identifier: str, category: str, element: str, severity: Severity, detail: str) -> Threat:
    return Threat(identifier, category, element, severity, detail, _MITIGATION[category])


def _put(threats: dict[tuple[str, str, str], Threat], threat: Threat, scope: str) -> None:
    threats[(scope, threat.element, threat.category)] = threat


def _rank(severity: Severity) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[severity.value]

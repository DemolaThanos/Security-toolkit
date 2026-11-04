from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from gha_audit.load import key_line, node_line

_MATRIX_REF = re.compile(r"matrix\.([A-Za-z0-9_-]+)")


@dataclass(frozen=True)
class Pair:
    key: str
    value: object
    line: int

    @property
    def text(self) -> str:
        if isinstance(self.value, str):
            return self.value
        if self.value is True:
            return "true"
        if self.value is False:
            return "false"
        if self.value is None:
            return "null"
        if isinstance(self.value, (int, float)) and not isinstance(self.value, bool):
            return str(self.value)
        return ""


@dataclass(frozen=True)
class Permissions:
    line: int
    shorthand: str | None
    scopes: tuple[tuple[str, str, int], ...]

    def scope(self, name: str) -> tuple[str, int] | None:
        for key, value, line in self.scopes:
            if key == name:
                return value, line
        return None


@dataclass(frozen=True)
class Step:
    line: int
    uses: str | None
    uses_line: int
    run: str | None
    run_line: int
    with_args: tuple[Pair, ...]
    env: tuple[Pair, ...]
    if_expr: str | None


@dataclass(frozen=True)
class Job:
    job_id: str
    line: int
    self_hosted: bool
    runs_on_line: int
    steps: tuple[Step, ...]
    permissions: Permissions | None
    uses: str | None
    uses_line: int
    secrets_inherit: bool
    secrets_line: int
    secret_args: tuple[Pair, ...]
    inputs: tuple[Pair, ...]
    env: tuple[Pair, ...]
    if_expr: str | None


@dataclass(frozen=True)
class Document:
    path: str
    kind: Literal["workflow", "action"]
    events: frozenset[str]
    on_line: int
    permissions: Permissions | None
    jobs: tuple[Job, ...]
    env: tuple[Pair, ...]


def classify(document: object) -> Literal["workflow", "action"] | None:
    if not isinstance(document, dict):
        return None
    if "on" in document:
        return "workflow"
    if "jobs" in document and "runs" not in document:
        return "workflow"
    runs = document.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("using"), str):
        return "action"
    return None


def parse_document(document: dict[str, Any], path: str) -> Document | None:
    kind = classify(document)
    if kind == "workflow":
        return _workflow(document, path)
    if kind == "action":
        return _action(document, path)
    return None


def _workflow(document: dict[str, Any], path: str) -> Document:
    events, on_line = _events(document)
    jobs_node = document.get("jobs")
    jobs: list[Job] = []
    if isinstance(jobs_node, dict):
        for job_id, body in jobs_node.items():
            if isinstance(job_id, str) and isinstance(body, dict):
                jobs.append(_job(job_id, body))
    return Document(
        path=path,
        kind="workflow",
        events=events,
        on_line=on_line,
        permissions=_permissions(document),
        jobs=tuple(jobs),
        env=_pairs(document.get("env"), document, "env"),
    )


def _action(document: dict[str, Any], path: str) -> Document:
    runs = document.get("runs")
    steps: tuple[Step, ...] = ()
    line = 1
    if isinstance(runs, dict):
        line = node_line(runs, key_line(document, "runs", 1))
        if runs.get("using") == "composite":
            steps = _steps(runs.get("steps"))
    job = Job(
        job_id="composite",
        line=line,
        self_hosted=False,
        runs_on_line=line,
        steps=steps,
        permissions=None,
        uses=None,
        uses_line=line,
        secrets_inherit=False,
        secrets_line=line,
        secret_args=(),
        inputs=(),
        env=(),
        if_expr=None,
    )
    return Document(
        path=path,
        kind="action",
        events=frozenset(),
        on_line=line,
        permissions=None,
        jobs=(job,),
        env=(),
    )


def _events(document: dict[str, Any]) -> tuple[frozenset[str], int]:
    if "on" not in document:
        return frozenset(), node_line(document)
    return _event_names(document.get("on")), key_line(document, "on", node_line(document))


def _event_names(value: object) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list):
        return frozenset(item for item in value if isinstance(item, str))
    if isinstance(value, dict):
        return frozenset(key for key in value if isinstance(key, str))
    return frozenset()


def _job(job_id: str, body: dict[str, Any]) -> Job:
    line = node_line(body, 1)
    matrix = _matrix(body.get("strategy"))
    runs_on = body.get("runs-on")
    return Job(
        job_id=job_id,
        line=line,
        self_hosted=_self_hosted(runs_on, matrix),
        runs_on_line=key_line(body, "runs-on", line) if "runs-on" in body else line,
        steps=_steps(body.get("steps")),
        permissions=_permissions(body),
        uses=_string(body.get("uses")),
        uses_line=key_line(body, "uses", line),
        secrets_inherit=body.get("secrets") == "inherit",
        secrets_line=key_line(body, "secrets", line),
        secret_args=_pairs(body.get("secrets"), body, "secrets") if isinstance(body.get("secrets"), dict) else (),
        inputs=_pairs(body.get("with"), body, "with"),
        env=_pairs(body.get("env"), body, "env"),
        if_expr=_expr(body.get("if")),
    )


def _matrix(strategy: object) -> object:
    if isinstance(strategy, dict):
        return strategy.get("matrix")
    return None


def _steps(value: object) -> tuple[Step, ...]:
    if not isinstance(value, list):
        return ()
    steps: list[Step] = []
    for item in value:
        if isinstance(item, dict):
            steps.append(_step(item))
    return tuple(steps)


def _step(body: dict[str, Any]) -> Step:
    line = node_line(body, 1)
    run = body.get("run")
    return Step(
        line=line,
        uses=_string(body.get("uses")),
        uses_line=key_line(body, "uses", line),
        run=run if isinstance(run, str) else None,
        run_line=key_line(body, "run", line),
        with_args=_pairs(body.get("with"), body, "with"),
        env=_pairs(body.get("env"), body, "env"),
        if_expr=_expr(body.get("if")),
    )


def _permissions(body: dict[str, Any]) -> Permissions | None:
    if "permissions" not in body:
        return None
    line = key_line(body, "permissions", node_line(body))
    value = body.get("permissions")
    if isinstance(value, str):
        return Permissions(line, value, ())
    scopes: list[tuple[str, str, int]] = []
    if isinstance(value, dict):
        for key, scope in value.items():
            if isinstance(key, str) and isinstance(scope, str):
                scopes.append((key, scope, key_line(value, key, line)))
    return Permissions(line, None, tuple(scopes))


def _pairs(value: object, parent: dict[str, Any], key: str) -> tuple[Pair, ...]:
    if not isinstance(value, dict):
        return ()
    default = key_line(parent, key, node_line(parent))
    pairs: list[Pair] = []
    for name, item in value.items():
        if isinstance(name, str):
            pairs.append(Pair(name, item, key_line(value, name, default)))
    return tuple(pairs)


def _string(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _expr(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if value is True:
        return "true"
    if value is False:
        return "false"
    return None


def _self_hosted(runs_on: object, matrix: object) -> bool:
    if isinstance(runs_on, str):
        if "self-hosted" in runs_on:
            return True
        return _matrix_self_hosted(runs_on, matrix)
    if isinstance(runs_on, list):
        return any(_self_hosted(item, matrix) for item in runs_on)
    if isinstance(runs_on, dict):
        if "group" in runs_on:
            return True
        labels = runs_on.get("labels")
        return labels is not None and _self_hosted(labels, matrix)
    return False


def _matrix_self_hosted(runs_on: str, matrix: object) -> bool:
    if not isinstance(matrix, dict) or "matrix." not in runs_on:
        return False
    for key in _MATRIX_REF.findall(runs_on):
        if _has_self_hosted(matrix.get(key)):
            return True
        include = matrix.get("include")
        if isinstance(include, list):
            for row in include:
                if isinstance(row, dict) and _has_self_hosted(row.get(key)):
                    return True
    return False


def _has_self_hosted(value: object) -> bool:
    if isinstance(value, str):
        return value.strip() == "self-hosted"
    if isinstance(value, list):
        return any(_has_self_hosted(item) for item in value)
    return False

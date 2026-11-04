from __future__ import annotations

import re

from gha_audit.expr import contains_secret, leaking_contexts
from gha_audit.models import Finding, Options, Rule, Severity
from gha_audit.workflow import Document, Job, Pair, Step

# Events an outside contributor can fire on a public repository.
# `pull_request` runs untrusted code, but GitHub withholds secrets from fork
# PRs, so it is not in the secret set. `pull_request_target` receives secrets.
_PUBLIC_EVENTS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
        "issues",
        "issue_comment",
        "discussion",
        "discussion_comment",
        "workflow_run",
        "fork",
    }
)
_SECRET_EVENTS = _PUBLIC_EVENTS - {"pull_request", "fork"}

_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_GIT = re.compile(r"(?m)\bgit\s+(checkout|switch|reset|fetch|pull|clone)\b")
_PUBLISH_RUN = re.compile(r"(?im)\bgit\s+push\b|\bgh\s+release\s+(?:create|upload)\b|\bgh\s+pr\s+create\b")
_TRUSTED_ACTOR = re.compile(r"['\"](?:OWNER|MEMBER|COLLABORATOR)['\"]", re.IGNORECASE)

_PR_HEAD = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.pull_request.head.repo.full_name",
    "github.event.pull_request.head.repo.clone_url",
)
_RUN_HEAD = (
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository.full_name",
)

_PUBLISH_ACTIONS = frozenset(
    {
        "ad-m/github-push-action",
        "crazy-max/ghaction-github-pages",
        "endbug/add-and-commit",
        "jamesives/github-pages-deploy-action",
        "ncipollo/release-action",
        "peaceiris/actions-gh-pages",
        "peter-evans/create-pull-request",
        "softprops/action-gh-release",
        "stefanzweifel/git-auto-commit-action",
    }
)

RULES: tuple[Rule, ...] = (
    Rule(
        "unpinned-action",
        Severity.HIGH,
        "A third-party action is not pinned to a full commit SHA.",
        "Set uses to a 40-character commit SHA. A tag or branch can be moved.",
    ),
    Rule(
        "pwn-request",
        Severity.CRITICAL,
        "A privileged workflow checks out pull request head code.",
        "Check out the base ref, or run untrusted code in a pull_request workflow that has no secrets.",
    ),
    Rule(
        "script-injection",
        Severity.CRITICAL,
        "An attacker-controlled context is interpolated into a run script.",
        "Pass the value through an environment variable and read that variable in the script.",
    ),
    Rule(
        "permissions-missing",
        Severity.MEDIUM,
        "The workflow has no top-level permissions block.",
        "Set top-level permissions, usually contents: read, and add scopes on the job that needs them.",
    ),
    Rule(
        "permissions-write-all",
        Severity.HIGH,
        "permissions is write-all.",
        "Replace write-all with the scopes this workflow actually uses.",
    ),
    Rule(
        "permissions-contents-write",
        Severity.LOW,
        "contents: write is set where no step looks like it publishes or pushes.",
        "Drop contents: write, or move it onto the job that pushes or creates a release.",
    ),
    Rule(
        "checkout-persist-credentials",
        Severity.MEDIUM,
        "actions/checkout persists credentials in the workspace.",
        "Set persist-credentials: false unless a later step in the job pushes with that credential.",
    ),
    Rule(
        "secret-untrusted",
        Severity.HIGH,
        "A secret is passed to a workflow triggered by an untrusted event.",
        "Keep the secret on a push workflow, or gate the step with a same-repo or trusted-actor check.",
    ),
    Rule(
        "secrets-inherit",
        Severity.HIGH,
        "A reusable workflow is called with secrets: inherit.",
        "Pass an explicit map of the secrets the called workflow needs.",
    ),
    Rule(
        "self-hosted-public",
        Severity.HIGH,
        "A self-hosted runner is used for a public trigger.",
        "Run untrusted events on a GitHub-hosted runner. Keep self-hosted runners on trusted events such as push.",
    ),
)

RULE_INDEX = {rule.id: rule for rule in RULES}


def check(doc: Document, options: Options) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_unpinned(doc, options))
    findings.extend(_pwn(doc))
    findings.extend(_injection(doc))
    findings.extend(_missing(doc))
    findings.extend(_write_all(doc))
    findings.extend(_contents(doc))
    findings.extend(_checkout(doc))
    findings.extend(_secrets(doc))
    findings.extend(_inherit(doc))
    findings.extend(_runners(doc))
    return findings


def _unpinned(doc: Document, options: Options) -> list[Finding]:
    findings: list[Finding] = []
    for job in doc.jobs:
        if job.uses:
            problem = _pin_problem(job.uses, allow_actions=options.allow_actions_refs)
            if problem:
                findings.append(_finding(doc, "unpinned-action", job.uses_line, f"{_where(doc, job)} calls {problem}"))
        for step in job.steps:
            if not step.uses:
                continue
            problem = _pin_problem(step.uses, allow_actions=options.allow_actions_refs)
            if problem:
                findings.append(_finding(doc, "unpinned-action", step.uses_line, f"{_where(doc, job)} uses {problem}"))
    return findings


def _pwn(doc: Document) -> list[Finding]:
    if doc.kind != "workflow" or not ({"pull_request_target", "workflow_run"} & doc.events):
        return []
    findings: list[Finding] = []
    for job in doc.jobs:
        for step in job.steps:
            trigger = _step_pwn(step, doc.events)
            if trigger is None:
                continue
            line = step.run_line if step.run and not _is_checkout(step.uses) else _checkout_ref_line(step)
            findings.append(
                _finding(doc, "pwn-request", line, f"{_where(doc, job)} checks out untrusted head code on {trigger}")
            )
    return findings


def _injection(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    for job in doc.jobs:
        for step in job.steps:
            if not step.run:
                continue
            for label in leaking_contexts(step.run):
                findings.append(
                    _finding(
                        doc,
                        "script-injection",
                        step.run_line,
                        f"{_where(doc, job)} interpolates {label} into a run script",
                    )
                )
    return findings


def _missing(doc: Document) -> list[Finding]:
    if doc.kind != "workflow" or doc.permissions is not None:
        return []
    return [_finding(doc, "permissions-missing", doc.on_line, "workflow has no top-level permissions block")]


def _write_all(doc: Document) -> list[Finding]:
    if doc.kind != "workflow":
        return []
    findings: list[Finding] = []
    if doc.permissions is not None and doc.permissions.shorthand == "write-all":
        findings.append(
            _finding(doc, "permissions-write-all", doc.permissions.line, "workflow permissions are write-all")
        )
    for job in doc.jobs:
        if job.permissions is not None and job.permissions.shorthand == "write-all":
            findings.append(
                _finding(
                    doc,
                    "permissions-write-all",
                    job.permissions.line,
                    f"{_where(doc, job)} permissions are write-all",
                )
            )
    return findings


def _contents(doc: Document) -> list[Finding]:
    if doc.kind != "workflow":
        return []
    findings: list[Finding] = []
    if doc.permissions is not None:
        scope = doc.permissions.scope("contents")
        inheriting = [job for job in doc.jobs if job.permissions is None]
        if scope is not None and scope[0] == "write" and any(not _needs_contents_write(job) for job in inheriting):
            findings.append(
                _finding(
                    doc,
                    "permissions-contents-write",
                    scope[1],
                    "workflow contents: write applies to a job that does not publish or push",
                )
            )
    for job in doc.jobs:
        if job.permissions is None:
            continue
        scope = job.permissions.scope("contents")
        if scope is not None and scope[0] == "write" and not _needs_contents_write(job):
            findings.append(
                _finding(
                    doc,
                    "permissions-contents-write",
                    scope[1],
                    f"{_where(doc, job)} sets contents: write without a step that publishes or pushes",
                )
            )
    return findings


def _checkout(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    for job in doc.jobs:
        for step in job.steps:
            if step.uses and _is_checkout(step.uses) and _persists_credentials(step):
                findings.append(
                    _finding(
                        doc,
                        "checkout-persist-credentials",
                        _persist_line(step),
                        f"{_where(doc, job)} leaves a checkout credential in the workspace",
                    )
                )
    return findings


def _secrets(doc: Document) -> list[Finding]:
    if doc.kind != "workflow":
        return []
    triggers = sorted(doc.events & _SECRET_EVENTS)
    if not triggers:
        return []
    shown = ", ".join(triggers)
    findings: list[Finding] = []
    if _workflow_env_exposed(doc):
        pair = _secret_pair(doc.env)
        if pair is not None:
            findings.append(_finding(doc, "secret-untrusted", pair.line, f"workflow passes a secret on {shown}"))
    for job in doc.jobs:
        if _guarded(job.if_expr):
            continue
        unguarded = [step for step in job.steps if not _guarded(step.if_expr)]
        if unguarded or not job.steps:
            pair = _secret_pair(job.env)
            if pair is not None:
                findings.append(
                    _finding(doc, "secret-untrusted", pair.line, f"{_where(doc, job)} passes a secret on {shown}")
                )
        for group in (job.inputs, job.secret_args):
            pair = _secret_pair(group)
            if pair is not None:
                findings.append(
                    _finding(doc, "secret-untrusted", pair.line, f"{_where(doc, job)} passes a secret on {shown}")
                )
        for step in unguarded:
            line = _step_secret_line(step)
            if line is not None:
                findings.append(
                    _finding(doc, "secret-untrusted", line, f"{_where(doc, job)} passes a secret on {shown}")
                )
    return findings


def _inherit(doc: Document) -> list[Finding]:
    if doc.kind != "workflow":
        return []
    findings: list[Finding] = []
    for job in doc.jobs:
        if not job.secrets_inherit:
            continue
        target = job.uses or "a reusable workflow"
        findings.append(
            _finding(
                doc,
                "secrets-inherit",
                job.secrets_line,
                f"{_where(doc, job)} calls {target} with secrets: inherit",
            )
        )
    return findings


def _runners(doc: Document) -> list[Finding]:
    if doc.kind != "workflow":
        return []
    triggers = sorted(doc.events & _PUBLIC_EVENTS)
    if not triggers:
        return []
    shown = ", ".join(triggers)
    return [
        _finding(
            doc,
            "self-hosted-public",
            job.runs_on_line,
            f"{_where(doc, job)} uses a self-hosted runner on {shown}",
        )
        for job in doc.jobs
        if job.self_hosted
    ]


def _pin_problem(uses: str, *, allow_actions: bool) -> str | None:
    text = " ".join(uses.split())
    if text.startswith("./") or text.startswith("docker://"):
        return None
    if "${{" in text:
        return f"{text}, which is an expression rather than a 40-character commit SHA"
    name, sep, ref = text.rpartition("@")
    if not sep or not ref.strip():
        return f"{text}, which is not pinned to a 40-character commit SHA"
    ref = ref.strip()
    if allow_actions and _actions_org(name):
        return None
    if _SHA.fullmatch(ref):
        return None
    return f"{text}, which is not pinned to a 40-character commit SHA"


def _actions_org(name: str) -> bool:
    owner, sep, rest = name.partition("/")
    return bool(sep and owner == "actions" and rest)


def _step_pwn(step: Step, events: frozenset[str]) -> str | None:
    if step.uses and _is_checkout(step.uses):
        text = "\n".join(pair.text for pair in step.with_args if pair.key in {"ref", "repository"})
        return _head_checkout(text, events)
    if step.run and _GIT.search(step.run):
        return _head_checkout(step.run, events)
    return None


def _head_checkout(text: str, events: frozenset[str]) -> str | None:
    compact = "".join(text.split())
    if "pull_request_target" in events:
        if any(item in compact for item in _PR_HEAD):
            return "pull_request_target"
        if "refs/pull/" in compact and ("/head" in compact or "/merge" in compact):
            return "pull_request_target"
    if "workflow_run" in events and any(item in compact for item in _RUN_HEAD):
        return "workflow_run"
    return None


def _is_checkout(uses: str | None) -> bool:
    if not uses:
        return False
    return uses.split("@", 1)[0].strip() == "actions/checkout"


def _persists_credentials(step: Step) -> bool:
    for arg in step.with_args:
        if arg.key != "persist-credentials":
            continue
        return not _is_false(arg.value)
    return True


def _is_false(value: object) -> bool:
    if value is False:
        return True
    return isinstance(value, str) and value.strip().lower() == "false"


def _persist_line(step: Step) -> int:
    for arg in step.with_args:
        if arg.key == "persist-credentials":
            return arg.line
    return step.uses_line


def _checkout_ref_line(step: Step) -> int:
    triggers = frozenset({"pull_request_target", "workflow_run"})
    for arg in step.with_args:
        if arg.key in {"ref", "repository"} and _head_checkout(arg.text, triggers):
            return arg.line
    return step.uses_line


def _needs_contents_write(job: Job) -> bool:
    for step in job.steps:
        if step.uses and _action_id(step.uses) in _PUBLISH_ACTIONS:
            return True
        if step.run and _PUBLISH_RUN.search(step.run):
            return True
    return False


def _action_id(uses: str) -> str:
    name = uses.split("@", 1)[0].strip()
    if name.startswith("./") or name.startswith("docker://"):
        return ""
    parts = [part for part in name.split("/") if part]
    if len(parts) < 2:
        return name.lower()
    return f"{parts[0]}/{parts[1]}".lower()


def _guarded(expr: str | None) -> bool:
    """Pattern match a same-repo or trusted-actor guard. This is not an evaluator."""
    if not expr:
        return False
    compact = "".join(expr.split()).lower()
    if "head.repo.full_name==github.repository" in compact:
        return True
    if "head.repo.full_name==github.event.pull_request.base.repo.full_name" in compact:
        return True
    if "head.repo.fork==false" in compact:
        return True
    return "author_association" in compact and _TRUSTED_ACTOR.search(expr) is not None


def _workflow_env_exposed(doc: Document) -> bool:
    if not doc.jobs:
        return True
    for job in doc.jobs:
        if _guarded(job.if_expr):
            continue
        if not job.steps or any(not _guarded(step.if_expr) for step in job.steps):
            return True
    return False


def _secret_pair(pairs: tuple[Pair, ...]) -> Pair | None:
    for pair in pairs:
        if contains_secret(pair.text):
            return pair
    return None


def _step_secret_line(step: Step) -> int | None:
    for group in (step.env, step.with_args):
        pair = _secret_pair(group)
        if pair is not None:
            return pair.line
    if step.run and contains_secret(step.run):
        return step.run_line
    return None


def _where(doc: Document, job: Job) -> str:
    if doc.kind == "action":
        return "composite action"
    return f"job {job.job_id}"


def _finding(doc: Document, rule_id: str, line: int, message: str) -> Finding:
    rule = RULE_INDEX[rule_id]
    return Finding(
        rule_id=rule.id,
        severity=rule.severity,
        message=message,
        path=doc.path,
        line=line if line > 0 else 1,
        remediation=rule.remediation,
    )

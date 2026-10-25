from __future__ import annotations

import posixpath
import re
from typing import Any

from k8s_harden.models import Finding, Severity

_POD_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

# Anything under these directories is the node, not the container.
_SENSITIVE_ROOTS = (
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/var/lib/containerd",
    "/var/lib/docker",
    "/var/lib/kubelet",
    "/var/run",
)
_DIGEST = re.compile(r"@sha256:[0-9a-fA-F]{64}$")
_POD_INHERITED = ("runAsGroup", "runAsNonRoot", "runAsUser", "seccompProfile")

_DANGEROUS_CAPS = frozenset(
    {
        "ALL",
        "CAP_ALL",
        "SYS_ADMIN",
        "CAP_SYS_ADMIN",
        "NET_ADMIN",
        "CAP_NET_ADMIN",
        "SYS_MODULE",
        "CAP_SYS_MODULE",
        "SYS_PTRACE",
        "CAP_SYS_PTRACE",
        "DAC_READ_SEARCH",
        "CAP_DAC_READ_SEARCH",
        "SYS_RAWIO",
        "CAP_SYS_RAWIO",
    }
)

_SECRET_ENV = re.compile(r"(?i)(password|passwd|secret|token|api_key|apikey|private_key|aws_secret_access_key)")
_PLACEHOLDER = re.compile(r"(?i)^(changeme|example|placeholder|todo|xxx+|redacted|\$\{.*\}|\{\{.*\}\})$")


def lint_document(document: dict[str, Any], path: str) -> list[Finding]:
    ignored = _ignored(document)
    kind, name, namespace = _meta(document)
    findings: list[Finding] = []
    if kind == "Secret":
        findings.extend(_secret(document, path, kind, name, namespace))
    elif kind == "ServiceAccount":
        findings.extend(_service_account(document, path, name))
    elif kind in {"Role", "ClusterRole"}:
        findings.extend(_rbac_rules(document, path, kind, name))
    elif kind in {"RoleBinding", "ClusterRoleBinding"}:
        findings.extend(_binding(document, path, kind, name))
    pod = _pod_spec(document)
    if pod is not None:
        findings.extend(_workload(document, pod, path, kind, name, namespace))
    return [item for item in findings if item.rule_id not in ignored and "*" not in ignored]


def workload_namespace(document: dict[str, Any]) -> str | None:
    if _pod_spec(document) is None:
        return None
    _, _, namespace = _meta(document)
    return namespace


def network_policy_namespace(document: dict[str, Any]) -> str | None:
    if document.get("kind") != "NetworkPolicy":
        return None
    _, _, namespace = _meta(document)
    return namespace


def ignores(document: dict[str, Any]) -> set[str]:
    return _ignored(document)


def _workload(
    document: dict[str, Any],
    pod: dict[str, Any],
    path: str,
    kind: str,
    name: str,
    namespace: str,
) -> list[Finding]:
    findings: list[Finding] = []
    who = f"{kind}/{name}"
    location = f"{who} {_pod_location(document)}"

    def add(rule_id: str, severity: Severity, message: str, where: str | None = None) -> None:
        findings.append(Finding(rule_id, severity, message, path, where or location))

    if namespace == "default":
        add("namespace-default", Severity.LOW, f"{who} is in the default namespace")
    if _as_bool(pod.get("hostNetwork")) is True:
        add("host-network", Severity.HIGH, f"{who} sets hostNetwork")
    if _as_bool(pod.get("hostPID")) is True:
        add("host-pid", Severity.HIGH, f"{who} sets hostPID")
    if _as_bool(pod.get("hostIPC")) is True:
        add("host-ipc", Severity.HIGH, f"{who} sets hostIPC")
    if _as_bool(pod.get("shareProcessNamespace")) is True:
        add("share-process-namespace", Severity.MEDIUM, f"{who} shares the process namespace")
    if _as_bool(pod.get("automountServiceAccountToken")) is not False:
        add(
            "automount-token",
            Severity.LOW,
            f"{who} mounts a service account token; set automountServiceAccountToken to false "
            "when the workload does not call the API",
        )
    for volume in _as_list(pod.get("volumes")):
        if not isinstance(volume, dict):
            continue
        host_path = volume.get("hostPath")
        if not isinstance(host_path, dict):
            continue
        raw_path = host_path.get("path")
        mounted = raw_path if isinstance(raw_path, str) else ""
        if _sensitive_host_path(mounted):
            add(
                "host-path-sensitive",
                Severity.CRITICAL,
                f"{who} mounts host path {mounted or '/'}",
            )
        else:
            add("host-path", Severity.HIGH, f"{who} mounts host path {mounted or '<empty>'}")

    containers = [("containers", item) for item in _as_list(pod.get("containers")) if isinstance(item, dict)]
    containers.extend(
        ("initContainers", item) for item in _as_list(pod.get("initContainers")) if isinstance(item, dict)
    )
    containers.extend(
        ("ephemeralContainers", item) for item in _as_list(pod.get("ephemeralContainers")) if isinstance(item, dict)
    )
    for field, container in containers:
        cname = container.get("name") if isinstance(container.get("name"), str) else "unnamed"
        where = f"{location}.{field}[{cname}]"
        context = _merged_context(pod, container)
        privileged = _as_bool(context.get("privileged")) is True
        if privileged:
            add("privileged", Severity.HIGH, f"{who} container {cname} is privileged", where)
        run_as_user = _as_int(context.get("runAsUser"))
        if run_as_user == 0:
            add("run-as-root", Severity.HIGH, f"{who} container {cname} runs as uid 0", where)
        elif _as_bool(context.get("runAsNonRoot")) is not True:
            add(
                "run-as-non-root",
                Severity.MEDIUM,
                f"{who} container {cname} does not set runAsNonRoot",
                where,
            )
        if not privileged and _as_bool(context.get("allowPrivilegeEscalation")) is not False:
            add(
                "allow-privilege-escalation",
                Severity.MEDIUM,
                f"{who} container {cname} does not set allowPrivilegeEscalation to false",
                where,
            )
        capabilities = _as_dict(context.get("capabilities"))
        for cap in _as_str_list(capabilities.get("add")):
            if cap.upper() in _DANGEROUS_CAPS:
                add(
                    "dangerous-capability",
                    Severity.HIGH,
                    f"{who} container {cname} adds capability {cap}",
                    where,
                )
        dropped = {item.upper() for item in _as_str_list(capabilities.get("drop"))}
        if "ALL" not in dropped:
            add(
                "drop-all-missing",
                Severity.LOW,
                f"{who} container {cname} does not drop all capabilities",
                where,
            )
        seccomp = _as_dict(context.get("seccompProfile"))
        seccomp_type = seccomp.get("type")
        if not isinstance(seccomp_type, str):
            add("seccomp-missing", Severity.LOW, f"{who} container {cname} has no seccomp profile", where)
        elif seccomp_type == "Unconfined":
            add("seccomp-unconfined", Severity.MEDIUM, f"{who} container {cname} sets seccomp Unconfined", where)
        if _as_bool(context.get("readOnlyRootFilesystem")) is not True:
            add(
                "read-only-root-missing",
                Severity.LOW,
                f"{who} container {cname} does not set a read-only root filesystem",
                where,
            )
        if context.get("procMount") == "Unmasked":
            add("proc-mount-unmasked", Severity.HIGH, f"{who} container {cname} unmasks /proc", where)
        image = container.get("image")
        if not isinstance(image, str) or _unpinned(image):
            shown = image if isinstance(image, str) else "<missing>"
            add("image-unpinned", Severity.MEDIUM, f"{who} container {cname} image {shown} is not pinned", where)
        limits = _as_dict(_as_dict(container.get("resources")).get("limits"))
        if _limit_missing(limits, "cpu") or _limit_missing(limits, "memory"):
            add(
                "resources-missing",
                Severity.MEDIUM,
                f"{who} container {cname} is missing a cpu or memory limit",
                where,
            )
        for port in _as_list(container.get("ports")):
            if isinstance(port, dict) and port.get("hostPort") is not None:
                add("host-port", Severity.MEDIUM, f"{who} container {cname} sets hostPort", where)
                break
        for env in _as_list(container.get("env")):
            if not isinstance(env, dict):
                continue
            env_name = env.get("name")
            value = env.get("value")
            if (
                isinstance(env_name, str)
                and isinstance(value, str)
                and value.strip()
                and _SECRET_ENV.search(env_name)
                and not _PLACEHOLDER.match(value.strip())
            ):
                add(
                    "plaintext-env-secret",
                    Severity.HIGH,
                    f"{who} container {cname} sets {env_name} to a literal value",
                    where,
                )
    return findings


def _service_account(document: dict[str, Any], path: str, name: str) -> list[Finding]:
    if _as_bool(document.get("automountServiceAccountToken")) is False:
        return []
    return [
        Finding(
            "automount-token",
            Severity.LOW,
            f"ServiceAccount/{name} does not set automountServiceAccountToken to false",
            path,
            f"ServiceAccount/{name}",
        )
    ]


def _secret(
    document: dict[str, Any],
    path: str,
    kind: str,
    name: str,
    namespace: str,
) -> list[Finding]:
    del document, kind, namespace
    return [
        Finding(
            "secret-manifest",
            Severity.MEDIUM,
            f"Secret/{name} keeps credential material in the manifest; use an external secret store",
            path,
            f"Secret/{name}",
        )
    ]


def _rbac_rules(document: dict[str, Any], path: str, kind: str, name: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, rule in enumerate(_as_list(document.get("rules"))):
        if not isinstance(rule, dict):
            continue
        verbs = {item.lower() for item in _as_str_list(rule.get("verbs"))}
        resources = {item.lower() for item in _as_str_list(rule.get("resources"))}
        where = f"{kind}/{name} rules[{index}]"
        if "*" in verbs and "*" in resources:
            findings.append(
                Finding(
                    "rbac-wildcard",
                    Severity.CRITICAL,
                    f"{kind}/{name} allows every verb on every resource",
                    path,
                    where,
                )
            )
            continue
        if "*" in verbs or "*" in resources:
            findings.append(
                Finding(
                    "rbac-wildcard",
                    Severity.HIGH,
                    f"{kind}/{name} uses a wildcard verb or resource",
                    path,
                    where,
                )
            )
        risky = sorted(verbs & {"bind", "escalate", "impersonate"})
        if risky and "*" not in verbs:
            findings.append(
                Finding(
                    "rbac-escalate",
                    Severity.HIGH,
                    f"{kind}/{name} grants {', '.join(risky)}",
                    path,
                    where,
                )
            )
        if "secrets" in resources and verbs & {"get", "list", "watch", "*"} and "*" not in resources:
            findings.append(
                Finding(
                    "rbac-secret-read",
                    Severity.HIGH,
                    f"{kind}/{name} can read Secret objects",
                    path,
                    where,
                )
            )
    return findings


def _binding(document: dict[str, Any], path: str, kind: str, name: str) -> list[Finding]:
    findings: list[Finding] = []
    role_ref = _as_dict(document.get("roleRef"))
    role_name = role_ref.get("name")
    if role_name == "cluster-admin":
        findings.append(
            Finding(
                "rbac-cluster-admin",
                Severity.CRITICAL,
                f"{kind}/{name} binds cluster-admin",
                path,
                f"{kind}/{name}",
            )
        )
    for subject in _as_list(document.get("subjects")):
        if not isinstance(subject, dict):
            continue
        subject_name = subject.get("name")
        if subject_name in {"system:anonymous", "system:unauthenticated", "*"}:
            findings.append(
                Finding(
                    "rbac-anonymous",
                    Severity.CRITICAL,
                    f"{kind}/{name} binds {subject_name}",
                    path,
                    f"{kind}/{name}",
                )
            )
    return findings


def _pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
    kind = document.get("kind")
    if isinstance(kind, str) and kind in _POD_PATHS:
        found = _dig(document, _POD_PATHS[kind])
        return found if isinstance(found, dict) else None
    for keys in (("spec", "template", "spec"), ("spec", "jobTemplate", "spec", "template", "spec")):
        found = _dig(document, keys)
        if isinstance(found, dict) and isinstance(found.get("containers"), list):
            return found
    return None


def _pod_location(document: dict[str, Any]) -> str:
    kind = document.get("kind")
    if isinstance(kind, str) and kind in _POD_PATHS:
        return ".".join(_POD_PATHS[kind])
    return "spec"


def _merged_context(pod: dict[str, Any], container: dict[str, Any]) -> dict[str, Any]:
    # Kubernetes only inherits identity and seccomp from the pod. privileged,
    # capabilities, and allowPrivilegeEscalation are container fields.
    pod_context = _as_dict(pod.get("securityContext"))
    merged = {key: pod_context[key] for key in _POD_INHERITED if key in pod_context}
    merged.update(_as_dict(container.get("securityContext")))
    return merged


def _ignored(document: dict[str, Any]) -> set[str]:
    found = _annotation_ignores(document.get("metadata"))
    for keys in (
        ("spec", "template", "metadata"),
        ("spec", "jobTemplate", "spec", "template", "metadata"),
    ):
        found |= _annotation_ignores(_dig(document, keys))
    return found


def _annotation_ignores(metadata: object) -> set[str]:
    annotations = _as_dict(_as_dict(metadata).get("annotations"))
    raw = annotations.get("k8s-harden.io/ignore", "")
    if not isinstance(raw, str):
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def _meta(document: dict[str, Any]) -> tuple[str, str, str]:
    kind_raw = document.get("kind")
    kind = kind_raw if isinstance(kind_raw, str) else "Unknown"
    metadata = _as_dict(document.get("metadata"))
    name_raw = metadata.get("name")
    namespace_raw = metadata.get("namespace")
    name = name_raw if isinstance(name_raw, str) else "<unnamed>"
    namespace = namespace_raw if isinstance(namespace_raw, str) else "default"
    return kind, name, namespace


def _sensitive_host_path(mounted: str) -> bool:
    if not mounted.startswith("/"):
        return False
    path = posixpath.normpath(mounted)
    if path == "/":
        return True
    return any(path == root or path.startswith(root + "/") for root in _SENSITIVE_ROOTS)


def _limit_missing(limits: dict[str, Any], key: str) -> bool:
    if key not in limits:
        return True
    return _zero_quantity(limits[key])


def _zero_quantity(value: object) -> bool:
    if isinstance(value, bool) or value is None:
        return True
    if isinstance(value, (int, float)):
        return value <= 0
    if not isinstance(value, str):
        return True
    number = ""
    for char in value.strip():
        if char.isdigit() or char == ".":
            number += char
            continue
        break
    if not number or number == ".":
        return True
    try:
        return float(number) <= 0
    except ValueError:
        return True


def _unpinned(image: str) -> bool:
    if any(char.isspace() for char in image):
        return True
    if "@" in image:
        return _DIGEST.search(image) is None
    last = image.split("/")[-1]
    if ":" not in last:
        return True
    tag = last.rsplit(":", 1)[-1]
    return tag == "" or tag.lower() == "latest"


def _dig(node: dict[str, Any], keys: tuple[str, ...]) -> object:
    current: object = node
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _as_list(value: object) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None

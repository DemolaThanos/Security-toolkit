# k8s-harden

Checks Kubernetes YAML and JSON manifests for weak RBAC, secrets committed in the clear, and missing workload isolation.

It only sees the files you pass. It does not talk to a cluster and it does not apply Pod Security Admission.

## Install

```bash
pip install .
```

Python 3.11 or newer.

## Usage

```bash
k8s-harden check ./deploy --fail-on high
k8s-harden check pod.yaml --format json
```

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` a file could not be parsed. Helm templates (`{{`) are skipped.

`examples/secure.yaml` is a deployment that stays quiet. `examples/insecure.yaml` is the opposite, on purpose.

## Ignore a rule

```yaml
metadata:
  annotations:
    k8s-harden.io/ignore: privileged,netpol-missing
```

`*` ignores every rule on that object. `netpol-missing` is suppressed only when every workload in the namespace ignores it.

## Rules

| Rule | Severity | What it catches |
| --- | --- | --- |
| `host-path-sensitive` | critical | hostPath of `/`, `/proc`, `/sys`, `/etc`, `/var/run`, or a container runtime socket |
| `rbac-wildcard` | critical when verb and resource are both `*` | wildcard Role or ClusterRole rules |
| `rbac-cluster-admin` | critical | binding to `cluster-admin` |
| `rbac-anonymous` | critical | subject `system:anonymous`, `system:unauthenticated`, or `*` |
| `privileged`, `host-network`, `host-pid`, `host-ipc`, `host-path` | high | workload sharing the node |
| `run-as-root`, `dangerous-capability`, `proc-mount-unmasked` | high | container breakout settings |
| `plaintext-env-secret` | high | literal `value` on a password, token, or key env var. `valueFrom` is not flagged |
| `rbac-secret-read`, `rbac-escalate` | high | reading Secrets, or `bind` / `escalate` / `impersonate` |
| `run-as-non-root`, `allow-privilege-escalation`, `seccomp-unconfined` | medium | identity and seccomp gaps |
| `image-unpinned`, `resources-missing`, `host-port`, `share-process-namespace` | medium | tag `latest`, no digest, missing limits |
| `secret-manifest` | medium | a `Secret` object in the repo. `SealedSecret` is ignored |
| `netpol-missing` | medium | a namespace has workloads and no NetworkPolicy in the scan set |
| `namespace-default`, `automount-token`, `seccomp-missing`, `drop-all-missing`, `read-only-root-missing` | low | defaults that are easy to tighten |

A NetworkPolicy is counted if it is present. The checker does not judge whether the policy is a default deny.

## License

MIT

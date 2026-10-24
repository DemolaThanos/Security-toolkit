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
k8s-harden check pod.yaml --format sarif --output k8s-harden.sarif
```

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` a file could not be parsed, the directory contained no manifests, or the scan was over 10,000 manifests. Helm templates (`{{`) are skipped. A limit of `0` or `0m` counts as missing. SARIF results include a stable `partialFingerprints.primaryLocationLineHash`. `K8S_HARDEN_LOG_FORMAT=json` writes one JSON object per log line.

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
| `host-path-sensitive` | critical | hostPath of `/`, or a path under `/etc`, `/proc`, `/root`, `/run`, `/sys`, `/var/lib/containerd`, `/var/lib/docker`, `/var/lib/kubelet`, or `/var/run`. `/etc-backup` is not this rule |
| `rbac-wildcard` | critical when verb and resource are both `*` | wildcard Role or ClusterRole rules |
| `rbac-cluster-admin` | critical | binding to `cluster-admin` |
| `rbac-anonymous` | critical | subject `system:anonymous`, `system:unauthenticated`, or `*` |
| `privileged`, `host-network`, `host-pid`, `host-ipc`, `host-path` | high | workload sharing the node |
| `run-as-root`, `dangerous-capability`, `proc-mount-unmasked` | high | container breakout settings |
| `plaintext-env-secret` | high | literal `value` on a password, token, or key env var. `valueFrom` is not flagged |
| `rbac-secret-read`, `rbac-escalate` | high | reading Secrets, or `bind` / `escalate` / `impersonate` |
| `run-as-non-root`, `allow-privilege-escalation`, `seccomp-unconfined` | medium | identity and seccomp gaps |
| `image-unpinned`, `resources-missing`, `host-port`, `share-process-namespace` | medium | missing tag, empty tag, `latest`, or a short digest (a non-latest tag or a full `sha256` digest is pinned); missing limits; hostPort; shared process namespace |
| `secret-manifest` | medium | a `Secret` object in the repo. `SealedSecret` is ignored |
| `netpol-missing` | medium | a namespace has workloads and no NetworkPolicy in the scan set |
| `namespace-default`, `automount-token`, `seccomp-missing`, `drop-all-missing`, `read-only-root-missing` | low | defaults that are easy to tighten. `automount-token` also fires on a ServiceAccount that does not set `automountServiceAccountToken: false` |

A NetworkPolicy is counted if it is present. The checker does not judge whether the policy is a default deny.

Pod `securityContext` contributes only `runAsUser`, `runAsNonRoot`, `runAsGroup`, and `seccompProfile`. `privileged`, `allowPrivilegeEscalation`, capabilities, and the root filesystem are read from the container. `exclude` matches a path prefix or a glob, not a substring. Symlinks that leave the directory you passed are skipped.

## License

MIT

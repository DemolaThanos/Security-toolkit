from pathlib import Path

from k8s_harden.cli import main
from k8s_harden.lint import lint_path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "automount-token",
    "dangerous-capability",
    "drop-all-missing",
    "host-ipc",
    "host-network",
    "host-path-sensitive",
    "host-pid",
    "host-port",
    "image-unpinned",
    "namespace-default",
    "netpol-missing",
    "plaintext-env-secret",
    "privileged",
    "proc-mount-unmasked",
    "rbac-anonymous",
    "rbac-cluster-admin",
    "rbac-wildcard",
    "read-only-root-missing",
    "resources-missing",
    "run-as-root",
    "seccomp-missing",
    "secret-manifest",
    "share-process-namespace",
}


def test_secure_example_is_clean() -> None:
    report = lint_path(ROOT / "examples" / "secure.yaml", max_bytes=1_000_000, exclude=())
    assert report.errors == ()
    assert report.findings == ()


def test_insecure_example_rules() -> None:
    report = lint_path(ROOT / "examples" / "insecure.yaml", max_bytes=1_000_000, exclude=())
    assert report.errors == ()
    assert {item.rule_id for item in report.findings} == EXPECTED


def test_cronjob_privileged(tmp_path: Path) -> None:
    manifest = tmp_path / "job.yaml"
    manifest.write_text(
        """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
  namespace: payments
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          automountServiceAccountToken: false
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: job
              image: ghcr.io/example/job:1.0.0
              securityContext:
                privileged: true
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities:
                  drop: ["ALL"]
              resources:
                limits:
                  cpu: "100m"
                  memory: 64Mi
""",
        encoding="utf-8",
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert "privileged" in {item.rule_id for item in report.findings}
    assert "netpol-missing" in {item.rule_id for item in report.findings}


def test_ignore_annotation(tmp_path: Path) -> None:
    manifest = tmp_path / "pod.yaml"
    manifest.write_text(
        """
apiVersion: v1
kind: Pod
metadata:
  name: kept
  namespace: payments
  annotations:
    k8s-harden.io/ignore: privileged,netpol-missing
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: ghcr.io/example/app:1
      securityContext:
        privileged: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "100m"
          memory: 64Mi
""",
        encoding="utf-8",
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert "privileged" not in {item.rule_id for item in report.findings}
    assert "netpol-missing" not in {item.rule_id for item in report.findings}


def test_least_privilege_role_is_quiet(tmp_path: Path) -> None:
    manifest = tmp_path / "role.yaml"
    manifest.write_text(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
""",
        encoding="utf-8",
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert report.findings == ()


def test_secret_read_and_escalate(tmp_path: Path) -> None:
    manifest = tmp_path / "role.yaml"
    manifest.write_text(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: risky
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["escalate", "bind"]
""",
        encoding="utf-8",
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert {item.rule_id for item in report.findings} == {"rbac-secret-read", "rbac-escalate"}


def test_list_kind(tmp_path: Path) -> None:
    manifest = tmp_path / "list.yaml"
    manifest.write_text(
        """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: wrapped
      namespace: payments
      annotations:
        k8s-harden.io/ignore: "*"
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
""",
        encoding="utf-8",
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert report.findings == ()


def test_template_is_skipped(tmp_path: Path) -> None:
    manifest = tmp_path / "chart.yaml"
    manifest.write_text("kind: ConfigMap\ndata:\n  a: {{ .Values.a }}\n", encoding="utf-8")
    assert main(["check", str(manifest)]) == 0


def test_invalid_yaml_exits_2(tmp_path: Path) -> None:
    manifest = tmp_path / "broken.yaml"
    manifest.write_text("kind: [\n", encoding="utf-8")
    assert main(["check", str(manifest)]) == 2

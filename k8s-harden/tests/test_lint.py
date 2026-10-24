from pathlib import Path

import pytest

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


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_host_path_prefix_and_pod_context(tmp_path: Path) -> None:
    sensitive = tmp_path / "sensitive.yaml"
    _write(
        sensitive,
        """
apiVersion: v1
kind: Pod
metadata:
  name: sample
  namespace: payments
spec:
  automountServiceAccountToken: false
  volumes:
    - name: etc
      hostPath:
        path: /etc/passwd
  containers:
    - name: app
      image: nginx:1.2.3
""",
    )
    report = lint_path(sensitive, max_bytes=1_000_000, exclude=())
    assert any(item.rule_id == "host-path-sensitive" and item.severity.value == "critical" for item in report.findings)

    sibling = tmp_path / "sibling.yaml"
    _write(sibling, sensitive.read_text(encoding="utf-8").replace("/etc/passwd", "/etc-backup"))
    report = lint_path(sibling, max_bytes=1_000_000, exclude=())
    ids = {item.rule_id for item in report.findings}
    assert "host-path-sensitive" not in ids
    assert "host-path" in ids

    inherited = tmp_path / "inherited.yaml"
    _write(
        inherited,
        """
apiVersion: v1
kind: Pod
metadata:
  name: sample
  namespace: payments
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
    allowPrivilegeEscalation: false
  containers:
    - name: app
      image: nginx:1.2.3
      securityContext:
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
""",
    )
    report = lint_path(inherited, max_bytes=1_000_000, exclude=())
    ids = {item.rule_id for item in report.findings}
    assert "allow-privilege-escalation" in ids
    assert "run-as-non-root" not in ids
    assert "seccomp-missing" not in ids


def test_image_pin_and_short_digest(tmp_path: Path) -> None:
    digest = "a" * 64
    manifest = tmp_path / "images.yaml"
    _write(
        manifest,
        f"""
apiVersion: v1
kind: Pod
metadata:
  name: sample
  namespace: payments
spec:
  automountServiceAccountToken: false
  containers:
    - name: bare
      image: localhost:5000/nginx
    - name: tagged
      image: nginx:1.2
    - name: digest
      image: nginx@sha256:{digest}
    - name: short
      image: nginx@sha256:abcd
    - name: spaced
      image: "nginx:1.2 "
""",
    )
    messages = [
        item.message
        for item in lint_path(manifest, max_bytes=1_000_000, exclude=()).findings
        if item.rule_id == "image-unpinned"
    ]
    assert any("localhost:5000/nginx" in item for item in messages)
    assert any("abcd" in item for item in messages)
    assert any("nginx:1.2 " in item for item in messages)
    assert not any("nginx:1.2 is" in item or item.endswith("nginx:1.2 is not pinned") for item in messages)
    assert not any(digest in item for item in messages)


def test_symlink_json_sealed_secret_and_exclude(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    _write(
        outside,
        """
apiVersion: v1
kind: Pod
metadata:
  name: escaped
  namespace: payments
spec:
  containers:
    - name: app
      image: nginx:1
      securityContext:
        privileged: true
""",
    )
    root = tmp_path / "manifests"
    root.mkdir()
    (root / "escape.yaml").symlink_to(outside)
    report = lint_path(root, max_bytes=1_000_000, exclude=())
    assert "privileged" not in {item.rule_id for item in report.findings}

    sealed = root / "sealed.yaml"
    _write(
        sealed,
        """
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db
  namespace: payments
spec:
  encryptedData:
    password: abc
""",
    )
    report = lint_path(sealed, max_bytes=1_000_000, exclude=())
    assert report.findings == ()

    bundle = root / "bundle.json"
    _write(
        bundle,
        """
[{"apiVersion":"v1","kind":"Secret","metadata":{"name":"db","namespace":"payments"},"stringData":{"password":"x"}}]
""",
    )
    report = lint_path(bundle, max_bytes=1_000_000, exclude=())
    assert any(item.rule_id == "secret-manifest" for item in report.findings)

    deploy = root / "deployments"
    deploy.mkdir()
    _write(
        deploy / "api.yaml",
        """
apiVersion: v1
kind: ConfigMap
metadata:
  name: from-deployments
  namespace: payments
data:
  note: deployments
""",
    )
    _write(
        root / "my-deploy.yaml",
        """
apiVersion: v1
kind: Pod
metadata:
  name: named
  namespace: payments
spec:
  containers:
    - name: app
      image: nginx:1
      securityContext:
        privileged: true
""",
    )
    both = lint_path(root, max_bytes=1_000_000, exclude=("deploy",))
    assert any(item.rule_id == "privileged" for item in both.findings)
    narrowed = lint_path(root, max_bytes=1_000_000, exclude=("deployments",))
    assert any(item.rule_id == "privileged" for item in narrowed.findings)
    assert all("deployments" not in item.path for item in narrowed.findings)


def test_alias_limit_is_not_treated_as_helm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import k8s_harden.load as load_mod

    monkeypatch.setattr(load_mod, "_MAX_ALIASES", 1)
    manifest = tmp_path / "bomb.yaml"
    manifest.write_text("a: &a [1]\nb: *a\nc: *a\n# {{\n", encoding="utf-8")
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert report.errors
    assert "limit" in report.errors[0]


def test_template_annotation_ignore(tmp_path: Path) -> None:
    manifest = tmp_path / "deploy.yaml"
    _write(
        manifest,
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
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
          image: nginx:1.2
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
    )
    report = lint_path(manifest, max_bytes=1_000_000, exclude=())
    assert "privileged" not in {item.rule_id for item in report.findings}

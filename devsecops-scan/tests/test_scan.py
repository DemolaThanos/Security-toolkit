import importlib
import json
import socket
from pathlib import Path

import pytest

from devsecops_scan.cli import main
from devsecops_scan.config import Settings, resolve_settings
from devsecops_scan.errors import ConfigError, PublishError, ScanError
from devsecops_scan.publish import post_webhook, publish_s3, refuse_redirect
from devsecops_scan.report import render
from devsecops_scan.scan import run_scan


def test_scan_skips_vendor_and_writes_sarif(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "index.js").write_text("eval(input)\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    settings = resolve_settings(
        root=tmp_path,
        config_path=None,
        fail_on="high",
        exclude=(),
        max_bytes=None,
        no_secrets=False,
        no_sast=False,
        no_sca=False,
        require_pins=None,
        advisories=None,
        dast_url=None,
        dast_authorized=False,
        s3_bucket=None,
        s3_key=None,
        s3_kms_key_id=None,
        webhook_url=None,
        report_format="sarif",
        output=None,
        timeout=1,
        env={},
    )
    report = run_scan(settings)
    assert any(item.rule_id == "python-eval" for item in report.findings)
    assert all(item.path != "node_modules/pkg/index.js" for item in report.findings)
    assert any(item.rule_id == "GHSA-9wx4-h78v-vm56" for item in report.findings)
    payload = json.loads(render(report, "sarif"))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
    assert payload["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]


def test_config_precedence(tmp_path: Path) -> None:
    config = tmp_path / ".devsecops-scan.toml"
    config.write_text(
        'fail_on = "low"\nexclude = ["skip-me/"]\n',
        encoding="utf-8",
    )
    settings = resolve_settings(
        root=tmp_path,
        config_path=config,
        fail_on="high",
        exclude=("also/",),
        max_bytes=None,
        no_secrets=True,
        no_sast=False,
        no_sca=False,
        require_pins=None,
        advisories=None,
        dast_url=None,
        dast_authorized=False,
        s3_bucket=None,
        s3_key=None,
        s3_kms_key_id=None,
        webhook_url=None,
        report_format=None,
        output=None,
        timeout=5,
        env={
            "DEVSECOPS_SCAN_S3_BUCKET": "from-env",
            "DEVSECOPS_SCAN_WEBHOOK_URL": "https://tracker.example/hook",
            "DEVSECOPS_SCAN_WEBHOOK_TOKEN": "${WEBHOOK_TOKEN}",
        },
    )
    assert settings.fail_on.value == "high"
    assert settings.exclude == ("skip-me/", "also/")
    assert settings.secrets is False
    assert settings.s3_bucket == "from-env"
    assert settings.webhook_url == "https://tracker.example/hook"
    assert settings.webhook_token == "${WEBHOOK_TOKEN}"


def test_unknown_config_key(tmp_path: Path) -> None:
    config = tmp_path / "scan.toml"
    config.write_text("extra = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown config keys"):
        resolve_settings(
            root=tmp_path,
            config_path=config,
            fail_on=None,
            exclude=(),
            max_bytes=None,
            no_secrets=False,
            no_sast=False,
            no_sca=False,
            require_pins=None,
            advisories=None,
            dast_url=None,
            dast_authorized=False,
            s3_bucket=None,
            s3_key=None,
            s3_kms_key_id=None,
            webhook_url=None,
            report_format=None,
            output=None,
            timeout=5,
            env={},
        )


def test_s3_encryption() -> None:
    class Client:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] | None = None

        def put_object(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    plain = Client()
    publish_s3(b"{}", bucket="audit", key="a.json", kms_key_id=None, client=plain)
    assert plain.kwargs is not None
    assert plain.kwargs["ServerSideEncryption"] == "AES256"
    locked = Client()
    publish_s3(b"{}", bucket="audit", key="a.json", kms_key_id="alias/logs", client=locked)
    assert locked.kwargs is not None
    assert locked.kwargs["ServerSideEncryption"] == "aws:kms"
    assert locked.kwargs["SSEKMSKeyId"] == "alias/logs"


def test_missing_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    real = importlib.import_module

    def boom(name: str, *args: object, **kwargs: object) -> object:
        if name == "boto3":
            raise ImportError("missing")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", boom)
    with pytest.raises(PublishError, match="boto3"):
        publish_s3(b"{}", bucket="audit", key="a.json", kms_key_id=None)


def test_webhook_scrubs_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "${WEBHOOK_TOKEN}"
    query = "trace=redacted-query"

    def fake_dns(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del host, args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_dns)

    def opener(request: object, timeout: float) -> object:
        del timeout
        raise OSError(f"boom {token} {getattr(request, 'full_url', '')}")

    with pytest.raises(PublishError) as caught:
        post_webhook(b"{}", f"https://tracker.example/hook?{query}", token, 1, opener)
    message = str(caught.value)
    assert token not in message
    assert "redacted-query" not in message
    assert "tracker.example" in message
    with pytest.raises(PublishError, match="not following"):
        refuse_redirect(302)


def test_webhook_rejects_cleartext_and_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError(args)

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(PublishError, match="https"):
        post_webhook(b"{}", "http://tracker.example/hook", None, 1)
    with pytest.raises(PublishError, match="link-local"):
        post_webhook(b"{}", "https://169.254.169.254/latest", None, 1)


def test_s3_rejects_bad_names_and_hides_client_text() -> None:
    with pytest.raises(PublishError, match="bucket"):
        publish_s3(b"{}", bucket="Not_A_Bucket", key="a.json", kms_key_id=None, client=object())
    with pytest.raises(PublishError, match="key"):
        publish_s3(b"{}", bucket="audit", key="a/../b.json", kms_key_id=None, client=object())

    class Client:
        def put_object(self, **kwargs: object) -> None:
            del kwargs
            raise RuntimeError("secret-bucket-detail")

    with pytest.raises(PublishError, match="RuntimeError") as caught:
        publish_s3(b"{}", bucket="audit", key="a.json", kms_key_id=None, client=Client())
    assert "secret-bucket-detail" not in str(caught.value)


def test_cli_exit_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--no-sca", "--fail-on", "high"]) == 1
    assert main(["scan", str(tmp_path), "--no-sca", "--no-sast", "--no-secrets"]) == 0


def _settings(root: Path) -> Settings:
    return resolve_settings(
        root=root,
        config_path=None,
        fail_on="high",
        exclude=(),
        max_bytes=None,
        no_secrets=False,
        no_sast=False,
        no_sca=False,
        require_pins=None,
        advisories=None,
        dast_url=None,
        dast_authorized=False,
        s3_bucket=None,
        s3_key=None,
        s3_kms_key_id=None,
        webhook_url=None,
        report_format="text",
        output=None,
        timeout=1,
        env={},
    )


def test_symlink_outside_the_root_is_not_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("eval(user_input)\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "link.py").symlink_to(outside)
    (root / "local.py").write_text("value = 1\n", encoding="utf-8")
    report = run_scan(_settings(root))
    assert all(item.rule_id != "python-eval" for item in report.findings)


def test_requirement_include_is_confined(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "requirements.txt").write_text("-r nested/extra.txt\nrequests==2.31.0\n", encoding="utf-8")
    (nested / "extra.txt").write_text("-r ../requirements.txt\n", encoding="utf-8")
    report = run_scan(_settings(root))
    assert any(item.rule_id == "GHSA-9wx4-h78v-vm56" for item in report.findings)

    (root / "requirements.txt").write_text("-r ../outside.txt\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    with pytest.raises(ScanError, match="escapes"):
        run_scan(_settings(root))


def test_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from devsecops_scan import scan as scan_mod

    assert scan_mod._MAX_FILES == 50_000
    monkeypatch.setattr(scan_mod, "_MAX_FILES", 1)
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(ScanError, match="more than"):
        run_scan(_settings(tmp_path))


def test_publish_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = tmp_path / "report.sarif"
    report.write_bytes(b"{}")
    seen: dict[str, object] = {}

    def fake(
        body: bytes,
        *,
        bucket: str,
        key: str,
        kms_key_id: str | None,
        content_type: str = "",
        client: object = None,
    ) -> None:
        del content_type, client
        seen["body"] = body
        seen["bucket"] = bucket
        seen["key"] = key
        seen["kms"] = kms_key_id

    monkeypatch.setattr("devsecops_scan.cli.publish_s3", fake)
    assert main(["publish", str(report), "--s3-bucket", "audit", "--s3-key", "reports/a.sarif"]) == 0
    assert seen == {"body": b"{}", "bucket": "audit", "key": "reports/a.sarif", "kms": None}
    assert main(["publish", str(tmp_path / "missing.sarif"), "--s3-bucket", "audit"]) == 2


def test_hidden_workflow_is_scanned_and_git_is_not(tmp_path: Path) -> None:
    token = "ghp_" + ("a" * 36)
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text(f"token = {token}\n", encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "ci.yml").write_text(f"token: {token}\n", encoding="utf-8")
    report = run_scan(_settings(tmp_path))
    paths = {item.path for item in report.findings if item.rule_id == "github-token"}
    assert paths == {".github/workflows/ci.yml"}


def test_config_rejects_credential_sinks_and_escaped_advisories(tmp_path: Path) -> None:
    config = tmp_path / ".devsecops-scan.toml"
    config.write_text(
        'webhook_url = "https://tracker.example/hook"\ns3_bucket = "audit"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="credential sink") as caught:
        _settings(tmp_path)
    assert "webhook_url" in str(caught.value)
    assert "s3_bucket" in str(caught.value)
    assert "DEVSECOPS_SCAN_WEBHOOK_TOKEN" in str(caught.value)
    outside = tmp_path.parent / "osv.json"
    config.write_text(f'advisories = "{outside}"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="scan root"):
        _settings(tmp_path)


def test_dast_metadata_and_timeout_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path), "--no-sca", "--no-sast", "--no-secrets", "--timeout", "0"]) == 2
    assert main(["scan", str(tmp_path), "--no-sca", "--dast-url", "http://169.254.169.254/"]) == 2
    assert "authorized" in capsys.readouterr().err
    assert main(["scan", str(tmp_path), "--no-sca", "--dast-url", "http://169.254.169.254/", "--i-am-authorized"]) == 2
    assert "link-local" in capsys.readouterr().err

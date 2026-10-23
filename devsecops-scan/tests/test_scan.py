import importlib
import json
from pathlib import Path

import pytest

from devsecops_scan.cli import main
from devsecops_scan.config import resolve_settings
from devsecops_scan.errors import ConfigError, PublishError
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


def test_config_precedence(tmp_path: Path) -> None:
    config = tmp_path / ".devsecops-scan.toml"
    config.write_text(
        'fail_on = "low"\nexclude = ["skip-me/"]\ns3_bucket = "from-file"\nwebhook_url = "https://tracker.example/hook"\n',
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
        env={"DEVSECOPS_SCAN_S3_BUCKET": "from-env", "DEVSECOPS_SCAN_WEBHOOK_TOKEN": "sekret"},
    )
    assert settings.fail_on.value == "high"
    assert settings.exclude == ("skip-me/", "also/")
    assert settings.secrets is False
    assert settings.s3_bucket == "from-env"
    assert settings.webhook_url == "https://tracker.example/hook"
    assert settings.webhook_token == "sekret"


def test_unknown_config_key(tmp_path: Path) -> None:
    config = tmp_path / "scan.toml"
    config.write_text('webhook_token = "nope"\n', encoding="utf-8")
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


def test_webhook_scrubs_token() -> None:
    token = "super-secret-token"

    def opener(request: object, timeout: float) -> object:
        del timeout
        raise OSError(f"boom {token} {getattr(request, 'full_url', '')}")

    with pytest.raises(PublishError) as caught:
        post_webhook(b"{}", "https://tracker.example/hook?token=abc", token, 1, opener)
    message = str(caught.value)
    assert token not in message
    assert "abc" not in message
    assert "tracker.example" in message
    with pytest.raises(PublishError, match="not following"):
        refuse_redirect(302)


def test_cli_exit_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--no-sca", "--fail-on", "high"]) == 1
    assert main(["scan", str(tmp_path), "--no-sca", "--no-sast", "--no-secrets"]) == 0

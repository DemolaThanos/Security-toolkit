import json
from pathlib import Path

import pytest

from gha_audit.cli import main
from gha_audit.ignore import ConfigError, load_config
from gha_audit.rules import RULES
from gha_audit.scan import scan

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def test_table_json_and_sarif(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    insecure = ROOT / "examples" / "insecure.yml"
    assert main([str(insecure), "--fail-on", "high"]) == 1
    table = capsys.readouterr().out
    assert table.startswith("severity  rule")
    assert "pwn-request" in table
    assert "findings" in table

    assert main([str(insecure), "--format", "json", "--fail-on", "info"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_checked"] == 1
    assert payload["errors"] == []
    assert {item["rule_id"] for item in payload["findings"]} >= {"pwn-request", "unpinned-action"}
    assert all(item["remediation"] for item in payload["findings"])

    out = tmp_path / "gha-audit.sarif"
    assert main([str(insecure), "--format", "sarif", "--output", str(out), "--fail-on", "critical"]) == 1
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "gha-audit"
    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert {rule.id for rule in RULES} <= rule_ids
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
    assert run["results"]
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        fingerprint = result["partialFingerprints"]["primaryLocationLineHash"]
        assert len(fingerprint) == 64
    levels = {result["ruleId"]: result["level"] for result in run["results"]}
    assert levels["pwn-request"] == "error"
    assert levels["permissions-missing"] == "warning"


def test_sarif_levels_and_stable_fingerprint(tmp_path: Path) -> None:
    out = tmp_path / "contents.sarif"
    contents = str(FIXTURES / "permissions-contents.yml")
    assert main([contents, "--format", "sarif", "--output", str(out), "--fail-on", "low"]) == 1
    sarif = json.loads(out.read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert results
    assert {item["level"] for item in results} == {"note"}
    first = scan([FIXTURES / "permissions-contents.yml"])
    second = scan([FIXTURES / "permissions-contents.yml"])
    assert first.findings == second.findings


def test_fail_on_threshold() -> None:
    contents = str(FIXTURES / "permissions-contents.yml")
    assert main([contents, "--fail-on", "high"]) == 0
    assert main([contents, "--fail-on", "low"]) == 1
    assert main([str(ROOT / "examples" / "secure.yml"), "--fail-on", "info"]) == 0
    assert main([str(FIXTURES / "pwn-request.yml")]) == 1


def test_config_ignore_and_actions_org(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "audit.toml"
    config.write_text(
        """
allow_actions_refs = true

[[ignore]]
rule = "permissions-missing"
path = "*"
justification = "The organization default token is read-only."
""",
        encoding="utf-8",
    )
    missing = FIXTURES / "permissions-missing.yml"
    assert main([str(missing), "--config", str(config), "--fail-on", "low"]) == 0
    assert "no findings" in capsys.readouterr().out

    options, ignores = load_config(config)
    report = scan([FIXTURES / "unpinned.yml"], options=options, ignores=ignores)
    assert [item.rule_id for item in report.findings] == ["unpinned-action"]
    assert "example/setup-tool@v1" in report.findings[0].message


def test_bad_config_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "bad.toml"
    config.write_text(
        """
[[ignore]]
rule = "not-a-rule"
justification = "This rule id is not one gha-audit knows."
""",
        encoding="utf-8",
    )
    assert main([str(FIXTURES / "checkout.yml"), "--config", str(config)]) == 2
    assert "unknown rule" in capsys.readouterr().err

    config.write_text(
        """
[[ignore]]
rule = "unpinned-action"
justification = "todo"
""",
        encoding="utf-8",
    )
    assert main([str(FIXTURES / "unpinned.yml"), "--config", str(config)]) == 2
    with pytest.raises(ConfigError):
        load_config(config)


def test_missing_path_and_empty_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert main([str(tmp_path / "missing.yml")]) == 2
    assert "does not exist" in capsys.readouterr().err

    monkeypatch.chdir(tmp_path)
    assert main([]) == 2
    assert "does not exist" in capsys.readouterr().err

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    assert main([]) == 2
    assert "no workflows found" in capsys.readouterr().err


def test_output_cannot_escape(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    workflow = tmp_path / "ci.yml"
    workflow.write_text("on: push\npermissions:\n  contents: read\njobs: {}\n", encoding="utf-8")
    assert main([str(workflow), "--output", "../gha-audit.sarif", "--format", "sarif"]) == 2
    assert not (tmp_path.parent / "gha-audit.sarif").exists()
    captured = capsys.readouterr()
    assert "working directory" in captured.err


def test_multiple_paths_and_bad_yaml(tmp_path: Path) -> None:
    assert main([str(FIXTURES / "push-runner.yml"), str(FIXTURES / "base-checkout.yml"), "--fail-on", "info"]) == 0
    broken = tmp_path / "broken.yml"
    broken.write_text("on: [\n", encoding="utf-8")
    assert main([str(broken), "--fail-on", "low"]) == 2


def test_log_format_must_be_known(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHA_AUDIT_LOG_FORMAT", "xml")
    assert main([str(ROOT / "examples" / "secure.yml")]) == 2

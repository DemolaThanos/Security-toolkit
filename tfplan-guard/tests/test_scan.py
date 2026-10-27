import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from tfplan_guard.cli import main
from tfplan_guard.rules import RULES, SENSITIVE_PORTS
from tfplan_guard.scan import scan_path

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 20_000_000

EXPECTED = {
    "aws-cloudtrail-logging-disabled",
    "aws-cloudtrail-not-multi-region",
    "aws-ebs-unencrypted",
    "aws-ec2-imdsv2-optional",
    "aws-iam-wildcard-action",
    "aws-iam-wildcard-resource",
    "aws-kms-rotation-disabled",
    "aws-rds-public",
    "aws-rds-unencrypted",
    "aws-s3-public-access-block",
    "aws-s3-public-acl",
    "aws-s3-public-policy",
    "aws-s3-unencrypted",
    "aws-sg-world-all-ports",
    "aws-sg-world-sensitive-port",
}


def test_readme_lists_every_rule() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for rule in RULES:
        assert f"`{rule.id}`" in readme
        assert rule.remediation
        assert rule.description


def test_sensitive_ports_skip_http() -> None:
    assert 22 in SENSITIVE_PORTS
    assert 3389 in SENSITIVE_PORTS
    assert 443 not in SENSITIVE_PORTS
    assert 80 not in SENSITIVE_PORTS


def test_secure_example_is_clean() -> None:
    report = scan_path(ROOT / "examples" / "secure.plan.json", max_bytes=MAX_BYTES, suppressions=())
    assert report.errors == ()
    assert report.files_checked == 1
    assert report.findings == ()


def test_insecure_example_rules() -> None:
    path = ROOT / "examples" / "insecure.plan.json"
    report = scan_path(path, max_bytes=MAX_BYTES, suppressions=())
    assert report.errors == ()
    counts = Counter(item.rule_id for item in report.findings)
    assert set(counts) == EXPECTED
    assert counts["aws-s3-public-acl"] == 3
    assert counts["aws-s3-public-access-block"] == 1
    assert counts["aws-s3-public-policy"] == 1
    assert counts["aws-s3-unencrypted"] == 1
    assert counts["aws-ebs-unencrypted"] == 3
    assert counts["aws-ec2-imdsv2-optional"] == 2
    assert counts["aws-rds-public"] == 1
    assert counts["aws-rds-unencrypted"] == 2
    assert counts["aws-sg-world-sensitive-port"] == 4
    assert counts["aws-sg-world-all-ports"] == 1
    assert counts["aws-iam-wildcard-action"] == 2
    assert counts["aws-iam-wildcard-resource"] == 1
    assert sum(counts.values()) == 25
    by_address = {(item.address, item.rule_id): item for item in report.findings}
    assert by_address[("aws_s3_bucket.public", "aws-s3-public-acl")].severity.value == "critical"
    assert by_address[("aws_s3_bucket.auth", "aws-s3-public-acl")].severity.value == "high"
    assert by_address[("aws_iam_policy.admin", "aws-iam-wildcard-action")].severity.value == "critical"
    assert by_address[("aws_iam_role_policy.star", "aws-iam-wildcard-action")].severity.value == "high"
    assert by_address[("aws_kms_key.plain", "aws-kms-rotation-disabled")].severity.value == "medium"
    text = path.read_text(encoding="utf-8").splitlines()
    for finding in report.findings:
        assert finding.address in text[finding.line - 1]


def test_cli_text_json_and_sarif(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    plan = ROOT / "examples" / "insecure.plan.json"
    assert main(["check", str(plan), "--fail-on", "critical"]) == 1
    text = capsys.readouterr().out
    assert "aws-rds-public" in text
    assert "Set publicly_accessible to false" in text
    assert text.endswith("findings\n")

    assert main(["check", str(plan), "--format", "json", "--fail-on", "info"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_checked"] == 1
    assert payload["errors"] == []
    assert any(item["remediation"] and item["line"] >= 1 for item in payload["findings"])

    out = tmp_path / "tfplan-guard.sarif"
    assert main(["check", str(plan), "--format", "sarif", "--output", str(out), "--fail-on", "low"]) == 1
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {item["id"] for item in run["tool"]["driver"]["rules"]}
    assert rule_ids >= EXPECTED
    admin = next(item for item in run["results"] if item["message"]["text"].startswith("policy statement Admin"))
    assert admin["level"] == "error"
    assert admin["locations"][0]["logicalLocations"][0]["name"] == "aws_iam_policy.admin"
    assert admin["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert "partialFingerprints" in admin
    help_text = next(item["help"]["text"] for item in run["tool"]["driver"]["rules"] if item["id"] == "aws-rds-public")
    assert "publicly_accessible" in help_text


def test_threshold_and_version(tmp_path: Path) -> None:
    path = _write(tmp_path, _plan([_res("aws_kms_key.app", "aws_kms_key", {"enable_key_rotation": False})]))
    assert main(["check", str(path), "--fail-on", "high"]) == 0
    assert main(["check", str(path), "--fail-on", "medium"]) == 1
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0


def test_suppressions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(
        tmp_path,
        _plan(
            [
                _res(
                    "aws_ebs_volume.scratch",
                    "aws_ebs_volume",
                    {
                        "encrypted": False,
                        "tags": {
                            "tfplan-guard/ignore:aws-ebs-unencrypted": (
                                "Scratch volume is rebuilt every hour from a snapshot."
                            ),
                        },
                    },
                ),
                _res("aws_ebs_volume.kept", "aws_ebs_volume", {"encrypted": False}),
            ]
        ),
    )
    report = scan_path(path, max_bytes=MAX_BYTES, suppressions=())
    assert {item.address for item in report.findings} == {"aws_ebs_volume.kept"}

    sup = tmp_path / "suppress.toml"
    sup.write_text(
        """
[[suppress]]
rule = "aws-ebs-unencrypted"
address = "aws_ebs_volume.*"
justification = "Both volumes are ephemeral build cache and hold no data."
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup), "--fail-on", "low"]) == 0
    assert "no findings" in capsys.readouterr().out

    sup.write_text(
        """
[[suppress]]
rule = "aws-ebs-unencrypted"
address = "*"
justification = "todo"
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup)]) == 2
    assert "justification" in capsys.readouterr().err

    bare = _write(
        tmp_path,
        _plan(
            [
                _res(
                    "aws_ebs_volume.scratch",
                    "aws_ebs_volume",
                    {"encrypted": False, "tags": {"tfplan-guard/ignore:aws-ebs-unencrypted": "n/a"}},
                )
            ]
        ),
        name="bare.json",
    )
    assert main(["check", str(bare), "--fail-on", "low"]) == 2
    captured = capsys.readouterr()
    assert "placeholder" in captured.err
    assert "aws-ebs-unencrypted" in captured.out


def test_unknown_rule_and_missing_justification(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path, _plan([_res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": True})]))
    sup = tmp_path / "suppress.toml"
    sup.write_text(
        """
[[suppress]]
rule = "not-a-rule"
address = "*"
justification = "This rule id was renamed last quarter."
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup)]) == 2
    assert "unknown rule" in capsys.readouterr().err

    sup.write_text(
        """
[[suppress]]
rule = "aws-ebs-unencrypted"
address = "*"
justification = "short"
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup)]) == 2


def test_state_and_planned_values(tmp_path: Path) -> None:
    state = {
        "format_version": "1.0",
        "terraform_version": "1.9.8",
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_ebs_volume.plain",
                        "mode": "managed",
                        "type": "aws_ebs_volume",
                        "name": "plain",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"encrypted": False},
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.db",
                        "resources": [
                            {
                                "address": "module.db.aws_db_instance.app",
                                "mode": "managed",
                                "type": "aws_db_instance",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "engine": "postgres",
                                    "publicly_accessible": True,
                                    "storage_encrypted": True,
                                },
                            }
                        ],
                    }
                ],
            }
        },
    }
    report = scan_path(_write(tmp_path, state, name="state.json"), max_bytes=MAX_BYTES, suppressions=())
    assert {(item.address, item.rule_id) for item in report.findings} == {
        ("aws_ebs_volume.plain", "aws-ebs-unencrypted"),
        ("module.db.aws_db_instance.app", "aws-rds-public"),
    }

    planned = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_ebs_volume.plain",
                        "mode": "managed",
                        "type": "aws_ebs_volume",
                        "name": "plain",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": {"encrypted": False},
                    }
                ]
            }
        },
    }
    report = scan_path(_write(tmp_path, planned, name="planned.json"), max_bytes=MAX_BYTES, suppressions=())
    assert [item.rule_id for item in report.findings] == ["aws-ebs-unencrypted"]

    both = {
        "format_version": "1.2",
        "resource_changes": [_res("aws_ebs_volume.kept", "aws_ebs_volume", {"encrypted": True})],
        "planned_values": planned["planned_values"],
        "prior_state": {"values": state["values"]},
    }
    report = scan_path(_write(tmp_path, both, name="both.json"), max_bytes=MAX_BYTES, suppressions=())
    assert report.findings == ()


def test_unknown_delete_and_non_aws(tmp_path: Path) -> None:
    resources = [
        _res(
            "aws_ebs_volume.pending",
            "aws_ebs_volume",
            {"encrypted": None},
            unknown={"encrypted": True},
        ),
        _res("aws_ebs_volume.gone", "aws_ebs_volume", None, actions=["delete"]),
        _res("aws_s3_bucket.public", "aws_s3_bucket", {"acl": "public-read", "bucket": "x"}, mode="data"),
        _res(
            "aws_s3_bucket.other",
            "aws_s3_bucket",
            {"acl": "public-read", "bucket": "y"},
            provider="registry.terraform.io/hashicorp/awscc",
        ),
        _res("awscc_s3_bucket.other", "awscc_s3_bucket", {"acl": "public-read"}),
        _res(
            "aws_db_instance.pending",
            "aws_db_instance",
            {"engine": "mysql", "storage_encrypted": None, "publicly_accessible": None},
            unknown={"storage_encrypted": True, "publicly_accessible": True},
        ),
    ]
    # delete leaves after null; the helper above passes None as after via actions handling in _res
    report = scan_path(_write(tmp_path, _plan(resources)), max_bytes=MAX_BYTES, suppressions=())
    assert report.findings == ()


def test_rule_edges(tmp_path: Path) -> None:
    resources = [
        _res("aws_s3_bucket.inline", "aws_s3_bucket", _inline_bucket()),
        _pab("inline", "inline-bucket"),
        _res("aws_s3_bucket.weak", "aws_s3_bucket", {"bucket": "weak-bucket", "id": "weak-bucket", "acl": "private"}),
        _res(
            "aws_s3_bucket_public_access_block.weak",
            "aws_s3_bucket_public_access_block",
            {
                "bucket": "weak-bucket",
                "block_public_acls": True,
                "block_public_policy": False,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
        ),
        _res(
            "aws_s3_bucket_acl.auth",
            "aws_s3_bucket_acl",
            {
                "bucket": "weak-bucket",
                "access_control_policy": [
                    {
                        "grant": [
                            {
                                "grantee": [
                                    {
                                        "type": "Group",
                                        "uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                                    }
                                ],
                                "permission": "READ",
                            }
                        ]
                    }
                ],
            },
        ),
        _res(
            "aws_s3_bucket_policy.aws_star",
            "aws_s3_bucket_policy",
            {
                "bucket": "weak-bucket",
                "policy": _policy(
                    [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": ["*"]},
                            "Action": "s3:GetObject",
                            "Resource": "*",
                        }
                    ]
                ),
            },
        ),
        _res(
            "aws_iam_role.app",
            "aws_iam_role",
            {
                "inline_policy": [
                    {
                        "name": "not",
                        "policy": _policy([{"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}]),
                    },
                    {
                        "name": "ok",
                        "policy": _policy(
                            [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::weak-bucket/*",
                                }
                            ]
                        ),
                    },
                ]
            },
        ),
        _res(
            "aws_iam_group_policy.not",
            "aws_iam_group_policy",
            {
                "policy": _policy(
                    [
                        {
                            "Effect": "Allow",
                            "NotAction": "iam:CreateUser",
                            "Resource": "arn:aws:iam::123:user/*",
                        }
                    ]
                )
            },
        ),
        _res(
            "aws_security_group.range",
            "aws_security_group",
            {
                "ingress": [
                    {"protocol": "tcp", "from_port": 20, "to_port": 22, "cidr_blocks": ["0.0.0.0/0", "::/0"]},
                    {"protocol": "tcp", "from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]},
                    {"protocol": "udp", "from_port": 53, "to_port": 53, "cidr_blocks": ["0.0.0.0/0"]},
                    {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]},
                ]
            },
        ),
        _res(
            "aws_launch_configuration.old",
            "aws_launch_configuration",
            {"root_block_device": {"encrypted": "false"}, "metadata_options": {"http_tokens": "Required"}},
        ),
        _res(
            "aws_kms_key.external",
            "aws_kms_key",
            {"enable_key_rotation": False, "origin": "EXTERNAL", "customer_master_key_spec": "SYMMETRIC_DEFAULT"},
        ),
        _res(
            "aws_kms_key.hmac",
            "aws_kms_key",
            {"enable_key_rotation": False, "origin": "AWS_KMS", "customer_master_key_spec": "HMAC_256"},
        ),
        _res(
            "aws_kms_key.computed",
            "aws_kms_key",
            {"enable_key_rotation": False, "origin": "AWS_KMS", "customer_master_key_spec": None},
            unknown={"customer_master_key_spec": True},
        ),
        _res("aws_kms_key.default", "aws_kms_key", {"description": "default"}),
        _res(
            "aws_cloudtrail.home",
            "aws_cloudtrail",
            {"name": "home", "s3_bucket_name": "trails"},
        ),
        _res("aws_instance.skipped", "aws_instance", {"metadata_options": None}, unknown={"metadata_options": True}),
    ]
    report = scan_path(_write(tmp_path, _plan(resources)), max_bytes=MAX_BYTES, suppressions=())
    found = {(item.address, item.rule_id, item.severity.value) for item in report.findings}
    assert ("aws_s3_bucket.inline", "aws-s3-unencrypted", "high") not in found
    assert ("aws_s3_bucket.inline", "aws-s3-public-access-block", "high") not in found
    assert ("aws_s3_bucket.weak", "aws-s3-public-access-block", "high") in found
    weak = [item for item in report.findings if item.address == "aws_s3_bucket.weak"]
    assert any("block_public_policy" in item.message for item in weak)
    assert ("aws_s3_bucket_acl.auth", "aws-s3-public-acl", "high") in found
    assert ("aws_s3_bucket_policy.aws_star", "aws-s3-public-policy", "critical") in found
    assert ("aws_iam_role.app", "aws-iam-wildcard-action", "critical") in found
    assert ("aws_iam_group_policy.not", "aws-iam-wildcard-action", "high") in found
    assert ("aws_security_group.range", "aws-sg-world-sensitive-port", "high") in found
    assert ("aws_security_group.range", "aws-sg-world-all-ports", "critical") in found
    range_findings = [item for item in report.findings if item.address == "aws_security_group.range"]
    assert len(range_findings) == 2
    assert any("0.0.0.0/0, ::/0" in item.message for item in range_findings)
    assert ("aws_launch_configuration.old", "aws-ebs-unencrypted", "high") in found
    assert ("aws_launch_configuration.old", "aws-ec2-imdsv2-optional", "high") not in found
    assert not any(item.address.startswith("aws_kms_key.external") for item in report.findings)
    assert not any(item.address == "aws_kms_key.hmac" for item in report.findings)
    assert not any(item.address == "aws_kms_key.computed" for item in report.findings)
    assert ("aws_kms_key.default", "aws-kms-rotation-disabled", "medium") in found
    assert ("aws_cloudtrail.home", "aws-cloudtrail-not-multi-region", "high") in found
    assert ("aws_cloudtrail.home", "aws-cloudtrail-logging-disabled", "high") not in found
    assert not any(item.address == "aws_instance.skipped" for item in report.findings)
    inline = [item for item in report.findings if item.address == "aws_s3_bucket.inline"]
    assert inline == []


def test_inline_encryption_and_access_block_are_quiet(tmp_path: Path) -> None:
    report = scan_path(
        _write(
            tmp_path,
            _plan(
                [
                    _res("aws_s3_bucket.inline", "aws_s3_bucket", _inline_bucket()),
                    _pab("inline", "inline-bucket"),
                ]
            ),
        ),
        max_bytes=MAX_BYTES,
        suppressions=(),
    )
    assert report.findings == ()


def test_directory_skips_other_json_and_rejects_broken_json(tmp_path: Path) -> None:
    root = tmp_path / "plans"
    root.mkdir()
    _write(root, _plan([_res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": False})]), name="plan.json")
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    report = scan_path(root, max_bytes=MAX_BYTES, suppressions=())
    assert report.files_checked == 1
    assert report.errors == ()
    assert len(report.findings) == 1

    (root / "broken.json").write_text("{", encoding="utf-8")
    assert main(["check", str(root)]) == 2
    assert main(["check", str(root / "package.json")]) == 2
    assert main(["check", str(tmp_path / "missing.json")]) == 2


def test_symlink_and_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(_plan([_res("aws_ebs_volume.escaped", "aws_ebs_volume", {"encrypted": False})])),
        encoding="utf-8",
    )
    root = tmp_path / "inside"
    root.mkdir()
    (root / "escape.json").symlink_to(outside)
    report = scan_path(root, max_bytes=MAX_BYTES, suppressions=())
    assert report.findings == ()
    assert report.files_checked == 0

    import tfplan_guard.load as load_mod

    monkeypatch.setattr(load_mod, "MAX_FILES", 1)
    _write(root, _plan([]), name="a.json")
    _write(root, _plan([]), name="b.json")
    report = scan_path(root, max_bytes=MAX_BYTES, suppressions=())
    assert report.errors
    assert "more than" in report.errors[0]


def test_counted_address_suppression_is_literal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(
        tmp_path,
        _plan(
            [
                _res(
                    'aws_ebs_volume.data["*"]',
                    "aws_ebs_volume",
                    {
                        "encrypted": False,
                        "tags": {
                            "tfplan-guard/ignore:aws-ebs-unencrypted": ("Ephemeral cache volume rebuilt every hour.")
                        },
                    },
                ),
                _res(
                    "aws_ebs_volume.data[0]",
                    "aws_ebs_volume",
                    {
                        "encrypted": False,
                        "tags": {
                            "tfplan-guard/ignore:aws-ebs-unencrypted": (
                                "Scratch disk for the image build and nothing else."
                            )
                        },
                    },
                ),
                _res("aws_ebs_volume.data0", "aws_ebs_volume", {"encrypted": False}),
                _res("aws_ebs_volume.other", "aws_ebs_volume", {"encrypted": False}),
            ]
        ),
    )
    report = scan_path(path, max_bytes=MAX_BYTES, suppressions=())
    assert report.errors == ()
    assert {item.address for item in report.findings} == {"aws_ebs_volume.data0", "aws_ebs_volume.other"}

    sup = tmp_path / "suppress.toml"
    sup.write_text(
        """
[[suppress]]
rule = "aws-ebs-unencrypted"
address = "aws_ebs_volume.data[0]"
justification = "This index is the scratch disk and holds no data."
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup), "--fail-on", "low"]) == 1
    text = capsys.readouterr().out
    assert "aws_ebs_volume.data[0]" not in text
    assert "aws_ebs_volume.data0" in text

    sup.write_text(
        f"""
[[suppress]]
rule = "*"
address = "{"a" * 1200}"
justification = "This address is far longer than a real resource."
""",
        encoding="utf-8",
    )
    assert main(["check", str(path), "--suppressions", str(sup)]) == 2
    assert "too long" in capsys.readouterr().err


def test_relative_path_cannot_leave_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _write(work, _plan([_res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": False})]))
    assert main(["check", "plan.json", "--format", "sarif", "--output", "out.sarif", "--fail-on", "low"]) == 1
    sarif = json.loads((work / "out.sarif").read_text(encoding="utf-8"))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "plan.json"
    assert main(["check", "./plan.json", "--fail-on", "low"]) == 1
    capsys.readouterr()

    outside = tmp_path / "outside.json"
    outside.write_text((work / "plan.json").read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["check", "../outside.json"]) == 2
    assert "working directory" in capsys.readouterr().err
    assert main(["check", "./../outside.json"]) == 2
    link = work / "linked.json"
    link.symlink_to(outside)
    assert main(["check", "linked.json"]) == 2
    assert main(["check", "plan.json", "--output", "../out.sarif", "--format", "sarif"]) == 2
    assert not (tmp_path / "out.sarif").exists()
    assert main(["check", "plan.json", "--suppressions", "../suppress.toml"]) == 2
    assert main(["check", "plan.json\x00"]) == 2


def test_cluster_instance_string_ports_and_bad_policy(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _plan(
            [
                _res("aws_rds_cluster_instance.pub", "aws_rds_cluster_instance", {"publicly_accessible": True}),
                _res(
                    "aws_security_group.strings",
                    "aws_security_group",
                    {
                        "ingress": [
                            {"protocol": "tcp", "from_port": "22", "to_port": "22", "cidr_blocks": ["0.0.0.0/0"]}
                        ]
                    },
                ),
                _res("aws_iam_policy.bad", "aws_iam_policy", {"policy": "{not json"}),
                _res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": False}),
            ]
        ),
    )
    report = scan_path(path, max_bytes=MAX_BYTES, suppressions=())
    found = {(item.address, item.rule_id) for item in report.findings}
    assert ("aws_rds_cluster_instance.pub", "aws-rds-public") in found
    assert ("aws_rds_cluster_instance.pub", "aws-rds-unencrypted") not in found
    assert ("aws_security_group.strings", "aws-sg-world-sensitive-port") in found
    assert ("aws_ebs_volume.plain", "aws-ebs-unencrypted") in found
    assert any("not valid JSON" in error for error in report.errors)
    assert main(["check", str(path), "--fail-on", "low"]) == 2


def test_unknown_bucket_name_is_not_joined(tmp_path: Path) -> None:
    pending = _res(
        "aws_s3_bucket.pending",
        "aws_s3_bucket",
        {"bucket": None, "id": None},
        unknown={"bucket": True, "id": True},
    )
    report = scan_path(_write(tmp_path, _plan([pending])), max_bytes=MAX_BYTES, suppressions=())
    ids = {item.rule_id for item in report.findings}
    assert "aws-s3-public-access-block" not in ids
    assert "aws-s3-unencrypted" in ids

    linked = _res(
        "aws_s3_bucket_server_side_encryption_configuration.pending",
        "aws_s3_bucket_server_side_encryption_configuration",
        {
            "bucket": None,
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
        },
        unknown={"bucket": True},
    )
    report = scan_path(
        _write(tmp_path, _plan([pending, linked]), name="linked.json"),
        max_bytes=MAX_BYTES,
        suppressions=(),
    )
    assert "aws-s3-unencrypted" not in {item.rule_id for item in report.findings}


def test_nested_documents_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    nested = '{"a":' * 2000 + "null" + "}" * 2000
    path = tmp_path / "deep.json"
    path.write_text(nested, encoding="utf-8")
    report = scan_path(path, max_bytes=MAX_BYTES, suppressions=())
    assert report.findings == ()
    assert any("nested" in error for error in report.errors)

    module: dict[str, Any] = {"resources": []}
    for _ in range(60):
        module = {"resources": [], "child_modules": [module]}
    state = {"format_version": "1.0", "values": {"root_module": module}}
    report = scan_path(_write(tmp_path, state, name="state.json"), max_bytes=MAX_BYTES, suppressions=())
    assert any("nesting" in error for error in report.errors)

    import tfplan_guard.suppress as suppress_mod

    monkeypatch.setattr(suppress_mod, "MAX_SUPPRESSION_BYTES", 32)
    sup = tmp_path / "suppress.toml"
    sup.write_bytes(b"x" * 200)
    plain = _write(
        tmp_path,
        _plan([_res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": True})]),
        name="plain.json",
    )
    assert main(["check", str(plain), "--suppressions", str(sup)]) == 2
    assert "larger than" in capsys.readouterr().err


def test_bad_log_format_and_max_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write(tmp_path, _plan([]))
    monkeypatch.setenv("TFPLAN_GUARD_LOG_FORMAT", "xml")
    assert main(["check", str(path)]) == 2
    monkeypatch.setenv("TFPLAN_GUARD_LOG_FORMAT", "json")
    assert main(["check", str(path), "--max-bytes", "0"]) == 2
    tiny = tmp_path / "tiny.json"
    tiny.write_text(
        json.dumps(_plan([_res("aws_ebs_volume.plain", "aws_ebs_volume", {"encrypted": False})])),
        encoding="utf-8",
    )
    assert main(["check", str(tiny), "--max-bytes", "10", "--fail-on", "low"]) == 2


def _pab(name: str, bucket: str) -> dict[str, Any]:
    return _res(
        f"aws_s3_bucket_public_access_block.{name}",
        "aws_s3_bucket_public_access_block",
        {
            "bucket": bucket,
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        },
    )


def _inline_bucket() -> dict[str, Any]:
    return {
        "bucket": "inline-bucket",
        "id": "inline-bucket",
        "server_side_encryption_configuration": [
            {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]}
        ],
    }


def _policy(statements: list[dict[str, Any]]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _plan(resources: list[dict[str, Any]]) -> dict[str, Any]:
    return {"format_version": "1.2", "terraform_version": "1.9.8", "resource_changes": resources}


def _res(
    address: str,
    type_name: str,
    after: dict[str, Any] | None,
    *,
    unknown: dict[str, Any] | None = None,
    actions: list[str] | None = None,
    mode: str = "managed",
    provider: str = "registry.terraform.io/hashicorp/aws",
) -> dict[str, Any]:
    return {
        "address": address,
        "mode": mode,
        "type": type_name,
        "name": address.rsplit(".", 1)[-1],
        "provider_name": provider,
        "change": {
            "actions": actions or ["create"],
            "before": None,
            "after": after,
            "after_unknown": unknown or {},
        },
    }


def _write(directory: Path, document: dict[str, Any], name: str = "plan.json") -> Path:
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path

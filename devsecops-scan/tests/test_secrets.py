from pathlib import Path

from devsecops_scan.secrets import scan_secrets

_SKIP = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "node_modules"}


def test_high_confidence_tokens_are_redacted_in_the_message() -> None:
    access_key = "AKIA" + "TESTKEY000000001"
    private_key = "-----BEGIN " + "PRIVATE KEY-----"
    documented = "wJalrXUtnFEMI" + "/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"
    live_secret = "ab" * 20
    password = "not-a" + "-real-password"
    text = "\n".join(
        [
            f'key = "{access_key}"',
            private_key,
            f'aws_secret_access_key = "{documented}"',
            f'aws_secret_access_key = "{live_secret}"',
            f'password = "{password}"',
            'password = "${NOT_A_REAL_VALUE}"',
            f'token = "{access_key}"  # devsecops-scan: ignore',
        ]
    )
    findings = scan_secrets(text, "app.py")
    ids = [item.rule_id for item in findings]
    assert ids == [
        "aws-access-key-id",
        "private-key",
        "aws-secret-access-key",
        "password-assignment",
    ]
    assert all(access_key not in item.message for item in findings)
    assert all(live_secret not in item.message for item in findings)
    assert all(password not in item.message for item in findings)


def test_gitlab_and_npm_tokens() -> None:
    gitlab = "glpat-" + ("a" * 20)
    text = "\n".join(
        [
            f"gitlab = '{gitlab}'",
            "npm = 'npm_" + ("a" * 36) + "'",
        ]
    )
    ids = {item.rule_id for item in scan_secrets(text, "ci.yml")}
    assert ids == {"gitlab-pat", "npm-token"}
    assert all(gitlab not in item.message for item in scan_secrets(text, "ci.yml"))


def test_documented_example_key_is_ignored() -> None:
    example = "AKIA" + "IOSFODNN7EXAMPLE"
    findings = scan_secrets(f'key = "{example}"\n', "app.py")
    assert findings == []


def test_committed_files_omit_contiguous_documentation_examples() -> None:
    banned = (
        "AKIA" + "IOSFODNN7EXAMPLE",
        "ASIA" + "IOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI" + "/K7MDENG" + "/bPxRfiCYEXAMPLEKEY",
    )
    root = Path(__file__).resolve().parents[2]
    offenders: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or _SKIP.intersection(path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for value in banned:
            if value in text:
                offenders.append(str(path.relative_to(root)))
                break
    assert offenders == []

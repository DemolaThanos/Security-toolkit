from devsecops_scan.secrets import scan_secrets


def test_high_confidence_tokens_are_redacted_in_the_message() -> None:
    text = "\n".join(
        [
            'key = "AKIATESTKEY000000001"',
            "-----BEGIN PRIVATE KEY-----",
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            'aws_secret_access_key = "abcdEFGHijklMNOPqrstUVWXyz0123456789abcd"',
            'password = "correct-horse"',
            'password = "${NOT_A_REAL_VALUE}"',
            'token = "AKIATESTKEY000000001"  # devsecops-scan: ignore',
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
    assert all("AKIATESTKEY000000001" not in item.message for item in findings)
    assert all("abcdEFGH" not in item.message for item in findings)


def test_documented_example_key_is_ignored() -> None:
    findings = scan_secrets('key = "AKIAIOSFODNN7EXAMPLE"\n', "app.py")
    assert findings == []

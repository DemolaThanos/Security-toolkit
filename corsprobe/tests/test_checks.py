from __future__ import annotations

from corsprobe.checks import RULES, classify
from corsprobe.models import Exchange, Severity, with_credentials
from corsprobe.origins import ARBITRARY_ORIGIN, CANARY_HEADER


def _exchange(
    case_id: str,
    origin: str,
    allow_origin: str | None,
    *,
    credentials: str | None = None,
    extra: tuple[tuple[str, str], ...] = (),
    host: str = "example.com",
    status: int = 200,
) -> Exchange:
    headers: list[tuple[str, str]] = []
    if allow_origin is not None:
        headers.append(("Access-Control-Allow-Origin", allow_origin))
    if credentials is not None:
        headers.append(("Access-Control-Allow-Credentials", credentials))
    headers.extend(extra)
    method = "OPTIONS" if case_id == "preflight" else "GET"
    return Exchange(case_id, origin, host, method, status, tuple(headers), "https://app.example/api")


def _ids(findings: object) -> dict[str, str]:
    assert isinstance(findings, tuple)
    return {item.rule_id: item.severity.value for item in findings}


def test_reflected_origin_and_credentials() -> None:
    plain = classify("https://app.example/api", (_exchange("origin-reflection", ARBITRARY_ORIGIN, ARBITRARY_ORIGIN),))
    assert _ids(plain) == {"origin-reflection": "high"}
    assert plain[0].credentials is False
    assert ARBITRARY_ORIGIN in plain[0].message

    creds = classify(
        "https://app.example/api",
        (_exchange("origin-reflection", ARBITRARY_ORIGIN, ARBITRARY_ORIGIN, credentials="true"),),
    )
    assert creds[0].severity is Severity.CRITICAL
    assert creds[0].credentials is True
    assert "allows credentials" in creds[0].message


def test_credentials_header_must_be_the_lowercase_token() -> None:
    findings = classify(
        "https://app.example/api",
        (_exchange("origin-reflection", ARBITRARY_ORIGIN, ARBITRARY_ORIGIN, credentials="True"),),
    )
    assert findings[0].severity is Severity.HIGH
    assert findings[0].credentials is False


def test_duplicate_allow_origin_is_not_a_match() -> None:
    item = _exchange("origin-reflection", ARBITRARY_ORIGIN, ARBITRARY_ORIGIN)
    doubled = Exchange(
        item.case_id,
        item.origin,
        item.host,
        item.method,
        item.status,
        (*item.headers, ("Access-Control-Allow-Origin", ARBITRARY_ORIGIN)),
        item.final_url,
    )
    assert classify("https://app.example/api", (doubled,)) == ()


def test_each_specific_bypass() -> None:
    cases = (
        ("null-origin", "null", "null", "example.com", "high"),
        (
            "prefix-bypass",
            "https://example.com.corsprobe.invalid",
            "https://example.com.corsprobe.invalid",
            "example.com",
            "high",
        ),
        ("suffix-bypass", "https://notexample.com", "https://notexample.com", "example.com", "high"),
        ("unescaped-dot", "https://examplexcom", "https://examplexcom", "example.com", "high"),
        ("any-subdomain", "https://corsprobe.example.com", "https://corsprobe.example.com", "example.com", "medium"),
        ("http-origin", "http://app.example", "http://app.example", "", "medium"),
    )
    for case_id, origin, echoed, host, severity in cases:
        found = classify("https://app.example/api", (_exchange(case_id, origin, echoed, host=host),))
        assert _ids(found) == {case_id: severity}
        assert found[0].origin == origin


def test_credentials_raise_a_medium_finding() -> None:
    found = classify(
        "https://app.example/api",
        (
            _exchange(
                "any-subdomain",
                "https://corsprobe.example.com",
                "https://corsprobe.example.com",
                credentials="true",
                host="example.com",
            ),
        ),
    )
    assert found[0].rule_id == "any-subdomain"
    assert found[0].severity is Severity.HIGH


def test_wildcard_is_not_reflection() -> None:
    found = classify("https://app.example/api", (_exchange("origin-reflection", ARBITRARY_ORIGIN, "*"),))
    assert _ids(found) == {"wildcard": "low"}
    assert "browsers ignore" not in found[0].message

    creds = classify(
        "https://app.example/api",
        (_exchange("origin-reflection", ARBITRARY_ORIGIN, "*", credentials="true"),),
    )
    assert creds[0].rule_id == "wildcard-credentials"
    assert creds[0].severity is Severity.MEDIUM
    assert "browsers ignore" in creds[0].message


def test_arbitrary_reflection_hides_narrower_probes() -> None:
    exchanges = (
        _exchange("origin-reflection", ARBITRARY_ORIGIN, ARBITRARY_ORIGIN),
        _exchange("null-origin", "null", "null"),
        _exchange("prefix-bypass", "https://example.com.corsprobe.invalid", "https://example.com.corsprobe.invalid"),
    )
    assert _ids(classify("https://app.example/api", exchanges)) == {"origin-reflection": "high"}


def test_wildcard_hides_narrower_probes() -> None:
    exchanges = (
        _exchange("origin-reflection", ARBITRARY_ORIGIN, "https://app.example"),
        _exchange("prefix-bypass", "https://example.com.corsprobe.invalid", "*"),
    )
    assert _ids(classify("https://app.example/api", exchanges)) == {"wildcard": "low"}


def test_preflight_methods_and_headers() -> None:
    item = _exchange(
        "preflight",
        ARBITRARY_ORIGIN,
        ARBITRARY_ORIGIN,
        extra=(
            ("Access-Control-Allow-Methods", "GET, DELETE, PATCH"),
            ("Access-Control-Allow-Headers", f"Content-Type, {CANARY_HEADER}, Authorization"),
        ),
    )
    found = classify("https://app.example/api", (item,))
    assert _ids(found) == {"origin-reflection": "high", "preflight-methods": "low", "preflight-headers": "low"}
    methods = next(item for item in found if item.rule_id == "preflight-methods")
    headers = next(item for item in found if item.rule_id == "preflight-headers")
    assert "DELETE" in methods.message
    assert "PATCH" in methods.message
    assert CANARY_HEADER in headers.message
    assert "authorization" in headers.message


def test_preflight_star_and_credentials() -> None:
    item = _exchange(
        "preflight",
        ARBITRARY_ORIGIN,
        "*",
        credentials="true",
        extra=(
            ("Access-Control-Allow-Methods", "*"),
            ("Access-Control-Allow-Headers", "*"),
        ),
    )
    found = classify("https://app.example/api", (item,))
    assert _ids(found)["wildcard-credentials"] == "medium"
    assert _ids(found)["preflight-methods"] == "medium"
    assert "preflight allows *" in next(item.message for item in found if item.rule_id == "preflight-methods")


def test_closed_preflight_is_quiet() -> None:
    item = _exchange(
        "preflight",
        ARBITRARY_ORIGIN,
        "https://app.example",
        extra=(
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
        ),
    )
    assert classify("https://app.example/api", (item,)) == ()


def test_non_200_responses_still_count() -> None:
    found = classify(
        "https://app.example/api",
        (_exchange("null-origin", "null", "null", status=204),),
    )
    assert found[0].rule_id == "null-origin"


def test_credentials_do_not_climb_past_critical() -> None:
    assert with_credentials(Severity.CRITICAL, True) is Severity.CRITICAL
    assert with_credentials(Severity.LOW, False) is Severity.LOW


def test_every_rule_id_is_in_the_catalog() -> None:
    assert {rule.id for rule in RULES} == set(_BASE_IDS())
    for rule in RULES:
        assert rule.description
        assert rule.remediation


def _BASE_IDS() -> set[str]:
    return {
        "origin-reflection",
        "null-origin",
        "prefix-bypass",
        "suffix-bypass",
        "unescaped-dot",
        "any-subdomain",
        "http-origin",
        "wildcard",
        "wildcard-credentials",
        "preflight-methods",
        "preflight-headers",
    }

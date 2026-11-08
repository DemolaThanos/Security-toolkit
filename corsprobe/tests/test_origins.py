from __future__ import annotations

import pytest

from corsprobe.errors import InputError
from corsprobe.net import parse_target, parse_trusted
from corsprobe.origins import ARBITRARY_ORIGIN, build_cases


def _origins(url: str, trusted: str | None = None, *, preflight: bool = True) -> list[tuple[str, str]]:
    cases = build_cases(parse_target(url), None if trusted is None else parse_trusted(trusted), preflight=preflight)
    return [(item.case_id, item.origin) for item in cases]


def test_trusted_domain_adds_bypass_origins() -> None:
    found = _origins("https://app.example.com/api", "example.com")
    assert found[0] == ("origin-reflection", ARBITRARY_ORIGIN)
    assert ("null-origin", "null") in found
    assert ("http-origin", "http://app.example.com") in found
    assert ("prefix-bypass", "https://app.example.com.corsprobe.invalid") in found
    assert ("prefix-bypass", "https://example.com.corsprobe.invalid") in found
    assert ("suffix-bypass", "https://notapp.example.com") in found
    assert ("suffix-bypass", "https://notexample.com") in found
    assert ("unescaped-dot", "https://appxexample.com") in found
    assert ("unescaped-dot", "https://examplexcom") in found
    assert ("any-subdomain", "https://corsprobe.app.example.com") in found
    assert ("any-subdomain", "https://corsprobe.example.com") in found
    assert found[-1][0] == "preflight"
    assert len(found) == 12


def test_same_trusted_host_is_not_duplicated() -> None:
    found = _origins("https://example.com/api", "https://example.com", preflight=False)
    assert len(found) == 7
    assert [item[0] for item in found].count("prefix-bypass") == 1


def test_http_target_skips_the_downgrade_probe() -> None:
    found = _origins("http://app.example/api", preflight=False)
    assert "http-origin" not in {item[0] for item in found}


def test_ip_target_skips_name_bypasses() -> None:
    found = _origins("https://1.1.1.1/health")
    assert [item[0] for item in found] == ["origin-reflection", "null-origin", "http-origin", "preflight"]
    assert ("http-origin", "http://1.1.1.1") in found


def test_custom_port_is_kept_on_same_site_origins_only() -> None:
    found = dict(_origins("https://app.example.com:8443/api", preflight=False))
    assert found["http-origin"] == "http://app.example.com:8443"
    assert found["any-subdomain"] == "https://corsprobe.app.example.com:8443"
    assert found["prefix-bypass"] == "https://app.example.com.corsprobe.invalid"
    assert ":8443" not in found["prefix-bypass"]


def test_first_dot_is_the_stand_in() -> None:
    found = _origins("https://a.b.example/api", preflight=False)
    assert ("unescaped-dot", "https://axb.example") in found


def test_trusted_must_be_a_hostname() -> None:
    assert parse_trusted("Example.COM.") == "example.com"
    with pytest.raises(InputError, match="wildcard"):
        parse_trusted("*.example.com")
    with pytest.raises(InputError, match="hostname"):
        parse_trusted("https://1.1.1.1")
    with pytest.raises(InputError, match="hostname"):
        parse_trusted("https://example.com/app")

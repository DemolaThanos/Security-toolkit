from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from corsprobe.errors import InputError, ProbeFailure
from corsprobe.http_client import USER_AGENT, Call, perform
from corsprobe.net import Scope, guard_addresses, parse_target
from corsprobe.probe import scan


class _Script:
    def __init__(self, responses: list[tuple[int, tuple[tuple[str, str], ...]]]) -> None:
        self.responses = list(responses)
        self.calls: list[Call] = []

    def __call__(self, call: Call) -> tuple[int, tuple[tuple[str, str], ...]]:
        self.calls.append(call)
        return self.responses.pop(0)


def _lookup(table: dict[str, tuple[str, ...]]) -> tuple[list[str], object]:
    seen: list[str] = []

    def lookup(host: str) -> tuple[str, ...]:
        seen.append(host)
        return table[host]

    return seen, lookup


def test_get_sends_origin_and_no_body() -> None:
    script = _Script([(200, (("Access-Control-Allow-Origin", "https://corsprobe.invalid"),))])
    status, headers, final = perform(
        "https://app.example/api?x=1",
        method="GET",
        origin="https://corsprobe.invalid",
        timeout=1.5,
        follow_off_host=False,
        transport=script,
        lookup=lambda host: ("93.184.216.34",),
    )
    assert status == 200
    assert headers[0][0] == "Access-Control-Allow-Origin"
    assert final == "https://app.example/api?x=1"
    call = script.calls[0]
    assert call.method == "GET"
    assert call.path == "/api?x=1"
    assert call.timeout == 1.5
    assert call.addresses == ("93.184.216.34",)
    sent = dict(call.headers)
    assert sent["Origin"] == "https://corsprobe.invalid"
    assert sent["User-Agent"] == USER_AGENT
    assert sent["Cache-Control"] == "no-cache"
    assert "Content-Length" not in sent
    assert "Authorization" not in sent
    assert "Cookie" not in sent


def test_methods_and_headers_are_limited() -> None:
    script = _Script([])
    with pytest.raises(ProbeFailure, match="method"):
        perform(
            "https://app.example/",
            method="POST",
            origin="https://corsprobe.invalid",
            timeout=1,
            follow_off_host=False,
            transport=script,
            lookup=lambda host: ("93.184.216.34",),
        )
    with pytest.raises(ProbeFailure, match="header"):
        perform(
            "https://app.example/",
            method="GET",
            origin="https://corsprobe.invalid",
            timeout=1,
            follow_off_host=False,
            extra_headers=(("Authorization", "Bearer secret"),),
            transport=script,
            lookup=lambda host: ("93.184.216.34",),
        )
    with pytest.raises(ProbeFailure, match="origin"):
        perform(
            "https://app.example/",
            method="GET",
            origin="https://evil.example\r\nX-Injected: 1",
            timeout=1,
            follow_off_host=False,
            transport=script,
            lookup=lambda host: ("93.184.216.34",),
        )
    assert script.calls == []


def test_off_host_redirect_is_not_followed() -> None:
    script = _Script([(302, (("Location", "http://169.254.169.254/latest/meta-data/"),))])
    seen, lookup = _lookup({"app.example": ("93.184.216.34",)})
    status, _, final = perform(
        "https://app.example/api",
        method="GET",
        origin="null",
        timeout=1,
        follow_off_host=False,
        transport=script,
        lookup=lookup,
    )
    assert status == 302
    assert final == "https://app.example/api"
    assert [call.host for call in script.calls] == ["app.example"]
    assert seen == ["app.example"]


def test_same_host_redirect_is_followed() -> None:
    script = _Script(
        [
            (302, (("Location", "/next"),)),
            (200, (("Access-Control-Allow-Origin", "https://corsprobe.invalid"),)),
        ]
    )
    status, _, final = perform(
        "https://app.example/api",
        method="GET",
        origin="https://corsprobe.invalid",
        timeout=1,
        follow_off_host=False,
        transport=script,
        lookup=lambda host: ("93.184.216.34",),
    )
    assert status == 200
    assert final == "https://app.example/next"
    assert [call.path for call in script.calls] == ["/api", "/next"]
    assert {call.host for call in script.calls} == {"app.example"}


def test_public_to_private_redirect_is_refused() -> None:
    script = _Script([(302, (("Location", "https://intra.example/secret"),))])
    seen, lookup = _lookup({"app.example": ("93.184.216.34",), "intra.example": ("10.1.1.1",)})
    with pytest.raises(ProbeFailure, match="private"):
        perform(
            "https://app.example/",
            method="GET",
            origin="https://corsprobe.invalid",
            timeout=1,
            follow_off_host=True,
            transport=script,
            lookup=lookup,
        )
    assert [call.host for call in script.calls] == ["app.example"]
    assert seen == ["app.example", "intra.example"]


def test_follow_off_host_reaches_another_public_host() -> None:
    script = _Script(
        [
            (302, (("Location", "https://cdn.example/app"),)),
            (204, ()),
        ]
    )
    status, _, final = perform(
        "https://app.example/",
        method="OPTIONS",
        origin="https://corsprobe.invalid",
        timeout=1,
        follow_off_host=True,
        transport=script,
        lookup=lambda host: ("93.184.216.34",),
    )
    assert status == 204
    assert final == "https://cdn.example/app"
    assert [call.host for call in script.calls] == ["app.example", "cdn.example"]
    assert {call.method for call in script.calls} == {"OPTIONS"}


def test_link_local_and_odd_spellings_are_not_dialed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(ProbeFailure, match="link-local"):
        perform(
            "http://169.254.169.254/",
            method="GET",
            origin="null",
            timeout=1,
            follow_off_host=True,
        )
    with pytest.raises(InputError, match="non-canonical"):
        parse_target("http://127.1/")
    with pytest.raises(InputError, match="non-canonical"):
        parse_target("http://0x7f000001/")
    with pytest.raises(InputError, match="credentials"):
        parse_target("https://user:secret@app.example/")


def test_mixed_answers_are_refused() -> None:
    script = _Script([])
    with pytest.raises(ProbeFailure, match="both public and private"):
        perform(
            "https://app.example/",
            method="GET",
            origin="null",
            timeout=1,
            follow_off_host=False,
            transport=script,
            lookup=lambda host: ("93.184.216.34", "10.0.0.1"),
        )
    assert script.calls == []


def test_address_classes() -> None:
    _, public = guard_addresses("app.example", ("1.1.1.1",))
    _, private = guard_addresses("staging.example", ("10.1.1.1", "192.168.0.9"))
    assert public is Scope.PUBLIC
    assert private is Scope.PRIVATE
    _, loop = guard_addresses("local", ("::1",))
    assert loop is Scope.PRIVATE
    with pytest.raises(ProbeFailure, match="non-routable"):
        guard_addresses("cgnat", ("100.64.0.1",))
    with pytest.raises(ProbeFailure, match="site-local"):
        guard_addresses("site", ("fec0::1",))
    with pytest.raises(ProbeFailure, match="multicast"):
        guard_addresses("cast", ("224.0.0.1",))
    mapped = parse_target("http://[::ffff:10.2.0.1]/")
    assert mapped.host == "10.2.0.1"


class _Handler(BaseHTTPRequestHandler):
    seen: ClassVar[list[dict[str, str | None]]] = []

    def do_GET(self) -> None:
        self._reply()

    def do_OPTIONS(self) -> None:
        self._reply()

    def _reply(self) -> None:
        origin = self.headers.get("Origin")
        _Handler.seen.append(
            {
                "method": self.command,
                "path": self.path,
                "origin": origin,
                "user_agent": self.headers.get("User-Agent"),
                "cache": self.headers.get("Cache-Control"),
                "length": self.headers.get("Content-Length"),
                "authorization": self.headers.get("Authorization"),
            }
        )
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, template: str, *args: object) -> None:
        del template, args


def test_loopback_server_is_probed_without_leaving_the_machine() -> None:
    _Handler.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        report = scan(
            (parse_target(f"http://127.0.0.1:{port}/health"),),
            trusted=None,
            timeout=2,
            concurrency=1,
            rate=0,
            preflight=True,
            follow_off_host=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert report.errors == ()
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "origin-reflection"
    assert report.findings[0].severity.value == "critical"
    assert {item["method"] for item in _Handler.seen} == {"GET", "OPTIONS"}
    assert {item["path"] for item in _Handler.seen} == {"/health"}
    assert {item["origin"] for item in _Handler.seen} == {"https://corsprobe.invalid", "null"}
    assert all(item["user_agent"] == USER_AGENT for item in _Handler.seen)
    assert all(item["cache"] == "no-cache" for item in _Handler.seen)
    assert all(item["length"] is None for item in _Handler.seen)
    assert all(item["authorization"] is None for item in _Handler.seen)

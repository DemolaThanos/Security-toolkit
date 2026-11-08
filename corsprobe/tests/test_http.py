from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from corsprobe.errors import InputError, ProbeFailure
from corsprobe.http_client import USER_AGENT, AddressPins, Call, perform
from corsprobe.models import Case
from corsprobe.net import (
    _LAN_V4,
    _SPECIAL_V4,
    _SPECIAL_V6,
    _ULA,
    Scope,
    guard_addresses,
    parse_target,
)
from corsprobe.probe import HttpFetcher, scan


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
    _, ula = guard_addresses("ula.example", ("fd12::1",))
    assert ula is Scope.PRIVATE
    _, mid = guard_addresses("lan", ("172.16.5.5",))
    assert mid is Scope.PRIVATE
    with pytest.raises(ProbeFailure, match="non-routable"):
        guard_addresses("cgnat", ("100.64.0.1",))
    with pytest.raises(ProbeFailure, match="non-routable"):
        guard_addresses("docs", ("192.0.2.1",))
    with pytest.raises(ProbeFailure, match="non-routable"):
        guard_addresses("bench", ("198.18.0.1",))
    with pytest.raises(ProbeFailure, match="non-routable"):
        guard_addresses("docs6", ("2001:db8::1",))
    with pytest.raises(ProbeFailure, match="site-local"):
        guard_addresses("site", ("fec0::1",))
    with pytest.raises(ProbeFailure, match="multicast"):
        guard_addresses("cast", ("224.0.0.1",))
    with pytest.raises(ProbeFailure, match="link-local"):
        guard_addresses("mapped", ("::ffff:169.254.169.254",))
    with pytest.raises(ProbeFailure, match="6to4"):
        guard_addresses("embed", ("2002:a9fe:a9fe::",))
    with pytest.raises(ProbeFailure, match="teredo"):
        guard_addresses("teredo", ("2001::1",))
    with pytest.raises(ProbeFailure, match="nat64"):
        guard_addresses("nat", ("64:ff9b::a9fe:a9fe",))
    with pytest.raises(ProbeFailure, match="6to4-relay"):
        guard_addresses("relay", ("192.88.99.1",))
    with pytest.raises(ProbeFailure, match="documentation"):
        guard_addresses("docprefix", ("3fff::1",))
    with pytest.raises(ProbeFailure, match="special-use"):
        guard_addresses("pcp", ("2001:1::1",))
    mapped = parse_target("http://[::ffff:10.2.0.1]/")
    assert mapped.host == "10.2.0.1"


def test_range_constants_are_the_named_networks() -> None:
    assert [str(item) for item in _LAN_V4] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert str(_ULA) == "fc00::/7"
    assert [str(item) for item, _ in _SPECIAL_V4] == ["192.88.99.0/24"]
    assert [str(item) for item, _ in _SPECIAL_V6] == [
        "2002::/16",
        "2001::/32",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "3fff::/20",
        "2001:1::/32",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
    ]


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


def test_https_downgrade_is_not_followed_and_upgrade_is() -> None:
    down = _Script([(301, (("Location", "http://app.example/next"),)), (200, ())])
    status, _, final = perform(
        "https://app.example/api",
        method="GET",
        origin="null",
        timeout=1,
        follow_off_host=True,
        transport=down,
        lookup=lambda host: ("93.184.216.34",),
    )
    assert status == 301
    assert final == "https://app.example/api"
    assert [call.scheme for call in down.calls] == ["https"]

    up = _Script([(301, (("Location", "https://app.example/next"),)), (204, ())])
    status, _, final = perform(
        "http://app.example/api",
        method="GET",
        origin="null",
        timeout=1,
        follow_off_host=False,
        transport=up,
        lookup=lambda host: ("93.184.216.34",),
    )
    assert status == 204
    assert final == "https://app.example/next"
    assert [call.scheme for call in up.calls] == ["http", "https"]


def test_redirect_loop_and_cap() -> None:
    loop = _Script([(302, (("Location", "/api"),))])
    with pytest.raises(ProbeFailure, match="redirect loop"):
        perform(
            "https://app.example/api",
            method="GET",
            origin="null",
            timeout=1,
            follow_off_host=False,
            transport=loop,
            lookup=lambda host: ("93.184.216.34",),
        )
    hops = _Script([(302, (("Location", f"/{number}"),)) for number in range(4)])
    with pytest.raises(ProbeFailure, match="stopped after 3 redirects"):
        perform(
            "https://app.example/start",
            method="GET",
            origin="null",
            timeout=1,
            follow_off_host=False,
            transport=hops,
            lookup=lambda host: ("93.184.216.34",),
        )


def test_redirect_onto_6to4_is_not_dialed() -> None:
    script = _Script([(302, (("Location", "https://embed.example/secret"),))])

    def lookup(host: str) -> tuple[str, ...]:
        if host == "app.example":
            return ("93.184.216.34",)
        return ("2002:a9fe:a9fe::",)

    with pytest.raises(ProbeFailure, match="6to4"):
        perform(
            "https://app.example/",
            method="GET",
            origin="null",
            timeout=1,
            follow_off_host=True,
            transport=script,
            lookup=lookup,
        )
    assert [call.host for call in script.calls] == ["app.example"]


def test_pins_keep_the_first_answer() -> None:
    script = _Script([(204, ()), (204, ())])
    answers = iter((("93.184.216.34",), ("10.1.1.1",)))
    seen: list[str] = []

    def lookup(host: str) -> tuple[str, ...]:
        seen.append(host)
        return next(answers)

    pins = AddressPins()
    kwargs = {
        "method": "GET",
        "origin": "null",
        "timeout": 1.0,
        "follow_off_host": False,
        "transport": script,
        "lookup": lookup,
        "pins": pins,
    }
    perform("https://app.example/a", **kwargs)
    perform("https://app.example/b", **kwargs)
    assert seen == ["app.example"]
    assert [call.addresses for call in script.calls] == [("93.184.216.34",), ("93.184.216.34",)]


def test_fetcher_reuses_one_pin_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _Script([(204, ()), (204, ())])
    seen: list[tuple[str, ...]] = []

    def lookup(host: str) -> tuple[str, ...]:
        del host
        answer = ("93.184.216.34",) if not seen else ("10.1.1.1",)
        seen.append(answer)
        return answer

    monkeypatch.setattr("corsprobe.http_client._transport", script)
    monkeypatch.setattr("corsprobe.http_client.system_lookup", lookup)
    fetcher = HttpFetcher()
    target = parse_target("https://app.example/api")
    case = Case("origin-reflection", "https://corsprobe.invalid", "")
    fetcher.fetch(case, target, timeout=1, follow_off_host=False)
    fetcher.fetch(case, target, timeout=1, follow_off_host=False)
    assert seen == [("93.184.216.34",)]
    assert [call.addresses for call in script.calls] == [("93.184.216.34",), ("93.184.216.34",)]


def test_connection_timeout_is_bounded() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    release = threading.Event()

    def hold() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        release.wait(2)
        conn.close()

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    try:
        with pytest.raises(ProbeFailure, match="timed out"):
            perform(
                f"http://127.0.0.1:{port}/",
                method="GET",
                origin="null",
                timeout=0.2,
                follow_off_host=False,
            )
    finally:
        release.set()
        listener.close()
        thread.join(timeout=1)


def test_response_body_is_not_read_to_the_end() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    seen: list[bytes] = []

    def serve() -> None:
        conn, _ = listener.accept()
        conn.recv(4096)
        message = b"HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\nConnection: close\r\n\r\n" + b"x" * 1024
        conn.sendall(message)
        conn.settimeout(1.5)
        try:
            seen.append(conn.recv(1))
        except TimeoutError:
            seen.append(b"stalled")
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        status, _, _ = perform(
            f"http://127.0.0.1:{port}/",
            method="GET",
            origin="null",
            timeout=2,
            follow_off_host=False,
        )
    finally:
        thread.join(timeout=2)
        listener.close()
    assert status == 200
    assert seen == [b""]


class _TLSServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, _Quiet)
        self._context = context

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        sock, addr = super().get_request()
        try:
            return self._context.wrap_socket(sock, server_side=True), addr
        except OSError:
            sock.close()
            raise


class _Quiet(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, template: str, *args: object) -> None:
        del template, args


def test_self_signed_certificate_is_rejected(tmp_path: Path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    server = _TLSServer(("127.0.0.1", 0), context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        with pytest.raises(ProbeFailure, match="tls"):
            perform(
                f"https://127.0.0.1:{port}/",
                method="GET",
                origin="null",
                timeout=2,
                follow_off_host=False,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

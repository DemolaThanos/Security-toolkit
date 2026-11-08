from __future__ import annotations

import io
import json
import socket
import sys
from pathlib import Path

import pytest

from corsprobe.cli import main
from corsprobe.models import Case, Exchange, Target
from corsprobe.origins import ARBITRARY_ORIGIN


class _Fetcher:
    def __init__(self, *, reflect: bool = False) -> None:
        self.reflect = reflect
        self.calls: list[tuple[str, str, str]] = []

    def fetch(self, case: Case, target: Target, *, timeout: float, follow_off_host: bool) -> Exchange:
        del timeout, follow_off_host
        self.calls.append((target.raw, case.case_id, case.origin))
        headers: tuple[tuple[str, str], ...] = ()
        if self.reflect and case.case_id == "origin-reflection":
            headers = (
                ("Access-Control-Allow-Origin", case.origin),
                ("Access-Control-Allow-Credentials", "true"),
            )
        return Exchange(case.case_id, case.origin, case.host, "GET", 200, headers, target.raw)


def _install(monkeypatch: pytest.MonkeyPatch, fetcher: _Fetcher) -> None:
    monkeypatch.setattr("corsprobe.probe.HttpFetcher", lambda: fetcher)


def test_refuses_without_authorisation(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def boom() -> _Fetcher:
        raise AssertionError("fetcher")

    monkeypatch.setattr("corsprobe.probe.HttpFetcher", boom)
    assert main(["scan", "https://app.example/"]) == 2
    err = capsys.readouterr().err
    assert "written permission" in err
    assert "refusing" in err


def test_table_and_fail_on(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _install(monkeypatch, _Fetcher(reflect=True))
    assert main(["scan", "https://app.example/", "--i-am-authorized"]) == 1
    out = capsys.readouterr().out
    assert "critical" in out
    assert "origin-reflection" in out
    assert "1 finding" in out

    _install(monkeypatch, _Fetcher(reflect=False))
    assert main(["scan", "https://app.example/", "--i-am-authorized", "--fail-on", "low"]) == 0
    assert "no findings" in capsys.readouterr().out


def test_env_flag_json_and_sarif(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _install(monkeypatch, _Fetcher(reflect=True))
    monkeypatch.setenv("CORSPROBE_AUTHORIZED", "1")
    destination = tmp_path / "report.json"
    assert (
        main(
            [
                "scan",
                "https://app.example/api",
                "--format",
                "json",
                "--output",
                str(destination),
                "--no-preflight",
            ]
        )
        == 1
    )
    assert capsys.readouterr().out == ""
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["targets_checked"] == 1
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["origin"] == ARBITRARY_ORIGIN

    sarif_path = tmp_path / "report.sarif"
    _install(monkeypatch, _Fetcher(reflect=True))
    assert main(["scan", "https://app.example/api", "--format", "sarif", "--output", str(sarif_path)]) == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "origin-reflection"
    assert result["partialFingerprints"]["primaryLocationLineHash"]


def test_urls_file_trusted_and_no_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fetcher = _Fetcher()
    _install(monkeypatch, fetcher)
    path = tmp_path / "urls.txt"
    path.write_text("# comment\n\nhttps://app.example/api\nhttps://app.example/api\n", encoding="utf-8")
    assert main(["scan", "--urls", str(path), "--i-am-authorized", "--trusted", "example.com", "--no-preflight"]) == 0
    captured = capsys.readouterr()
    assert "written permission" in captured.err
    origins = {origin for _, _, origin in fetcher.calls}
    assert "https://example.com.corsprobe.invalid" in origins
    assert "https://notexample.com" in origins
    assert "https://examplexcom" in origins
    assert "https://corsprobe.example.com" in origins
    assert all(case_id != "preflight" for _, case_id, _ in fetcher.calls)
    assert len({raw for raw, _, _ in fetcher.calls}) == 1


def test_stdin_and_bad_log_format(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    fetcher = _Fetcher()
    _install(monkeypatch, fetcher)

    class Stdin:
        buffer = io.BytesIO(b"https://app.example/\n")

    monkeypatch.setattr(sys, "stdin", Stdin())
    monkeypatch.setenv("CORSPROBE_LOG_FORMAT", "json")
    assert main(["scan", "--urls", "-", "--i-am-authorized", "-v", "--no-preflight"]) == 0
    assert '"message"' in capsys.readouterr().err
    assert fetcher.calls

    monkeypatch.setenv("CORSPROBE_LOG_FORMAT", "yaml")
    assert main(["scan", "https://app.example/", "--i-am-authorized"]) == 2


def test_bad_input_does_not_probe(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom() -> _Fetcher:
        raise AssertionError("fetcher")

    monkeypatch.setattr("corsprobe.probe.HttpFetcher", boom)
    assert main(["scan", "--i-am-authorized"]) == 2
    assert main(["scan", "https://user:secret@app.example/", "--i-am-authorized"]) == 2
    assert main(["scan", "https://app.example/", "--i-am-authorized", "--timeout", "nan"]) == 2
    assert main(["scan", "https://app.example/", "--i-am-authorized", "--trusted", "*.example.com"]) == 2
    assert main(["scan", "https://app.example/", "--i-am-authorized", "--urls", "../urls.txt"]) == 2
    missing = tmp_path / "missing" / "out.json"
    assert main(["scan", "https://app.example/", "--i-am-authorized", "--output", str(missing)]) == 2


def test_link_local_is_refused_after_the_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    code = main(["scan", "http://169.254.169.254/", "--i-am-authorized"])
    err = capsys.readouterr().err
    assert code == 2
    assert "link-local" in err

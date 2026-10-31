from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from subtake.cli import main
from subtake.dns import QueryResult
from subtake.errors import SubtakeError
from subtake.http_client import HttpSnapshot
from subtake.models import Report, Result, Verdict
from subtake.report import render

ROOT = Path(__file__).resolve().parents[2]


class _Lookup:
    def __init__(self, records: dict[tuple[str, str], QueryResult]) -> None:
        self.records = records
        self.queries: list[tuple[str, str]] = []

    def query(self, name: str, rdtype: str) -> QueryResult:
        self.queries.append((name, rdtype))
        return self.records.get((name, rdtype), QueryResult(nxdomain=True))


class _Probe:
    def __init__(self, snapshot: HttpSnapshot) -> None:
        self.snapshot = snapshot
        self.calls: list[tuple[object, ...]] = []

    def probe(self, host: str, sni: str, addresses: tuple[str, ...], timeout: float) -> HttpSnapshot:
        self.calls.append((host, sni, addresses, timeout))
        return self.snapshot


def _write(tmp_path: Path, text: str = "blog.example\nwww.example\n") -> str:
    path = tmp_path / "hosts.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def _install(monkeypatch: pytest.MonkeyPatch, lookup: _Lookup, probe: _Probe) -> None:
    monkeypatch.setattr("subtake.cli.SystemLookup", lambda timeout: lookup)
    monkeypatch.setattr("subtake.cli.HttpProber", lambda: probe)


def test_refuses_to_run_without_authorisation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[object] = []

    def boom(timeout: float) -> object:
        calls.append(timeout)
        raise AssertionError(timeout)

    monkeypatch.setattr("subtake.cli.SystemLookup", boom)
    assert main(["check", "hosts.txt"]) == 2
    assert calls == []
    err = capsys.readouterr().err
    assert "written permission" in err
    assert "refusing" in err


def test_likely_finding_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup(
        {
            ("assets.example", "CNAME"): QueryResult(names=("bucket.s3.amazonaws.com",)),
            ("bucket.s3.amazonaws.com", "CNAME"): QueryResult(),
            ("bucket.s3.amazonaws.com", "A"): QueryResult(names=("93.184.216.34",)),
            ("bucket.s3.amazonaws.com", "AAAA"): QueryResult(),
            ("www.example", "CNAME"): QueryResult(),
        }
    )
    probe = _Probe(HttpSnapshot(404, "The specified bucket does not exist", None))
    _install(monkeypatch, lookup, probe)
    code = main(["check", _write(tmp_path, "assets.example\nwww.example\n"), "--i-am-authorized", "--timeout", "2.5"])
    captured = capsys.readouterr()
    assert code == 1
    assert "likely-vulnerable" in captured.out
    assert "www.example" in captured.out
    assert "no CNAME" in captured.out
    assert "written permission" in captured.err
    assert probe.calls
    assert probe.calls[0][0] == "assets.example"
    assert probe.calls[0][1] == "bucket.s3.amazonaws.com"
    assert probe.calls[0][3] == 2.5
    assert all(call[0] != "www.example" for call in probe.calls)


def test_edge_does_not_fail_the_default_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup(
        {
            ("blog.example", "CNAME"): QueryResult(names=("user.github.io",)),
            ("user.github.io", "CNAME"): QueryResult(),
            ("user.github.io", "A"): QueryResult(names=("93.184.216.34",)),
            ("user.github.io", "AAAA"): QueryResult(),
        }
    )
    _install(monkeypatch, lookup, _Probe(HttpSnapshot(404, "nothing we recognise", None)))
    path = _write(tmp_path, "blog.example\n")
    assert main(["check", path, "--i-am-authorized"]) == 0
    assert "edge-case" in capsys.readouterr().out
    assert main(["check", path, "--i-am-authorized", "--fail-on", "edge"]) == 1


def test_authorisation_does_not_allow_a_private_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup(
        {
            ("blog.example", "CNAME"): QueryResult(names=("user.github.io",)),
            ("user.github.io", "CNAME"): QueryResult(),
            ("user.github.io", "A"): QueryResult(names=("169.254.169.254",)),
            ("user.github.io", "AAAA"): QueryResult(),
        }
    )
    probe = _Probe(HttpSnapshot(200, "should not be fetched", None))
    _install(monkeypatch, lookup, probe)
    monkeypatch.setenv("SUBTAKE_AUTHORIZED", "1")
    code = main(["check", _write(tmp_path, "blog.example\n")])
    assert code == 0
    assert probe.calls == []
    assert "refusing non-public address" in capsys.readouterr().out


def test_json_and_sarif_and_output_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup(
        {
            ("blog.example", "CNAME"): QueryResult(names=("app.eu-west-1.elasticbeanstalk.com",)),
            ("app.eu-west-1.elasticbeanstalk.com", "CNAME"): QueryResult(nxdomain=True),
            ("www.example", "CNAME"): QueryResult(nxdomain=True),
        }
    )
    _install(monkeypatch, lookup, _Probe(HttpSnapshot(200, "", None)))
    destination = tmp_path / "report.json"
    code = main(
        [
            "check",
            _write(tmp_path),
            "--i-am-authorized",
            "--format",
            "json",
            "--output",
            str(destination),
        ]
    )
    assert code == 1
    assert capsys.readouterr().out == ""
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["hosts_checked"] == 2
    assert payload["likely_vulnerable"] == 1
    assert payload["not_vulnerable"] == 1
    finding = next(item for item in payload["results"] if item["host"] == "blog.example")
    assert finding["verdict"] == "likely-vulnerable"
    assert finding["fingerprint"] == "aws-elastic-beanstalk"
    assert finding["cname_chain"] == ["app.eu-west-1.elasticbeanstalk.com"]

    sarif_path = tmp_path / "report.sarif"
    assert main(["check", _write(tmp_path), "--i-am-authorized", "--format", "sarif", "--output", str(sarif_path)]) == 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "subtake"
    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "subtake/aws-elastic-beanstalk"
    assert results[0]["level"] == "error"
    assert results[0]["partialFingerprints"]["primaryLocationLineHash"]
    assert "www.example" not in json.dumps(results)


def test_custom_fingerprints_and_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom = tmp_path / "fingerprints.json"
    custom.write_text(
        json.dumps(
            {
                "services": [
                    {
                        "id": "example-cdn",
                        "service": "Example CDN",
                        "cname": ["*.example-cdn.test"],
                        "nxdomain": "likely-vulnerable",
                        "on_miss": "not-vulnerable",
                        "http": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    lookup = _Lookup(
        {
            ("assets.example", "CNAME"): QueryResult(names=("gone.example-cdn.test",)),
            ("gone.example-cdn.test", "CNAME"): QueryResult(nxdomain=True),
        }
    )
    probe = _Probe(HttpSnapshot(200, "", None))
    _install(monkeypatch, lookup, probe)

    class Stdin:
        buffer = io.BytesIO(b"assets.example\n# comment\n\nassets.example\n")

    monkeypatch.setattr(sys, "stdin", Stdin())
    code = main(["check", "-", "--i-am-authorized", "--fingerprints", str(custom), "--format", "json"])
    assert code == 1
    assert probe.calls == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["hosts_checked"] == 1
    assert payload["results"][0]["fingerprint"] == "example-cdn"


def test_bad_fingerprints_do_not_resolve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[object] = []

    def boom(timeout: float) -> object:
        calls.append(timeout)
        raise AssertionError(timeout)

    monkeypatch.setattr("subtake.cli.SystemLookup", boom)
    broken = tmp_path / "fingerprints.json"
    broken.write_text("{", encoding="utf-8")
    code = main(["check", _write(tmp_path), "--i-am-authorized", "--fingerprints", str(broken)])
    assert code == 2
    assert calls == []


def test_bad_timeout_does_not_query(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lookup = _Lookup({})

    def query(name: str, rdtype: str) -> QueryResult:
        raise AssertionError((name, rdtype))

    lookup.query = query  # type: ignore[method-assign]
    monkeypatch.setattr("subtake.cli.SystemLookup", lambda timeout: lookup)
    monkeypatch.setattr("subtake.cli.HttpProber", lambda: _Probe(HttpSnapshot(200, "", None)))
    assert main(["check", _write(tmp_path), "--i-am-authorized", "--timeout", "nan"]) == 2


def test_json_logs_and_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup({})
    _install(monkeypatch, lookup, _Probe(HttpSnapshot(200, "", None)))
    monkeypatch.setenv("SUBTAKE_LOG_FORMAT", "json")
    assert main(["check", _write(tmp_path, "www.example\n"), "--i-am-authorized", "-v"]) == 0
    err = capsys.readouterr().err
    assert '"message"' in err
    assert "likely-vulnerable" in err

    def explode(*args: object, **kwargs: object) -> Report:
        raise RuntimeError("boom")

    monkeypatch.setattr("subtake.cli.check_hosts", explode)
    assert main(["check", _write(tmp_path), "--i-am-authorized"]) == 2
    with pytest.raises(RuntimeError, match="boom"):
        main(["check", _write(tmp_path), "--i-am-authorized", "-vv"])


def test_invalid_log_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUBTAKE_LOG_FORMAT", "yaml")
    assert main(["check", "hosts.txt", "--i-am-authorized"]) == 2


def test_table_sarif_and_summary() -> None:
    report = Report(
        (
            Result(
                "blog.example",
                Verdict.LIKELY,
                "GitHub Pages",
                "github-pages",
                ("user.github.io",),
                404,
                "blog.example -> user.github.io; HTTP 404 matched GitHub Pages",
            ),
            Result("www.example", Verdict.SAFE, None, None, (), None, "no CNAME"),
            Result("odd.example", Verdict.EDGE, None, None, ("cdn.example",), None, "line\nnext"),
        )
    )
    table = render(report, "table")
    assert "likely-vulnerable  blog.example" in table
    assert "line next" in table
    assert "\nnext" not in table
    assert table.endswith("1 likely-vulnerable, 1 edge-case, 1 not-vulnerable\n")
    sarif = json.loads(render(report, "sarif"))
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "subtake/github-pages"
    assert results[1]["ruleId"] == "subtake/unconfirmed"
    assert results[1]["level"] == "note"
    first = results[0]["partialFingerprints"]["primaryLocationLineHash"]
    again = json.loads(render(report, "sarif"))
    assert first == again["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    with pytest.raises(ValueError):
        render(report, "xml")
    with pytest.raises(SubtakeError):
        report.failing("critical")


def test_github_signature_does_not_fail_the_default_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lookup = _Lookup(
        {
            ("blog.example", "CNAME"): QueryResult(names=("user.github.io",)),
            ("user.github.io", "CNAME"): QueryResult(),
            ("user.github.io", "A"): QueryResult(names=("93.184.216.34",)),
            ("user.github.io", "AAAA"): QueryResult(),
        }
    )
    _install(monkeypatch, lookup, _Probe(HttpSnapshot(404, "There isn't a GitHub Pages site here.", None)))
    code = main(["check", _write(tmp_path, "blog.example\n"), "--i-am-authorized"])
    captured = capsys.readouterr()
    assert code == 0
    assert "edge-case" in captured.out
    assert "likely-vulnerable  blog.example" not in captured.out


def test_a_thrown_check_exits_2_without_leaking_the_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Boom:
        def query(self, name: str, rdtype: str) -> QueryResult:
            if name == "bad.example":
                raise RuntimeError("secret resolver detail")
            return QueryResult(nxdomain=True)

    monkeypatch.setattr("subtake.cli.SystemLookup", lambda timeout: Boom())
    monkeypatch.setattr("subtake.cli.HttpProber", lambda: _Probe(HttpSnapshot(200, "", None)))
    destination = tmp_path / "report.json"
    code = main(
        [
            "check",
            _write(tmp_path, "bad.example\nok.example\n"),
            "--i-am-authorized",
            "--format",
            "json",
            "--output",
            str(destination),
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "secret" not in captured.err
    assert "secret" not in captured.out
    assert "check failed for bad.example" in captured.err
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert [item["host"] for item in payload["results"]] == ["bad.example", "ok.example"]
    assert payload["results"][0]["evidence"] == "check failed"
    assert payload["results"][1]["verdict"] == "not-vulnerable"


def test_output_path_is_rejected_before_any_lookup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    hosts = work / "hosts.txt"
    hosts.write_text("www.example\n", encoding="utf-8")
    calls: list[object] = []

    def boom(timeout: float) -> object:
        calls.append(timeout)
        raise AssertionError(timeout)

    monkeypatch.setattr("subtake.cli.SystemLookup", boom)
    assert main(["check", "hosts.txt", "--i-am-authorized", "--output", "missing/out.json"]) == 2
    assert calls == []
    assert "output directory" in capsys.readouterr().err

    outside = tmp_path / "out.json"
    link = work / "out.json"
    link.symlink_to(outside)
    assert main(["check", "hosts.txt", "--i-am-authorized", "--output", "out.json"]) == 2
    assert calls == []
    assert not outside.exists()


def test_host_list_symlink_cannot_escape(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    outside = tmp_path / "hosts.txt"
    outside.write_text("www.example\n", encoding="utf-8")
    link = work / "hosts.txt"
    link.symlink_to(outside)
    calls: list[object] = []
    monkeypatch.setattr("subtake.cli.SystemLookup", lambda timeout: calls.append(timeout))
    assert main(["check", "hosts.txt", "--i-am-authorized"]) == 2
    assert calls == []
    assert "working directory" in capsys.readouterr().err


def test_ci_runs_subtake() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "subtake" in workflow
    assert "/subtake" in dependabot
    assert "[subtake](subtake/)" in readme

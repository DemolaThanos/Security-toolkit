from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from subtake.check import Limiter, assess, check_hosts
from subtake.dns import QueryResult, SystemLookup, resolve_chain
from subtake.errors import SubtakeError
from subtake.fingerprints import Service, load_fingerprints, match_name
from subtake.hosts import parse_hosts, read_host_list
from subtake.http_client import HttpSnapshot
from subtake.models import Verdict
from subtake.net import normalize_hostname, public_addresses
from tests.fakes import GITHUB, S3, MapLookup, ScriptedProbe, linked

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "aws-cloudfront",
    "aws-elastic-beanstalk",
    "aws-elb",
    "aws-s3",
    "azure-api",
    "azure-app-service",
    "azure-blob",
    "azure-cdn",
    "azure-cloudapp",
    "azure-front-door",
    "azure-static-apps",
    "azure-static-website",
    "azure-traffic-manager",
    "bitbucket-pages",
    "fastly",
    "firebase",
    "fly-io",
    "gcp-storage",
    "ghost",
    "github-pages",
    "helpscout",
    "heroku",
    "netlify",
    "pantheon",
    "railway",
    "shopify",
    "surge",
    "tumblr",
    "vercel",
    "zendesk",
}


def _pace() -> Limiter:
    return Limiter(0)


def _page(status: int, body: str) -> ScriptedProbe:
    return ScriptedProbe(HttpSnapshot(status, body, None))


def test_hostname_normalisation() -> None:
    assert normalize_hostname("Example.COM.") == "example.com"
    assert normalize_hostname("Bücher.Example") == "xn--bcher-kva.example"
    with pytest.raises(SubtakeError):
        normalize_hostname("*.example.com")
    with pytest.raises(SubtakeError):
        normalize_hostname("127.0.0.1")
    with pytest.raises(SubtakeError):
        normalize_hostname("-bad.example")
    with pytest.raises(SubtakeError):
        normalize_hostname("bad..example")
    with pytest.raises(SubtakeError):
        normalize_hostname("a" * 64 + ".example")


def test_parse_hosts_skips_comments_and_duplicates() -> None:
    text = "# scope\n\nBlog.Example # prod\nblog.example\nshop.example\n"
    assert parse_hosts(text, limit=10) == ("blog.example", "shop.example")
    with pytest.raises(SubtakeError, match="line 3"):
        parse_hosts("# c\n\nbad host\n", limit=10)
    with pytest.raises(SubtakeError, match="no hostnames"):
        parse_hosts("# nothing\n\n", limit=10)
    with pytest.raises(SubtakeError, match="more than 1"):
        parse_hosts("a.example\nb.example\n", limit=1)


def test_read_host_list_accepts_a_bom_and_rejects_junk(tmp_path: Path) -> None:
    path = tmp_path / "hosts.txt"
    path.write_bytes(b"\xef\xbb\xbfwww.example\n")
    assert read_host_list(str(path), limit=10) == ("www.example",)
    huge = tmp_path / "huge.txt"
    huge.write_bytes(b"a.example\n" + b"x" * 1_000_000)
    with pytest.raises(SubtakeError, match="larger than"):
        read_host_list(str(huge), limit=10)
    with pytest.raises(SubtakeError, match="not a file"):
        read_host_list(str(tmp_path), limit=10)
    binary = tmp_path / "bin.txt"
    binary.write_bytes(b"www.example\xff\n")
    with pytest.raises(SubtakeError, match="UTF-8"):
        read_host_list(str(binary), limit=10)


def test_example_host_file_parses() -> None:
    hosts = read_host_list(str(ROOT / "subtake" / "examples" / "hosts.txt"), limit=10)
    assert hosts == ("blog.example.com", "shop.example.com")


@pytest.mark.parametrize(
    "value",
    [
        "10.1.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "0.0.0.0",
        "224.0.0.1",
        "ff02::1",
        "::1",
        "fe80::1",
        "fec0::1",
        "::ffff:10.1.1.1",
        "::ffff:169.254.169.254",
        "not-an-ip",
    ],
)
def test_non_public_addresses_are_rejected(value: str) -> None:
    assert public_addresses((value,)) is None


def test_public_addresses_unwrap_and_dedupe() -> None:
    assert public_addresses(()) == ()
    assert public_addresses(("::ffff:93.184.216.34", "93.184.216.34")) == ("93.184.216.34",)
    assert public_addresses(("93.184.216.34", "10.0.0.1")) is None


def test_bundled_fingerprints_match_known_providers() -> None:
    services = load_fingerprints()
    assert {item.id for item in services} == EXPECTED
    cases = {
        "user.github.io": "github-pages",
        "github.io": None,
        "foo.github.io.attacker.test": None,
        "bucket.s3.amazonaws.com": "aws-s3",
        "bucket.s3.eu-west-1.amazonaws.com": "aws-s3",
        "bucket.s3.dualstack.eu-west-1.amazonaws.com": "aws-s3",
        "www.example.com.s3-website-eu-west-1.amazonaws.com": "aws-s3",
        "bucket.s3-website.eu-west-1.amazonaws.com": "aws-s3",
        "not-s3.amazonaws.com": None,
        "name.elb.us-east-1.amazonaws.com": "aws-elb",
        "name-1.us-east-1.elb.amazonaws.com": "aws-elb",
        "d111.cloudfront.net": "aws-cloudfront",
        "c.storage.googleapis.com": "gcp-storage",
        "old.herokuapp.com": "heroku",
        "edge.herokudns.com": "heroku",
        "shops.myshopify.com": "shopify",
        "cname.vercel-dns.com": "vercel",
        "domains.tumblr.com": "tumblr",
        "app.azurewebsites.net": "azure-app-service",
        "account.blob.core.windows.net": "azure-blob",
        "account.z13.web.core.windows.net": "azure-static-website",
        "foo.1.azurestaticapps.net": "azure-static-apps",
        "gone.up.railway.app": "railway",
    }
    for host, service_id in cases.items():
        matched = match_name(host, services)
        assert (None if matched is None else matched.id) == service_id


def test_fingerprint_file_is_strict(tmp_path: Path) -> None:
    def write(payload: object) -> str:
        path = tmp_path / "fingerprints.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    base = {
        "id": "example-cdn",
        "service": "Example CDN",
        "cname": ["*.example-cdn.test"],
        "nxdomain": "likely-vulnerable",
        "on_miss": "not-vulnerable",
        "http": [],
    }
    assert len(load_fingerprints(write({"services": [base]}))) == 1
    with pytest.raises(SubtakeError, match="invalid fields"):
        load_fingerprints(write({"services": [{**base, "note": "x"}]}))
    with pytest.raises(SubtakeError, match="duplicate fingerprint"):
        load_fingerprints(write({"services": [base, dict(base)]}))
    other = dict(base)
    other["id"] = "other-cdn"
    with pytest.raises(SubtakeError, match="duplicate CNAME"):
        load_fingerprints(write({"services": [base, other]}))
    with pytest.raises(SubtakeError, match="invalid CNAME"):
        load_fingerprints(write({"services": [{**base, "cname": ["*.com"]}]}))
    with pytest.raises(SubtakeError, match="8 to 200"):
        load_fingerprints(write({"services": [{**base, "http": [{"body": "short", "verdict": "likely-vulnerable"}]}]}))
    with pytest.raises(SubtakeError, match="nxdomain"):
        load_fingerprints(write({"services": [{**base, "nxdomain": "not-vulnerable"}]}))
    with pytest.raises(SubtakeError, match="on_miss"):
        load_fingerprints(write({"services": [{**base, "on_miss": "likely-vulnerable"}]}))
    with pytest.raises(SubtakeError, match="no services"):
        load_fingerprints(write({"services": []}))
    with pytest.raises(SubtakeError, match="services array"):
        load_fingerprints(write([]))
    with pytest.raises(SubtakeError, match="not JSON"):
        path = tmp_path / "broken.json"
        path.write_text("{", encoding="utf-8")
        load_fingerprints(str(path))
    too_many = []
    for index in range(201):
        item = dict(base)
        item["id"] = f"cdn-{index}"
        item["cname"] = [f"*.n{index}.example-cdn.test"]
        too_many.append(item)
    with pytest.raises(SubtakeError, match="more than 200"):
        load_fingerprints(write({"services": too_many}))


def test_no_cname_is_not_vulnerable_and_does_not_query_addresses() -> None:
    lookup = MapLookup({("www.example", "CNAME"): QueryResult()})
    probe = _page(200, "hello")
    result = assess("www.example", lookup, probe, (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.SAFE
    assert result.evidence == "no CNAME"
    assert lookup.calls == [("www.example", "CNAME")]
    assert probe.calls == []


def test_missing_name_is_not_a_dangling_cname() -> None:
    lookup = MapLookup({("gone.example", "CNAME"): QueryResult(nxdomain=True)})
    result = assess("gone.example", lookup, _page(404, ""), (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.SAFE
    assert result.evidence == "name does not resolve"


def test_nxdomain_on_a_tracked_target_is_the_service_verdict() -> None:
    lookup = linked("blog.example", "old.herokuapp.com", nxdomain=True)
    heroku = Service(
        id="heroku",
        service="Heroku",
        cname=("*.herokuapp.com",),
        nxdomain=Verdict.LIKELY,
        on_miss=Verdict.SAFE,
        http=(),
    )
    probe = _page(200, "no")
    result = assess("blog.example", lookup, probe, (heroku,), 1, _pace())
    assert result.verdict is Verdict.LIKELY
    assert result.fingerprint == "heroku"
    assert result.evidence == "blog.example -> old.herokuapp.com; old.herokuapp.com does not resolve"
    assert probe.calls == []
    assert ("old.herokuapp.com", "A") not in lookup.calls


def test_s3_nxdomain_stays_an_edge_case() -> None:
    lookup = linked("assets.example", "bucket.s3.amazonaws.com", nxdomain=True)
    result = assess("assets.example", lookup, _page(404, "NoSuchBucket"), (S3,), 1, _pace())
    assert result.verdict is Verdict.EDGE
    assert result.fingerprint == "aws-s3"


def test_untracked_nxdomain_is_an_edge_case() -> None:
    lookup = linked("blog.example", "cdn.example.net", nxdomain=True)
    result = assess("blog.example", lookup, _page(200, ""), (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.EDGE
    assert result.service is None
    assert "not a tracked service" in result.evidence


def test_live_provider_response_is_not_vulnerable() -> None:
    lookup = linked("blog.example", "user.github.io")
    probe = _page(200, "There isn't a GitHub Pages site here")
    result = assess("blog.example", lookup, probe, (GITHUB,), 5, _pace())
    assert result.verdict is Verdict.SAFE
    assert "looks live" in result.evidence
    assert probe.calls == [("blog.example", "user.github.io", ("93.184.216.34",), 5)]


def test_github_404_matches_and_a_plain_404_is_an_edge() -> None:
    lookup = linked("blog.example", "user.github.io")
    hit = assess(
        "blog.example",
        lookup,
        _page(404, "There isn't a GitHub Pages site here."),
        (GITHUB,),
        1,
        _pace(),
    )
    assert hit.verdict is Verdict.LIKELY
    assert hit.http_status == 404
    assert hit.evidence.endswith("HTTP 404 matched GitHub Pages")
    miss = assess("blog.example", lookup, _page(404, "custom application 404"), (GITHUB,), 1, _pace())
    assert miss.verdict is Verdict.EDGE
    assert "did not match" in miss.evidence


def test_redirect_without_a_fingerprint_looks_live() -> None:
    lookup = linked("blog.example", "user.github.io")
    result = assess("blog.example", lookup, _page(301, ""), (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.SAFE
    assert "looks live" in result.evidence


def test_s3_bucket_missing_is_likely_and_access_denied_is_not() -> None:
    lookup = linked("assets.example", "bucket.s3.amazonaws.com")
    missing = assess("assets.example", lookup, _page(404, "<Code>NoSuchBucket</Code>"), (S3,), 1, _pace())
    assert missing.verdict is Verdict.LIKELY
    denied = assess("assets.example", lookup, _page(403, "<Code>AccessDenied</Code>"), (S3,), 1, _pace())
    assert denied.verdict is Verdict.SAFE
    assert denied.fingerprint == "aws-s3"


def test_private_and_mixed_answers_are_not_probed() -> None:
    probe = _page(200, "There isn't a GitHub Pages site here")
    private = linked("blog.example", "user.github.io", addresses=("10.1.1.1",))
    result = assess("blog.example", private, probe, (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.EDGE
    assert "refusing non-public address" in result.evidence
    assert probe.calls == []
    mixed = linked("blog.example", "user.github.io", addresses=("93.184.216.34", "169.254.169.254"))
    again = assess("blog.example", mixed, probe, (GITHUB,), 1, _pace())
    assert again.verdict is Verdict.EDGE
    assert probe.calls == []
    mapped = linked("blog.example", "user.github.io", addresses=("::ffff:93.184.216.34",))
    mapped_probe = _page(404, "There isn't a GitHub Pages site here")
    hit = assess("blog.example", mapped, mapped_probe, (GITHUB,), 1, _pace())
    assert hit.verdict is Verdict.LIKELY
    assert mapped_probe.calls[0][2] == ("93.184.216.34",)


def test_http_failure_is_an_edge_case() -> None:
    lookup = linked("blog.example", "user.github.io")
    probe = ScriptedProbe(HttpSnapshot(None, "", "https tls failed; http connection failed"))
    result = assess("blog.example", lookup, probe, (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.EDGE
    assert "HTTP probe failed (https tls failed; http connection failed)" in result.evidence


def test_cname_loop_and_long_chain_stop() -> None:
    loop = MapLookup(
        {
            ("start.example", "CNAME"): QueryResult(names=("a.example",)),
            ("a.example", "CNAME"): QueryResult(names=("b.example",)),
            ("b.example", "CNAME"): QueryResult(names=("a.example",)),
        }
    )
    probe = _page(200, "")
    looped = assess("start.example", loop, probe, (GITHUB,), 1, _pace())
    assert looped.verdict is Verdict.EDGE
    assert "CNAME loop at a.example" in looped.evidence
    assert probe.calls == []

    class ChainLookup:
        def query(self, name: str, rdtype: str) -> QueryResult:
            if rdtype != "CNAME":
                raise AssertionError(rdtype)
            if name == "start.example":
                return QueryResult(names=("c1.example",))
            number = int(name.removeprefix("c").split(".", 1)[0])
            if number >= 8:
                raise AssertionError(name)
            return QueryResult(names=(f"c{number + 1}.example",))

    long = assess("start.example", ChainLookup(), probe, (), 1, _pace())
    assert "longer than 8" in long.evidence
    assert long.verdict is Verdict.EDGE


def test_aaaa_is_used_when_a_record_times_out() -> None:
    records = {
        ("blog.example", "CNAME"): QueryResult(names=("user.github.io",)),
        ("user.github.io", "CNAME"): QueryResult(),
        ("user.github.io", "A"): QueryResult(error="dns timeout"),
        ("user.github.io", "AAAA"): QueryResult(names=("2606:4700:4700::1111",)),
    }
    probe = _page(404, "There isn't a GitHub Pages site here")
    result = assess("blog.example", MapLookup(records), probe, (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.LIKELY
    assert probe.calls[0][2] == ("2606:4700:4700::1111",)


def test_dns_timeout_does_not_probe() -> None:
    lookup = MapLookup({("www.example", "CNAME"): QueryResult(error="dns timeout")})
    probe = _page(200, "")
    result = assess("www.example", lookup, probe, (GITHUB,), 1, _pace())
    assert result.verdict is Verdict.EDGE
    assert result.evidence == "dns timeout"
    assert probe.calls == []


def test_unusable_cname_target() -> None:
    lookup = MapLookup({("blog.example", "CNAME"): QueryResult(names=("10.1.1.1",))})
    result = assess("blog.example", lookup, _page(200, ""), (GITHUB,), 1, _pace())
    assert "unusable CNAME target" in result.evidence


def test_system_lookup_translates_resolver_results() -> None:
    import dns.exception
    import dns.resolver

    class Rdata:
        def __init__(self, text: str) -> None:
            self._text = text

        def to_text(self) -> str:
            return self._text

    class Stub:
        def __init__(self, outcome: object) -> None:
            self.outcome = outcome
            self.lifetime = 0.0
            self.timeout = 0.0
            self.calls: list[tuple[str, str, bool]] = []

        def resolve(self, qname: str, rdtype: str, *, search: bool = True) -> list[Rdata]:
            self.calls.append((qname, rdtype, search))
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome  # type: ignore[return-value]

    stub = Stub(dns.resolver.NoAnswer())
    lookup = SystemLookup(2.5, resolver_factory=lambda: stub)
    assert lookup.query("Blog.Example", "CNAME") == QueryResult()
    assert stub.calls == [("blog.example", "CNAME", False)]
    assert stub.lifetime == 2.5

    stub.outcome = [Rdata("User.GitHub.io.")]
    found = lookup.query("blog.example", "CNAME")
    assert found.names == ("user.github.io",)

    stub.outcome = dns.resolver.NXDOMAIN()
    assert lookup.query("blog.example", "A").nxdomain is True
    stub.outcome = dns.exception.Timeout("secret resolver 10.0.0.1")
    assert lookup.query("blog.example", "A").error == "dns timeout"
    stub.outcome = dns.resolver.NoNameservers()
    failed = lookup.query("blog.example", "A")
    assert failed.error == "dns lookup failed"
    assert "secret" not in (failed.error or "")

    def explode() -> Stub:
        raise AssertionError("resolver")

    assert SystemLookup(1, resolver_factory=explode).query("127.0.0.1", "A").error == "unusable name"


def test_resolver_sees_idna() -> None:
    class Stub:
        lifetime = 0.0
        timeout = 0.0

        def __init__(self) -> None:
            self.names: list[str] = []

        def resolve(self, qname: str, rdtype: str, *, search: bool = True) -> list[object]:
            self.names.append(qname)
            raise dns_no_answer()

    stub = Stub()
    SystemLookup(1, resolver_factory=lambda: stub).query("Bücher.example", "CNAME")
    assert stub.names == ["xn--bcher-kva.example"]


def dns_no_answer() -> Exception:
    import dns.resolver

    return dns.resolver.NoAnswer()


def test_limiter_spaces_calls_and_zero_does_not_sleep() -> None:
    class Clock:
        def __init__(self) -> None:
            self.now = 0.0
            self.slept: list[float] = []

        def time(self) -> float:
            return self.now

        def sleep(self, delay: float) -> None:
            self.slept.append(delay)
            self.now += delay

    clock = Clock()
    limiter = Limiter(2, now=clock.time, sleep=clock.sleep)
    for _ in range(3):
        limiter.wait()
    assert clock.slept == [0.5, 0.5]

    def explode(delay: float) -> None:
        raise AssertionError(delay)

    quiet = Limiter(0, now=lambda: 0.0, sleep=explode)
    quiet.wait()
    quiet.wait()


def test_bounds_and_one_failure_do_not_drop_other_hosts() -> None:
    class Boom:
        def query(self, name: str, rdtype: str) -> QueryResult:
            if name == "bad.example":
                raise RuntimeError("nope")
            return QueryResult(nxdomain=True)

    probe = _page(200, "")
    with pytest.raises(SubtakeError, match="timeout"):
        check_hosts(
            ("a.example",),
            lookup=Boom(),
            prober=probe,
            services=(),
            timeout=float("nan"),
            concurrency=1,
            rate=0,
        )
    with pytest.raises(SubtakeError, match="concurrency"):
        check_hosts(("a.example",), lookup=Boom(), prober=probe, services=(), timeout=1, concurrency=0, rate=0)
    with pytest.raises(SubtakeError, match="rate"):
        check_hosts(("a.example",), lookup=Boom(), prober=probe, services=(), timeout=1, concurrency=1, rate=-1)
    report = check_hosts(
        ("bad.example", "ok.example"),
        lookup=Boom(),
        prober=probe,
        services=(),
        timeout=1,
        concurrency=2,
        rate=0,
    )
    assert report.results[0].evidence == "check failed"
    assert report.results[0].verdict is Verdict.EDGE
    assert report.results[1].evidence == "name does not resolve"
    assert [item.host for item in report.results] == ["bad.example", "ok.example"]


def test_results_follow_input_order_when_the_first_is_slower() -> None:
    class Lookup:
        def query(self, name: str, rdtype: str) -> QueryResult:
            if name == "slow.example":
                time.sleep(0.05)
            return QueryResult(nxdomain=True)

    report = check_hosts(
        ("slow.example", "fast.example"),
        lookup=Lookup(),
        prober=_page(200, ""),
        services=(),
        timeout=1,
        concurrency=2,
        rate=0,
    )
    assert [item.host for item in report.results] == ["slow.example", "fast.example"]


def test_checks_run_concurrently() -> None:
    barrier = threading.Barrier(4, timeout=5)

    class Lookup:
        def query(self, name: str, rdtype: str) -> QueryResult:
            if rdtype != "CNAME":
                raise AssertionError(rdtype)
            barrier.wait()
            return QueryResult(nxdomain=True)

    hosts = tuple(f"h{index}.example" for index in range(4))
    report = check_hosts(
        hosts,
        lookup=Lookup(),
        prober=_page(200, ""),
        services=(),
        timeout=1,
        concurrency=4,
        rate=0,
    )
    assert [item.host for item in report.results] == list(hosts)
    assert {item.verdict for item in report.results} == {Verdict.SAFE}


def test_resolve_chain_does_not_follow_a_ninth_cname() -> None:
    class Lookup:
        def query(self, name: str, rdtype: str) -> QueryResult:
            assert rdtype == "CNAME"
            if name == "start.example":
                return QueryResult(names=("c1.example",))
            number = int(name.removeprefix("c").split(".", 1)[0])
            assert number < 8
            return QueryResult(names=(f"c{number + 1}.example",))

    chain = resolve_chain("start.example", Lookup())
    assert chain.error == "CNAME chain is longer than 8"
    assert len(chain.cnames) == 8

from pathlib import Path

import pytest

from stride_model.catalog import generate
from stride_model.cli import main
from stride_model.parse import ModelError, parse_model
from stride_model.render import render_markdown

CHECKOUT = """
name: checkout
description: Card checkout API and its order store.
trust_zones:
  - id: internet
    description: Customer network
    external: true
  - id: app
    description: Application tier
  - id: data
    description: Data tier
components:
  - id: browser
    type: external
    zone: internet
    description: Customer browser
  - id: api
    type: process
    zone: app
    description: Checkout API
    logs_actions: true
    rate_limited: true
  - id: orders
    type: data-store
    zone: data
    description: Orders database
    encrypted_at_rest: true
    logs_actions: true
flows:
  - id: submit
    source: browser
    destination: api
    protocol: https
    authenticated: true
    data_classes: [credential, payment]
  - id: persist
    source: api
    destination: orders
    protocol: tls
    authenticated: true
    data_classes: [payment]
"""

BAD = """
name: bad
description: missing controls
trust_zones:
  - id: internet
    description: outside
    external: true
  - id: app
    description: app
components:
  - id: user
    type: external
    zone: internet
    description: caller
  - id: api
    type: process
    zone: app
    description: api
    logs_actions: false
  - id: db
    type: data-store
    zone: app
    description: db
flows:
  - id: call
    source: user
    destination: api
    protocol: http
    authenticated: false
    data_classes: [payment]
  - id: write
    source: api
    destination: db
    protocol: tcp
    authenticated: false
    data_classes: [payment]
"""


def test_controlled_model_keeps_only_residual_dos() -> None:
    threats = generate(parse_model(CHECKOUT))
    assert [(item.id, item.severity.value) for item in threats] == [("dos:api", "low")]


def test_missing_controls() -> None:
    threats = generate(parse_model(BAD))
    assert [(item.id, item.severity.value) for item in threats] == [
        ("spoofing:call", "critical"),
        ("spoofing:write", "critical"),
        ("disclosure:call", "high"),
        ("disclosure:db", "high"),
        ("disclosure:write", "high"),
        ("elevation:api", "high"),
        ("tampering:call", "high"),
        ("tampering:write", "high"),
        ("dos:api", "medium"),
        ("repudiation:api", "medium"),
        ("repudiation:db", "low"),
    ]


def test_unknown_key() -> None:
    with pytest.raises(ModelError) as caught:
        parse_model("name: x\ndescription: y\nextra: 1\ntrust_zones: []\ncomponents: []\n")
    assert any("unknown keys" in problem for problem in caught.value.problems)


def test_cli_gate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "model.yaml"
    path.write_text(CHECKOUT, encoding="utf-8")
    assert main(["render", str(path), "--format", "json"]) == 0
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["trust_zones"][0]["id"] == "internet"
    assert payload["components"][1]["id"] == "api"
    assert payload["flows"][0]["protocol"] == "https"
    assert payload["threats"][0]["id"] == "dos:api"
    assert main(["render", str(path), "--fail-on", "low"]) == 1
    assert main(["render", str(path), "--fail-on", "high"]) == 0


COLLISION = """
name: collision
description: overlapping ids
trust_zones:
  - id: app
    description: Application tier
components:
  - id: api
    type: process
    zone: app
    description: API
    logs_actions: true
  - id: db
    type: data-store
    zone: app
    description: database
    encrypted_at_rest: false
flows:
  - id: db
    source: api
    destination: db
    protocol: http
    authenticated: true
    data_classes: [pii]
"""


def test_flow_and_store_keep_separate_disclosure_threats() -> None:
    threats = [item for item in generate(parse_model(COLLISION)) if item.id == "disclosure:db"]
    details = {item.detail for item in threats}
    assert any("unprotected" in detail for detail in details)
    assert any("encryption at rest" in detail for detail in details)
    assert len(threats) == 2


def test_store_sensitivity_without_a_flow() -> None:
    model = parse_model(
        """
name: records
description: a store
trust_zones:
  - id: data
    description: data
components:
  - id: db
    type: data-store
    zone: data
    description: records
    encrypted_at_rest: false
    data_classes: [pii]
flows: []
"""
    )
    threats = {item.id: item.severity.value for item in generate(model)}
    assert threats["disclosure:db"] == "high"


def test_sftp_is_protected_and_pipes_are_escaped() -> None:
    model = parse_model(
        """
name: transfer
description: file drop
trust_zones:
  - id: app
    description: app
components:
  - id: job
    type: process
    zone: app
    description: copier
    logs_actions: true
  - id: files
    type: data-store
    zone: app
    description: files
    encrypted_at_rest: true
    logs_actions: true
flows:
  - id: copy
    source: job
    destination: files
    protocol: sftp
    authenticated: true
    data_classes: [payment]
"""
    )
    assert [item.category for item in generate(model)] == []

    piped = parse_model(BAD.replace("protocol: http", "protocol: tcp|raw", 1))
    rendered = render_markdown(piped, generate(piped))
    assert "tcp\\|raw" in rendered
    assert "| tcp|raw" not in rendered

    quoted = parse_model(BAD.replace("protocol: http", "protocol: https`evil", 1))
    rendered = render_markdown(quoted, generate(quoted))
    assert "https'evil" in rendered
    assert "https`evil" not in rendered


def test_internet_zone_is_external_and_large_models_stop(tmp_path: Path) -> None:
    model = parse_model(
        """
name: edge
description: inferred zone
trust_zones:
  - id: internet
    description: outside
  - id: app
    description: app
components:
  - id: user
    type: external
    zone: internet
    description: caller
  - id: api
    type: process
    zone: app
    description: api
    logs_actions: true
flows:
  - id: call
    source: user
    destination: api
    protocol: https
    authenticated: true
    data_classes: []
"""
    )
    assert model.zone("internet").external is True
    assert any(item.id == "dos:api" for item in generate(model))

    path = tmp_path / "huge.yaml"
    path.write_bytes(b"name: x\n" + b"a" * 1_000_001)
    assert main(["render", str(path)]) == 2
    with pytest.raises(ModelError, match="single line"):
        parse_model('name: "a\\nb"\ndescription: ok\ntrust_zones: []\ncomponents: []\n')

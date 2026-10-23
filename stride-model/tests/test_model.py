from pathlib import Path

import pytest

from stride_model.catalog import generate
from stride_model.cli import main
from stride_model.parse import ModelError, parse_model

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


def test_cli_gate(tmp_path: Path) -> None:
    path = tmp_path / "model.yaml"
    path.write_text(CHECKOUT, encoding="utf-8")
    assert main(["render", str(path), "--format", "json"]) == 0
    assert main(["render", str(path), "--fail-on", "low"]) == 1
    assert main(["render", str(path), "--fail-on", "high"]) == 0

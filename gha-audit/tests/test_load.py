from pathlib import Path

from gha_audit.scan import scan


def test_duplicate_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "twice.yml"
    path.write_text("on: push\non: pull_request\npermissions:\n  contents: read\njobs: {}\n", encoding="utf-8")
    report = scan([path])
    assert report.findings == ()
    assert report.errors
    assert "duplicate" in report.errors[0]


def test_deep_document_is_rejected(tmp_path: Path) -> None:
    nested = "1"
    for _ in range(80):
        nested = "{k: " + nested + "}"
    path = tmp_path / "deep.yml"
    path.write_text(f"on: {nested}\n", encoding="utf-8")
    report = scan([path])
    assert report.findings == ()
    assert report.errors
    assert "depth" in report.errors[0] or "nested" in report.errors[0]


def test_anchor_expansion_is_capped(tmp_path: Path) -> None:
    lines = ["l0: &l0 [1]"]
    for level in range(1, 6):
        refs = ", ".join(f"*l{level - 1}" for _ in range(12))
        lines.append(f"l{level}: &l{level} [{refs}]")
    path = tmp_path / "expand.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan([path])
    assert report.findings == ()
    assert any("expansion" in error or "alias" in error for error in report.errors)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yml"
    path.write_text("on: push\n", encoding="utf-8")
    report = scan([path], max_bytes=4)
    assert report.findings == ()
    assert any("larger" in error for error in report.errors)

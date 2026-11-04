from pathlib import Path

from gha_audit.models import Options
from gha_audit.rules import RULES
from gha_audit.scan import scan

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"


def _ids(path: Path, *, options: Options | None = None) -> set[str]:
    report = scan([path], options=options)
    assert report.errors == ()
    return {item.rule_id for item in report.findings}


def test_secure_example_is_clean() -> None:
    report = scan([ROOT / "examples" / "secure.yml"])
    assert report.errors == ()
    assert report.findings == ()
    assert report.files_checked == 1


def test_insecure_example_covers_the_common_set() -> None:
    report = scan([ROOT / "examples" / "insecure.yml"])
    assert report.errors == ()
    assert {item.rule_id for item in report.findings} == {
        "checkout-persist-credentials",
        "permissions-missing",
        "pwn-request",
        "script-injection",
        "secret-untrusted",
        "secrets-inherit",
        "self-hosted-public",
        "unpinned-action",
    }
    assert sum(item.rule_id == "unpinned-action" for item in report.findings) == 3
    assert any("pull_request_target" in item.message for item in report.findings if item.rule_id == "pwn-request")


def test_every_rule_has_a_fixture() -> None:
    covered = set()
    for path in (
        FIXTURES / "unpinned.yml",
        FIXTURES / "pwn-request.yml",
        FIXTURES / "workflow-run.yml",
        FIXTURES / "injection.yml",
        FIXTURES / "permissions-missing.yml",
        FIXTURES / "permissions-write-all.yml",
        FIXTURES / "permissions-contents.yml",
        FIXTURES / "checkout.yml",
        FIXTURES / "secrets.yml",
        FIXTURES / "self-hosted.yml",
        FIXTURES / "composite-bad" / "action.yml",
    ):
        covered |= _ids(path)
    assert covered == {rule.id for rule in RULES}


def test_unpinned_ignores_local_and_digests() -> None:
    report = scan([FIXTURES / "unpinned.yml"])
    assert {item.rule_id for item in report.findings} == {"unpinned-action"}
    assert [item.message for item in report.findings] == [
        "job build uses actions/checkout@v4, which is not pinned to a 40-character commit SHA",
        "job build uses example/setup-tool@v1, which is not pinned to a 40-character commit SHA",
        "job build uses docker://alpine:3.19, which is not pinned to an image digest",
    ]
    assert all(PIN not in item.message for item in report.findings)
    assert all("sha256:0123456789abcdef" not in item.message for item in report.findings)


def test_actions_org_can_be_exempted() -> None:
    report = scan([FIXTURES / "unpinned.yml"], options=Options(allow_actions_refs=True))
    assert report.errors == ()
    assert [item.message for item in report.findings] == [
        "job build uses example/setup-tool@v1, which is not pinned to a 40-character commit SHA",
        "job build uses docker://alpine:3.19, which is not pinned to an image digest",
    ]


def test_pwn_request_and_base_checkout() -> None:
    pwn = scan([FIXTURES / "pwn-request.yml"])
    assert {item.rule_id for item in pwn.findings} == {"pwn-request", "script-injection"}
    assert sum(item.rule_id == "pwn-request" for item in pwn.findings) == 2
    assert _ids(FIXTURES / "workflow-run.yml") == {"pwn-request"}
    assert _ids(FIXTURES / "base-checkout.yml") == set()


def test_injection_labels() -> None:
    report = scan([FIXTURES / "injection.yml"])
    labels = {item.message.split("interpolates ", 1)[1].split(" into ", 1)[0] for item in report.findings}
    assert labels == {
        "github.event.comment.body",
        "github.event.commits",
        "github.event.issue.body",
        "github.event.issue.title",
        "github.event.pull_request.body",
        "github.head_ref",
    }
    assert len(report.findings) == 6


def test_permission_rules() -> None:
    assert _ids(FIXTURES / "permissions-missing.yml") == {"permissions-missing"}
    write_all = scan([FIXTURES / "permissions-write-all.yml"])
    assert [item.message for item in write_all.findings] == [
        "workflow permissions are write-all",
        "job extra permissions are write-all",
    ]
    contents = scan([FIXTURES / "permissions-contents.yml"])
    assert {item.rule_id for item in contents.findings} == {"permissions-contents-write"}
    assert len(contents.findings) == 2


def test_checkout_credentials() -> None:
    report = scan([FIXTURES / "checkout.yml"])
    assert len(report.findings) == 2
    assert {item.rule_id for item in report.findings} == {"checkout-persist-credentials"}


def test_secrets_and_guards(tmp_path: Path) -> None:
    report = scan([FIXTURES / "secrets.yml"])
    assert sum(item.rule_id == "secret-untrusted" for item in report.findings) == 2
    assert sum(item.rule_id == "secrets-inherit" for item in report.findings) == 1
    assert _ids(FIXTURES / "pull-request-secret.yml") == set()

    guarded = tmp_path / "guarded.yml"
    guarded.write_text(
        """
name: guarded
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  label:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo ok
  reply:
    if: contains(fromJSON('["OWNER","MEMBER"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo ok
""",
        encoding="utf-8",
    )
    assert _ids(guarded) == set()

    open_comment = tmp_path / "open.yml"
    open_comment.write_text(
        """
name: open
on:
  issue_comment:
permissions:
  contents: read
jobs:
  reply:
    if: github.event.comment.author_association == 'NONE'
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo ok
""",
        encoding="utf-8",
    )
    assert _ids(open_comment) == {"secret-untrusted"}

    inherit = tmp_path / "inherit.yml"
    inherit.write_text(
        """
on: push
permissions:
  contents: read
jobs:
  call:
    uses: ./.github/workflows/deploy.yml
    secrets: inherit
""",
        encoding="utf-8",
    )
    assert _ids(inherit) == {"secrets-inherit"}


def test_self_hosted_only_on_public_triggers(tmp_path: Path) -> None:
    assert _ids(FIXTURES / "push-runner.yml") == set()
    report = scan([FIXTURES / "self-hosted.yml"])
    assert len(report.findings) == 2
    assert all("pull_request" in item.message for item in report.findings)

    matrix = tmp_path / "matrix.yml"
    matrix.write_text(
        f"""
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    strategy:
      matrix:
        runner: [ubuntu-latest, self-hosted]
    runs-on: ${{{{ matrix.runner }}}}
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
""",
        encoding="utf-8",
    )
    assert _ids(matrix) == {"self-hosted-public"}


def test_composite_actions(tmp_path: Path) -> None:
    assert _ids(FIXTURES / "composite-bad" / "action.yml") == {
        "checkout-persist-credentials",
        "unpinned-action",
    }
    assert _ids(FIXTURES / "composite-good" / "action.yml") == set()
    generated = tmp_path / "action.yml"
    generated.write_text(
        "\n".join(
            [
                "name: risky",
                "description: Generated here so the repo does not ship a vulnerable action.yml.",
                "runs:",
                "  using: composite",
                "  steps:",
                "    - shell: bash",
                '      run: echo "${{ github.event.issue.title }}"',
            ]
        ),
        encoding="utf-8",
    )
    assert _ids(generated) == {"script-injection"}


def test_inline_ignore() -> None:
    report = scan([FIXTURES / "inline-ignore.yml"])
    assert report.findings == ()
    assert report.ignored == 2


def test_repo_discovery_skips_vendor_and_nested_workflows() -> None:
    report = scan([FIXTURES / "repo"])
    assert report.errors == ()
    assert report.files_checked == 2
    assert {item.rule_id for item in report.findings} == {"permissions-missing"}


def test_short_ignore_does_not_hide_the_finding(tmp_path: Path) -> None:
    workflow = tmp_path / "short.yml"
    workflow.write_text(
        """
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: example/action@v1  # gha-audit: ignore[unpinned-action] later
""",
        encoding="utf-8",
    )
    report = scan([workflow])
    assert {item.rule_id for item in report.findings} == {"unpinned-action"}
    assert report.errors
    assert "justification" in report.errors[0]


def test_python_tag_is_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    workflow = tmp_path / "evil.yml"
    workflow.write_text(
        f"on: !!python/object/apply:pathlib.Path.touch [{str(marker)!r}]\n",
        encoding="utf-8",
    )
    report = scan([workflow])
    assert not marker.exists()
    assert report.findings == ()
    assert report.errors


def test_alias_limit(tmp_path: Path) -> None:
    lines = ["a: &a 1", *(f"b{index}: *a" for index in range(1200))]
    path = tmp_path / "bomb.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = scan([path])
    assert report.findings == ()
    assert any("alias" in error for error in report.errors)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_head_checkout_shapes(tmp_path: Path) -> None:
    bracket = _write(
        tmp_path,
        "bracket.yml",
        f"""
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          ref: ${{{{ github['event']['pull_request']['head']['sha'] }}}}
          persist-credentials: false
      - run: gh pr checkout ${{{{ github.event.pull_request.number }}}}
      - uses: ./.github/actions/build
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
""",
    )
    report = scan([bracket])
    assert report.errors == ()
    assert sum(item.rule_id == "pwn-request" for item in report.findings) == 3

    copied = _write(
        tmp_path,
        "copied.yml",
        f"""
on: workflow_run
permissions:
  contents: read
jobs:
  build:
    env:
      HEAD: ${{{{ github.event.workflow_run.pull_requests[0].head.sha }}}}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          ref: ${{{{ env.HEAD }}}}
          persist-credentials: false
""",
    )
    assert _ids(copied) == {"pwn-request"}

    pull_ref = _write(
        tmp_path,
        "pull-ref.yml",
        """
on: workflow_run
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: git fetch origin refs/pull/7/head && git checkout FETCH_HEAD
""",
    )
    assert _ids(pull_ref) == {"pwn-request"}

    safe = _write(
        tmp_path,
        "base-ref.yml",
        f"""
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          ref: ${{{{ github.event.pull_request.base.sha }}}}
          persist-credentials: false
      - run: git checkout ${{{{ github.sha }}}}
""",
    )
    assert _ids(safe) == set()


def test_false_credential_spellings_and_checkout_case(tmp_path: Path) -> None:
    spelled = _write(
        tmp_path,
        "spell.yml",
        f"""
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: Actions/Checkout@{PIN}
        with:
          persist-credentials: no
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: off
""",
    )
    assert _ids(spelled) == set()


def test_self_hosted_label_is_exact(tmp_path: Path) -> None:
    custom = _write(
        tmp_path,
        "custom.yml",
        f"""
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: my-self-hosted
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
""",
    )
    assert _ids(custom) == set()
    quoted = _write(
        tmp_path,
        "quoted.yml",
        f"""
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ${{{{ 'self-hosted' }}}}
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
""",
    )
    assert _ids(quoted) == {"self-hosted-public"}


def test_secret_context_and_guard_order(tmp_path: Path) -> None:
    quoted = _write(
        tmp_path,
        "quoted-secret.yml",
        """
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ 'secrets.NPM_TOKEN' }}"
""",
    )
    assert _ids(quoted) == set()

    dumped = _write(
        tmp_path,
        "dumped.yml",
        """
on: issue_comment
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ toJSON(secrets) }}"
""",
    )
    assert _ids(dumped) == {"secret-untrusted"}

    reversed_guard = _write(
        tmp_path,
        "reversed.yml",
        """
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    if: github.repository == github.event.pull_request.head.repo.full_name
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: echo ok
""",
    )
    assert _ids(reversed_guard) == set()


def test_script_sinks_and_extra_contexts(tmp_path: Path) -> None:
    workflow = _write(
        tmp_path,
        "sinks.yml",
        f"""
on: issue_comment
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@{PIN}
        with:
          script: console.log("${{{{ github.event.comment.body }}}}")
      - run: echo "${{{{ github.event.head_commit.committer.email }}}}"
      - run: echo "${{{{ github.event.pull_request.head.repo.default_branch }}}}"
      - env:
          BODY: ${{{{ github.event.comment.body }}}}
        run: echo "$BODY"
""",
    )
    report = scan([workflow])
    assert report.errors == ()
    labels = {item.message.split("interpolates ", 1)[1].split(" into ", 1)[0] for item in report.findings}
    assert labels == {
        "github.event.comment.body",
        "github.event.head_commit.committer.email",
        "github.event.pull_request.head.repo.default_branch",
    }
    assert any("github-script" in item.message for item in report.findings)
    assert sum(item.rule_id == "script-injection" for item in report.findings) == 3


def test_merge_keeps_the_explicit_key(tmp_path: Path) -> None:
    workflow = _write(
        tmp_path,
        "merge.yml",
        f"""
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - &creds
        with:
          persist-credentials: false
      - <<: *creds
        uses: actions/checkout@{PIN}
      - uses: example/tool@v1
""",
    )
    report = scan([workflow])
    assert report.errors == ()
    assert [item.rule_id for item in report.findings] == ["unpinned-action"]
    assert "example/tool@v1" in report.findings[0].message


def test_unquoted_on_is_the_trigger(tmp_path: Path) -> None:
    workflow = _write(
        tmp_path,
        "trigger.yml",
        """
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo ok
""",
    )
    assert _ids(workflow) == {"self-hosted-public"}


def test_action_symlink_stays_inside_the_tree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\npermissions:\n  contents: read\njobs: {}\n",
        encoding="utf-8",
    )
    real = repo / "real"
    real.mkdir()
    (real / "action.yml").write_text(
        "name: real\n"
        "description: linked\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: example/tool@v1\n"
        "      shell: bash\n",
        encoding="utf-8",
    )
    (repo / "linked").symlink_to(real, target_is_directory=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "action.yml").write_text(
        "name: out\n"
        "description: skipped\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: evil/tool@v1\n"
        "      shell: bash\n",
        encoding="utf-8",
    )
    (repo / "escape").symlink_to(outside, target_is_directory=True)
    report = scan([repo])
    assert report.errors == ()
    assert report.files_checked == 2
    assert [item.message for item in report.findings] == [
        "composite action uses example/tool@v1, which is not pinned to a 40-character commit SHA"
    ]

from gha_audit.expr import contains_secret, leaking_contexts


def test_direct_interpolation_leaks() -> None:
    assert leaking_contexts('echo "${{ github.event.issue.title }}"') == ["github.event.issue.title"]


def test_boolean_checks_do_not_leak() -> None:
    script = "\n".join(
        [
            "echo ${{ contains(github.event.issue.title, 'bug') }}",
            "echo ${{ startsWith(github.head_ref, 'feat') }}",
            "echo ${{ github.event.issue.title == 'ship it' }}",
            "echo ${{ !contains(github.event.pull_request.body, 'skip') }}",
        ]
    )
    assert leaking_contexts(script) == []


def test_format_and_or_leak() -> None:
    assert leaking_contexts("echo ${{ format('{0}', github.event.issue.body) }}") == ["github.event.issue.body"]
    assert leaking_contexts("echo ${{ github.event.issue.title || 'fallback' }}") == ["github.event.issue.title"]


def test_index_and_commit_message() -> None:
    assert leaking_contexts("echo ${{ github['event']['issue']['title'] }}") == ["github.event.issue.title"]
    assert leaking_contexts("echo ${{ github.event.commits[0].message }}") == ["github.event.commits"]
    assert leaking_contexts("echo ${{ github.event.pages[0].page_name }}") == ["github.event.pages"]
    assert leaking_contexts("echo ${{ github.event.workflow_run.head_commit.message }}") == [
        "github.event.workflow_run.head_commit"
    ]


def test_secret_references() -> None:
    assert contains_secret("echo ${{ secrets.NPM_TOKEN }}")
    assert contains_secret("echo ${{ secrets['NPM_TOKEN'] }}")
    assert contains_secret("echo ${{ github.token }}")
    assert contains_secret("echo ${{ toJSON(secrets) }}")
    assert contains_secret("echo ${{ secrets }}")
    assert not contains_secret("echo no secrets here")
    assert not contains_secret("echo ${{ github.token_name }}")
    assert not contains_secret("echo ${{ 'secrets.NPM_TOKEN' }}")
    assert not contains_secret("echo ${{ 'github.token' }}")
    assert not contains_secret("echo ${{ env.secrets }}")

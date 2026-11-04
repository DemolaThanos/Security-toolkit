# gha-audit

Checks GitHub Actions workflow files and composite actions for patterns that show up in real supply-chain incidents: unpinned actions, `pull_request_target` checking out a pull request head, untrusted `${{ }}` values spliced into `run:` scripts, broad token permissions, checkout credentials left in the workspace, secrets handed to untrusted events, and self-hosted runners on those events.

It reads YAML. It does not run a workflow, clone an action, or talk to GitHub. `devsecops-scan` runs scanners inside CI; this checks the workflow files those scanners run from.

`examples/secure.yml` stays quiet. `examples/insecure.yml` is the opposite, on purpose.

## Install

```bash
pip install .
```

Python 3.11 or newer. The only runtime dependency is PyYAML, and the loader is a `SafeLoader`.

## Usage

```bash
gha-audit
gha-audit .github/workflows
gha-audit . --fail-on high
gha-audit examples/insecure.yml --format sarif --output gha-audit.sarif
```

With no paths, it reads `.github/workflows`. A directory that contains `.github/workflows` is treated as a repository: that folder is scanned, and so is every `action.yml` under it. `node_modules`, `vendor`, `.git`, and virtualenvs are skipped. Pass a file to check just that workflow or composite action.

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` a file could not be read, the path is rejected, an ignore is invalid, or there was nothing to scan. The default threshold is `high`. Findings below the threshold are still printed. `GHA_AUDIT_LOG_FORMAT=json` writes one JSON object per log line.

`--format` is `table` (default), `json`, or `sarif`. SARIF is 2.1.0. Each result has `partialFingerprints.primaryLocationLineHash`, and a file that could not be parsed is a `parse-error` result. Relative paths have to stay inside the working directory after symlinks are resolved. A workflow passed as an absolute path is read from that path. `--output` and `--config` are different: the file they name has to resolve inside the working directory, including when the path is absolute or a symlink.

`gha-audit examples/insecure.yml` prints one row per finding. The run below is shortened; the real table is aligned:

```
medium    permissions-missing           examples/insecure.yml:3   workflow has no top-level permissions block
high      unpinned-action               examples/insecure.yml:14  job build uses actions/checkout@v4, which is not pinned to a 40-character commit SHA
critical  pwn-request                   examples/insecure.yml:16  job build checks out untrusted head code on pull_request_target
critical  script-injection              examples/insecure.yml:19  job build interpolates github.event.pull_request.title into a run script
11 findings
```

## CI

`security-events: write` is what the upload step needs. The audit itself only reads the checkout.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
    with:
      python-version: "3.12"
  - name: Install
    run: python -m pip install ./gha-audit
  - name: Audit workflows
    run: gha-audit . --format sarif --output gha-audit.sarif --fail-on high
  - name: Upload SARIF
    uses: github/codeql-action/upload-sarif@<40-character-sha>
    with:
      sarif_file: gha-audit.sarif
      category: gha-audit
```

Pin `github/codeql-action/upload-sarif` to a full commit SHA, the same way the workflows in this repo pin their actions. `gha-audit .` is the repository root, so composite `action.yml` files are included. `gha-audit` on its own only reads `.github/workflows`.

## Ignore a finding

An ignore needs a justification of at least 12 characters. `todo`, `ignore`, and `n/a` are rejected. An unknown rule id is an error and does not hide the finding.

Inline, on the line or on the line above the step. A comment on its own line covers the next line and lines nested under it.

```yaml
# gha-audit: ignore[unpinned-action] internal mirror reviews this tag every Monday
- uses: example/internal-action@v1
```

`*` ignores every rule on those lines. Several ids can be listed: `ignore[unpinned-action, checkout-persist-credentials]`.

The same acceptances can live in `.gha-audit.toml` in the working directory, or in the file passed to `--config`:

```toml
# Floating tags for actions/* only. Third-party actions still need a SHA.
allow_actions_refs = false

[[ignore]]
rule = "permissions-contents-write"
path = ".github/workflows/release.yml"
justification = "The release job pushes the tag and opens the GitHub release."
```

`path` is optional. `*` matches every file. A name without a slash matches the file name. `rule` is a rule id or `*`.

`--allow-actions-refs` is the same switch as `allow_actions_refs` and forces it on.

## Rules

| Rule | Severity | What it catches |
| --- | --- | --- |
| `unpinned-action` | high | `uses` is not a 40-character commit SHA. A `docker://` image must use a `sha256` or `sha512` digest. A local `./` action is not pinned by SHA. `actions/*` is included unless `allow_actions_refs` is set |
| `pwn-request` | critical | `pull_request_target` or `workflow_run` checks out the head SHA, head ref, head repository, or `refs/pull/.../head` or `/merge`. Bracket notation (`github['event']...`) counts. So does `gh pr checkout`, a `git checkout` of that ref, a head SHA copied into `env:` and read back in the same job, and a `ref` passed into a local `./` action |
| `script-injection` | critical | an attacker-controlled context is interpolated into `run:` or into `actions/github-script`'s `script` input. The contexts are the ones in GitHub Security Lab's untrusted-input list: issue, pull request, comment, review, and discussion title or body, `github.head_ref`, head ref and label, commit messages and author or committer name and email, `pages` page names, the default branch of a pull request head repo, and `workflow_run` head branch, display title, head commit, and `pull_requests`. `contains`, `startsWith`, `endsWith`, and comparisons are not this rule. `&&` and `||` are, because they can return an operand. Passing the value through `env:` is the fix |
| `permissions-missing` | medium | no top-level `permissions` block. A job-level block does not clear this. `permissions: {}` is an explicit empty token and is not this rule |
| `permissions-write-all` | high | workflow or job `permissions: write-all` |
| `permissions-contents-write` | low | `contents: write` on a job that does not push or call a known release or commit action. Workflow-level `contents: write` is flagged when a job that inherits it does not publish. A job that sets its own `permissions` does not inherit the workflow value |
| `checkout-persist-credentials` | medium | `actions/checkout` without `persist-credentials` set to false. `false`, `no`, and `off` count. The action name is matched case-insensitively |
| `secret-untrusted` | high | `secrets`, `secrets.*`, or `github.token` is passed to a step on `pull_request_target`, `workflow_run`, or an issue, comment, review, or discussion event. A quoted literal such as `'secrets.TOKEN'` does not count. A same-repo comparison written either way around, or an `OWNER` / `MEMBER` / `COLLABORATOR` guard on the job or step, suppresses it |
| `secrets-inherit` | high | a reusable workflow is called with `secrets: inherit` |
| `self-hosted-public` | high | `runs-on` is the label `self-hosted`, a runner `group`, or a matrix value `self-hosted`, and the workflow has a public trigger such as `pull_request`. A longer label that merely contains the words is not this rule |

`pull_request` is a public trigger for self-hosted runners. It is not in `secret-untrusted`, because GitHub does not pass secrets to workflows run from forks. `pull_request_target` is in both.

A job is treated as needing `contents: write` when a step runs `git push`, `gh release create`, `gh release upload`, or `gh pr create`, or uses one of: `ad-m/github-push-action`, `crazy-max/ghaction-github-pages`, `endbug/add-and-commit`, `jamesives/github-pages-deploy-action`, `ncipollo/release-action`, `peaceiris/actions-gh-pages`, `peter-evans/create-pull-request`, `softprops/action-gh-release`, `stefanzweifel/git-auto-commit-action`.

## Limitations

actionlint is the syntax checker: workflow schema, expression types, and shellcheck. [zizmor](https://github.com/zizmorcore/zizmor) covers a wider set of Actions bugs than this tool does, including obfuscated expressions, cache poisoning, known-vulnerable actions, and impostor commits. gha-audit does not. The untrusted-context list follows GitHub Security Lab's published note, [Keeping your GitHub Actions and workflows secure: Untrusted input](https://securitylab.github.com/research/github-actions-untrusted-input/). The code is not taken from zizmor or actionlint.

The guard check looks for a few well-known expressions. It does not evaluate `if:`. A guard that is true for some other reason is still a finding, and a guard written in an unusual shape may be missed. A head SHA copied through a step output, or through another job, is not followed. A local action is not inlined into the workflow that calls it, except for a `ref`-style input written on the calling step. Run `gha-audit .` if composite `action.yml` files should be checked on their own. `gha-audit` with no path only reads `.github/workflows`.

`contents: write` is a heuristic. A custom publish script that does not look like `git push` or `gh release` is flagged. Suppress it with a justification.

Reusable workflows are not fetched. A `uses` call is judged from the caller only. `permissions: read-all` is not flagged. A `runs-on` group is reported even when the group is a GitHub-hosted larger runner, because the file does not say who owns the group. A self-hosted runner selected only by a custom label is not detected.

Script injection covers the contexts in the table, on `run:` and on `actions/github-script`. It does not cover every action input. A context buried in an expression this parser cannot read is flagged if the text of that context is still there.

`allow_actions_refs` accepts any ref of `actions/*`, including branches. It does not exempt any other owner, and it does not exempt `docker://` images.

A file that cannot be parsed is an error. The command exits 2. It is not reported as clean. Files over 1 MB are rejected. Documents deeper than 64 levels are rejected. YAML anchors are capped on the way in and again while they expand, so a small file cannot blow up into a huge one. Merge keys (`<<`) are expanded. A repeated key in the file itself is an error. `on:` stays the trigger key; YAML 1.1 would otherwise read it as a boolean.

This is not a substitute for zizmor, actionlint, or OpenSSF Scorecard.

## License

MIT

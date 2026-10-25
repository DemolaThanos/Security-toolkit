# devsecops-scan

Scans a working tree for secrets, a short list of risky code patterns, and dependencies listed in an OSV feed. It can also do one passive header check against a URL you are allowed to request. Reports are text, JSON, or SARIF. A bucket or a webhook is optional.

This is a CI gate, not a replacement for Semgrep, Gitleaks, or a full advisory database. It reads the files in the working tree. It does not walk git history.

## Install

```bash
pip install .
pip install ".[s3]"   # only for S3 uploads
```

Python 3.11 or newer.

## Usage

```bash
devsecops-scan scan . --fail-on high --format sarif --output devsecops-scan.sarif
devsecops-scan scan . --dast-url https://app.example --i-am-authorized
```

`--i-am-authorized` (or `DEVSECOPS_SCAN_DAST_AUTHORIZED=1`) is required before any DAST request. The scanner resolves each host once and connects to those addresses. A redirect back to a host it already resolved reuses that answer, so a second DNS reply cannot move the connection. It refuses link-local addresses, including cloud metadata, and non-canonical spellings such as hex or octal. A TLS failure stays a failure: verification is not turned off for a second try. Redirects may continue to another public host, up to five hops. A redirect into a private or link-local address is refused.

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` the scan did not finish. A path that yields no readable file exits 2. That covers an empty directory, an exclude that matches every file, and a tree whose files are all over `max_bytes`. When `--dast-url` is set, the header check still runs.

## Configuration

`.devsecops-scan.toml` next to the scan root:

```toml
fail_on = "high"
exclude = ["fixtures/"]
max_bytes = 1000000
secrets = true
sast = true
sca = true
require_pins = true
advisories = "advisories/osv.json"
```

CLI flags override the file. `--no-config` skips the file, so a committed config cannot turn checks off, exclude the tree, lower `max_bytes`, or replace the advisory feed. `require_pins` defaults to true, so a dependency with no exact version is reported at medium. `--allow-unpinned` turns that report off. An advisory with no severity label and no CVSS v3 score is treated as high. A CVSS v3 base score is used when the feed does not include a label.

## Credentials

A file in the tree is untrusted. `.devsecops-scan.toml` cannot set a destination or a credential. These keys are rejected: `s3_bucket`, `s3_key`, `s3_kms_key_id`, `webhook_url`, `webhook_token`, `aws_role_arn`, `token`, `password`.

| Variable | Source | Use |
| --- | --- | --- |
| `DEVSECOPS_SCAN_S3_BUCKET` | environment or `--s3-bucket` | bucket for the report |
| `DEVSECOPS_SCAN_S3_KEY` | environment or `--s3-key` | object key |
| `DEVSECOPS_SCAN_S3_KMS_KEY_ID` | environment or `--s3-kms-key-id` | KMS key id; empty uses SSE-S3 |
| `DEVSECOPS_SCAN_WEBHOOK_URL` | environment or `--webhook-url` | HTTPS endpoint with no user, password, or token in the URL |
| `DEVSECOPS_SCAN_WEBHOOK_TOKEN` | environment only | bearer token, for example `${WEBHOOK_TOKEN}` |
| `AWS_ROLE_ARN` | Actions secret `secrets.AWS_ROLE_ARN` | role assumed by the publish job (`aws-role-arn`) |

`DEVSECOPS_SCAN_DAST_AUTHORIZED` and `DEVSECOPS_SCAN_LOG_FORMAT` are not credentials. `DEVSECOPS_SCAN_LOG_FORMAT=json` writes one JSON object per log line.

Webhooks are HTTPS, the connection is pinned the same way as DAST, and redirects are not followed. S3 objects are encrypted with SSE-S3, or with the KMS key id when one is set. Bucket and key names are checked before the upload. The workflow does not embed long-lived cloud keys.

An `advisories` path in the config file has to stay inside the scan root. `--advisories` on the command line may point anywhere the operator can read.

A line containing `devsecops-scan: ignore` is skipped. `node_modules`, `.git`, virtualenvs, tool caches, and `vendor` are not walked. Other hidden directories, including `.github`, are scanned. Symlinks that resolve outside the scan root are skipped. The walk stops after 50,000 files. Files over `max_bytes` are skipped and counted. `-r` and `-c` lines in `requirements.txt` are read only when the included file stays inside that root. `go.mod` `replace` directives are what get checked when they name a module and a version. Lockfiles are still checked for secrets.

## Advisories

`src/devsecops_scan/advisories/starter.json` is a small OSV snapshot for `requests` (GHSA-9wx4-h78v-vm56, GHSA-9hjg-9r4m-mvj7, GHSA-gc5v-m9x4-r6x2). Replace it with an export from your own feed. Affected ranges are walked in order, so a package that was fixed and later reintroduced is still reported. Supported manifests: `requirements.txt` exact `==` pins, npm `package-lock.json` (and exact versions in `package.json` when no lock is present), and `go.mod`.

## GitHub Actions

Composite action, after `setup-python`:

```yaml
- uses: DemolaThanos/Security-toolkit/devsecops-scan@<commit>
  with:
    fail-on: high
```

Reusable workflow: `.github/workflows/security-scan.yml`.

```yaml
jobs:
  security:
    uses: DemolaThanos/Security-toolkit/.github/workflows/security-scan.yml@<40-hex-sha>
    with:
      fail-on: high
      toolkit-ref: <same 40-hex-sha>
    secrets:
      aws-role-arn: ${{ secrets.AWS_ROLE_ARN }}
```

`toolkit-ref` has to be that commit SHA. A branch name is rejected. The scan path is relative to the caller checkout. The composite action and this workflow both pass `--no-config`. The scan job does not request `id-token`. When `s3-bucket` is set, a second job assumes `aws-role-arn` and uploads the SARIF. The workflow does not embed long-lived cloud keys.

## Rules

Secret rules match AWS key ids, GitHub tokens, GitLab personal access tokens, npm tokens, Slack tokens and webhooks, Stripe live keys, PyPI tokens, private-key blocks, and credential assignments. The AWS documentation example key is ignored. Finding messages do not include the matched secret.

SAST rules are limited to `eval`/`exec`, `shell=True`, `os.system`/`os.popen`, unsafe `yaml.load`, `pickle`, `verify=False`, string-built SQL, `innerHTML`, `dangerouslySetInnerHTML`, and JWT algorithm `none`.

SARIF results include `partialFingerprints.primaryLocationLineHash` so a code-scanning importer can keep a stable identity for a result.

Passive DAST checks HSTS, CSP, `X-Content-Type-Options`, clickjacking controls, and `Referrer-Policy` on the final response.

## License

MIT

# Security

Report a vulnerability in this toolkit privately to the repository owner. Do not open a public issue for a flaw in a scanner, a manifest linter, or a client that connects to a host.

If a credential was committed, including in an old commit, report that privately as well. Say which file and commit, and rotate the credential. Do not paste the value into the report. History is not rewritten from a pull request. The owner has to approve that.

CI runs gitleaks 8.30.1 over the full clone (`fetch-depth: 0`) with `.gitleaks.toml`. A pre-commit hook runs the same scanner on what you are about to commit. `.gitignore` ignores `.env` files, private keys, and local coverage output. That does not remove a secret that is already in history.

These tools are small, offline-first checks. They are not a substitute for Gitleaks, Semgrep, Trivy, kube-linter, or testssl. Each README says what that tool will and will not do.

stride-model is a STRIDE review generator for a YAML system model. It does not exchange diagrams, model authorization, or run a threat-model lifecycle.

tfplan-guard reads a Terraform plan or state JSON file you pass on the command line. It does not run Terraform, call AWS, or parse HCL.

subtake reads hostnames you pass and checks them for dangling CNAMEs. It does not claim those names or brute-force labels. It refuses to run without `--i-am-authorized`, does not follow redirects, and will not connect to a non-public address.

corsprobe sends GET and OPTIONS, with a crafted Origin, to URLs you pass. It refuses to run without `--i-am-authorized`. It does not send a body, cookies, or Authorization. TLS is verified. It will not connect to a link-local, documentation, or transition address, and it will not follow a redirect from a public address onto a LAN. A loopback, RFC 1918, or IPv6 unique-local address you named can be checked.

A report in a repository that is being scanned is untrusted input. Destinations and credentials are not stored in this repository. The reusable workflow and the composite action pass `--no-config`, so a committed `.devsecops-scan.toml` cannot turn checks off or choose a destination. devsecops-scan accepts destinations only from the environment or the command line:

- `DEVSECOPS_SCAN_S3_BUCKET`, `DEVSECOPS_SCAN_S3_KEY`, `DEVSECOPS_SCAN_S3_KMS_KEY_ID` (or `--s3-bucket`, `--s3-key`, `--s3-kms-key-id`)
- `DEVSECOPS_SCAN_WEBHOOK_URL` (or `--webhook-url`); the URL must be HTTPS and must not embed a user, password, or token
- `DEVSECOPS_SCAN_WEBHOOK_TOKEN` (environment only; use a value such as `${WEBHOOK_TOKEN}`)

The reusable workflow assumes a role from the Actions secret `secrets.AWS_ROLE_ARN`, passed as `aws-role-arn`. A config file that sets `s3_bucket`, `s3_key`, `s3_kms_key_id`, `webhook_url`, `webhook_token`, `aws_role_arn`, `token`, or `password` is rejected.

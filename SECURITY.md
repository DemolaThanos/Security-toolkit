# Security

Report a vulnerability in this toolkit privately to the repository owner. Do not open a public issue for a flaw in a scanner, a manifest linter, or a client that connects to a host.

These tools are small, offline-first checks. They are not a substitute for Gitleaks, Semgrep, Trivy, kube-linter, or testssl. Each README says what that tool will and will not do.

stride-model is a STRIDE review generator for a YAML system model. It does not exchange diagrams, model authorization, or run a threat-model lifecycle.

A report in a repository that is being scanned is untrusted input. Destinations and credentials are not stored in this repository. The reusable workflow and the composite action pass `--no-config`, so a committed `.devsecops-scan.toml` cannot turn checks off or choose a destination. devsecops-scan accepts destinations only from the environment or the command line:

- `DEVSECOPS_SCAN_S3_BUCKET`, `DEVSECOPS_SCAN_S3_KEY`, `DEVSECOPS_SCAN_S3_KMS_KEY_ID` (or `--s3-bucket`, `--s3-key`, `--s3-kms-key-id`)
- `DEVSECOPS_SCAN_WEBHOOK_URL` (or `--webhook-url`); the URL must be HTTPS and must not embed a user, password, or token
- `DEVSECOPS_SCAN_WEBHOOK_TOKEN` (environment only; use a value such as `${WEBHOOK_TOKEN}`)

The reusable workflow assumes a role from the Actions secret `secrets.AWS_ROLE_ARN`, passed as `aws-role-arn`. A config file that sets `s3_bucket`, `s3_key`, `s3_kms_key_id`, `webhook_url`, `webhook_token`, `aws_role_arn`, `token`, or `password` is rejected.

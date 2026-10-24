# Security

Report a vulnerability in this toolkit privately to the repository owner. Do not open a public issue for a flaw in a scanner, a manifest linter, or a client that connects to a host.

These tools are small, offline-first checks. They are not a substitute for Gitleaks, Semgrep, Trivy, kube-linter, or testssl. Each README says what that tool will and will not do.

A report in a repository that is being scanned is untrusted input. Destinations that use ambient credentials (S3, webhook bearer tokens) are accepted only from the command line or the environment, not from a config file in the tree.

# Security toolkit

[![CI](https://github.com/DemolaThanos/Security-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/DemolaThanos/Security-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Reusable application-security tools. Each project stands on its own and can be copied into another repo.

| Project | What it does |
| --- | --- |
| [devsecops-scan](devsecops-scan/) | Secret, SAST, and dependency advisory scan for GitHub Actions, with SARIF output, a passive DAST gate, and optional S3 or webhook publishing |
| [k8s-harden](k8s-harden/) | Checks Kubernetes manifests for weak RBAC, secrets in the clear, and missing workload isolation |
| [tfplan-guard](tfplan-guard/) | Checks AWS Terraform plan and state JSON for public storage, open security groups, and weak encryption or IAM |
| [stride-model](stride-model/) | STRIDE review generator for a YAML system model |
| [authrecon](authrecon/) | Authorised reconnaissance of one web host: security headers, TLS, and a short TCP connect check |
| [subtake](subtake/) | Authorised subdomain-takeover check for dangling CNAMEs, with table, JSON, and SARIF output |
| [gha-audit](gha-audit/) | Static checks for GitHub Actions workflows and composite actions, with table, JSON, and SARIF output |
| [corsprobe](corsprobe/) | Authorised CORS checks for reflection, null and wildcard origins, bypasses, and permissive preflights |

`.github/workflows/ci.yml` lints, typechecks, runs bandit, and tests every project on Python 3.11 and 3.12, and scans the git history with gitleaks. `.github/workflows/security-scan.yml` is the reusable scan workflow. `.github/workflows/release.yml` builds wheels when a version tag is pushed. It does not publish them.

Report a vulnerability privately. See [SECURITY.md](SECURITY.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Third-party notes: [NOTICE](NOTICE).

## Licence

MIT. Copyright 2026 Ademola (Hammed) Gbadamosi.

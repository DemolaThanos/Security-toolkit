# Security toolkit

Reusable application-security tools. Each project stands on its own and can be copied into another repo.

| Project | What it does |
| --- | --- |
| [devsecops-scan](devsecops-scan/) | Secret, SAST, and dependency advisory scan for GitHub Actions, with SARIF output, a passive DAST gate, and optional S3 or webhook publishing |
| [k8s-harden](k8s-harden/) | Checks Kubernetes manifests for weak RBAC, secrets in the clear, and missing workload isolation |
| [tfplan-guard](tfplan-guard/) | Checks AWS Terraform plan and state JSON for public storage, open security groups, and weak encryption or IAM |
| [stride-model](stride-model/) | STRIDE review generator for a YAML system model |
| [authrecon](authrecon/) | Authorised reconnaissance of one web host: security headers, TLS, and a short TCP connect check |

`.github/workflows/ci.yml` lints and tests every project on Python 3.11 and 3.12. `.github/workflows/security-scan.yml` is the reusable scan workflow. Report a vulnerability privately; see [SECURITY.md](SECURITY.md).

## License

MIT

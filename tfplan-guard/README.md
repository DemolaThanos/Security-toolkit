# tfplan-guard

Checks AWS Terraform for security misconfigurations by reading the JSON from `terraform show -json`. It uses the resolved values in a plan or a state file, so it does not parse HCL.

It does not run Terraform and it does not call AWS. Account-level controls that are not in the file (an organization trail, account-wide S3 Block Public Access, default EBS encryption) are invisible.

## Install

```bash
pip install .
```

Python 3.11 or newer. There are no runtime dependencies.

## Usage

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
tfplan-guard check plan.json --fail-on high
tfplan-guard check plan.json --format sarif --output tfplan-guard.sarif
tfplan-guard check state.json --suppressions tfplan-guard.toml
```

`state.json` is `terraform show -json terraform.tfstate`. A directory of JSON files is scanned the same way. JSON that is not a plan or state is skipped when you pass a directory. A single file that is not a plan or state is an error.

Exit codes: `0` nothing at or above the threshold, `1` findings, `2` a file could not be read, a suppression is invalid, or there was nothing to scan. The default threshold is `high`. `TFPLAN_GUARD_LOG_FORMAT=json` writes one JSON object per log line.

`examples/secure.plan.json` stays quiet. `examples/insecure.plan.json` is the opposite, on purpose.

## Suppress a finding

A suppression needs a justification of at least 12 characters. `todo`, `ignore`, and `n/a` are rejected.

Inline, as a tag that shows up in the plan:

```hcl
tags = {
  "tfplan-guard/ignore:aws-kms-rotation-disabled" = "Signing key is rotated by the platform account, not this stack."
}
```

`tfplan-guard/ignore:*` suppresses every rule on that resource. The tag value has to be known at plan time. Resources without tags, such as `aws_security_group_rule`, use a file:

```toml
[[suppress]]
rule = "aws-sg-world-sensitive-port"
address = "aws_security_group.bastion"
justification = "SSH is limited to the office CIDR published by the VPN module."
```

`address` is a resource address or a glob (`module.legacy.*` or `*`). `rule` is a rule id or `*`. An unknown rule id is an error.

## Rules

| Rule | Severity | What it catches |
| --- | --- | --- |
| `aws-s3-public-acl` | critical, or high for `authenticated-read` | canned ACL `public-read`, `public-read-write`, or `authenticated-read`, or a grant to AllUsers or AuthenticatedUsers |
| `aws-s3-public-access-block` | high | bucket with no `aws_s3_bucket_public_access_block` that sets all four restrictions |
| `aws-s3-public-policy` | critical | bucket policy Allow with Principal `*` and no Condition |
| `aws-s3-unencrypted` | high | bucket with no SSE configuration using AES256 or aws:kms |
| `aws-ebs-unencrypted` | high | `aws_ebs_volume`, instance or launch-configuration block device, or launch-template EBS mapping with `encrypted` not true |
| `aws-rds-unencrypted` | high | `storage_encrypted` is not true on an RDS instance or cluster. Aurora instances are judged on the cluster |
| `aws-rds-public` | high | `publicly_accessible` is true |
| `aws-sg-world-all-ports` | critical | ingress from `0.0.0.0/0` or `::/0` for every port, or protocol `-1` |
| `aws-sg-world-sensitive-port` | high | ingress from `0.0.0.0/0` or `::/0` that overlaps an admin or data port |
| `aws-iam-wildcard-action` | critical when Resource is also `*`, otherwise high | Allow with Action `*` or NotAction |
| `aws-iam-wildcard-resource` | high | Allow with a service-wide action such as `s3:*` and Resource `*` |
| `aws-cloudtrail-logging-disabled` | high | `enable_logging` is false |
| `aws-cloudtrail-not-multi-region` | high | `is_multi_region_trail` is not true |
| `aws-kms-rotation-disabled` | medium | symmetric `aws_kms_key` with `enable_key_rotation` not true |
| `aws-ec2-imdsv2-optional` | high | instance, launch template, or launch configuration does not set `http_tokens` to `required` |

Sensitive ports are 20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 9300, 11211, 27017, 27018, and 27019. Ports 80 and 443 are not in that set. Egress is not checked. Security group rules are read from `aws_security_group` ingress blocks, `aws_security_group_rule`, and `aws_vpc_security_group_ingress_rule`.

IAM policies are read from `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`, and `aws_iam_role` inline policies.

## CI

Producing the plan is up to the job. The check itself is:

```yaml
name: terraform-plan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install ./tfplan-guard
      - name: Show the saved plan
        run: terraform show -json tfplan > plan.json
      - name: Check
        run: tfplan-guard check plan.json --fail-on high --format sarif --output tfplan-guard.sarif
```

Upload `tfplan-guard.sarif` with GitHub code scanning if you want the results on the pull request. Pin `github/codeql-action/upload-sarif` the same way the workflows in this repo pin their actions. SARIF locations point at the plan JSON you passed in, not at the `.tf` files.

## Limitations

Resolved values only. An attribute Terraform has not computed yet is skipped, not failed. A plan that uses `-target`, or a state that does not contain a resource, cannot reveal it.

`delete` actions are ignored. A replacement (`delete` then `create`) is checked.

S3 public access blocks and encryption configs are joined on the bucket name or id. When the bucket name is still unknown, a missing block is not reported, because the link cannot be proved. A bucket policy that has any Condition is not flagged, even when the condition does not restrict the principal.

`Resource *` with a specific action is not flagged. ARN wildcards such as `arn:aws:s3:::*` are not treated as `*`. Trust policies (`assume_role_policy`) are not checked.

CloudTrail is judged only when a trail is in the file. A stack that does not manage a trail is not reported as CloudTrail being off. `enable_logging` defaults to on when the attribute is absent; `is_multi_region_trail` defaults to off.

KMS automatic rotation does not apply to asymmetric, HMAC, external, or CloudHSM keys, and those are not flagged. A computed key spec or origin is skipped.

Absent IMDS metadata, absent EBS `encrypted`, and absent RDS `storage_encrypted` are findings, matching AWS provider defaults. `http_endpoint = disabled` is not a finding. Aurora instance storage is not flagged; the cluster is.

This is not a substitute for tfsec, Checkov, or AWS Config.

## License

MIT

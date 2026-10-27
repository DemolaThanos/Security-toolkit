from __future__ import annotations

import json
import logging
from typing import Any

from tfplan_guard.models import Finding, Resource, Rule, Severity
from tfplan_guard.values import (
    Attr,
    as_int,
    as_str,
    as_str_list,
    block_pairs,
    explicitly_true,
    field,
    known_false,
    lookup,
    require_true,
)

logger = logging.getLogger("tfplan_guard.rules")

# Admin and data-plane ports. 80 and 443 are left out on purpose.
SENSITIVE_PORTS = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        110,
        135,
        143,
        445,
        1433,
        1434,
        1521,
        2049,
        2375,
        2376,
        3306,
        3389,
        5432,
        5900,
        5985,
        5986,
        6379,
        9200,
        9300,
        11211,
        27017,
        27018,
        27019,
    }
)

_WORLD = frozenset({"0.0.0.0/0", "::/0"})
_TCP_UDP = frozenset({"tcp", "udp", "6", "17"})
_ALL_PROTOCOLS = frozenset({"-1", "all", "*"})
_SSE = frozenset({"aes256", "aws:kms", "aws:kms:dsse"})
_PAB_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)
_PUBLIC_ACL = {
    "public-read": Severity.CRITICAL,
    "public-read-write": Severity.CRITICAL,
    "authenticated-read": Severity.HIGH,
}
_ALL_USERS = "http://acs.amazonaws.com/groups/global/allusers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/authenticatedusers"
# Automatic rotation is only supported for symmetric AWS_KMS keys.
_NO_ROTATION_SPEC = frozenset(
    {
        "RSA_2048",
        "RSA_3072",
        "RSA_4096",
        "ECC_NIST_P256",
        "ECC_NIST_P384",
        "ECC_NIST_P521",
        "ECC_SECG_P256K1",
        "HMAC_224",
        "HMAC_256",
        "HMAC_384",
        "HMAC_512",
        "SM2",
    }
)
_NO_ROTATION_ORIGIN = frozenset({"EXTERNAL", "AWS_CLOUDHSM"})
_IAM_POLICIES = frozenset({"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"})
_IMDS_TYPES = frozenset({"aws_instance", "aws_launch_template", "aws_launch_configuration"})
_EBS_TYPES = frozenset({"aws_instance", "aws_launch_template", "aws_launch_configuration", "aws_ebs_volume"})

RULES: tuple[Rule, ...] = (
    Rule(
        "aws-s3-public-acl",
        Severity.CRITICAL,
        "S3 bucket ACL or grant allows anonymous or authenticated-AWS access.",
        "Set the canned ACL to private and remove grants for AllUsers and AuthenticatedUsers.",
    ),
    Rule(
        "aws-s3-public-access-block",
        Severity.HIGH,
        "S3 bucket has no public access block with all four restrictions enabled.",
        "Add aws_s3_bucket_public_access_block with block_public_acls, block_public_policy, "
        "ignore_public_acls, and restrict_public_buckets set to true.",
    ),
    Rule(
        "aws-s3-public-policy",
        Severity.CRITICAL,
        "S3 bucket policy allows Principal * without a Condition.",
        "Remove the public Allow, or keep Principal * only with a Condition such as aws:SourceAccount.",
    ),
    Rule(
        "aws-s3-unencrypted",
        Severity.HIGH,
        "S3 bucket has no server-side encryption configuration in the plan or state.",
        "Add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm AES256 or aws:kms.",
    ),
    Rule(
        "aws-ebs-unencrypted",
        Severity.HIGH,
        "EBS volume or block device is not encrypted.",
        "Set encrypted to true. Encryption cannot be turned on in place; the volume is replaced.",
    ),
    Rule(
        "aws-rds-unencrypted",
        Severity.HIGH,
        "RDS instance or cluster storage is not encrypted.",
        "Set storage_encrypted to true before the database is created. It cannot be enabled later.",
    ),
    Rule(
        "aws-rds-public",
        Severity.HIGH,
        "RDS instance is publicly accessible.",
        "Set publicly_accessible to false and reach the database over a private network.",
    ),
    Rule(
        "aws-sg-world-all-ports",
        Severity.CRITICAL,
        "Security group ingress allows every port from the internet.",
        "Remove 0.0.0.0/0 and ::/0 from this ingress rule, or limit the protocol and port range.",
    ),
    Rule(
        "aws-sg-world-sensitive-port",
        Severity.HIGH,
        "Security group ingress exposes an admin or data port to the internet.",
        "Do not publish SSH, RDP, or database ports to 0.0.0.0/0 or ::/0. Limit the CIDR to a known network.",
    ),
    Rule(
        "aws-iam-wildcard-action",
        Severity.CRITICAL,
        "IAM policy allows Action * or NotAction. Critical when Resource is also *.",
        "Replace Action * with the actions this principal needs. Avoid NotAction on Allow statements.",
    ),
    Rule(
        "aws-iam-wildcard-resource",
        Severity.HIGH,
        "IAM policy allows a service-wide action wildcard on Resource *.",
        "Replace Resource * with the ARNs this statement should reach, or drop the service-wide action.",
    ),
    Rule(
        "aws-cloudtrail-logging-disabled",
        Severity.HIGH,
        "CloudTrail trail has logging turned off.",
        "Set enable_logging to true.",
    ),
    Rule(
        "aws-cloudtrail-not-multi-region",
        Severity.HIGH,
        "CloudTrail trail does not record every region.",
        "Set is_multi_region_trail to true so events outside the home region are kept.",
    ),
    Rule(
        "aws-kms-rotation-disabled",
        Severity.MEDIUM,
        "Symmetric KMS key does not rotate automatically.",
        "Set enable_key_rotation to true. Asymmetric, HMAC, and external keys are not flagged.",
    ),
    Rule(
        "aws-ec2-imdsv2-optional",
        Severity.HIGH,
        "EC2 instance or launch template does not require IMDSv2.",
        "Set metadata_options.http_tokens to required on the instance, launch template, or launch configuration.",
    ),
)

RULE_INDEX = {rule.id: rule for rule in RULES}


def evaluate(resources: list[Resource]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_s3(resources))
    for resource in resources:
        findings.extend(_ebs(resource))
        findings.extend(_rds(resource))
        findings.extend(_security_group(resource))
        findings.extend(_iam(resource))
        findings.extend(_cloudtrail(resource))
        findings.extend(_kms(resource))
        findings.extend(_imds(resource))
    return findings


def _finding(rule_id: str, resource: Resource, message: str, severity: Severity | None = None) -> Finding:
    rule = RULE_INDEX[rule_id]
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        message=message,
        path=resource.path,
        address=resource.address,
        remediation=rule.remediation,
        line=resource.line if resource.line > 0 else 1,
    )


def _s3(resources: list[Resource]) -> list[Finding]:
    findings: list[Finding] = []
    buckets = [item for item in resources if item.type == "aws_s3_bucket"]
    blocks, _blocks_unknown = _by_bucket(resources, "aws_s3_bucket_public_access_block")
    encryption, encryption_unknown = _by_bucket(resources, "aws_s3_bucket_server_side_encryption_configuration")
    for resource in resources:
        findings.extend(_acl(resource))
        if resource.type in {"aws_s3_bucket", "aws_s3_bucket_policy"}:
            findings.extend(_bucket_policy(resource))
    for bucket in buckets:
        findings.extend(_access_block(bucket, blocks))
        findings.extend(_bucket_encryption(bucket, encryption, encryption_unknown))
    return findings


def _acl(resource: Resource) -> list[Finding]:
    if resource.type not in {"aws_s3_bucket", "aws_s3_bucket_acl"}:
        return []
    findings: list[Finding] = []
    canned = lookup(resource, "acl")
    if canned.known and isinstance(canned.value, str):
        severity = _PUBLIC_ACL.get(canned.value.strip().lower())
        if severity is not None:
            findings.append(
                _finding(
                    "aws-s3-public-acl",
                    resource,
                    f"ACL {canned.value.strip()} allows broad access",
                    severity,
                )
            )
    grant_severity, who = _grant_exposure(resource)
    if grant_severity is not None and who:
        findings.append(
            _finding(
                "aws-s3-public-acl",
                resource,
                f"ACL grant for {who} allows broad access",
                grant_severity,
            )
        )
    return findings


def _grant_exposure(resource: Resource) -> tuple[Severity | None, str]:
    policy = lookup(resource, "access_control_policy")
    if not policy.known:
        return None, ""
    worst: Severity | None = None
    names: list[str] = []
    for block, block_unknown in block_pairs(policy.value, policy.unknown):
        grants = field(block, block_unknown, "grant")
        if not grants.known:
            continue
        for grant, grant_unknown in block_pairs(grants.value, grants.unknown):
            grantee = field(grant, grant_unknown, "grantee")
            if not grantee.known:
                continue
            for body, body_unknown in block_pairs(grantee.value, grantee.unknown):
                uri = field(body, body_unknown, "uri")
                if not uri.known or not isinstance(uri.value, str):
                    continue
                label, severity = _uri_severity(uri.value)
                if severity is None or label is None:
                    continue
                if label not in names:
                    names.append(label)
                if worst is None or _worse(severity, worst):
                    worst = severity
    return worst, " and ".join(names)


def _uri_severity(uri: str) -> tuple[str | None, Severity | None]:
    lowered = uri.strip().lower()
    if lowered == _ALL_USERS:
        return "AllUsers", Severity.CRITICAL
    if lowered == _AUTH_USERS:
        return "AuthenticatedUsers", Severity.HIGH
    return None, None


def _worse(candidate: Severity, current: Severity) -> bool:
    rank = {Severity.HIGH: 1, Severity.CRITICAL: 2}
    return rank.get(candidate, 0) > rank.get(current, 0)


def _bucket_policy(resource: Resource) -> list[Finding]:
    attr = lookup(resource, "policy")
    if not attr.known or attr.value in (None, ""):
        return []
    document = _parse_policy(resource, attr.value)
    if document is None:
        return []
    findings: list[Finding] = []
    for index, statement in enumerate(_statements(document)):
        if not _allows(statement):
            continue
        if not _principal_public(statement.get("Principal", statement.get("principal"))):
            continue
        condition = statement.get("Condition", statement.get("condition"))
        if isinstance(condition, dict) and condition:
            continue
        sid = _sid(statement, index)
        findings.append(_finding("aws-s3-public-policy", resource, f"bucket policy {sid} allows Principal *"))
    return findings


def _access_block(bucket: Resource, blocks: dict[str, list[Resource]]) -> list[Finding]:
    names = _bucket_names(bucket)
    if not names:
        return []
    matches = _matches(blocks, names)
    statuses = [_pab_status(item) for item in matches]
    if any(status in {"ok", "unknown"} for status, _flags in statuses):
        return []
    if not matches:
        shown = ", ".join(sorted(names))
        return [_finding("aws-s3-public-access-block", bucket, f"no public access block covers bucket {shown}")]
    weak_flags: list[str] = []
    for _status, flags in statuses:
        for flag in flags:
            if flag not in weak_flags:
                weak_flags.append(flag)
    detail = ", ".join(weak_flags) if weak_flags else "one or more restrictions"
    return [
        _finding(
            "aws-s3-public-access-block",
            bucket,
            f"public access block does not enable {detail}",
        )
    ]


def _pab_status(resource: Resource) -> tuple[str, list[str]]:
    weak: list[str] = []
    unknown = False
    for name in _PAB_FLAGS:
        attr = lookup(resource, name)
        if not attr.known:
            unknown = True
            continue
        if not explicitly_true(attr):
            weak.append(name)
    if weak:
        return "weak", weak
    if unknown:
        return "unknown", []
    return "ok", []


def _bucket_encryption(
    bucket: Resource,
    linked: dict[str, list[Resource]],
    unknown_target: bool,
) -> list[Finding]:
    inline = _sse_status(lookup(bucket, "server_side_encryption_configuration"), inline=True)
    if inline == "ok":
        return []
    names = _bucket_names(bucket)
    matches = _matches(linked, names) if names else []
    linked_status = [_sse_status(lookup(item, "rule"), inline=False) for item in matches]
    if inline == "unknown" or "ok" in linked_status or "unknown" in linked_status:
        return []
    # A computed bucket id cannot be joined to aws_s3_bucket_server_side_encryption_configuration.
    if not names and unknown_target:
        return []
    problem = inline if inline not in {"missing", "ok", "unknown"} else None
    if problem is None:
        problem = next((item for item in linked_status if item not in {"missing", "ok", "unknown"}), None)
    if problem:
        return [_finding("aws-s3-unencrypted", bucket, f"server-side encryption uses {problem}")]
    return [_finding("aws-s3-unencrypted", bucket, "server-side encryption is not configured")]


def _sse_status(attr: Attr, *, inline: bool) -> str:
    if not attr.known:
        return "unknown"
    if attr.value in (None, [], {}):
        return "missing"
    algorithms: set[str] = set()
    saw_unknown = False
    containers = block_pairs(attr.value, attr.unknown)
    rule_pairs: list[tuple[dict[str, Any], object]] = []
    if inline:
        for container, container_unknown in containers:
            rules = field(container, container_unknown, "rule")
            if not rules.known:
                saw_unknown = True
                continue
            rule_pairs.extend(block_pairs(rules.value, rules.unknown))
    else:
        rule_pairs = containers
    if not rule_pairs and not saw_unknown:
        return "missing"
    for rule, rule_unknown in rule_pairs:
        if rule_unknown is True:
            saw_unknown = True
            continue
        defaults = field(rule, rule_unknown, "apply_server_side_encryption_by_default")
        if not defaults.known:
            saw_unknown = True
            continue
        if defaults.value in (None, [], {}):
            continue
        for default, default_unknown in block_pairs(defaults.value, defaults.unknown):
            algo = field(default, default_unknown, "sse_algorithm")
            if not algo.known:
                saw_unknown = True
                continue
            if isinstance(algo.value, str) and algo.value.strip():
                algorithms.add(algo.value.strip().lower())
    if algorithms & _SSE:
        return "ok"
    if saw_unknown:
        return "unknown"
    if algorithms:
        return ", ".join(sorted(algorithms))
    return "missing"


def _ebs(resource: Resource) -> list[Finding]:
    if resource.type not in _EBS_TYPES:
        return []
    findings: list[Finding] = []
    if resource.type == "aws_ebs_volume" and require_true(lookup(resource, "encrypted")):
        findings.append(_finding("aws-ebs-unencrypted", resource, "volume is not encrypted"))
    if resource.type in {"aws_instance", "aws_launch_configuration"}:
        for name in ("root_block_device", "ebs_block_device"):
            attr = lookup(resource, name)
            if not attr.known:
                continue
            for index, (block, unknown) in enumerate(block_pairs(attr.value, attr.unknown)):
                if require_true(field(block, unknown, "encrypted")):
                    findings.append(_finding("aws-ebs-unencrypted", resource, f"{name}[{index}] is not encrypted"))
    if resource.type == "aws_launch_template":
        attr = lookup(resource, "block_device_mappings")
        if not attr.known:
            return findings
        for index, (mapping, mapping_unknown) in enumerate(block_pairs(attr.value, attr.unknown)):
            ebs = field(mapping, mapping_unknown, "ebs")
            if not ebs.known or ebs.value in (None, [], {}):
                continue
            device = mapping.get("device_name")
            label = device if isinstance(device, str) and device else str(index)
            for block, unknown in block_pairs(ebs.value, ebs.unknown):
                if require_true(field(block, unknown, "encrypted")):
                    findings.append(
                        _finding(
                            "aws-ebs-unencrypted",
                            resource,
                            f"block_device_mappings[{label}] is not encrypted",
                        )
                    )
    return findings


def _rds(resource: Resource) -> list[Finding]:
    findings: list[Finding] = []
    if resource.type == "aws_db_instance":
        if explicitly_true(lookup(resource, "publicly_accessible")):
            findings.append(_finding("aws-rds-public", resource, "instance is publicly accessible"))
        engine = lookup(resource, "engine")
        # Aurora storage encryption is set on the cluster, not the instance.
        if not engine.known:
            return findings
        if isinstance(engine.value, str) and engine.value.lower().startswith("aurora"):
            return findings
        if require_true(lookup(resource, "storage_encrypted")):
            findings.append(_finding("aws-rds-unencrypted", resource, "storage is not encrypted"))
    elif resource.type == "aws_rds_cluster" and require_true(lookup(resource, "storage_encrypted")):
        findings.append(_finding("aws-rds-unencrypted", resource, "storage is not encrypted"))
    return findings


def _security_group(resource: Resource) -> list[Finding]:
    if resource.type == "aws_security_group":
        attr = lookup(resource, "ingress")
        if not attr.known:
            return []
        findings: list[Finding] = []
        for index, (block, unknown) in enumerate(block_pairs(attr.value, attr.unknown)):
            findings.extend(_ingress(resource, block, unknown, f"ingress[{index}]"))
        return findings
    if resource.type == "aws_security_group_rule":
        kind = lookup(resource, "type")
        if not kind.known or not isinstance(kind.value, str) or kind.value.lower() != "ingress":
            return []
        return _ingress(resource, resource.values, resource.unknown, "ingress")
    if resource.type == "aws_vpc_security_group_ingress_rule":
        return _ingress(resource, resource.values, resource.unknown, "ingress")
    return []


def _ingress(resource: Resource, block: dict[str, Any], unknown: object, label: str) -> list[Finding]:
    worlds = _world_cidrs(block, unknown)
    if not worlds:
        return []
    protocol_attr = _protocol(block, unknown)
    if not protocol_attr.known or not isinstance(protocol_attr.value, str):
        return []
    protocol = protocol_attr.value.strip().lower()
    start_attr = field(block, unknown, "from_port")
    end_attr = field(block, unknown, "to_port")
    start = as_int(start_attr.value) if start_attr.known else None
    end = as_int(end_attr.value) if end_attr.known else None
    if protocol not in _ALL_PROTOCOLS and (not start_attr.known or not end_attr.known):
        return []
    opened = ", ".join(worlds)
    if _all_ports(protocol, start, end):
        return [_finding("aws-sg-world-all-ports", resource, f"{label} all ports open to {opened}")]
    if _hits_sensitive(protocol, start, end):
        return [
            _finding(
                "aws-sg-world-sensitive-port",
                resource,
                f"{label} {protocol}/{_port_span(start, end)} open to {opened}",
            )
        ]
    return []


def _world_cidrs(block: dict[str, Any], unknown: object) -> list[str]:
    found: list[str] = []
    for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
        attr = field(block, unknown, key)
        if not attr.known:
            continue
        for cidr in as_str_list(attr.value):
            cleaned = cidr.strip()
            if cleaned in _WORLD and cleaned not in found:
                found.append(cleaned)
    return found


def _protocol(block: dict[str, Any], unknown: object) -> Attr:
    protocol = field(block, unknown, "protocol")
    if protocol.known and isinstance(protocol.value, str) and protocol.value.strip():
        return protocol
    if not protocol.known:
        return protocol
    ip_protocol = field(block, unknown, "ip_protocol")
    if ip_protocol.known and isinstance(ip_protocol.value, str):
        return ip_protocol
    if not ip_protocol.known:
        return ip_protocol
    if isinstance(protocol.value, int) and not isinstance(protocol.value, bool):
        return Attr(True, str(protocol.value), None)
    return Attr(True, None, None)


def _all_ports(protocol: str, start: int | None, end: int | None) -> bool:
    if protocol in _ALL_PROTOCOLS:
        return True
    if protocol not in _TCP_UDP or start is None or end is None:
        return False
    return start <= 0 and end >= 65535


def _hits_sensitive(protocol: str, start: int | None, end: int | None) -> bool:
    if protocol not in _TCP_UDP or start is None or end is None or end < start:
        return False
    return any(start <= port <= end for port in SENSITIVE_PORTS)


def _port_span(start: int | None, end: int | None) -> str:
    if start is None or end is None or start == end:
        return str(start if start is not None else end)
    return f"{start}-{end}"


def _iam(resource: Resource) -> list[Finding]:
    findings: list[Finding] = []
    for label, raw in _policy_values(resource):
        document = _parse_policy(resource, raw)
        if document is None:
            continue
        for index, statement in enumerate(_statements(document)):
            finding = _iam_statement(resource, statement, index, label)
            if finding is not None:
                findings.append(finding)
    return findings


def _policy_values(resource: Resource) -> list[tuple[str, object]]:
    if resource.type in _IAM_POLICIES:
        attr = lookup(resource, "policy")
        if attr.known and attr.value not in (None, ""):
            return [("policy", attr.value)]
        return []
    if resource.type != "aws_iam_role":
        return []
    inline = lookup(resource, "inline_policy")
    if not inline.known:
        return []
    documents: list[tuple[str, object]] = []
    for index, (block, unknown) in enumerate(block_pairs(inline.value, inline.unknown)):
        policy = field(block, unknown, "policy")
        if policy.known and policy.value not in (None, ""):
            documents.append((f"inline_policy[{index}]", policy.value))
    return documents


def _iam_statement(resource: Resource, statement: dict[str, Any], index: int, label: str) -> Finding | None:
    if not _allows(statement):
        return None
    actions = as_str_list(statement.get("Action", statement.get("action")))
    not_actions = as_str_list(statement.get("NotAction", statement.get("notaction")))
    resources = as_str_list(statement.get("Resource", statement.get("resource")))
    star_resource = any(item.strip() == "*" for item in resources)
    star_action = any(item.strip() in {"*", "*:*"} for item in actions) or bool(not_actions)
    where = _sid(statement, index)
    scope = f"{label} {where}"
    if star_action and star_resource:
        kind = "NotAction" if not_actions and not any(item.strip() in {"*", "*:*"} for item in actions) else "Action *"
        return _finding(
            "aws-iam-wildcard-action",
            resource,
            f"{scope} allows {kind} on Resource *",
            Severity.CRITICAL,
        )
    if star_action:
        kind = "NotAction" if not_actions and not any(item.strip() in {"*", "*:*"} for item in actions) else "Action *"
        return _finding("aws-iam-wildcard-action", resource, f"{scope} allows {kind}", Severity.HIGH)
    service_wild = sorted({item.strip() for item in actions if _service_wildcard(item)})
    if service_wild and star_resource:
        shown = ", ".join(service_wild[:3])
        return _finding("aws-iam-wildcard-resource", resource, f"{scope} allows {shown} on Resource *")
    return None


def _service_wildcard(action: str) -> bool:
    service, separator, rest = action.strip().partition(":")
    return bool(separator) and bool(service) and service != "*" and rest == "*"


def _cloudtrail(resource: Resource) -> list[Finding]:
    if resource.type != "aws_cloudtrail":
        return []
    findings: list[Finding] = []
    if known_false(lookup(resource, "enable_logging")):
        findings.append(_finding("aws-cloudtrail-logging-disabled", resource, "logging is disabled"))
    if require_true(lookup(resource, "is_multi_region_trail")):
        findings.append(_finding("aws-cloudtrail-not-multi-region", resource, "trail is not multi-region"))
    return findings


def _kms(resource: Resource) -> list[Finding]:
    if resource.type != "aws_kms_key":
        return []
    origin = lookup(resource, "origin")
    if not origin.known:
        return []
    if isinstance(origin.value, str) and origin.value.strip().upper() in _NO_ROTATION_ORIGIN:
        return []
    primary = lookup(resource, "customer_master_key_spec")
    secondary = lookup(resource, "key_spec")
    if not primary.known or not secondary.known:
        return []
    chosen = primary.value if isinstance(primary.value, str) and primary.value.strip() else secondary.value
    if isinstance(chosen, str) and chosen.strip().upper() in _NO_ROTATION_SPEC:
        return []
    if require_true(lookup(resource, "enable_key_rotation")):
        return [_finding("aws-kms-rotation-disabled", resource, "automatic key rotation is disabled")]
    return []


def _imds(resource: Resource) -> list[Finding]:
    if resource.type not in _IMDS_TYPES:
        return []
    meta = lookup(resource, "metadata_options")
    if not meta.known:
        return []
    pairs = block_pairs(meta.value, meta.unknown)
    if not pairs:
        return [_finding("aws-ec2-imdsv2-optional", resource, "metadata_options.http_tokens is not required")]
    block, unknown = pairs[0]
    endpoint = field(block, unknown, "http_endpoint")
    tokens = field(block, unknown, "http_tokens")
    if endpoint.known and isinstance(endpoint.value, str) and endpoint.value.strip().lower() == "disabled":
        return []
    if not endpoint.known and not tokens.known:
        return []
    if not tokens.known:
        return []
    if isinstance(tokens.value, str) and tokens.value.strip().lower() == "required":
        return []
    return [_finding("aws-ec2-imdsv2-optional", resource, "metadata_options.http_tokens is not required")]


def _by_bucket(resources: list[Resource], type_name: str) -> tuple[dict[str, list[Resource]], bool]:
    found: dict[str, list[Resource]] = {}
    unknown = False
    for resource in resources:
        if resource.type != type_name:
            continue
        attr = lookup(resource, "bucket")
        if not attr.known:
            unknown = True
            continue
        if isinstance(attr.value, str) and attr.value:
            found.setdefault(attr.value, []).append(resource)
    return found, unknown


def _bucket_names(resource: Resource) -> set[str]:
    names: set[str] = set()
    for key in ("bucket", "id"):
        attr = lookup(resource, key)
        if attr.known and isinstance(attr.value, str) and attr.value:
            names.add(attr.value)
    return names


def _matches(index: dict[str, list[Resource]], names: set[str]) -> list[Resource]:
    seen: set[str] = set()
    found: list[Resource] = []
    for name in names:
        for resource in index.get(name, []):
            if resource.address in seen:
                continue
            seen.add(resource.address)
            found.append(resource)
    return found


def _parse_policy(resource: Resource, raw: object) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("skipping unreadable policy on %s", resource.address)
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    raw = document.get("Statement", document.get("statement"))
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _allows(statement: dict[str, Any]) -> bool:
    effect = statement.get("Effect", statement.get("effect", "Allow"))
    return isinstance(effect, str) and effect.lower() == "allow"


def _principal_public(principal: object) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, list):
        return any(_principal_public(item) for item in principal)
    if isinstance(principal, dict):
        aws = principal.get("AWS", principal.get("aws"))
        return _aws_star(aws)
    return False


def _aws_star(value: object) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(item == "*" for item in value)
    return False


def _sid(statement: dict[str, Any], index: int) -> str:
    sid = as_str(statement.get("Sid", statement.get("sid")))
    if sid and sid.strip():
        return f"statement {sid.strip()}"
    return f"statement {index + 1}"

"""Conservative AWS compliance predicates assigned to swarm slice 06.

Every evaluator first verifies a complete, same-scope inventory. New detail
facts are deliberately required: their absence is UNKNOWN, never a clean bill.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_network
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, guard, optional


def _inventory(item, index, kind):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS provider authority unavailable")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"[0-9]{12}/[a-z0-9-]+", scope):
        raise Unavailable("AWS account/Region scope unavailable")
    if scope.endswith("/global") != (kind in {"cloudfront_distribution", "route53_zone"}):
        raise Unavailable("collection global/regional scope mismatch")
    envelopes = get(index, "collections", dict).get(kind)
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or
            envelopes[0].get("type") != kind or envelopes[0].get("scope") != scope or
            envelopes[0].get("status") not in ("collected", "empty") or
            not isinstance(envelopes[0].get("items"), list) or
            (envelopes[0]["status"] == "empty" and envelopes[0]["items"])):
        raise Unavailable("complete same-scope inventory unavailable: " + kind)
    rows = complete_items(index, kind)
    wrappers = get(index, kind, list)
    if any(not isinstance(wrapper, dict) or wrapper.get("type") != kind or
           wrapper.get("scope") != scope for wrapper in wrappers):
        raise Unavailable("foreign or malformed resource projection: " + kind)
    if rows != envelopes[0]["items"]:
        raise Unavailable("inventory projection differs from envelope")
    if any(sum(candidate == row for candidate in rows) != 1 for row in rows):
        raise Unavailable("duplicate inventory resource")
    identity_field = {"security_group": "GroupId", "msk_cluster": "ClusterArn",
                      "ebs_snapshot": "SnapshotId", "client_vpn_endpoint": "ClientVpnEndpointId",
                      "lambda_function": "FunctionArn", "lightsail_bucket": "name",
                      "route53_zone": "Id", "securityhub_hub": "HubArn", "kms_key": "KeyId",
                      "cloudfront_distribution": "Id", "vpc": "VpcId"}[kind]
    identities = [get(row, identity_field, str) for row in rows]
    if any(not identity for identity in identities) or len(identities) != len(set(identities)):
        raise Unavailable("missing or duplicate resource identity")
    account, region = scope.split("/")
    for row in rows:
        for field, service in (("FunctionArn", "lambda"), ("ClusterArn", "kafka"), ("HubArn", "securityhub"),
                               ("KeyArn", "kms"), ("arn", "lightsail"), ("ARN", "cloudfront")):
            if field in row:
                arn = get(row, field, str)
                native_region = "" if service == "cloudfront" else region
                if not arn.startswith(f"arn:aws:{service}:{native_region}:{account}:"):
                    raise Unavailable("resource ARN belongs to a foreign scope")
        if kind == "security_group" and "OwnerId" in row and get(row, "OwnerId", str) != account:
            raise Unavailable("security group belongs to a foreign account")
        if kind == "kms_key" and "Metadata" in row:
            metadata = get(row, "Metadata.KeyMetadata", dict)
            if "AWSAccountId" in metadata and get(metadata, "AWSAccountId", str) != account:
                raise Unavailable("KMS detail belongs to a foreign account")
    if sum(row == item for row in rows) != 1:
        raise Unavailable("resource absent or duplicated in scoped inventory")
    return scope, rows


def _params(index):
    # The engine carries snapshot metadata into context; it does not populate
    # a context.parameters field.
    return get(get(index, "context.metadata", dict), "parameters", dict)


def _strings(value, *, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value) or any(
            not isinstance(x, str) or not x for x in value):
        raise Unavailable("malformed string inventory")
    return value


def _sg_world(item):
    rules = get(item, "IpPermissions", list)
    hits = []
    for rule in rules:
        proto = get(rule, "IpProtocol", str)
        if not re.fullmatch(r"-1|[0-9]{1,3}|tcp|udp|icmp|icmpv6", proto):
            raise Unavailable("malformed security-group protocol")
        if proto.isdigit():
            if int(proto) > 255:
                raise Unavailable("security-group protocol number outside IP range")
            proto = str(int(proto))
        ranges = get(rule, "Ipv6Ranges", list)
        world = False
        for row in ranges:
            cidr = get(row, "CidrIpv6", str)
            try:
                parsed = ip_network(cidr, strict=False)
            except ValueError as exc:
                raise Unavailable("malformed IPv6 CIDR") from exc
            if parsed.version != 6:
                raise Unavailable("IPv4 CIDR in IPv6 range")
            world |= parsed.prefixlen == 0
        if proto == "-1":
            low, high = 0, 65535
        elif proto in ("6", "17", "tcp", "udp"):
            low, high = get(rule, "FromPort", int), get(rule, "ToPort", int)
            if not 0 <= low <= high <= 65535:
                raise Unavailable("malformed security-group port range")
        else:
            low, high = None, None
        if world:
            hits.append((proto, low, high))
    return hits


def _ipv6_ports(item, index, ports):
    _inventory(item, index, "security_group")
    hits = _sg_world(item)
    bad = [(proto, low, high) for proto, low, high in hits
           if proto == "-1" or proto in ("6", "tcp") and
           any(low <= port <= high for port in ports)]
    return result(bool(bad), group_id=get(item, "GroupId", str),
                  offending_rules=bad)


def _ipv6_tcp_udp(item, index):
    _inventory(item, index, "security_group")
    bad = [row for row in _sg_world(item) if row[0] in ("-1", "6", "17", "tcp", "udp")]
    return result(bool(bad), group_id=get(item, "GroupId", str), offending_rules=bad)


def _msk_tls(item, index):
    _inventory(item, index, "msk_cluster")
    kind = get(item, "ClusterType", str)
    if kind == "SERVERLESS":
        return "NOT_APPLICABLE", {"reason": "serverless cluster has no provisioned broker in-cluster TLS field"}
    if kind != "PROVISIONED":
        return unknown("unrecognized MSK cluster type")
    arn = get(item, "ClusterArn", str)
    detail = get(item, "Detail.ClusterInfo", dict)
    if get(detail, "ClusterArn", str) != arn:
        return unknown("MSK detail identity differs from listed cluster")
    enabled = get(detail, "Provisioned.EncryptionInfo.EncryptionInTransit.InCluster", bool)
    return result(not enabled, cluster_arn=arn, in_cluster_tls=enabled)


def _ebs_trusted(item, index):
    scope, _ = _inventory(item, index, "ebs_snapshot")
    if get(item, "OwnerId", str) != scope.split("/")[0]:
        return unknown("snapshot owner differs from audited account")
    approved = set(_strings(get(_params(index), "trusted_account_ids", list)))
    if any(not re.fullmatch(r"[0-9]{12}", x) for x in approved):
        return unknown("malformed trusted account ID")
    grants = get(item, "CreateVolumePermissions", list)
    bad = []
    for grant in grants:
        guard(grant)
        if set(grant) - {"Group", "UserId", "_coverage"} or len(set(grant) & {"Group", "UserId"}) != 1:
            return unknown("unrecognized snapshot permission")
        if "Group" in grant:
            if get(grant, "Group", str) != "all":
                return unknown("unrecognized snapshot permission group")
            bad.append("all")
        elif "UserId" in grant:
            principal = get(grant, "UserId", str)
            if not re.fullmatch(r"[0-9]{12}", principal):
                return unknown("malformed snapshot grantee account")
            if principal not in approved:
                bad.append(principal)
        else:
            return unknown("snapshot permission lacks grantee")
    return result(bool(bad), snapshot_id=get(item, "SnapshotId", str), unapproved_grantees=sorted(bad))


def _vpn_auth(item, index):
    _inventory(item, index, "client_vpn_endpoint")
    endpoint_id = get(item, "ClientVpnEndpointId", str)
    status = get(item, "Status.Code", str)
    if status != "available":
        if status in {"pending-associate", "pending-acceptance", "deleting", "deleted", "failed"}:
            return "NOT_APPLICABLE", {"endpoint_id": endpoint_id, "reason": "endpoint not available"}
        return unknown("unrecognized Client VPN endpoint state")
    cert = get(item, "ServerCertificateArn", str)
    methods = get(item, "AuthenticationOptions", list)
    allowed = {"certificate-authentication", "directory-service-authentication", "federated-authentication"}
    seen = []
    for method in methods:
        value = get(method, "Type", str)
        if value not in allowed:
            return unknown("unrecognized Client VPN authentication type")
        seen.append(value)
    return result(not cert or not seen, endpoint_id=endpoint_id,
                  server_certificate_present=bool(cert), authentication_types=seen)


def _lambda_signing(item, index):
    _inventory(item, index, "lambda_function")
    function_arn = get(item, "FunctionArn", str)
    state = get(item, "Configuration.State", str)
    if state != "Active":
        if state in {"Pending", "Inactive", "Failed"}:
            return "NOT_APPLICABLE", {"function_arn": function_arn, "reason": "function is not active"}
        return unknown("unrecognized Lambda function state")
    signing = get(item, "CodeSigning", dict)
    if get(signing, "FunctionArn", str) != function_arn:
        return unknown("code-signing detail identity mismatch")
    config_arn = get(signing, "CodeSigningConfigArn", str)
    if not config_arn:
        return result(True, function_arn=function_arn, reason="no code-signing config")
    config = get(item, "CodeSigningConfig.CodeSigningConfig", dict)
    if get(config, "CodeSigningConfigArn", str) != config_arn:
        return unknown("code-signing config identity mismatch")
    publishers = _strings(get(config, "AllowedPublishers.SigningProfileVersionArns", list))
    policy = get(config, "CodeSigningPolicies.UntrustedArtifactOnDeployment", str)
    if policy not in ("Enforce", "Warn"):
        return unknown("unrecognized untrusted artifact policy")
    return result(not publishers or policy != "Enforce", function_arn=function_arn,
                  config_arn=config_arn, publisher_count=len(publishers), policy=policy)


def _lightsail_logging(item, index):
    _inventory(item, index, "lightsail_bucket")
    name = get(item, "name", str)
    logging = get(item, "accessLogConfig", dict)
    enabled = get(logging, "enabled", bool)
    destination = optional(logging, "destination", "", str)
    return result(not enabled or not destination, bucket=name,
                  access_logging_enabled=enabled, destination=destination)


def _route53_dnssec(item, index):
    _inventory(item, index, "route53_zone")
    zone_id = get(item, "Id", str)
    private = get(item, "Config.PrivateZone", bool)
    if private:
        return "NOT_APPLICABLE", {"zone_id": zone_id, "reason": "private hosted zone"}
    detail = get(item, "DNSSEC", dict)
    if get(detail, "HostedZoneId", str) != zone_id:
        return unknown("DNSSEC response hosted-zone identity mismatch")
    signature = get(detail, "Status.ServeSignature", str)
    if signature not in ("SIGNING", "NOT_SIGNING"):
        return unknown("unrecognized DNSSEC serving state")
    keys = get(detail, "KeySigningKeys", list)
    statuses = [get(key, "Status", str) for key in keys]
    if any(status not in {"ACTIVE", "INACTIVE", "DELETING", "ACTION_NEEDED"} for status in statuses):
        return unknown("unrecognized key-signing key state")
    return result(signature != "SIGNING" or "ACTIVE" not in statuses,
                  zone_id=zone_id, serve_signature=signature, key_statuses=statuses)


def _securityhub_critical(item, index):
    _inventory(item, index, "securityhub_hub")
    hub_arn = get(item, "HubArn", str)
    findings = get(item, "CriticalFindings", dict)
    metadata = get(index, "context.metadata", dict)
    parameters = metadata.get("parameters", {})
    configured = parameters.get("audited_regions") if isinstance(parameters, dict) else None
    if configured is None:
        account = get(index, "context.scope", str).split("/", 1)[0]
        configured = get(metadata, "audited_regions_by_account", dict).get(account)
    required_regions = set(_strings(configured, nonempty=True))
    covered_regions = _strings(get(findings, "covered_regions", list), nonempty=True)
    if (len(covered_regions) != len(set(covered_regions)) or
            set(covered_regions) != required_regions or
            any(not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", x)
                for x in required_regions)):
        return unknown("critical findings query does not cover every audited Region")
    if get(findings, "collection_status", str) not in ("collected", "empty"):
        return unknown("critical findings inventory incomplete")
    rows = get(findings, "items", list)
    if findings["collection_status"] == "empty" and rows:
        return unknown("malformed empty findings inventory")
    unresolved = []
    for finding in rows:
        finding_id = get(finding, "Id", str)
        if not finding_id:
            return unknown("critical finding identity missing")
        if (get(finding, "Severity.Label", str) != "CRITICAL" or
                get(finding, "RecordState", str) != "ACTIVE" or
                get(finding, "Region", str) not in required_regions):
            return unknown("critical finding query returned out-of-filter row")
        status = get(finding, "Workflow.Status", str)
        if status not in {"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"}:
            return unknown("unrecognized finding workflow status")
        if status not in {"RESOLVED", "SUPPRESSED"}:
            unresolved.append(finding_id)
    return result(bool(unresolved), hub_arn=hub_arn, unresolved_finding_ids=unresolved)


def _kms_expiry(item, index):
    _inventory(item, index, "kms_key")
    metadata = get(item, "Metadata.KeyMetadata", dict)
    if get(metadata, "KeyId", str) != get(item, "KeyId", str):
        return unknown("KMS key metadata identity mismatch")
    origin = get(metadata, "Origin", str)
    state = get(metadata, "KeyState", str)
    if origin not in {"AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"}:
        return unknown("unrecognized KMS key origin")
    if state not in {"Enabled", "Disabled", "PendingDeletion", "PendingImport", "Unavailable", "Updating"}:
        return unknown("unrecognized KMS key state")
    enabled = optional(metadata, "Enabled", None, bool)
    if enabled is not None and enabled != (state == "Enabled"):
        return unknown("KMS Enabled flag contradicts KeyState")
    expired = False
    if origin == "EXTERNAL":
        model = optional(metadata, "ExpirationModel", None, str)
        if model == "KEY_MATERIAL_DOES_NOT_EXPIRE":
            if "ValidTo" in metadata:
                return unknown("nonexpiring imported KMS material has contradictory ValidTo")
        elif model in (None, "KEY_MATERIAL_EXPIRES"):
            # Older snapshots omitted ExpirationModel but retained ValidTo.
            valid_to = get(metadata, "ValidTo", str)
            captured = get(get(index, "context", dict), "created_at", str)
            try:
                end = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))
                now = datetime.fromisoformat(captured.replace("Z", "+00:00"))
            except ValueError as exc:
                raise Unavailable("malformed KMS expiry or capture time") from exc
            if end.tzinfo is None or now.tzinfo is None:
                return unknown("KMS expiry and capture time require timezone")
            expired = end <= now
        else:
            return unknown("unrecognized imported KMS material expiration model")
    # Either complete DescribeKey witness is independent of the Retired tag:
    # expired imported material fails, and Disabled satisfies any retired tag.
    # An unread ListResourceTags never proves that a tag is absent.
    if expired:
        return result(True, key_id=metadata["KeyId"], imported_material_expired=True,
                      key_state=state, retirement_marker="not_evaluated")
    if state == "Disabled":
        return result(False, key_id=metadata["KeyId"], imported_material_expired=False,
                      key_state=state, retirement_marker="not_evaluated")
    tags = get(item, "Tags", list)
    retired = False
    for tag in tags:
        key, value = get(tag, "TagKey", str), get(tag, "TagValue", str)
        if key == "Retired" and value.lower() == "true":
            retired = True
    return result(expired or retired and state != "Disabled", key_id=metadata["KeyId"],
                  imported_material_expired=expired, retired=retired, key_state=state)


def _kms_cryptoperiod(item, index):
    _inventory(item, index, "kms_key")
    key_id = get(item, "KeyId", str)
    params = _params(index)
    designated = set(_strings(get(params, "cardholder_data_key_ids", list)))
    if key_id not in designated:
        return "NOT_APPLICABLE", {"key_id": key_id, "reason": "not designated for cardholder data"}
    threshold = get(params, "approved_cryptoperiod_days", int)
    if threshold <= 0:
        return unknown("invalid approved cryptoperiod")
    metadata = get(item, "Metadata.KeyMetadata", dict)
    if get(metadata, "KeyId", str) != key_id:
        return unknown("KMS metadata identity mismatch")
    if get(metadata, "Origin", str) != "AWS_KMS":
        return unknown("externally rotated or imported key requires documented replacement date")
    rotation = get(item, "Rotation", dict)
    enabled = get(rotation, "KeyRotationEnabled", bool)
    if not enabled:
        return result(True, key_id=key_id, rotation_enabled=False,
                      approved_cryptoperiod_days=threshold)
    period = get(rotation, "RotationPeriodInDays", int)
    if period <= 0:
        return unknown("invalid KMS rotation period")
    return result(not enabled or period > threshold, key_id=key_id,
                  rotation_enabled=enabled, rotation_period_days=period,
                  approved_cryptoperiod_days=threshold)


_TLS_POLICIES = {"SSLv3": 0, "TLSv1": 1, "TLSv1_2016": 2,
                 "TLSv1.1_2016": 3, "TLSv1.2_2018": 4,
                 "TLSv1.2_2019": 5, "TLSv1.2_2021": 6,
                 "TLSv1.2_2025": 7, "TLSv1.3_2025": 8}


def _cloudfront_tls(item, index):
    _inventory(item, index, "cloudfront_distribution")
    baseline = get(_params(index), "minimum_tls_policy", str)
    configured = get(item, "Config.DistributionConfig.ViewerCertificate.MinimumProtocolVersion", str)
    certificate = get(item, "Config.DistributionConfig.ViewerCertificate", dict)
    default_certificate = optional(certificate, "CloudFrontDefaultCertificate", False, bool)
    if baseline not in _TLS_POLICIES or configured not in _TLS_POLICIES:
        return unknown("unrecognized CloudFront TLS policy or configured baseline")
    if _TLS_POLICIES[baseline] < 1:
        return unknown("configured minimum TLS baseline is below TLSv1")
    if default_certificate:
        configured = "TLSv1"
    return result(_TLS_POLICIES[configured] < _TLS_POLICIES[baseline],
                  distribution_id=get(item, "Id", str), configured_policy=configured,
                  required_policy=baseline)


def _lambda_expected(item, index):
    _inventory(item, index, "lambda_function")
    arn = get(item, "FunctionArn", str)
    approved = get(_params(index), "expected_lambda_configuration", dict)
    expected = get(approved, arn, dict)
    detail = get(item, "Configuration", dict)
    if get(detail, "FunctionArn", str) != arn:
        return unknown("Lambda configuration identity mismatch")
    differences = []
    for field, kind in (("Runtime", str), ("Role", str), ("Timeout", int), ("MemorySize", int)):
        approved_value = get(expected, field, kind)
        configured = get(detail, field, kind)
        if not approved_value or not configured or (kind is int and (approved_value < 0 or configured < 0)):
            return unknown("empty expected or configured Lambda value", field=field)
        if configured != approved_value:
            differences.append(field)
    return result(bool(differences), function_arn=arn, differing_fields=differences)


def _vpn_all_groups(item, index):
    _inventory(item, index, "client_vpn_endpoint")
    endpoint_id = get(item, "ClientVpnEndpointId", str)
    exceptions = set(_strings(get(_params(index), "approved_authorize_all_groups_endpoint_ids", list)))
    detail = get(item, "AuthorizationRules", dict)
    if get(detail, "ClientVpnEndpointId", str) != endpoint_id:
        return unknown("VPN authorization inventory identity mismatch")
    if get(detail, "collection_status", str) not in ("collected", "empty"):
        return unknown("VPN authorization inventory incomplete")
    rules = get(detail, "items", list)
    if detail["collection_status"] == "empty" and rules:
        return unknown("malformed empty VPN authorization inventory")
    bad = []
    for rule in rules:
        code = get(rule, "Status.Code", str)
        if code not in {"active", "authorizing", "revoking"}:
            return unknown("unrecognized VPN authorization state")
        all_groups = get(rule, "AuthorizeAllGroups", bool)
        destination = get(rule, "DestinationCidr", str)
        try:
            ip_network(destination)
        except ValueError as exc:
            raise Unavailable("malformed VPN authorization destination") from exc
        if code == "active" and all_groups and endpoint_id not in exceptions:
            bad.append(destination)
    return result(bool(bad), endpoint_id=endpoint_id, unauthorized_destinations=bad)


def _vpc_endpoints(item, index):
    scope, _ = _inventory(item, index, "vpc")
    vpc_id = get(item, "VpcId", str)
    required_by_vpc = get(_params(index), "required_vpc_endpoint_services", dict)
    required = set(_strings(get(required_by_vpc, vpc_id, list)))
    envelopes = get(index, "collections", dict).get("vpc_endpoint")
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or
            not isinstance(envelopes[0], dict) or
            envelopes[0].get("type") != "vpc_endpoint" or
            envelopes[0].get("scope") != scope or
            envelopes[0].get("status") not in ("collected", "empty") or
            not isinstance(envelopes[0].get("items"), list) or
            (envelopes[0]["status"] == "empty" and envelopes[0]["items"])):
        return unknown("complete same-scope VPC endpoint inventory unavailable")
    wrappers = get(index, "vpc_endpoint", list)
    if any(not isinstance(wrapper, dict) or wrapper.get("type") != "vpc_endpoint" or
           wrapper.get("scope") != scope for wrapper in wrappers):
        return unknown("VPC endpoint resource has foreign scope")
    endpoints = complete_items(index, "vpc_endpoint")
    if endpoints != envelopes[0]["items"]:
        return unknown("VPC endpoint projection differs from envelope")
    available = set()
    seen_ids = set()
    for endpoint in endpoints:
        endpoint_id = get(endpoint, "VpcEndpointId", str)
        parent = get(endpoint, "VpcId", str)
        service = get(endpoint, "ServiceName", str)
        state = get(endpoint, "State", str)
        if endpoint_id in seen_ids or state not in {"available", "pending", "deleting", "deleted", "failed", "rejected", "expired"}:
            return unknown("duplicate endpoint or unrecognized endpoint state")
        seen_ids.add(endpoint_id)
        if parent == vpc_id and state == "available":
            available.add(service)
    missing = sorted(required - available)
    return result(bool(missing), vpc_id=vpc_id, missing_services=missing,
                  semantics="Endpoint exists and is available; route use not verified")


def _lightsail_instance_access(item, index):
    _inventory(item, index, "lightsail_bucket")
    name = get(item, "name", str)
    mapping = get(_params(index), "required_lightsail_bucket_instance_arns", dict)
    required = set(_strings(get(mapping, name, list)))
    if not required:
        return "NOT_APPLICABLE", {"bucket": name, "reason": "no required instance relation configured"}
    receiving = set(_strings(get(item, "resourcesReceivingAccess", list)))
    missing = sorted(required - receiving)
    return result(bool(missing), bucket=name, missing_instance_arns=missing)



SPEC_SHA256 = {
    'aws_security_group_common_ports_ipv6_all': '75b05a41bc206f01b546a161a27e9a56519a16b3deeb76b5c1aaea476c16e006',
    'aws_security_group_ssh_ipv6_all': '030b54351fd4e16209ec77a351d0a354d6a52c9acde86c7df3bab06b268012a4',
    'aws_security_group_tcp_udp_ipv6_all': 'fc5e5ea2cea5e33ed01ffc4d9f81266294339fd482e480cc6a0584cfbb9b7650',
    'aws_msk_in_cluster_tls_enabled': 'a4fa0012a16b90f4e1a397111f20fd3c95d927fba5d39787cc63410b1eaf8f3a',
    'aws_ebs_snapshot_trusted_accounts': '2c95643d716c111e7aee846bd94552213dfb528bc3368de438277782b0b5a347',
    'aws_client_vpn_authentication_configured': 'e4a84f8ec5e6a25b46dd66f073ee73e4a3b27547c76cd4f7c8301ce760e72141',
    'aws_lambda_code_signing_configured': 'a5348f0944b9c88e5ee6af749b48837ebcde377988b1758fb59d1f97c622011a',
    'aws_cis_lightsail_bucket_access_logging': '01fb26bc57281ffddf9858ea7a48291ec0f51b54122a3b5a6fd3c5e4e739b9b3',
    'aws_route53_hosted_zone_dnssec_enabled': 'e2de5eb0c22351e734ac1d081eec1fdcc1f0a2b2a9c76dfbbf245cda10457a74',
    'aws_securityhub_no_critical_findings': '87f6be913391ea106e9d3cda3d7dbe5923565ce2a59f909aec264f87a38053e0',
    'aws_kms_key_expiry': 'ed88e3d60cee6cf35d559915abaa1f0361f17e24d5576becbdf5857ec5f58784',
    'aws.pci.kms.cryptoperiod_rotation': '68af13d8289bfcd25d1c45dcf7a3b4766bb9708b0b49ed4c0c07866037070854',
    'aws.pci.cloudfront.min_tls_policy': 'b4ada2cb7dcf7a9192fb4285c399d25bff6f477bf6801d5e8d1367ade51ccfab',
}


@register('aws_security_group_common_ports_ipv6_all', 'aws', 'hardening', 'security_group', 'Security groups restrict common IPv6 ports', 'medium', 'CM-6', 'Remove ::/0 ingress entries covering TCP ports 20, 21, 22, 3306, 3389 or 4333, including protocol -1.',
          dependencies=['security_group'])
def check_aws_security_group_common_ports_ipv6_all(item, index):
    return _ipv6_ports(item, index, {20, 21, 22, 3306, 3389, 4333})


@register('aws_security_group_ssh_ipv6_all', 'aws', 'hardening', 'security_group', 'Security groups restrict IPv6 SSH ingress', 'medium', 'CM-6', 'Remove security-group ::/0 ingress for TCP port 22 and replace it with approved IPv6 CIDRs.',
          dependencies=['security_group'])
def check_aws_security_group_ssh_ipv6_all(item, index):
    return _ipv6_ports(item, index, {22})


@register('aws_security_group_tcp_udp_ipv6_all', 'aws', 'hardening', 'security_group', 'Security groups restrict IPv6 TCP and UDP ingress', 'medium', 'CM-6', 'Remove security-group ::/0 TCP, UDP and protocol -1 ingress, then add scoped IPv6 CIDRs.',
          dependencies=['security_group'])
def check_aws_security_group_tcp_udp_ipv6_all(item, index):
    return _ipv6_tcp_udp(item, index)


@register('aws_msk_in_cluster_tls_enabled', 'aws', 'hardening', 'msk_cluster', 'MSK broker-to-broker encryption is enabled', 'medium', 'CM-6', 'Enable in-cluster encryption on a replacement MSK cluster and migrate workloads.',
          dependencies=['msk_cluster'])
def check_aws_msk_in_cluster_tls_enabled(item, index):
    return _msk_tls(item, index)


@register('aws_ebs_snapshot_trusted_accounts', 'aws', 'hardening', 'ebs_snapshot', 'aws-perimeter.control.ebs_snapshot_shared_with_trusted_accounts', 'medium', 'CM-6', 'Revoke EBS snapshot createVolumePermission from accounts outside the trusted account ID allowlist.',
          dependencies=['ebs_snapshot'])
def check_aws_ebs_snapshot_trusted_accounts(item, index):
    return _ebs_trusted(item, index)


@register('aws_client_vpn_authentication_configured', 'aws', 'hardening', 'client_vpn_endpoint', 'Client VPN endpoint uses authentication', 'medium', 'CM-6', 'In Client VPN endpoint settings, configure mutual certificate, Active Directory or federated authentication and remove open access.',
          dependencies=['client_vpn_endpoint'])
def check_aws_client_vpn_authentication_configured(item, index):
    return _vpn_auth(item, index)


@register('aws_lambda_code_signing_configured', 'aws', 'hardening', 'lambda_function', 'Lambda code signing validates deployed packages', 'medium', 'CM-6', 'Create or attach a Lambda code-signing configuration with the approved signing profile and enforce signing on updates.',
          dependencies=['lambda_function'])
def check_aws_lambda_code_signing_configured(item, index):
    return _lambda_signing(item, index)


@register('aws_cis_lightsail_bucket_access_logging', 'aws', 'hardening', 'lightsail_bucket', 'Lightsail storage buckets have request logging', 'medium', 'CM-6', 'Enable supported bucket request logging or capture equivalent object requests through CloudTrail data events.',
          dependencies=['lightsail_bucket'])
def check_aws_cis_lightsail_bucket_access_logging(item, index):
    return _lightsail_logging(item, index)


@register('aws_route53_hosted_zone_dnssec_enabled', 'aws', 'hardening', 'route53_zone', 'Public Route 53 hosted zone signs DNSSEC', 'medium', 'CM-6', 'Enable DNSSEC signing for the public hosted zone and activate a key-signing key in Route 53.',
          dependencies=['route53_zone'])
def check_aws_route53_hosted_zone_dnssec_enabled(item, index):
    return _route53_dnssec(item, index)


@register('aws_securityhub_no_critical_findings', 'aws', 'hardening', 'securityhub_hub', 'No active critical Security Hub findings', 'medium', 'CM-6', 'Resolve or suppress verified Security Hub CRITICAL findings after fixing the underlying resources.',
          dependencies=['securityhub_hub'])
def check_aws_securityhub_no_critical_findings(item, index):
    return _securityhub_critical(item, index)


@register('aws_kms_key_expiry', 'aws', 'hardening', 'kms_key', 'Expired or retired KMS material is inactive', 'high', 'CM-6', 'Disable retired keys and replace expiring imported key material.',
          dependencies=['kms_key'])
def check_aws_kms_key_expiry(item, index):
    return _kms_expiry(item, index)


@register('aws.pci.kms.cryptoperiod_rotation', 'aws', 'hardening', 'kms_key', 'Cardholder-data KMS keys rotate within cryptoperiod', 'medium', 'CM-6', 'Enable KMS automatic rotation with a RotationPeriodInDays no greater than the approved cryptoperiod, or replace externally rotated key material on schedule.',
          dependencies=['kms_key'])
def check_aws_pci_kms_cryptoperiod_rotation(item, index):
    return _kms_cryptoperiod(item, index)


@register('aws.pci.cloudfront.min_tls_policy', 'aws', 'hardening', 'cloudfront_distribution', 'CloudFront viewer minimum TLS policy', 'medium', 'CM-6', 'Set CloudFront DistributionConfig.ViewerCertificate.MinimumProtocolVersion to the approved TLS policy and deploy the distribution.',
          dependencies=['cloudfront_distribution'])
def check_aws_pci_cloudfront_min_tls_policy(item, index):
    return _cloudfront_tls(item, index)


SPEC_SHA256.update({
    'aws.pci.lambda.expected_configuration': 'b4d7bd1cd936ea96f11fe006de0ef1fbfae95a9526b5579eefcf562a29681616',
    'aws.pci.client_vpn.no_authorize_all_groups': 'a95cc8de01511c8af40d76875e25457e7c03fb500c2d4ebc7bb3613631ede806',
    'aws_cis_vpc_service_endpoints_required': '7588abf3bf7efe808f51fa85a241db08f751cd0ff2bd9734a2618b1f45bcbef6',
    'aws_cis_lightsail_bucket_instance_access': 'dcc33195b34acbfc3a184f8ca93d72c588270afe0e88bbaf777650402cfd0351',
})


@register('aws.pci.lambda.expected_configuration', 'aws', 'hardening', 'lambda_function', 'Lambda functions match approved settings', 'medium', 'CM-6', 'Update the Lambda Runtime, execution Role, Timeout and MemorySize to the approved per-function values.',
          dependencies=['lambda_function'])
def check_aws_pci_lambda_expected_configuration(item, index):
    return _lambda_expected(item, index)


@register('aws.pci.client_vpn.no_authorize_all_groups', 'aws', 'network', 'client_vpn_endpoint', 'Client VPN rules restrict all-client access', 'medium', 'CM-6', 'Replace Client VPN authorization rules with AuthorizeAllGroups=true by group-specific rules using aws ec2 authorize-client-vpn-ingress.',
          dependencies=['client_vpn_endpoint'])
def check_aws_pci_client_vpn_no_authorize_all_groups(item, index):
    return _vpn_all_groups(item, index)


@register('aws_cis_vpc_service_endpoints_required', 'aws', 'network', 'vpc', 'In-use VPCs have required AWS service endpoints', 'medium', 'CM-6', 'Create available VPC endpoints for each required service in each in-use VPC.',
          dependencies=['vpc', 'vpc_endpoint'])
def check_aws_cis_vpc_service_endpoints_required(item, index):
    return _vpc_endpoints(item, index)


@register('aws_cis_lightsail_bucket_instance_access', 'aws', 'hardening', 'lightsail_bucket', 'Required Lightsail instance bucket access is attached', 'medium', 'CM-6', 'Attach only the intended Lightsail instances to the bucket.',
          dependencies=['lightsail_bucket'])
def check_aws_cis_lightsail_bucket_instance_access(item, index):
    return _lightsail_instance_access(item, index)

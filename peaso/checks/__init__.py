"""Native checks: pure functions over facts, with conservative provider semantics."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from functools import wraps
from ipaddress import ip_network
from .facts import get, list_of_objects, optional, Unavailable

HACKTRICKS = "HackTricks Cloud Best Practices"
FRAMEWORKS = (HACKTRICKS, "NIST 800-53")
HACKTRICKS_URL = "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/pentesting-cloud-methodology.md"


@dataclass(frozen=True)
class Check:
    id: str
    provider: str
    category: str
    kind: str
    title: str
    severity: str
    control: str
    remediation: str
    evaluate: Callable
    target: str = "resource"
    declared_dependencies: tuple = ()
    allow_incomplete_failure: bool = False
    empty_applicability_dependencies: tuple = ()

    @property
    def evaluation_mode(self):
        return self.target

    @property
    def frameworks(self):
        from .catalog import framework_names_for
        return framework_names_for(self.id)

    @property
    def framework_ids(self):
        from .catalog import framework_ids_for
        return framework_ids_for(self.id)

    @property
    def mapping(self):
        from .catalog import mappings_for
        return mappings_for(self.id, self.category, self.control)

    @property
    def dependencies(self):
        if self.declared_dependencies:
            return list(self.declared_dependencies)
        from sys import modules
        for provider in ("aws", "gcp", "azure", "k8s"):
            module = modules.get("peaso.checks." + provider + "_extended")
            declared = getattr(module, "DEPENDENCIES", {}).get(self.id) if module else None
            if declared is not None:
                return list(declared)
        return [self.kind]

    def public(self):
        from peaso.finding_types import type_for
        from .catalog import description_for, provenance_for, proposal_provenance_for, requirement_tags_for
        from .facts import FIELD_SPECS
        from .batch import scalar_sql
        from peaso.remediation import details_for
        from peaso.finding_priority import effective_priority, review_metadata
        from peaso.finding_presentation import evaluator_contract_fingerprint
        detail = details_for(self.id, provider=self.provider)
        result = {"id": self.id, "provider": self.provider, "category": self.category, "type": self.kind,
                "finding_type": type_for(self.id),
                "title": self.title, "severity": effective_priority(self.id, self.severity), "frameworks": self.frameworks,
                "framework_ids": self.framework_ids,
                "mapping": self.mapping, "remediation": detail["summary"] if detail else self.remediation,
                **({"remediation_details": detail} if detail else {}),
                "dependencies": self.dependencies, "target": self.target, "evaluator_version": "1.0.0",
                "evaluator": {"language": "python", "entrypoint": "peaso.checks:evaluate_check", "check_id": self.id,
                    **({"alternative": {"language": "sql", "backend": "duckdb", "version": "1.0.0", "sql": scalar_sql(self.id)}} if self.id in FIELD_SPECS else {})},
                "sources": provenance_for(self.id),
                "expected_cost": {"cloud_calls": 0, "time": "linear in applicable snapshot facts"},
                "rationale": self.title + "; inspect collected configuration without inferring effective access."}
        reviewed = description_for(self.id)
        if reviewed:
            result.update(reviewed)
            result["rationale"] = reviewed["description"]
            result["requirement_controls"] = requirement_tags_for(self.id)
        if detail:
            # Signed source hints remain in their source contract; the public
            # hint must agree with its separately reviewed presentation.
            result["remediation"] = detail["summary"]
        result["clarity_evaluation_contract"] = evaluator_contract_fingerprint()
        proposal = proposal_provenance_for(self.id)
        priority_review = review_metadata(self.id, self.severity)
        if priority_review:
            result["severity_review"] = priority_review
        if proposal:
            result["proposal_provenance"] = proposal
        return result


CHECKS = []
# Retired native ids that were exact duplicates (identical PASS/FAIL on every input) of a surviving native. Only the
# survivor is registered, so one finding is emitted per resource; the retired id stays resolvable for stored scans,
# diffs and check selections.
CHECK_ALIASES = {}


def alias_check(retired, survivor):
    if retired == survivor or retired in CHECK_ALIASES or survivor in CHECK_ALIASES or any(c.id == retired for c in CHECKS):
        raise ValueError("invalid native check alias: " + retired)
    CHECK_ALIASES[retired] = survivor


def resolve_check_id(check_id):
    return CHECK_ALIASES.get(check_id, check_id)


def evaluate_check(check_id, item, index=None):
    check_id = resolve_check_id(check_id)
    check = next((c for c in CHECKS if c.id == check_id), None)
    if check is None:
        raise ValueError("unknown native check ID")
    return check.evaluate(item, {} if index is None else index)


def register(id, provider, category, kind, title, severity, control, remediation, *, target="resource", dependencies=None, allow_incomplete_failure=False, empty_applicability_dependencies=()):
    if provider not in ("aws", "gcp", "azure", "k8s") or category not in ("hardening", "exposure", "least_privilege", "iam_graph", "network"):
        raise ValueError("native registry accepts supported providers and defensive categories only")
    if severity not in ("critical", "high", "medium", "low", "info"):
        raise ValueError("unknown check severity")
    if target not in ("resource", "scope"):
        raise ValueError("check target must be resource or scope")
    if dependencies is not None and (not isinstance(dependencies, (list, tuple)) or not all(isinstance(x, str) for x in dependencies)):
        raise ValueError("check dependencies must be collection-type strings")
    if type(allow_incomplete_failure) is not bool:
        raise ValueError("incomplete-inventory failure evaluation must be boolean")
    if (not isinstance(empty_applicability_dependencies, (list, tuple)) or
            any(not isinstance(value, str) for value in empty_applicability_dependencies) or
            len(set(empty_applicability_dependencies)) != len(empty_applicability_dependencies) or
            empty_applicability_dependencies and (target != "scope" or dependencies is None or
                not set(empty_applicability_dependencies) <= set(dependencies))):
        raise ValueError("empty applicability must name declared scoped dependencies")
    def decorate(function):
        for existing in CHECKS:
            if existing.id == id:
                raise ValueError("duplicate check id: " + id)
        if id in CHECK_ALIASES:
            raise ValueError("duplicate check id: " + id)
        @wraps(function)
        def safe(item, index):
            status, evidence = checked(item, index)
            if provider == "k8s" and target == "resource" and id != "k8s.cis.namespace_has_networkpolicy":
                # Provider/control-plane-managed objects: see peaso.checks.k8s_managed.
                from .k8s_managed import apply
                return apply(kind, item, index, status, evidence)
            return status, evidence

        def checked(item, index):
            from .facts import Unavailable, guard
            try:
                guard(item)
                status, evidence = function(item, index)
                if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE", "EMPTY") or not isinstance(evidence, dict):
                    raise ValueError("invalid evaluator result")
                return status, evidence
            except Unavailable as exc:
                return unknown(str(exc))
            except (ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as exc:
                return unknown("malformed or missing native facts", error_type=type(exc).__name__)
        CHECKS.append(Check(id, provider, category, kind, title, severity, control, remediation, safe, target,
                            tuple(dependencies or ()), allow_incomplete_failure, tuple(empty_applicability_dependencies)))
        return function
    return decorate


def result(failed, **evidence):
    return ("FAIL" if failed else "PASS"), evidence


def unknown(reason, **evidence):
    return "UNKNOWN", {"reason": reason, **evidence}


def array(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    raise ValueError("expected string or list")


def statements(document):
    if isinstance(document, str):
        import json
        from urllib.parse import unquote
        document = json.loads(unquote(document))
    if not isinstance(document, dict) or "Statement" not in document:
        raise ValueError("missing IAM statements")
    rows = get(document, "Statement")
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or any(not isinstance(s, dict) for s in rows):
        raise ValueError("malformed IAM statements")
    return rows


def aws_documents(item):
    documents, unresolved = [], 0
    try:
        direct = optional(item, "PolicyDocument", None)
        if "PolicyDocument" in item:
            documents.append(direct)
    except (Unavailable, ValueError):
        unresolved += 1
    if "PolicyVersionList" in item or "DefaultVersionId" in item:
        try:
            default_id = get(item, "DefaultVersionId", str)
            versions = list_of_objects(get(item, "PolicyVersionList", list))
            version_ids = [get(version, "VersionId", str) for version in versions]
            flags = [get(version, "IsDefaultVersion", bool) for version in versions]
            if (not default_id.strip() or any(not ident.strip() for ident in version_ids)
                    or len(version_ids) != len(set(version_ids))):
                raise Unavailable("managed policy version identity is incomplete or duplicated")
            selected = [version for version, flag in zip(versions, flags) if flag]
            if len(selected) != 1 or get(selected[0], "VersionId", str) != default_id:
                raise Unavailable("managed policy default version is inconsistent")
            # Do not consume any managed document until all version identities
            # and flags agree with the policy's selected native default.
            documents.append(get(selected[0], "Document"))
        except (Unavailable, ValueError):
            unresolved += 1
    for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):
        try:
            policies = list_of_objects(optional(item, key, [], list))
        except (Unavailable, ValueError):
            unresolved += 1
            continue
        for policy in policies:
            try:
                documents.append(get(policy, "PolicyDocument"))
            except (Unavailable, ValueError):
                unresolved += 1
    return documents, unresolved


@register("aws.iam.no_full_admin", "aws", "least_privilege", "iam_policy", "Managed policy has no unconditional full administrator grant", "high", "AC-6", "Replace full administrator grants with the actions and resources required for the workload; review conditions and explicit denies.")
def aws_admin(item, index):
    documents, unresolved = aws_documents(item)
    if not documents:
        return unknown("default policy document was not collected")
    flagged, conditional = [], []
    for document in documents:
        try:
            rows = statements(document)
        except (Unavailable, ValueError):
            unresolved += 1
            continue
        for statement in rows:
            try:
                effect = get(statement, "Effect", str)
                if effect not in ("Allow", "Deny"):
                    raise Unavailable("policy statement has no valid Effect")
                if not any(k in statement for k in ("Action", "NotAction")) or not any(k in statement for k in ("Resource", "NotResource")):
                    raise Unavailable("identity policy statement action or resource missing")
                if effect != "Allow":
                    continue
                actions = array(optional(statement, "Action", []))
                resources = array(optional(statement, "Resource", []))
                if any(not isinstance(value, str) for value in actions + resources):
                    raise Unavailable("malformed policy action/resource")
                if "*" in actions and "*" in resources:
                    condition = optional(statement, "Condition", None, dict)
                    (conditional if condition else flagged).append(statement)
            except (Unavailable, ValueError):
                unresolved += 1
    if flagged:
        return result(True, full_admin_statements=flagged, semantics="Declared policy grants; this is not effective access.")
    if unresolved:
        return unknown("policy statement fields unavailable", unresolved_statements=unresolved)
    if conditional:
        return "MANUAL", {"conditional_admin_statements": conditional, "semantics": "Declared allow only; conditions, denies, SCPs, boundaries and session policies require review."}
    return result(False, full_admin_statements=[], semantics="Declared policy grants; this is not effective access.")


@register("aws.iam.restrict_public_trust", "aws", "iam_graph", "iam_role", "Role trust avoids an unrestricted public principal", "high", "AC-3", "Limit role trust to intended principals and review trust conditions, organizational controls and federation settings.")
def aws_trust(item, index):
    document = get(item, "AssumeRolePolicyDocument")
    broad, conditional, unresolved = [], [], 0
    for statement in statements(document):
        try:
            effect = get(statement, "Effect", str)
            if effect not in ("Allow", "Deny"):
                raise Unavailable("trust statement effect missing or invalid")
            if "Principal" not in statement or not any(k in statement for k in ("Action", "NotAction")):
                raise Unavailable("trust principal or action missing")
            if effect != "Allow":
                continue
            for field in ("Action", "NotAction"):
                values = array(optional(statement, field, []))
                if any(not isinstance(value, str) for value in values):
                    raise Unavailable("malformed trust action")
            principal = get(statement, "Principal")
            if isinstance(principal, dict):
                keys = (set(principal) | set(principal.get("_coverage", {}))) - {"collection_status"}
                keys = {key for key in keys if not key.startswith("_")}
                if not keys:
                    raise Unavailable("trust principal members missing")
                wildcard, unreadable_principal = False, False
                for key in keys:
                    try:
                        values = array(get(principal, key))
                        if any(not isinstance(value, str) for value in values):
                            raise Unavailable("malformed trust principal values")
                        wildcard |= "*" in values
                    except (Unavailable, ValueError):
                        unreadable_principal = True
                if not wildcard and unreadable_principal:
                    raise Unavailable("trust principal members unavailable")
            elif isinstance(principal, str):
                wildcard = principal == "*"
            else:
                raise Unavailable("malformed trust principal")
            if wildcard:
                condition = optional(statement, "Condition", None, dict)
                (conditional if condition else broad).append(statement)
        except (Unavailable, ValueError):
            unresolved += 1
    if broad:
        return result(True, unrestricted_trust_statements=broad)
    if unresolved:
        return unknown("trust statement fields unavailable", unresolved_statements=unresolved)
    if conditional:
        return "MANUAL", {"conditional_public_trust": conditional, "semantics": "Conditions constrain declared trust; review manually."}
    return result(False, unrestricted_trust_statements=[])


@register("aws.iam.console_mfa", "aws", "hardening", "iam_user", "Console users have MFA configured", "high", "IA-2", "Enable MFA for console users; prefer federated short-lived access.")
def aws_mfa(item, index):
    if "LoginProfile" not in item or "MFADevices" not in item:
        return unknown("authorization-details inventory does not establish console login or MFA; add read-only login/MFA evidence")
    login = get(item, "LoginProfile")
    if login is None:
        return "NOT_APPLICABLE", {"console_login": False}
    if not isinstance(login, dict):
        return unknown("malformed console login evidence")
    status = optional(login, "collection_status", None, str)
    if status not in (None, "collected", "empty"):
        return unknown("unrecognized console login collection status")
    absent = optional(login, "absent", False, bool)
    profile = optional(login, "LoginProfile", None, dict)
    if status == "empty":
        if absent and profile is None:
            return "NOT_APPLICABLE", {"console_login": False}
        return unknown("empty console login receipt contradicts absence or retained profile")
    if absent:
        if status is None and profile is None:
            return "NOT_APPLICABLE", {"console_login": False}
        return unknown("console login absence contradicts collection status or retained profile")
    if profile is None:
        return unknown("console login profile unavailable")
    devices = get(item, "MFADevices")
    if isinstance(devices, dict):
        status = optional(devices, "collection_status", "collected", str)
        items = get(devices, "items", list)
        if status == "empty" and items:
            return unknown("MFA device collection status contradicts retained items")
        devices = items
    if not isinstance(devices, list):
        return unknown("malformed MFA devices")
    observed, uncertain = 0, False
    for device in devices:
        try:
            if not get(device, "SerialNumber", str).strip():
                raise Unavailable("empty MFA device serial number")
            observed += 1
        except Unavailable:
            uncertain = True
    if not observed and uncertain:
        return unknown("MFA device observations unavailable or malformed")
    return result(not observed, console_login=True, mfa_device_count=observed)


@register("aws.s3.public_access_block", "aws", "exposure", "bucket", "Bucket public access block is fully configured", "high", "AC-3", "Enable all four bucket Public Access Block settings and review account-level policy and ACL controls.",
          dependencies=["bucket", "s3_account_public_access_block"])
def aws_bucket_public(item, index):
    """Effective S3 Block Public Access = bucket setting OR account setting (s3control GetPublicAccessBlock)."""
    names = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    from .aws_a_facts import complete_items
    bucket = {key: None for key in names}
    try:
        config = get(item, "PublicAccessBlock", dict)
        absent = optional(config, "absent", False, bool)
        if absent:
            bucket = {key: False for key in names}
        else:
            settings = get(config, "PublicAccessBlockConfiguration", dict)
            for key in names:
                try:
                    bucket[key] = get(settings, key, bool)
                except Unavailable:
                    pass
    except Unavailable:
        pass
    # Each of the four bucket flags alone can establish its effective setting.
    if all(value is True for value in bucket.values()):
        return result(False, settings=bucket, account_public_access_block="not required",
                      semantics="Bucket-level preventative configuration, not proof of effective public access.")
    account = {key: None for key in names}
    try:
        scope = index.get("context", {}).get("scope")
        account_items = complete_items(index, "s3_account_public_access_block",
                                       scope=scope if isinstance(scope, str) else None)
        if len(account_items) > 1:
            raise Unavailable("ambiguous account public access block")
        if not account_items:
            account = {key: False for key in names}
        else:
            entry = account_items[0]
            if "AccountId" in entry or "AccountId" in entry.get("_coverage", {}):
                if not isinstance(scope, str) or get(entry, "AccountId", str) != scope.split("/", 1)[0]:
                    raise Unavailable("account public access block identity mismatch")
            if ("PublicAccessBlockConfiguration" in entry
                    or "PublicAccessBlockConfiguration" in entry.get("_coverage", {})):
                settings = get(entry, "PublicAccessBlockConfiguration", dict)
            else:
                settings = entry
            for key in names:
                if bucket[key] is True:
                    continue
                try:
                    account[key] = get(settings, key, bool)
                except Unavailable:
                    pass
    except Unavailable:
        pass
    effective = {key: True if bucket[key] is True or account[key] is True
                 else False if bucket[key] is False and account[key] is False
                 else None for key in names}
    evidence = {"effective_settings": effective, "bucket_public_access_block": bucket,
                "account_public_access_block": account,
                "semantics": "Effective bucket OR account Block Public Access; preventative configuration, not proof of public access."}
    if any(value is False for value in effective.values()):
        return result(True, **evidence)
    if all(value is True for value in effective.values()):
        return result(False, **evidence)
    return unknown("effective public access block fields unavailable", **evidence)


@register("aws.s3.default_encryption", "aws", "hardening", "bucket", "Bucket default encryption is configured", "medium", "SC-13", "Configure and verify server-side encryption; select an appropriate managed key for sensitive data.")
def aws_bucket_encryption(item, index):
    data = get(item, "Encryption", dict)
    if optional(data, "absent", False, bool):
        return unknown("default encryption unavailable; S3 encrypts new objects by default and absent legacy configuration alone is not a failure")
    config = get(data, "ServerSideEncryptionConfiguration", dict)
    rules = list_of_objects(get(config, "Rules", list))
    if not rules:
        return unknown("default encryption rules missing")
    algorithms = [get(get(rule, "ApplyServerSideEncryptionByDefault", dict), "SSEAlgorithm", str)
                  for rule in rules]
    if any(x not in ("AES256", "aws:kms", "aws:kms:dsse") for x in algorithms):
        return unknown("malformed or unrecognized encryption algorithm", algorithms=algorithms)
    return result(False, algorithms=algorithms, semantics="Default configuration; existing object encryption was not collected.")


@register("aws.ec2.restrict_internet_ingress", "aws", "network", "security_group", "Security group avoids broad internet ingress", "high", "SC-7", "Restrict ingress CIDRs and ports to intended clients; confirm routing, attached interfaces and network ACLs separately.")
def aws_ingress(item, index):
    rules = get(item, "IpPermissions", list)
    broad, unresolved = [], []
    for rule in rules:
        try:
            protocol = get(rule, "IpProtocol", str)
            named = protocol.lower() in ("tcp", "udp", "icmp", "icmpv6", "-1")
            numbered = protocol.isascii() and protocol.isdecimal() and 0 <= int(protocol) <= 255
            if not named and not numbered:
                raise Unavailable("unrecognized ingress protocol")
        except (Unavailable, ValueError) as exc:
            unresolved.append(str(exc))
            continue
        for ranges, key, version in (("IpRanges", "CidrIp", 4), ("Ipv6Ranges", "CidrIpv6", 6)):
            try:
                sources = list_of_objects(optional(rule, ranges, [], list))
            except Unavailable as exc:
                unresolved.append(str(exc))
                continue
            for source in sources:
                try:
                    cidr = get(source, key, str)
                    network = ip_network(cidr, strict=False)
                    if network.version != version:
                        raise Unavailable("ingress address family differs from source field")
                except (Unavailable, ValueError):
                    unresolved.append("ingress CIDR unavailable or malformed")
                    continue
                if network.prefixlen == 0:
                    observed = {"source": cidr, "protocol": protocol}
                    # Port fields describe the observation but do not change this
                    # CIDR-only declaration predicate. Unavailable ports are omitted.
                    for field, label in (("FromPort", "from_port"), ("ToPort", "to_port")):
                        try:
                            observed[label] = optional(rule, field, None, int)
                        except Unavailable:
                            pass
                    broad.append(observed)
    if broad:
        return result(True, internet_ingress=broad, semantics="Declared ingress; reachable services are not inferred.")
    if unresolved:
        return unknown("; ".join(sorted(set(unresolved))))
    return result(False, internet_ingress=[], semantics="Declared ingress; reachable services are not inferred.")


@register("aws.ec2.imdsv2", "aws", "hardening", "instance", "Instance requires IMDSv2 tokens when metadata is enabled", "medium", "CM-6", "Require IMDSv2 or disable instance metadata if the workload does not need it.")
def aws_imds(item, index):
    metadata = get(item, "MetadataOptions", dict)
    endpoint = get(metadata, "HttpEndpoint", str)
    if endpoint == "disabled":
        return "PASS", {"metadata_endpoint": "disabled"}
    if endpoint != "enabled":
        return unknown("metadata endpoint state unavailable")
    tokens = get(metadata, "HttpTokens", str)
    if tokens not in ("optional", "required"):
        return unknown("token requirement unavailable")
    return result(tokens != "required", metadata_options=metadata)


@register("gcp.iam.restrict_public_members", "gcp", "exposure", "iam_policy", "Project IAM avoids public members", "high", "AC-3", "Remove public IAM grants unless explicitly approved; account for binding conditions and inherited policies.")
def gcp_public(item, index):
    bindings = list_of_objects(get(item, "bindings", list))
    public, conditional, unresolved = [], [], []
    for binding in bindings:
        try:
            role = get(binding, "role", str)
            members = get(binding, "members", list)
            if any(not isinstance(member, str) for member in members):
                raise Unavailable("malformed IAM members")
            selected = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
            if not selected:
                continue
            condition = optional(binding, "condition", None, dict)
            (conditional if condition else public).append({"role": role, "members": selected, "condition": condition})
        except Unavailable as exc:
            unresolved.append(str(exc))
    if public:
        return result(True, public_bindings=public, semantics="Project policy declarations; inherited and effective permissions unassessed.")
    if unresolved:
        return unknown("project IAM binding facts unavailable", unresolved=unresolved, conditional_public_bindings=conditional)
    if conditional:
        return "MANUAL", {"conditional_public_bindings": conditional}
    return result(False, public_bindings=[], semantics="Project policy only; organization/folder inheritance and deny policies were not collected.")


@register("gcp.iam.avoid_basic_roles", "gcp", "least_privilege", "iam_policy", "Project IAM avoids broad owner/editor roles", "high", "AC-6", "Replace basic owner/editor roles with reviewed predefined or custom roles; preserve only approved administrative access.")
def gcp_basic(item, index):
    bindings = list_of_objects(get(item, "bindings", list))
    broad, unresolved = [], []
    for binding in bindings:
        try:
            role = get(binding, "role", str)
            members = get(binding, "members", list)
            if any(not isinstance(member, str) for member in members):
                raise Unavailable("malformed IAM members")
            if role in ("roles/owner", "roles/editor"):
                broad.append(binding)
        except Unavailable as exc:
            unresolved.append(str(exc))
    if broad:
        return result(True, broad_bindings=broad, semantics="Declared project grants, including conditions; not effective permissions.")
    if unresolved:
        return unknown("project IAM binding facts unavailable", unresolved=unresolved)
    return result(False, broad_bindings=[], semantics="Declared project grants, including conditions; not effective permissions.")


@register("gcp.storage.uniform_access", "gcp", "hardening", "bucket", "Bucket uses uniform bucket-level access", "medium", "AC-3", "Enable uniform bucket-level access after reviewing object ACL dependencies.")
def gcp_uniform(item, index):
    value = get(item, "iamConfiguration.uniformBucketLevelAccess.enabled", bool)
    if type(value) is not bool:
        return unknown("uniform bucket-level access flag missing")
    return result(not value, uniform_bucket_level_access=value)


def gcp_effective_boolean_constraint(index, constraint):
    """Resolve an effective boolean policy only for this exact project/constraint.

    Imported snapshots retain the provider's policy name independently of the
    collection wrapper. A numeric project alias needs the producer's CRM read
    binding and its matching request trace; the policy payload is not an alias
    authority.
    """
    import re
    from .facts import Unavailable, complete_items
    envelopes = index.get("collections", {}).get("org_policy_effective", [])
    if not isinstance(envelopes, list) or len(envelopes) != 1 or not isinstance(envelopes[0], dict):
        raise Unavailable("effective org policy scope ambiguous")
    scope = envelopes[0].get("scope")
    if not isinstance(scope, str) or not re.fullmatch(r"projects/[^/:%]+", scope):
        raise Unavailable("effective org policy project scope unavailable")
    context = index.get("context")
    if (not isinstance(context, dict) or context.get("scope") != scope
            or context.get("provider") != "gcp"):
        raise Unavailable("effective org policy context scope mismatch")
    policies = [p for p in complete_items(index, "org_policy_effective") if get(p, "constraint", str) == constraint]
    if len(policies) != 1:
        raise Unavailable("effective org policy missing or ambiguous: " + constraint)
    policy = policies[0]
    suffix = "/policies/" + constraint
    name = get(policy, "name", str)
    if not isinstance(name, str) or not name.endswith(suffix):
        raise Unavailable("effective org policy name/constraint mismatch")
    parent = name[:-len(suffix)]
    provenance = optional(policy, "_provenance", {}, dict)
    if not isinstance(provenance, dict) or (optional(provenance, "scope", None, str) not in (None, scope)):
        raise Unavailable("effective org policy provenance scope mismatch")
    alias = optional(policy, "project_alias", None, dict)
    if parent == scope:
        if alias is not None:
            raise Unavailable("unexpected effective org policy alias")
    else:
        if (not re.fullmatch(r"projects/[1-9][0-9]*", parent)
                or not isinstance(alias, dict)
                or get(alias, "requested_scope", str) != scope
                or get(alias, "project_id", str) != scope.split("/", 1)[1]
                or get(alias, "canonical_name", str) != parent
                or get(alias, "source_operation", str) != "projects.get"
                or not isinstance(get(alias, "source_request", str), str)
                or not get(alias, "source_request", str)):
            raise Unavailable("effective org policy project alias unresolved")
        requests = optional(get(context, "metadata", dict), "source_requests", [], list)
        if not isinstance(requests, list):
            raise Unavailable("effective org policy alias request trace missing")
        expected_url = "https://cloudresourcemanager.googleapis.com/v3/" + scope
        matches = [entry for entry in requests if isinstance(entry, dict)
                   and get(entry, "id", str) == get(alias, "source_request", str)]
        if (len(matches) != 1 or get(matches[0], "url", str) != expected_url
                or get(matches[0], "method", str) != "GET"
                or get(matches[0], "scope", str) != scope
                or get(matches[0], "status", str) != "collected"):
            raise Unavailable("effective org policy alias request unverified")
    # An evaluated Policy with no spec/rules means nothing is set anywhere in
    # the hierarchy: a boolean constraint is then not enforced.
    spec = optional(policy, "spec", {}, dict)
    rules = list_of_objects(optional(spec, "rules", [], list))
    if any(set(rule) - {"enforce", "_coverage"} or set(optional(rule, "_coverage", {}, dict)) - {"enforce"} for rule in rules):
        raise Unavailable("conditional or non-boolean effective org policy rule: " + constraint)
    values = {get(rule, "enforce", bool) for rule in rules}
    if len(values) > 1:
        raise Unavailable("contradictory effective org policy rules: " + constraint)
    return values == {True}, name

class ComputeDisabled(Exception):
    """The project's own Compute Engine API is disabled: no VM reads its metadata."""


def gcp_project_metadata_items(project):
    """Project commonInstanceMetadata.items from compute projects.get.

    The collector copies commonInstanceMetadata only from a successful read, and
    the Compute API returns the message (fingerprint) even when no metadata is set,
    with `items` omitted when empty. So an absent `items` is "nothing set", while an
    absent commonInstanceMetadata means the read failed: UNKNOWN, or ComputeDisabled
    when the project's own compute.googleapis.com is SERVICE_DISABLED."""
    from .facts import Unavailable
    if "commonInstanceMetadata" not in project:
        coverage = project.get("_coverage", {}).get("computeConfig", {}) if isinstance(project.get("_coverage"), dict) else {}
        error = coverage.get("error", {}) if isinstance(coverage, dict) else {}
        scope = project.get("_provenance", {}).get("scope") if isinstance(project.get("_provenance"), dict) else None
        if isinstance(error, dict) and error.get("reason") == "SERVICE_DISABLED" and error.get("service") == "compute.googleapis.com" \
                and scope and error.get("consumer") == scope:
            raise ComputeDisabled(scope)
    metadata = get(project, "commonInstanceMetadata", dict)
    if "items" in metadata:
        return list_of_objects(get(metadata, "items", list))
    # Omitted items is "nothing set" only on a fetched Metadata message (fingerprint).
    get(metadata, "fingerprint", str)
    if "items" in metadata.get("_coverage", {}):
        raise Unavailable("project metadata items unavailable")
    return []


def gcp_oslogin_unset(index):
    """enable-oslogin not set at the instance or project: SSH falls back to
    metadata-managed keys ("By default, Compute Engine uses custom project and/or
    instance metadata to configure SSH keys") unless compute.requireOsLogin is
    enforced. Returns (enabled, effective policy name); Unavailable when the
    effective policy was not collected."""
    enforced, name = gcp_effective_boolean_constraint(index, "compute.requireOsLogin")
    return enforced, name


def gcp_oslogin_flag(rows, where):
    from .facts import Unavailable
    values = [get(row, "value", str).lower() for row in list_of_objects(rows) if get(row, "key", str).lower() == "enable-oslogin"]
    if len(values) > 1 or any(value not in ("true", "false") for value in values):
        raise Unavailable("ambiguous or unrecognized OS Login metadata in " + where)
    return (values[0] == "true") if values else None


def gcp_instance_oslogin(item, index):
    """Instance enable-oslogin overrides project metadata ("Setting enable-oslogin
    to FALSE in instance metadata disables OS Login for the VM even if
    enable-oslogin is set to TRUE in project metadata"); unset at both levels
    falls back to the effective compute.requireOsLogin."""
    from .facts import Unavailable, complete_items
    instance = get(item, "metadata", dict)
    setting = gcp_oslogin_flag(optional(instance, "items", [], list), "instance metadata")
    if setting is not None:
        return result(not setting, declared_at="instance", instance_enable_oslogin=setting,
            semantics="Instance declaration overrides project metadata, not guest-agent execution proof")
    scope = get(item, "_provenance.scope", str)
    matches = [project for project in complete_items(index, "project") if project.get("_provenance", {}).get("scope") == scope
               or project.get("name") == scope or "projects/" + str(project.get("projectId", "")) == scope]
    if len(matches) != 1:
        return unknown("project metadata relation unavailable or ambiguous")
    try:
        inherited = gcp_oslogin_flag(gcp_project_metadata_items(matches[0]), "project metadata")
    except ComputeDisabled:
        raise Unavailable("project compute metadata unavailable")
    if inherited is not None:
        return result(not inherited, declared_at="project", project_enable_oslogin=inherited,
            semantics="Declared metadata precedence, not effective SSH authorization")
    enforced, policy = gcp_oslogin_unset(index)
    return result(not enforced, declared_at="organization_policy", effective_org_policy=policy, require_os_login_enforced=enforced,
        semantics="enable-oslogin unset on instance and project; compute.requireOsLogin decides")


@register("gcp.storage.public_access_prevention", "gcp", "exposure", "bucket", "Bucket public access prevention is enforced", "high", "AC-3", "Enforce public access prevention or verify the inherited organization policy; review bucket IAM separately.",
          dependencies=["bucket", "org_policy_effective"])
def gcp_prevention(item, index):
    value = get(item, "iamConfiguration.publicAccessPrevention", str)
    if value == "inherited":
        from .facts import Unavailable
        try:
            enforced, policy = gcp_effective_boolean_constraint(index, "storage.publicAccessPrevention")
        except Unavailable as exc:
            return unknown("public access prevention is inherited; effective organization policy unavailable", configured=value, detail=str(exc))
        return result(not enforced, configured=value, effective_org_policy=policy, org_policy_enforced=enforced,
                      semantics="Bucket inherits storage.publicAccessPrevention; evaluated via getEffectivePolicy for the project.")
    if value != "enforced":
        return unknown("public access prevention setting missing", configured=value)
    return result(False, configured=value, semantics="Preventative setting; bucket IAM and object ACL public access not evaluated.")


@register("gcp.compute.restrict_internet_ingress", "gcp", "network", "firewall", "Firewall avoids broad internet ingress", "high", "SC-7", "Restrict source ranges and service ports; review target tags, service accounts and higher-priority firewall policies.")
def gcp_ingress(item, index):
    applicability_unknown = False
    disabled, direction = None, None
    try:
        disabled = optional(item, "disabled", False, bool)
    except Unavailable:
        applicability_unknown = True
    try:
        direction = optional(item, "direction", "INGRESS", str)
        if direction not in ("INGRESS", "EGRESS"):
            raise Unavailable("unrecognized firewall direction")
    except Unavailable:
        applicability_unknown = True
    if disabled is True or direction == "EGRESS":
        return "NOT_APPLICABLE", {"disabled": disabled, "direction": direction}
    if applicability_unknown:
        return unknown("firewall applicability unavailable or malformed")

    def protocol(rule):
        value = get(rule, "IPProtocol", str)
        if value not in ("tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp", "all") and not (value.isascii() and value.isdigit() and 0 <= int(value) <= 255):
            raise Unavailable("unrecognized firewall IP protocol")
        return value

    denied = optional(item, "denied", [], list)
    for rule in denied:
        protocol(rule)
    if denied:
        return "NOT_APPLICABLE", {"disabled": disabled, "direction": direction}
    allowed = get(item, "allowed", list)
    allowed_observed, uncertain = False, False
    for rule in allowed:
        try:
            protocol(rule)
            allowed_observed = True
        except Unavailable:
            uncertain = True
    # Explicit unreadability never selects the native omitted-source default.
    selectors, sources, source_uncertain = [], None, False
    for field in ("sourceTags", "sourceServiceAccounts"):
        try:
            values = optional(item, field, [], list)
            if any(not isinstance(value, str) or not value for value in values):
                raise Unavailable("malformed firewall source selectors")
            selectors.extend(values)
        except Unavailable:
            source_uncertain = True
    try:
        sources = optional(item, "sourceRanges", None, list)
    except Unavailable:
        source_uncertain = True
    if sources == [] and not selectors and not source_uncertain and allowed_observed:
        return unknown("explicit empty sourceRanges without source selectors does not establish restriction; native source default unresolved")
    if sources is None:
        sources = [] if selectors or source_uncertain else ["0.0.0.0/0"]
    uncertain = uncertain or source_uncertain
    broad = False
    for source in sources:
        try:
            if not isinstance(source, str):
                raise ValueError("malformed source range")
            broad = broad or ip_network(source, strict=False).prefixlen == 0
        except ValueError:
            uncertain = True
    failed = allowed_observed and broad
    if not failed and uncertain:
        return unknown("firewall declaration facts unavailable or malformed")
    return result(failed, source_ranges=sources, allowed=allowed, network=item.get("network"),
        target_tags=item.get("targetTags", []), target_service_accounts=item.get("targetServiceAccounts", []), priority=item.get("priority", 1000),
        **(gcp_firewall_targets(item, index) if failed else {}), semantics="Declared firewall rule only, not effective reachability.")


def gcp_firewall_targets(item, index):
    """Source-bound declaration attribution only; incomplete facts never lower risk."""
    from .facts import Unavailable, complete_items, guard

    missing = object()

    def selected(row, key, expected, default=missing):
        # An empty read can carry an empty array, but cannot authenticate a
        # retained nonempty value from a prior or partial projection.
        guard(row)
        parent_coverage = row.get("_coverage", {})
        if "collection_status" in parent_coverage:
            proof = parent_coverage["collection_status"]
            if not isinstance(proof, dict) or proof.get("status") not in ("collected", "empty"):
                raise Unavailable("target parent status unavailable")
            if (proof["status"] == "empty") != ("collection_status" not in row):
                raise Unavailable("target parent status contradicts field coverage")
        if "collection_status" in row and row["collection_status"] != "collected":
            raise Unavailable("target parent unavailable")
        coverage = row.get("_coverage", {}).get(key)
        if (isinstance(coverage, dict) and coverage.get("status") == "empty"
                and key in row and bool(row[key])):
            raise Unavailable("nonempty selected field contradicts empty coverage: " + key)
        if default is missing:
            return get(row, key, expected)
        return optional(row, key, default, expected)

    def string_set(values):
        if any(not isinstance(value, str) or not value for value in values):
            raise Unavailable("malformed target selector")
        return set(values)

    def network(link):
        if not isinstance(link, str) or not link:
            raise Unavailable("network identity unavailable")
        return link.split("/projects/", 1)[-1].removeprefix("projects/")

    try:
        instances = complete_items(index, "instance")
        wanted_network = network(selected(item, "network", str))
        tags = string_set(selected(item, "targetTags", list, []))
        accounts = string_set(selected(item, "targetServiceAccounts", list, []))
    except Unavailable:
        return {"target_instances": "unknown (instance inventory or rule attribution unavailable)",
                "target_instances_running": "unknown (target attribution unavailable)",
                "target_instances_complete": False}

    from .gcp_firewall_target_index import attributed
    matched, unresolved = attributed(index, instances, wanted_network, tags, accounts, selected, network, string_set)
    running = sum(row["status"] == "RUNNING" for row in matched)
    running_unknown = unresolved or any(row["status"] is None for row in matched)
    evidence = {"target_instances": "unknown (target attribution incomplete)" if unresolved else len(matched),
                "target_instances_complete": not unresolved,
                "target_instances_running": "unknown (running target count incomplete)" if running_unknown else running,
                "target_instance_sample": matched[:10],
                "target_attribution_semantics": "Declared network and target selectors in the scoped inventory; not effective reachability."}
    if unresolved:
        evidence["target_instances_lower_bound"] = len(matched)
    if running_unknown:
        evidence["target_instances_running_lower_bound"] = running
    if not matched and not unresolved:
        evidence.update(practical_severity="low", practical_severity_reason="No VM in this project matches the rule's network and targets; the exposure is latent")
    return evidence


@register("gcp.compute.no_external_ip", "gcp", "exposure", "instance", "Instance avoids an unreviewed external IP", "medium", "SC-7", "Use private connectivity where possible; review approved public endpoints and firewall restrictions.")
def gcp_ip(item, index):
    from .facts import guard
    from ipaddress import ip_address
    interfaces = get(item, "networkInterfaces", list)
    addresses, uncertain = [], False
    for nic in interfaces:
        try:
            guard(nic)
        except Unavailable:
            uncertain = True
            continue
        for field, key in (("accessConfigs", "natIP"), ("ipv6AccessConfigs", "externalIpv6")):
            try:
                configs = optional(nic, field, [], list)
            except Unavailable:
                uncertain = True
                continue
            for config in configs:
                try:
                    address = get(config, key, str)
                    if ip_address(address).version != (4 if key == "natIP" else 6):
                        raise ValueError("external address has wrong IP family")
                    addresses.append(address)
                except (Unavailable, ValueError):
                    uncertain = True
    if not addresses and uncertain:
        return unknown("external address configuration unavailable or malformed")
    return result(bool(addresses), external_ips=addresses, semantics="Assigned addresses; no reachability test was performed.")


@register("azure.storage.https_only", "azure", "hardening", "storage_account", "Storage account requires secure transfer", "high", "SC-8", "Enable secure transfer required for the storage account.")
def azure_https(item, index):
    value = get(item, "properties.supportsHttpsTrafficOnly", bool)
    if type(value) is not bool:
        return unknown("secure transfer flag missing")
    return result(not value, supports_https_traffic_only=value)


@register("azure.storage.no_blob_public_access", "azure", "exposure", "storage_account", "Storage account disables anonymous blob access", "high", "AC-3", "Disable account-level anonymous blob access and review existing container access policies.")
def azure_blob(item, index):
    value = get(item, "properties.allowBlobPublicAccess", bool)
    if type(value) is not bool:
        return unknown("anonymous blob access flag missing; omitted API fields are not treated as safe defaults")
    return result(value, allow_blob_public_access=value, semantics="Account-level capability; no container data-plane inventory was collected.")


@register("azure.storage.minimum_tls", "azure", "hardening", "storage_account", "Storage account requires TLS 1.2 or newer", "medium", "SC-8", "Set minimumTlsVersion to TLS1_2 or newer supported policy.")
def azure_tls(item, index):
    value = get(item, "properties.minimumTlsVersion", str)
    if value not in ("TLS1_0", "TLS1_1", "TLS1_2"):
        return unknown("minimum TLS version missing or unknown", configured=value)
    return result(value in ("TLS1_0", "TLS1_1"), minimum_tls_version=value)


@register("azure.iam.review_owner_assignment", "azure", "least_privilege", "role_assignment", "Owner assignments receive least-privilege review", "high", "AC-6", "Review whether the principal requires Owner; replace with a narrower role and time-bound administrative eligibility where appropriate.")
def azure_owner(item, index):
    properties = get(item, "properties", dict)
    role = get(properties, "roleDefinitionId", str)
    principal = get(properties, "principalId", str)
    if not role or not principal:
        return unknown("role assignment principal or role missing")
    owner = role.lower().endswith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
    return result(owner, principal_id=principal, role_definition_id=role,
        assignment_scope=properties.get("scope"), condition=properties.get("condition"), semantics="Declared assignment only; deny assignments, group membership, PIM eligibility and inheritance were not evaluated.")


@register("azure.iam.no_full_custom_role", "azure", "least_privilege", "role_definition", "Custom role avoids unrestricted control-plane or data-plane actions", "high", "AC-6", "Limit custom-role actions, dataActions and assignable scopes; review notActions and notDataActions exclusions.")
def azure_custom(item, index):
    properties = get(item, "properties", dict)
    role_type = get(properties, "type", str)
    if role_type == "BuiltInRole":
        return "NOT_APPLICABLE", {"role_type": "BuiltInRole"}
    if role_type != "CustomRole":
        return unknown("custom role type missing or unrecognized")
    permissions = get(properties, "permissions", list)
    unrestricted, excluded, unresolved = [], [], False
    for permission in permissions:
        block_unrestricted, block_excluded = False, False
        for grant, exclusion in (("actions", "notActions"), ("dataActions", "notDataActions")):
            try:
                values = optional(permission, grant, [], list)
                if any(not isinstance(action, str) for action in values):
                    raise Unavailable("malformed role permission actions")
                if "*" not in values:
                    continue
                exclusions = optional(permission, exclusion, [], list)
                if any(not isinstance(action, str) for action in exclusions):
                    raise Unavailable("malformed role permission exclusions")
                if exclusions:
                    block_excluded = True
                else:
                    block_unrestricted = True
            except Unavailable:
                unresolved = True
        if block_unrestricted:
            unrestricted.append(permission)
        elif block_excluded:
            excluded.append(permission)
    if unrestricted:
        return result(True, unrestricted_permission_blocks=unrestricted, assignable_scopes=properties.get("assignableScopes", []))
    if unresolved:
        return unknown("custom role permission actions or exclusions unavailable", wildcard_blocks_with_exclusions=excluded)
    if excluded:
        return "MANUAL", {"wildcard_blocks_with_exclusions": excluded, "semantics": "Exclusions are not denies; review control-plane and data-plane semantics separately."}
    return result(False, unrestricted_permission_blocks=[], assignable_scopes=properties.get("assignableScopes", []))


@register("azure.network.restrict_internet_ingress", "azure", "network", "nsg", "NSG avoids broad internet allow rules", "high", "SC-7", "Restrict allow-rule source prefixes and ports; review NSG priority, subnet/NIC attachment and effective routes.")
def azure_ingress(item, index):
    from .claude_azure_common import nsg_sources
    rules = list_of_objects(get(item, "properties.securityRules", list))
    broad, unresolved = [], []
    for rule in rules:
        try:
            p = get(rule, "properties", dict)
            direction, access = get(p, "direction", str), get(p, "access", str)
            if direction not in ("Inbound", "Outbound") or access not in ("Allow", "Deny"):
                raise Unavailable("malformed NSG rule direction or access")
            if direction == "Inbound" and access == "Allow":
                sources = nsg_sources(p)
                if any(source in ("*", "Internet", "0.0.0.0/0", "::/0") for source in sources):
                    broad.append({"name": rule.get("name"), "priority": p.get("priority"), "source": sources,
                        "destination_ports": p.get("destinationPortRanges") or [p.get("destinationPortRange")], "protocol": p.get("protocol")})
        except Unavailable as exc:
            unresolved.append(str(exc))
    if broad:
        return result(True, broad_ingress_rules=broad, semantics="Declared custom allow rules; effective ordering and reachability unassessed.")
    if unresolved:
        return unknown("NSG custom rule facts unavailable", unresolved=unresolved)
    return result(False, broad_ingress_rules=[], semantics="Declared custom allow rules; effective priority ordering, defaults and reachability require review.")


@register("k8s.rbac.no_wildcards", "k8s", "least_privilege", "clusterrole", "ClusterRole avoids wildcard rules", "high", "AC-6", "Replace wildcard RBAC grants with specific reviewed API groups, resources and verbs.")
@register("k8s.rbac.role_no_wildcards", "k8s", "least_privilege", "role", "Role avoids wildcard rules", "high", "AC-6", "Replace wildcard RBAC grants with specific reviewed API groups, resources and verbs.")
def k8s_wildcards(item, index):
    rules = get(item, "rules", list)
    broad = []
    unresolved = False
    for rule in rules:
        if not isinstance(rule, dict):
            unresolved = True
            continue
        rule_broad = False
        try:
            verbs = get(rule, "verbs", list)
        except Unavailable:
            unresolved = True
            continue
        if not verbs or any(not isinstance(v, str) for v in verbs):
            unresolved = True
            continue
        if "*" in verbs:
            rule_broad = True
        for field in ("resources", "apiGroups", "nonResourceURLs"):
            try:
                values = optional(rule, field, [], list)
                if any(not isinstance(v, str) for v in values):
                    unresolved = True
                elif "*" in values:
                    rule_broad = True
            except Unavailable:
                unresolved = True
        if rule_broad:
            broad.append(rule)
    if broad:
        return result(True, wildcard_rules=broad, aggregation_rule=item.get("aggregationRule"), semantics="Declared RBAC; bindings and authorization integrations determine effective access.")
    if unresolved:
        return unknown("RBAC rule fields unavailable or malformed; aggregated roles require their resolved rules")
    return result(False, wildcard_rules=[], aggregation_rule=item.get("aggregationRule"), semantics="Declared RBAC; bindings and authorization integrations determine effective access.")


@register("k8s.rbac.review_broad_subjects", "k8s", "iam_graph", "clusterrolebinding", "ClusterRoleBinding avoids broad authenticated groups", "high", "AC-3", "Bind reviewed roles to intended users or service accounts and review aggregated role definitions.")
@register("k8s.rbac.review_namespaced_subjects", "k8s", "iam_graph", "rolebinding", "RoleBinding avoids broad authenticated groups", "high", "AC-3", "Bind namespace roles to intended users or service accounts.")
def k8s_subjects(item, index):
    subjects = get(item, "subjects", list)
    role_ref = get(item, "roleRef", dict)
    broad = []
    unresolved = False
    for subject in subjects:
        try:
            kind = get(subject, "kind", str)
            if kind == "Group" and get(subject, "name", str) in ("system:authenticated", "system:unauthenticated", "system:serviceaccounts"):
                broad.append(subject)
        except Unavailable:
            unresolved = True
    if broad:
        return result(True, broad_subjects=broad, role_ref=role_ref, semantics="Declared binding; grants are not a calculated effective-access claim.")
    if unresolved:
        return unknown("binding subject fields unavailable or malformed")
    return result(False, broad_subjects=[], role_ref=role_ref, semantics="Declared binding; grants are not a calculated effective-access claim.")


@register("k8s.pod.no_privileged_containers", "k8s", "hardening", "pod", "Pod avoids privileged containers", "high", "CM-6", "Disable privileged containers and enforce an appropriate Pod Security Admission policy.")
def k8s_privileged(item, index):
    spec = get(item, "spec", dict)
    containers = get(spec, "containers", list)
    if not containers:
        return unknown("pod container specifications missing")
    all_containers = list(containers)
    unresolved = False
    for field in ("initContainers", "ephemeralContainers"):
        try:
            all_containers.extend(optional(spec, field, [], list))
        except Unavailable:
            unresolved = True
    privileged = []
    for container in all_containers:
        try:
            context = optional(container, "securityContext", {}, dict)
            if optional(context, "privileged", False, bool) is True:
                privileged.append(container.get("name"))
        except Unavailable:
            unresolved = True
    if privileged:
        return result(True, privileged_containers=privileged, semantics="Observed pod spec; admission enforcement not inferred.")
    if unresolved:
        return unknown("container inventory or privileged flag unavailable or malformed")
    return result(False, privileged_containers=[], semantics="Observed pod spec; admission enforcement not inferred.")


@register("k8s.pod.no_host_namespaces", "k8s", "hardening", "pod", "Pod avoids host namespaces", "high", "CM-6", "Disable hostNetwork, hostPID and hostIPC unless the workload has an approved operational requirement.")
def k8s_host(item, index):
    spec = get(item, "spec", dict)
    values = {}
    unresolved = False
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        try:
            values[key] = optional(spec, key, False, bool)
        except Unavailable:
            unresolved = True
    if any(values.values()):
        return result(True, host_namespace_flags=values)
    if unresolved:
        return unknown("host namespace flags unavailable or malformed")
    return result(False, host_namespace_flags=values)


@register("k8s.service.review_public_type", "k8s", "exposure", "service", "Service avoids unreviewed external publication", "medium", "SC-7", "Review LoadBalancer, NodePort and externalIPs services against approved ingress and network controls.")
def k8s_service(item, index):
    from ipaddress import ip_address
    spec = get(item, "spec", dict)
    try:
        service_type = optional(spec, "type", "ClusterIP", str)
        if service_type not in ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName"):
            raise Unavailable("unknown service type")
    except Unavailable:
        service_type = None

    # A known external IP or NodePort independently establishes publication.
    external_ips, external_unknown = [], False
    try:
        values = optional(spec, "externalIPs", [], list)
        for value in values:
            try:
                if not isinstance(value, str):
                    raise ValueError("external IP is not a string")
                ip_address(value)
                external_ips.append(value)
            except ValueError:
                external_unknown = True
    except Unavailable:
        external_unknown = True
    semantics = "Publication configuration only; internet reachability was not tested."
    if external_ips:
        return result(True, service_type=service_type, external_ips=external_ips, semantics=semantics)
    if service_type == "NodePort":
        return result(True, service_type=service_type, semantics=semantics,
            **({"external_ips": external_ips} if not external_unknown else {}))
    if service_type is None:
        return unknown("service type unavailable or malformed")
    if service_type in ("ClusterIP", "ExternalName"):
        if external_unknown:
            return unknown("external IP list unavailable or malformed")
        return result(False, service_type=service_type, external_ips=external_ips, semantics=semantics)

    # LoadBalancer-only restrictions. Keep literal annotation keys intact:
    # facts.get would split their periods and miss exact _coverage entries.
    from peaso.analysis.internet_exposure import INTERNAL, SOURCE_ANNOTATIONS, k8s_internal, k8s_source_ranges
    range_unknown, internal_unknown = False, False
    try:
        raw_ranges = optional(spec, "loadBalancerSourceRanges", [], list)
    except Unavailable:
        raw_ranges, range_unknown = [], True
    safe_ranges = []
    for value in raw_ranges:
        if isinstance(value, str):
            safe_ranges.append(value)
        else:
            range_unknown = True
    try:
        meta = optional(item, "metadata", {}, dict)
        annotations = optional(meta, "annotations", {}, dict)
    except Unavailable:
        annotations = {}
        internal_unknown = range_unknown = True
    from .facts import guard
    def literal_annotation(key):
        guard(annotations)
        coverage_entries = annotations.get("_coverage", {})
        coverage = coverage_entries.get(key)
        if key in coverage_entries:
            if not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty"):
                raise Unavailable("annotation unavailable: " + key)
            if coverage["status"] == "empty":
                if key in annotations:
                    raise Unavailable("empty annotation has retained value: " + key)
                return None
        if key not in annotations:
            if key in coverage_entries:
                raise Unavailable("collected annotation missing: " + key)
            return None
        value = annotations[key]
        if not isinstance(value, str):
            raise Unavailable("malformed annotation: " + key)
        return value

    safe_annotations = {}
    for key in INTERNAL:
        try:
            value = literal_annotation(key)
            if value is not None:
                safe_annotations[key] = value
        except Unavailable:
            internal_unknown = True
    for key in SOURCE_ANNOTATIONS:
        try:
            value = literal_annotation(key)
            if value is not None:
                safe_annotations[key] = value
        except Unavailable:
            range_unknown = True
    safe_meta = {"annotations": safe_annotations}
    raw_sources = k8s_source_ranges({"loadBalancerSourceRanges": safe_ranges}, safe_meta)
    ranges = []
    for source in raw_sources:
        try:
            ip_network(source, strict=False)
            ranges.append(source)
        except ValueError:
            range_unknown = True
    internal = k8s_internal(safe_meta)
    if internal:
        if external_unknown:
            return unknown("external IP list unavailable or malformed")
        return result(False, service_type=service_type, external_ips=external_ips,
            internal_annotations=internal, semantics=semantics)
    if internal_unknown:
        return unknown("internal load balancer annotation unavailable or malformed")
    broad = any(ip_network(source, strict=False).prefixlen == 0 for source in ranges)
    if not internal and broad:
        return result(True, service_type=service_type, external_ips=external_ips,
            load_balancer_source_ranges=ranges, internal_annotations=internal, semantics=semantics)
    if range_unknown:
        return unknown("load balancer source ranges unavailable or malformed")
    restricted = bool(internal) or bool(ranges)
    if restricted and external_unknown:
        return unknown("external IP list unavailable or malformed")
    return result(not restricted, service_type=service_type, external_ips=external_ips,
        load_balancer_source_ranges=ranges, internal_annotations=internal, semantics=semantics)


@register("k8s.network.namespace_policy_inventory", "k8s", "network", "namespace", "Namespace has NetworkPolicy inventory for review", "medium", "SC-7", "Define reviewed default-deny ingress/egress policies and verify that the cluster network plugin enforces them.")
def k8s_policies(item, index):
    name = get(item, "metadata.name", str)
    if not name:
        return unknown("namespace name missing")
    envelopes = index.get("collections", {}).get("networkpolicy", [])
    # Qualified scopes identify a cluster and namespace. A cluster-scoped namespace
    # list must not turn another namespace's missing policy inventory into a FAIL.
    relevant = [c for c in envelopes if c["scope"] in ("*", name) or c["scope"].endswith(("/" + name, "/*"))]
    if not relevant or any(c["status"] not in ("collected", "empty") for c in relevant):
        return unknown("network policy inventory missing or incomplete")
    policies, unresolved = [], False
    # The complete source rows retain evidence that public resource wrappers
    # may deduplicate by identity. Every row must be attributable for absence.
    for collection in relevant:
        for policy in list_of_objects(get(collection, "items", list)):
            try:
                if get(policy, "metadata.namespace", str) == name:
                    policies.append(policy)
            except Unavailable:
                unresolved = True
    if not policies and unresolved:
        return unknown("network policy namespace identities unavailable")
    if not policies:
        return result(True, namespace=name, network_policy_count=0, semantics="No policies observed in complete inventory; enforcement and other cluster controls are not known.")
    return "MANUAL", {"namespace": name, "network_policy_count": len(policies), "reason": "Policy presence is not proof of pod coverage, default deny, or CNI enforcement."}


# Registration imports happen after the compatibility helpers are defined.
from . import aws, gcp, azure, k8s  # noqa: E402,F401
from . import k8s_extended  # noqa: E402,F401
from . import gcp_extended  # noqa: E402,F401
from . import aws_extended  # noqa: E402,F401
from . import azure_extended  # noqa: E402,F401
from . import k8s_ports_workloads  # noqa: E402,F401
from . import azure_ports_services  # noqa: E402,F401
from . import aws_a_iam  # noqa: E402,F401
from . import aws_b_core, aws_b_loadbalancing  # noqa: E402,F401
from . import k8s_ports_components  # noqa: E402,F401
from . import aws_b_regional  # noqa: E402,F401
from . import gcp_ports_services  # noqa: E402,F401
from . import aws_b_cloudfront  # noqa: E402,F401
from . import aws_a_regional, azure_ports_defender, k8s_ports_cluster  # noqa: E402,F401
from . import aws_b_storage  # noqa: E402,F401
from . import aws_b_compute  # noqa: E402,F401
from . import azure_ports_paas  # noqa: E402,F401
from . import azure_ports_common, aws_b_ecr, aws_a_cloudwatch  # noqa: E402,F401
from . import aws_b_apigateway, k8s_ports_reference_config  # noqa: E402,F401
from . import azure_ports_directory  # noqa: E402,F401
from . import gcp_ports_compute  # noqa: E402,F401
from . import aws_b_dms, azure_ports_monitor, gcp_ports_keys, aws_a_cloudtrail  # noqa: E402,F401
from . import claude_azure  # noqa: E402,F401
from . import gcp_ports_configuration, azure_ports_vault, aws_b_databases  # noqa: E402,F401
from . import gcp_ports_iam, gcp_ports_relationships, gcp_ports_perimeter, aws_b_inspector  # noqa: E402,F401
from . import exposure_endpoints  # noqa: E402,F401
from . import claude_aws_a  # noqa: E402,F401
from . import claude_aws_b  # noqa: E402,F401
from . import claude_gcp_k8s  # noqa: E402,F401
from . import claude2_gcp  # noqa: E402,F401
from . import claude2_aws_b  # noqa: E402,F401
from . import claude2_aws_a  # noqa: E402,F401
from . import aws_a_accessanalyzer, aws_a_cloudtrail_variants, aws_a_iam_lifecycle, aws_a_iam_policies, aws_a_iam_usage, aws_a_kms, aws_a_s3, aws_b_cognito, aws_b_redshift, azure_ports_legacy_plans, azure_ports_storage, gcp_ports_logging, gcp_ports_metadata, aws_a_account  # noqa: E402,F401  (supervisor-admitted Codex modules)
from . import claude2_azure  # noqa: E402,F401
from . import k8s_gap_admission  # noqa: E402,F401  (framework/coverage gap audit: CIS K8s 1.2.3/1.2.9)
from . import hacktricks_bp_k8s, hacktricks_bp_aws, hacktricks_bp_aws_ext, hacktricks_bp_gcp, hacktricks_bp_azure, hacktricks_bp_links  # noqa: E402,F401  (HackTricks Cloud Best Practices checks)
from . import aws_gap_core  # noqa: E402,F401  (AWS upstream-gap audit: corrected predicates for rejected upstream rows)
from . import aws_gap_metrics, aws_gap_account, aws_gap_ec2  # noqa: E402,F401  (AWS upstream-gap audit: monitoring/contact/instance-role natives)
from . import azure_gap_nsg  # noqa: E402,F401  (framework/coverage gap audit: CIS Azure NSG declaration audits 6.1/6.2/6.4/6.6)
from . import gcp_gap_cis  # noqa: E402,F401  (framework/coverage gap audit: CIS GCP 1.5 / 3.10 declaration audits)
from . import compliance_new_aws, compliance_new_gcp, compliance_new_azure, compliance_new_k8s  # noqa: E402,F401  (supervisor-signed defensive requirement predicates)
from . import compliance_new_aws_acm_expiry, compliance_new_aws_backup, compliance_new_aws_ec2, compliance_new_aws_guardduty, compliance_new_aws_s3  # noqa: E402,F401  (signed 80-check compliance batch)
from . import compliance_new_azure_defender, compliance_new_azure_logs  # noqa: E402,F401  (signed 80-check compliance batch)
from . import compliance_new_gcp_backend, compliance_new_gcp_bigquery, compliance_new_gcp_sql, compliance_new_gcp_storage  # noqa: E402,F401  (signed 80-check compliance batch)
from . import compliance_new_k8s_file_metadata, compliance_new_k8s_network, compliance_new_k8s_workload_ingress  # noqa: E402,F401  (signed 80-check compliance batch)
from . import compliance_new_aws_lambda, compliance_new_gcp_cloudbuild, compliance_new_gcp_appengine  # noqa: E402,F401  (signed 92-check compliance batch)
from . import compliance_new_k8s_owner_policy, compliance_new_azure_pricing, compliance_new_azure_data_protection  # noqa: E402,F401  (signed 92-check compliance batch)
from . import compliance_new_azure_network_monitoring  # noqa: E402,F401  (signed 94-check compliance batch)
from . import compliance_new_aws_apigateway  # noqa: E402,F401  (signed 96-check compliance batch)
from . import compliance_new_aws_inspector_ec2, compliance_new_gcp_api_keys  # noqa: E402,F401  (signed 98-check compliance batch)
from . import aws_config_recording  # noqa: E402,F401  (signed admission: aws_config_all_resources_recorded)
from . import aws_backup_plan_frequency  # noqa: E402,F401  (signed admission: aws_nist_backup_plan_min_retention_35_days)
from . import k8s_namespace_policy_presence  # noqa: E402,F401  (signed CIS 5.3.2 namespace declaration check)
from . import compliance_new_k8s_component  # noqa: E402,F401  (two declarations here; rotation is registered by the reviewed batch)
from . import gcp_data_access  # noqa: E402,F401  (signed Spanner and Pub/Sub Data Access declaration checks)
from . import wafv2_basic  # noqa: E402,F401  (signed WAFv2 rule-group PCI checks)
from . import compliance_next_k8s  # noqa: E402,F401  (three signed Kubernetes declaration checks)
from . import batch_remaining_aws, batch_remaining_azure, batch_remaining_gcp, batch_remaining_k8s, batch_remaining_azure_vm_storage  # noqa: E402,F401  (single signed remaining-native batch)
from .fixtures import restore_remaining_batch_cases as _restore_remaining_batch_cases  # noqa: E402
_restore_remaining_batch_cases()
del _restore_remaining_batch_cases
alias_check('aws_g6_redshift_automatic_version_upgrade', 'aws.cb.redshift.allow_version_upgrade')  # exact signed duplicate; one canonical evaluator
alias_check('aws.pci.cloudtrail.authentication_events', 'aws.gap.cloudtrail.region_logging_management_events')  # exact regional CloudTrail signed duplicate
from . import post_dfaf_aws, post_dfaf_azure  # noqa: E402,F401 (reviewed ten-ID successor)
post_dfaf_aws.install()
post_dfaf_azure.install()
from .fixtures import restore_remaining_batch_cases as _restore_post_dfaf_cases
_restore_post_dfaf_cases()
del _restore_post_dfaf_cases

from . import next20_aws  # noqa: E402,F401 (two reviewed signed AWS predicates)
from .fixtures import restore_remaining_batch_cases as _restore_next20_cases
_restore_next20_cases()
del _restore_next20_cases

from . import azure_apim_native  # noqa: E402,F401 (signed APIM native metadata path)
azure_apim_native.install()

from . import gcp_audit_native  # noqa: E402,F401 (observed-event signed GCP audit checks)
gcp_audit_native.install({
    'gcp_logging_detect_t1136': {'title': 'Suspicious service account creation', 'severity': 'high', 'remediation_hint': 'Remove unauthorized service accounts and revoke CreateServiceAccount from principals outside approved_identity_admins.'},
    'gcp_logging_detect_t1546': {'title': 'Suspicious event trigger creation', 'severity': 'high', 'remediation_hint': 'Delete unauthorized Cloud Build triggers or Scheduler jobs and revoke creation permissions from unapproved principals.'},
})


# Root-reviewed next grouped native admissions; keep all earlier hooks.
from . import azure_appservice_identity_followup, azure_easm_native, azure_graph_credential_age, azure_log_profile_retention, remaining_aws_gcp_native  # noqa: E402,F401

from . import gcp_psc_dns  # noqa: E402,F401 (scoped PSC/DNS declaration evidence)
gcp_psc_dns.install()

from . import aws_all_policies  # Full managed and inline IAM configuration inventory.

from . import gcp_audit_rates  # Native RPC read rates; observed events only.

from . import native_storage_compute  # Complete native EFS/EMR/SQL joins.

# One signed bulk admission; prior callbacks and aliases remain immutable.
from . import bulk_pending  # noqa: E402,F401
bulk_pending.install()

from . import aws_review_20261019  # Reviewed read-only AWS security extensions.
aws_review_20261019.install()
from . import aws_resource_policy_scope  # Complete native resource-policy declaration review.
aws_resource_policy_scope.install()
from . import gcp_workbench_review_20261019  # Native, policy-independent Workbench settings.
gcp_workbench_review_20261019.install()
from . import gcp_function_secret_review_20261019
gcp_function_secret_review_20261019.install()

from . import gcp_configuration_secret_review_20261019
gcp_configuration_secret_review_20261019.install()

from . import gcp_log_secret_review_20261019
gcp_log_secret_review_20261019.install()

from . import gcp_selected_object_secret_review_20261019
gcp_selected_object_secret_review_20261019.install()

from . import gcp_image_secret_review_20261019
gcp_image_secret_review_20261019.install()

from . import gcp_selected_archive_secret_review_20261019
gcp_selected_archive_secret_review_20261019.install()
from . import gcp_additional_literal_secret_review_20261019
gcp_additional_literal_secret_review_20261019.install()

from . import gcp_dataform_secret_review_20261019
gcp_dataform_secret_review_20261019.install()
from . import gcp_job_literal_secret_review_20261019
gcp_job_literal_secret_review_20261019.install()
from . import gcp_gke_literal_secret_review_20261019
gcp_gke_literal_secret_review_20261019.install()
from . import gcp_notebook_airflow_secret_review_20261019
gcp_notebook_airflow_secret_review_20261019.install()
from . import gcp_function_source_secret_review_20261019
gcp_function_source_secret_review_20261019.install()
from . import gcp_artifact_file_secret_review_20261019
gcp_artifact_file_secret_review_20261019.install()
from . import gcp_composer_source_secret_review_20261019
gcp_composer_source_secret_review_20261019.install()
from . import gcp_os_security_update_review_20261019
gcp_os_security_update_review_20261019.install()
from . import gcp_cloudsql_backup_alert_native
gcp_cloudsql_backup_alert_native.install_fixtures()
from . import gcp_cloudbuild_log_secret_review_20261019
gcp_cloudbuild_log_secret_review_20261019.install()

from . import gcp_appengine_source_secret_review_20261019
gcp_appengine_source_secret_review_20261019.install()

from . import gcp_cloudbuild_artifact_secret_review_20261019
gcp_cloudbuild_artifact_secret_review_20261019.install()

from . import gcp_clouddeploy_source_secret_review_20261019
gcp_clouddeploy_source_secret_review_20261019.install()

from . import gcp_sourcerepo_secret_review_20261019
gcp_sourcerepo_secret_review_20261019.install()

from . import gcp_task_routine_secret_review_20261020
gcp_task_routine_secret_review_20261020.install()

from . import azure_app_settings_secret_review_20261020
azure_app_settings_secret_review_20261020.install()

from . import k8s_literal_secret_review_20261020
k8s_literal_secret_review_20261020.install()
from . import k8s_literal_current_metadata_20261020
k8s_literal_current_metadata_20261020.install()
from . import k8s_selected_text_content_review
k8s_selected_text_content_review.install()

from . import azure_acr_image_secret_review_20261020
azure_acr_image_secret_review_20261020.install()
from . import azure_acr_image_vulnerabilities_20261021
azure_acr_image_vulnerabilities_20261021.install()

from . import aws_lambda_environment_secret_review_20261020
aws_lambda_environment_secret_review_20261020.install()

from . import azure_ai_services_review_20261020
azure_ai_services_review_20261020.install()

from . import azure_synapse_dependency_review_20261020
azure_synapse_dependency_review_20261020.install()
from . import azure_synapse_selected_notebook_secret_review_20261021
azure_synapse_selected_notebook_secret_review_20261021.install()

from . import azure_hsm_audit_review_20261020
azure_hsm_audit_review_20261020.install(register)

from . import azure_acr_public_ip_review_20261020
azure_acr_public_ip_review_20261020.install()

from . import azure_automation_aci_metadata_review_20261020
azure_automation_aci_metadata_review_20261020.install()

from . import azure_final_native_admission_20261020
azure_final_native_admission_20261020.install()

from . import azure_edge_native_admission_20261020
azure_edge_native_admission_20261020.install()

from . import k8s_annotation_native_admission_20261020
k8s_annotation_native_admission_20261020.install()

from . import aws_selected_configuration_admission_20261020
aws_selected_configuration_admission_20261020.install()

from . import azure_selected_secrets_admission_20261020
azure_selected_secrets_admission_20261020.install()

from . import azure_declaration_secrets_admission_20261020
azure_declaration_secrets_admission_20261020.install()

from . import k8s_kubelet_configmap_admission_20261020
k8s_kubelet_configmap_admission_20261020.install()

from . import aws_ecs_environment_file_secret_review_20261021
aws_ecs_environment_file_secret_review_20261021.install(register)

from . import aws_s3_selected_source_admission_20261020
aws_s3_selected_source_admission_20261020.install()

from . import azure_log_samples_admission_20261020
azure_log_samples_admission_20261020.install()

from . import azure_ml_job_secrets_admission_20261020
azure_ml_job_secrets_admission_20261020.install()

from . import azure_databricks_notebook_secrets_admission_20261020
azure_databricks_notebook_secrets_admission_20261020.install()

from . import azure_ml_asset_secrets_admission_20261020
azure_ml_asset_secrets_admission_20261020.install()

from . import azure_function_settings_runtime_admission_20261020
azure_function_settings_runtime_admission_20261020.install()

from . import k8s_selected_log_sample_admission_20261020
k8s_selected_log_sample_admission_20261020.install()

from . import azure_sas_policy_declaration_admission_20261020
azure_sas_policy_declaration_admission_20261020.install()

from . import gcp_dataproc_source_runtime_admission_20261020
gcp_dataproc_source_runtime_admission_20261020.install()

from . import azure_nsp_query_cmk_runtime_admission_20261020
azure_nsp_query_cmk_runtime_admission_20261020.install()
from . import k8s_selected_metadata_runtime_admission_20261020
k8s_selected_metadata_runtime_admission_20261020.install()
from . import gcp_workbench_source_runtime_admission_20261020
gcp_workbench_source_runtime_admission_20261020.install()
from . import gcp_dataflow_batch_source_runtime_admission_20261020
gcp_dataflow_batch_source_runtime_admission_20261020.install()
from . import aws_codebuild_buildspec_runtime_admission_20261020
aws_codebuild_buildspec_runtime_admission_20261020.install()
from . import azure_function_package_integration_admission_20261020
azure_function_package_integration_admission_20261020.install()
from . import gcp_function_secret_page_admission_20261020
gcp_function_secret_page_admission_20261020.install()
from . import aws_workload_command_runtime_admission_20261020
aws_workload_command_runtime_admission_20261020.install()

from . import gcp_workbench_head3_admission_20261020
gcp_workbench_head3_admission_20261020.install_bundle()

from . import gcp_cloudrun_job_image_secret_review_20261020
gcp_cloudrun_job_image_secret_review_20261020.install()

from . import aws_ai_recheck_corrections_20261020
aws_ai_recheck_corrections_20261020.install()

# Final bounded provider-group admission; apply only with its reviewed source closure.
from pathlib import Path as _ProviderGroupPath
from . import provider_group_install_20261021 as _provider_group_install_20261021
from . import storage_immutability_native_successor as _provider_group_storage_20261021
from . import azure_app_service_runtime_native_20261021 as _provider_group_runtime_20261021
from . import gcp_job_trivy_vulnerability_review_20261020 as _provider_group_gcp_20261021
from . import aws_image_vulnerabilities_20261021 as _provider_group_aws_20261021
_provider_group_root_20261021 = _ProviderGroupPath(__file__).resolve().parents[2]
_provider_group_install_20261021.install(
    storage=_provider_group_storage_20261021,
    runtime=_provider_group_runtime_20261021,
    gcp=_provider_group_gcp_20261021,
    aws=_provider_group_aws_20261021,
    root=_provider_group_root_20261021,
    source_paths=_provider_group_install_20261021.deployed_sources(_provider_group_root_20261021),
)

# Practical bounded selected GCP image reads; grouped provider integration.
from . import gcp_image_stream_review_20261021 as _gcp_image_stream
_gcp_image_stream.install()

# Default-off selected standalone immutable registry image vulnerabilities.
from .gcp_registry_trivy_review_20261021 import install as _install_registry_image_cves
_install_registry_image_cves(__import__(__name__, fromlist=['CHECKS']))

# Explicit selected Pod-bound registry image checks.
from .k8s_selected_registry_image_review_20261021 import install as _install_k8s_registry_images
_install_k8s_registry_images(register)
from .azure_selected_aks_image_review_20261021 import install as _install_azure_aks_image
_install_azure_aks_image()

from .k8s_selected_flux_artifact_review_20261021 import install as _install_flux_artifact
_install_flux_artifact(register)

from . import aws_workload_referenced_source_review
aws_workload_referenced_source_review.install(register)

from . import aws_build_deployment_referenced_source_review
aws_build_deployment_referenced_source_review.install(register)

from . import gcp_workerpool_image_secret_review_20261021
gcp_workerpool_image_secret_review_20261021.install()

from . import gcp_developerconnect_file_secret_review_20261021
gcp_developerconnect_file_secret_review_20261021.install()

from . import gcp_appengine_flex_image_review_20261021
gcp_appengine_flex_image_review_20261021.install()

from . import gcp_gke_selected_pod_image_review_20261021
gcp_gke_selected_pod_image_review_20261021.install()

from . import azure_ml_selected_job_secret_review_20261020 as _selected_ml_job_variants
_selected_ml_job_variants.install_current_native_cases()

from . import aws_workload_image_secret_review_20261021 as _aws_workload_image_secrets
_aws_workload_image_secrets.install(__import__(__name__, fromlist=['CHECKS']))

from .aws_ecr_public_image_review_20261021 import install as _install_ecr_public_image
_install_ecr_public_image(register)

from . import azure_flex_deployment_archives_review_20261021
azure_flex_deployment_archives_review_20261021.install(register)

# Unused identities and grants are native Hardening controls.
from peaso import unused_iam_hardening as _unused_iam_hardening
from peaso import unused_iam_k8s as _unused_iam_k8s
_unused_iam_hardening.install(__import__(__name__, fromlist=['CHECKS']))
_unused_iam_k8s.install(__import__(__name__, fromlist=['CHECKS']))

from peaso import unused_iam_azure as _unused_iam_azure
_unused_iam_azure.install(__import__(__name__, fromlist=['CHECKS']))

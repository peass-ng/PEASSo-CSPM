# API presentation copy of the native grouping algorithm. Only the two display
# imports and regionless roster loader differ; output parity tests compare it
# with the native source.
from pathlib import Path

"""One check card with lossless underlying observations and explicit mixed verdicts."""
from collections import Counter, defaultdict
from functools import lru_cache
import json
import re

from peaso.finding_groups import (
    CONTAINER_CVES_CHECK, container_cve_summary, container_cve_title, group_id, group_key,
)

STATUS_ORDER = {"FAIL": 0, "UNKNOWN": 1, "DENIED": 2, "MANUAL": 3, "PASS": 4, "NOT_APPLICABLE": 5, "EMPTY": 6}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


@lru_cache(maxsize=1)
def regionless_checks():
    raw = Path(__file__).with_name('finding_groups_regionless_20261021.json').read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError('API grouping metadata budget')
    rows = json.loads(raw)
    if (not isinstance(rows, list) or any(not isinstance(cid, str) for cid in rows)
            or rows != sorted(set(rows))):
        raise ValueError('Invalid API grouping metadata')
    return frozenset(rows)


def member_scopes(finding):
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    scopes = evidence.get("observed_in_scopes") or evidence.get("scopes")
    scopes = [scope for scope in scopes if isinstance(scope, str)] if isinstance(scopes, list) else []
    scopes = scopes or [str(finding.get("scope", ""))]
    if finding.get("provider") == "aws" and finding.get("check_id") in regionless_checks():
        scopes = [scope.split("/", 1)[0] + "/global" if re.fullmatch(r"[0-9]{12}/.+", scope) else scope for scope in scopes]
    return sorted(set(scopes))


def placement(finding, native=None, *, kind=None):
    provider = finding.get("provider")
    scope = str(finding.get("scope") or "")
    identifier = str(finding.get("native_resource_id") or finding.get("resource_id") or "")
    native = native if isinstance(native, dict) else {}
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    region = finding.get("region") or native.get("Region") or native.get("location") or native.get("region") or evidence.get("region") or evidence.get("location") or ""
    region = region if isinstance(region, str) else ""
    if provider == "aws":
        match = re.match(r"^(\d{12})(?:/([^/]+))?$", scope)
        account, scoped_region = (match[1], match[2] or "") if match else ("", "")
        arn = re.match(r"arn:[^:]+:[^:]*:([^:]*):(\d{12}):", identifier)
        account = account or (arn[2] if arn else "")
        region = region or (arn[1] if arn else "") or scoped_region
        if (kind == "bucket" or finding.get("service") == "s3") and "Location" in native:
            # ListBuckets is account-global; its collection scope is not the
            # bucket's storage location. Use only the readable native response.
            from peaso.checks.claude_aws_a_s3 import bucket_region
            from peaso.checks.facts import Unavailable
            try:
                region = bucket_region(native)
            except Unavailable:
                region = ""
        if finding.get("check_id") in regionless_checks():
            region = ""
    elif provider == "gcp":
        match = re.search(r"(?:^|/)(?:projects|folders|organizations)/([^/]+)", scope + "/" + identifier)
        account = match[1] if match else scope.split("/", 1)[0]
        match = re.search(r"/(regions|zones|locations)/([^/]+)", identifier)
        region = region or (match[2] if match else "")
        if isinstance(native.get("zone"), str) and not region:
            region = native["zone"].rsplit("/", 1)[-1]
    elif provider == "azure":
        match = re.search(r"/(?:subscriptions|tenants)/([^/]+)", scope + "/" + identifier, re.I)
        account = match[1] if match else scope.split("/", 1)[0]
    else:
        account = scope
    if provider == "gcp" and re.fullmatch(r"[a-z]+(?:-[a-z]+)*[0-9]+-[a-z]", region.rsplit("/", 1)[-1]):
        region = region.rsplit("/", 1)[-1].rsplit("-", 1)[0]
    if region in ("global", "unknown", "selected", "*"):
        region = ""
    if "/" in region:
        region = region.rsplit("/", 1)[-1]
    return account, region


def verdict(counts):
    if counts.get("FAIL"):
        return "FAIL"
    if counts.get("UNKNOWN") or counts.get("DENIED"):
        return "DENIED" if set(counts) == {"DENIED"} else "UNKNOWN"
    return next((status for status in ("MANUAL", "PASS", "NOT_APPLICABLE", "EMPTY") if counts.get(status)), "UNKNOWN")


def type_group_key(row):
    title = row.get("title")
    finding_type = row.get("finding_type")
    if row.get("secret_fingerprint") or finding_type == "detected_leaks":
        return None
    if row.get("check_id") == CONTAINER_CVES_CHECK:
        title = container_cve_title(row.get("service") or "")
    if isinstance(title, str) and title.strip() and isinstance(finding_type, str) and finding_type:
        return ("type", row.get("provider") or "", finding_type, title.strip())
    return None


def type_group_id(key):
    _, provider, finding_type, title = key
    return group_id(provider, "finding-type:" + finding_type, title)


def group_findings(findings, *, observations=False, by_type=False):
    from .service_labels_static_20261020 import finding_service
    grouped = defaultdict(list)
    for row in findings:
        service = finding_service(row)
        if service and service != row.get("service"):
            row = dict(row, service=service)
        identity = type_group_key(row) if by_type else None
        grouped[identity or ("check", *group_key(row))].append(row)
    result = []
    for identity, rows in sorted(grouped.items()):
        title_group = identity[0] == "type"
        provider, cid, secret, service = group_key(rows[0])
        if cid == "analysis.internet_exposure" and (not title_group or len(rows) == 1):
            # This analyzer emits one finding per exposed asset/path. Its title,
            # service and evidence describe that asset, so a check-wide card
            # would mislabel unrelated API, Lambda and storage exposures.
            for row in sorted(rows, key=lambda item: str(item.get("id", ""))):
                result.append(dict(row, **({"observations": [row]} if observations else {})))
            continue
        if secret:
            # The analyzer already merged this secret across checks and assets.
            result.append(dict(rows[0], **({"observations": rows} if observations else {})))
            continue
        # Stable ordering makes grouping independent of collector completion order.
        rows.sort(key=lambda row: (STATUS_ORDER.get(row.get("status"), 1),
            SEVERITY_ORDER.get(row.get("severity"), 4), str(row.get("scope", "")), str(row.get("resource_id", "")), row.get("id", "")))
        counts = dict(sorted(Counter(row.get("status", "UNKNOWN") for row in rows).items()))
        status = verdict(counts)
        primary = rows[0]
        affected = [row for row in rows if row.get("status") == status or status == "UNKNOWN" and row.get("status") == "DENIED"]
        affected = affected or rows
        scopes = sorted({scope for row in affected for scope in member_scopes(row)})
        places = [placement(dict(row, scope=scope)) for row in affected for scope in member_scopes(row)]
        accounts = sorted({account for account, _ in places if account})
        regions = sorted({region for _, region in places if region})
        from peaso.finding_subjects import grouped_subjects
        asset_count, affected_settings, scope_incomplete = grouped_subjects(affected)
        identifier = type_group_id(identity) if title_group else group_id(provider, cid, service)
        group = dict(primary, id=identifier, resource_id="check:" + primary.get("check_id", ""),
            scope=accounts[0] if len(accounts) == 1 else "selected_scopes", status=status,
            severity=min((str(row.get("severity") or "info") for row in affected), key=lambda value: SEVERITY_ORDER.get(value, 4)),
            grouped=True, member_count=len(rows), status_counts=counts,
            affected_asset_count=asset_count, affected_scopes=affected_settings, observed_scopes=scopes,
            affected_scope_incomplete=scope_incomplete, affected_regions=regions, affected_accounts=accounts,
            assessment_complete=not any(counts.get(key) for key in ("UNKNOWN", "DENIED", "MANUAL")))
        group.pop("native_resource_id", None)
        group.pop("region", None)
        group.pop("affected_subjects", None)
        group.pop("evidence_summary", None)
        group["resource_name"] = f"{asset_count} {'asset' if asset_count == 1 else 'assets'}" if asset_count else (
            f"{len(affected_settings)} {'scope' if len(affected_settings) == 1 else 'scopes'}" if affected_settings else
            f"{len(affected)} {'observation' if len(affected) == 1 else 'observations'}")
        group["evidence"] = {"status_counts": counts, "affected_regions": regions, "affected_scopes": affected_settings, "observed_scopes": scopes,
            "affected_asset_count": asset_count, "observation_count": len(rows)}
        if title_group:
            group["title"] = identity[3]
            group["grouped_by_title"] = True
            services = sorted({row["service"] for row in rows if row.get("service")})
            group["service"] = ", ".join(services)
        elif cid == CONTAINER_CVES_CHECK:
            group["title"] = container_cve_title(service)
        group["evidence_summary"] = summary(group)
        # A command bound to one member must never masquerade as a group-wide operation.
        details = group.get("remediation_details")
        if isinstance(details, dict):
            group["remediation_details"] = {key: value for key, value in dict(details, cli=[], console=[]).items() if key != "iac"}
        if observations:
            group["observations"] = rows
        result.append(group)
    return result


def summary(group):
    counts = group.get("status_counts", {})
    status = group.get("status", "UNKNOWN")
    if not group.get("grouped_by_title") and group.get("check_id") == CONTAINER_CVES_CHECK and status == "FAIL" and group.get("affected_asset_count"):
        return container_cve_summary(group["affected_asset_count"])
    if (group.get("check_id") == "analysis.exposed_privileged_workload" and status == "FAIL"
            and group.get("affected_asset_count")):
        number = group.get("affected_asset_count", 0)
        noun = "workload" if number == 1 else "workloads"
        return (f"{number} {noun} are linked to configured public entry points and use identities with recorded high-impact grants.\n"
            "If one of these workloads is compromised, its identity could be used against resources covered by those grants.\n"
            "That may affect the people or data those resources serve.")
    affected = counts.get(status, 0) + (counts.get("DENIED", 0) if status == "UNKNOWN" else 0)
    noun = "assets" if group.get("affected_asset_count") else "scopes" if group.get("affected_scopes") else "observations"
    number = group.get("affected_asset_count") or len(group.get("affected_scopes", [])) or affected
    phrase = {"FAIL": "fail this check", "PASS": "pass this check", "UNKNOWN": "could not be assessed", "DENIED": "could not be assessed because read access was denied", "MANUAL": "require further assessment", "EMPTY": "contain no applicable resources", "NOT_APPLICABLE": "are not applicable to this check"}.get(status, "could not be assessed")
    if number == 1:
        noun = noun.rstrip("s")
        phrase = {"fail this check": "fails this check", "pass this check": "passes this check",
                  "require further assessment": "requires further assessment",
                  "contain no applicable resources": "contains no applicable resources",
                  "are not applicable to this check": "is not applicable to this check"}.get(phrase, phrase)
    sentence = f"{number} {noun} {phrase}."
    regions = group.get("affected_regions", [])
    if regions:
        sentence += " Regions: " + ", ".join(regions) + "."
    others = [f"{count} {key.lower().replace('_', ' ')}" for key, count in counts.items() if key != status]
    if others:
        sentence += " Other results: " + "; ".join(others) + "."
    return sentence


def group_report(report):
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return report
    if report.get("finding_grouping") == "check-v1":
        return report
    from .report_projection_static_20261020 import hydrate_finding
    metadata = report.get("check_meta") or {}
    def minimal_rows():
        for row in report["findings"]:
            defaults = metadata.get(row.get("check_id")) or {}
            yield dict(row, provider=row.get("provider") or report.get("provider", ""),
                severity=row.get("severity") or defaults.get("severity", "info"),
                category=row.get("category") or defaults.get("category", "hardening"))
    groups = [hydrate_finding(row, report.get("check_frameworks"), metadata,
        report.get("check_meta_encoding"), report.get("remediation_templates"))
        for row in group_findings(minimal_rows(), observations=True)]
    old_stats = report.get("stats", {})
    stats = dict(old_stats, observation_count=len(report["findings"]), observation_by_status=old_stats.get("by_status", {}),
        observation_by_severity=old_stats.get("by_severity", {}),
        finding_count=len(groups), by_severity=dict(Counter(row["severity"] for row in groups if row["status"] == "FAIL")), by_status=dict(Counter(row["status"] for row in groups)),
        by_category=dict(Counter(row["category"] for row in groups)))
    return dict(report, findings=groups, stats=stats, finding_grouping="check-v1")

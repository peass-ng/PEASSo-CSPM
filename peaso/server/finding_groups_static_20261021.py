# API presentation copy of the native grouping algorithm. Only the two display
# imports and regionless roster loader differ; focused AST/output parity binds
# every other function to the native source. No evaluator/admission changes.
from pathlib import Path
SOURCE_SHA256 = '988d84b1d701b8e22163fa77c58302e7f1761f388578666887160111eb494be0'
NATIVE_GENERATION = '6b6ee759234d7e2dad978342838cb3af4e1fe767'
REGIONLESS_SHA256 = 'ebc38d9d7d22575e52e5cc4bdecb609cc12ba2ca621413d8a415b775786eadfd'

"""One check card with lossless underlying observations and explicit mixed verdicts."""
from collections import Counter, defaultdict
from functools import lru_cache
import hashlib
import json
import re

STATUS_ORDER = {"FAIL": 0, "UNKNOWN": 1, "DENIED": 2, "MANUAL": 3, "PASS": 4, "NOT_APPLICABLE": 5, "EMPTY": 6}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def group_id(provider, check_id):
    return "check-" + hashlib.sha256(json.dumps([provider, check_id], separators=(",", ":")).encode()).hexdigest()


@lru_cache(maxsize=1)
def regionless_checks():
    raw = Path(__file__).with_name('finding_groups_regionless_20261021.json').read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != REGIONLESS_SHA256:
        raise ValueError('API grouping metadata identity differs')
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


def is_asset(finding):
    return bool(finding.get("resource_id")) and not str(finding["resource_id"]).startswith(("scope:", "inventory:", "aggregate:", "check:"))


def group_findings(findings, *, observations=False):
    from .service_labels_static_20261020 import finding_service
    grouped = defaultdict(list)
    for row in findings:
        service = finding_service(row)
        if service and service != row.get("service"):
            row = dict(row, service=service)
        grouped[(row.get("provider", ""), row.get("check_id", ""), row.get("secret_fingerprint", ""))].append(row)
    result = []
    for (provider, cid, secret), rows in sorted(grouped.items()):
        if cid == "analysis.internet_exposure":
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
        assets = {(row.get("scope"), row.get("native_resource_id") or row.get("resource_id")) for row in affected if is_asset(row)}
        group = dict(primary, id=group_id(provider, cid), resource_id="check:" + cid,
            scope=accounts[0] if len(accounts) == 1 else "selected_scopes", status=status,
            severity=min((str(row.get("severity") or "info") for row in affected), key=lambda value: SEVERITY_ORDER.get(value, 4)),
            grouped=True, member_count=len(rows), status_counts=counts,
            affected_asset_count=len(assets), affected_scopes=scopes, affected_regions=regions, affected_accounts=accounts,
            assessment_complete=not any(counts.get(key) for key in ("UNKNOWN", "DENIED", "MANUAL")))
        group.pop("native_resource_id", None)
        group.pop("region", None)
        group.pop("evidence_summary", None)
        group["resource_name"] = f"{len(assets)} {'asset' if len(assets) == 1 else 'assets'}" if assets else f"{len(scopes)} {'scope' if len(scopes) == 1 else 'scopes'}"
        group["evidence"] = {"status_counts": counts, "affected_regions": regions, "affected_scopes": scopes,
            "affected_asset_count": len(assets), "observation_count": len(rows)}
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
    if group.get("check_id") == "analysis.exposed_privileged_workload" and status == "FAIL":
        number = group.get("affected_asset_count", 0)
        noun = "workload" if number == 1 else "workloads"
        return (f"{number} {noun} are linked to configured public entry points and use identities with recorded high-impact grants.\n"
            "If one of these workloads is compromised, its identity could be used against resources covered by those grants.\n"
            "That may affect the people or data those resources serve.")
    affected = counts.get(status, 0) + (counts.get("DENIED", 0) if status == "UNKNOWN" else 0)
    noun = "assets" if group.get("affected_asset_count") else "scopes"
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

"""Customer-versus-scan analyzer facts shared by the Access Analyzer checks.

When a Region has no usable analyzer, collection creates a temporary
``peaso-scan-*`` analyzer, reads its findings and deletes it again. That
analyzer is scan tooling, not a customer resource: it must never make an
"analyzer exists/active" control pass, and its findings must be reported
against the externally accessible resources they name, not against itself.
"""
from __future__ import annotations

from collections.abc import Mapping

from .facts import Unavailable, guard

SCAN_ANALYZER_PREFIX = "peaso-scan-"
COMPLETE = ("collected", "empty")
FINDING_STATES = ("ACTIVE", "ARCHIVED", "RESOLVED")
EVIDENCE_LIMIT = 200


def is_scan_temporary(analyzer):
    """True for an analyzer created by a PEASO scan (this one or a leftover)."""
    if not isinstance(analyzer, Mapping):
        return False
    name = analyzer.get("name")
    arn = analyzer.get("arn")
    return (analyzer.get("_scan_temporary") is True
            or isinstance(name, str) and name.startswith(SCAN_ANALYZER_PREFIX)
            or isinstance(arn, str) and arn.rsplit("/", 1)[-1].startswith(SCAN_ANALYZER_PREFIX))


def inventory(index, scope=None):
    """Return ``(customer, temporary, listing_complete)`` for the scoped analyzers.

    ``listing_complete`` is True when every envelope is complete, or when its
    only incompleteness comes after a complete ListAnalyzers read: collection
    creates a temporary analyzer only after a complete listing proved that no
    usable analyzer existed, so the customer rows of that envelope are whole.
    """
    if not isinstance(index, Mapping) or not isinstance(index.get("collections"), Mapping):
        raise Unavailable("missing collection index")
    envelopes = index["collections"].get("access_analyzer")
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable("inventory not collected: access_analyzer")
    customer, temporary, complete = [], [], True
    for envelope in envelopes:
        if not isinstance(envelope, Mapping):
            raise Unavailable("malformed inventory: access_analyzer")
        if scope:
            account = scope.split("/")[0]
            same_scope = envelope.get("scope") == scope
            same_global = envelope.get("global") is True and envelope.get("account_id") == account
            if not same_scope and not same_global:
                raise Unavailable("foreign/unverified dependency scope: access_analyzer")
            if envelope.get("account_id") not in (None, account):
                raise Unavailable("conflicting dependency account identity: access_analyzer")
        batch = envelope.get("items")
        if not isinstance(batch, list) or any(not isinstance(item, Mapping) for item in batch):
            raise Unavailable("malformed inventory: access_analyzer")
        scan_rows = [item for item in batch if is_scan_temporary(item)]
        if envelope.get("status") not in COMPLETE and not (envelope.get("status") == "partial" and any(
                item.get("_scan_temporary") is True for item in scan_rows)):
            complete = False
        for item in batch:
            if is_scan_temporary(item):
                temporary.append(item)
            else:
                guard(item)
                customer.append(item)
    return customer, temporary, complete


def _external_access(finding):
    details = []
    nested = finding.get("FindingDetails")
    rows = nested.get("items") if isinstance(nested, Mapping) else None
    for row in rows if isinstance(rows, list) else []:
        access = row.get("externalAccessDetails") if isinstance(row, Mapping) else None
        if isinstance(access, Mapping):
            details.append(access)
    if not details and any(key in finding for key in ("principal", "condition", "isPublic", "action")):
        details.append(finding)  # ListFindings (v1) summaries carry the access inline.
    out = []
    for access in details:
        entry = {key: access.get(source) for key, source in (("principal", "principal"), ("action", "action"),
                 ("condition", "condition"), ("is_public", "isPublic"), ("sources", "sources")) if access.get(source) not in (None, [], {})}
        if entry and entry not in out:
            out.append(entry)
    return out


def describe(finding, analyzer):
    """The customer-facing view of one analyzer finding: the resource it names."""
    temporary = is_scan_temporary(analyzer)
    row = {"resource": finding.get("resource"), "resource_type": finding.get("resourceType"),
           "resource_owner_account": finding.get("resourceOwnerAccount"),
           "finding_type": finding.get("findingType") or "ExternalAccess", "finding_id": finding.get("id"),
           "reported_by": "temporary PEASO scan analyzer (deleted after the scan)" if temporary else "customer analyzer"}
    if not temporary:
        row["analyzer"] = analyzer.get("arn")
    access = _external_access(finding)
    if access:
        row["external_access"] = access
    return {key: value for key, value in row.items() if value is not None}


def is_external_access(finding):
    kind = finding.get("findingType")
    return kind in (None, "ExternalAccess") or bool(_external_access(finding))


def bounded(rows):
    return rows[:EVIDENCE_LIMIT], max(0, len(rows) - EVIDENCE_LIMIT)

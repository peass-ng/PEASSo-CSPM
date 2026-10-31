"""Read-only Graph producer for the signed SW18 per-user MFA branch.

Only the enabled/enforced branch is resolved here. Incomplete joins emit a
subject row with false coverage and an explicit reason for the signed consumer.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from urllib.parse import quote, urlencode

GRAPH = "https://graph.microsoft.com"
CHECK = "azure.cis.multifactor_auth_status_non_privileged_users"
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)
PARENTS = ("directory_user", "directory_group", "directory_membership",
           "directory_user_group_membership", "directory_role_assignment",
           "directory_role_definition", "directory_role_eligibility_schedule",
           "directory_role_eligibility_instance", "directory_role_assignment_instance",
           "user_registration_detail")


def _id(value):
    if not isinstance(value, str) or not GUID.fullmatch(value):
        raise ValueError("malformed Graph identity")
    return value.casefold()


def _opaque(value):
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError("malformed Graph object identity")
    return value


def _inventory(reader, kind, scope, *, many=False):
    rows = [c for c in reader.collections if c.get("type") == kind]
    if many:
        rows = [c for c in rows if c.get("scope", "").casefold().startswith(scope.casefold() + "/groups/")]
        return rows
    rows = [c for c in rows if c.get("scope", "").casefold() == scope.casefold()]
    if len(rows) == 1 and rows[0].get("status") not in ("collected", "empty"):
        # A denied or unread parent leaves the evidence unknown, not malformed.
        from .azure import AzureReadError
        raise AzureReadError("native_parent_inventory_incomplete")
    if len(rows) != 1 or rows[0].get("service") != "Microsoft.Graph" or rows[0].get("status") not in ("collected", "empty"):
        raise ValueError("incomplete or ambiguous " + kind)
    return rows[0]["items"]


def _unique(rows, kind, *, identity=_id):
    result = {}
    for row in rows:
        key = identity(row.get("id"))
        if key in result:
            raise ValueError("duplicate " + kind)
        result[key] = row
    return result


def _paged(reader, request, url, *, identity=_id):
    rows = []
    for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
        rows.extend(page)
    return _unique(rows, url, identity=identity)


def _time(value):
    if not isinstance(value, str):
        raise ValueError("missing eligibility time")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("unbound eligibility time")
    return result


def _active(instance, now, *, current_assignment_proven=False):
    raw_start = instance.get("startDateTime")
    if raw_start is None:
        if not current_assignment_proven:
            raise ValueError("null start time without current assignment proof")
        start = None
    else:
        start = _time(raw_start)
    end = instance.get("endDateTime")
    return (start is None or start <= now) and (end is None or now < _time(end))


def _same_role_assignment(instance, assignments):
    """An exact current v1 role assignment corroborates a null PIM start."""
    scope = instance.get("directoryScopeId")
    if not isinstance(scope, str) or not scope:
        return False
    return any(a.get("principalId", "").casefold() == instance.get("principalId", "").casefold()
               and a.get("roleDefinitionId", "").casefold() == instance.get("roleDefinitionId", "").casefold()
               and a.get("directoryScopeId", "").casefold() == scope.casefold()
               and a.get("appScopeId") == instance.get("appScopeId") for a in assignments)


def collect(reader, request, wanted, transport, credential_context_id, customer_context_id):
    if "azure_sw18_evidence" not in wanted:
        return
    from .azure import _safe_error
    tenant = getattr(transport, "verified_tenant", None)
    if not isinstance(tenant, str) or not GUID.fullmatch(tenant):
        reader.unavailable("azure_sw18_evidence", "/tenants/unverified", "Microsoft.Graph",
                           ValueError("unverified Graph tenant"))
        return
    scope = "/tenants/" + tenant
    proof = {"read_only": True, "adapter": "sw18-resolved-v1", "tenant_id": tenant,
             "tenant_verified": True, "credential_context_id": credential_context_id,
             "customer_context_id": customer_context_id,
             "observed_at": datetime.now(timezone.utc).isoformat()}
    try:
        users = _unique(_inventory(reader, "directory_user", scope), "directory user")
    except Exception as exc:
        reader.unavailable("azure_sw18_evidence", scope, "Microsoft.Graph", exc)
        return

    shared = {}
    failures = {}
    for kind in PARENTS[1:]:
        try:
            shared[kind] = _inventory(reader, kind, scope, many=kind == "directory_membership")
        except Exception as exc:
            failures[kind] = str(exc)
    try:
        definitions = _paged(reader, request, GRAPH + "/beta/roleManagement/directory/roleDefinitions?$select=id,isPrivileged")
        if any(type(row.get("isPrivileged")) is not bool for row in definitions.values()):
            raise ValueError("beta isPrivileged unavailable")
    except Exception as exc:
        definitions = None
        failures["beta_role_definitions"] = _safe_error(exc)[1]["code"]

    # A group inventory with a hidden/dynamic/partial member page cannot prove
    # that a user is outside a role-assigned group.
    try:
        groups = _unique(shared["directory_group"], "directory group")
        memberships = shared["directory_membership"]
        indexed = {}
        for entry in memberships:
            gid = _id(entry["scope"].rsplit("/", 1)[-1])
            if (gid in indexed or gid not in groups or entry.get("service") != "Microsoft.Graph"
                    or entry.get("status") not in ("collected", "empty")):
                raise ValueError("partial, foreign, or duplicate group membership")
            indexed[gid] = entry
        if set(indexed) != set(groups):
            raise ValueError("group membership universe incomplete")
        shared["groups_index"] = groups
    except Exception as exc:
        failures["groups"] = str(exc)

    try:
        registration = _unique(shared["user_registration_detail"], "registration detail")
    except Exception as exc:
        registration = {}
        failures["registration"] = str(exc)
    now = datetime.now(timezone.utc)
    owner_cache = {}
    rows = []
    # Each enabled user's requirements read is independent: prefetch them
    # bounded in parallel; outcomes are consumed in user order below.
    from .azure import ordered_parallel
    enabled = [uid for uid, user in users.items() if user.get("accountEnabled") is True]
    def requirements(uid):
        return reader.call(request, GRAPH + "/beta/users/" + uid + "/authentication/requirements", audience=GRAPH)
    prefetched = dict(zip(enabled, ordered_parallel(reader, requirements, enabled)))
    for uid, user in users.items():
        if user.get("accountEnabled") is not True:
            continue
        coverage = {key: False for key in ("directory_roles", "groups", "registration", "per_user_requirements")}
        reasons = dict(failures)
        row = {"id": user["id"] + "#sw18:" + CHECK, "subject_id": user["id"],
               "check_id": CHECK, "scope": scope, "coverage": coverage,
               "_provenance": dict(proof)}
        try:
            ok, value = prefetched[uid]
            if not ok:
                raise value
            if not isinstance(value, dict) or value.get("perUserMfaState") not in ("disabled", "enabled", "enforced"):
                raise ValueError("beta perUserMfaState unavailable")
            if "id" in value and _id(value["id"]) != uid:
                raise ValueError("foreign requirements subject")
            row["requirements"] = {"perUserMfaState": value["perUserMfaState"]}
            coverage["per_user_requirements"] = True
        except Exception as exc:
            reasons["per_user_requirements"] = _safe_error(exc)[1]["code"]
        try:
            detail = registration[uid]
            if type(detail.get("isMfaCapable")) is not bool:
                raise ValueError("isMfaCapable unavailable")
            row["registration"] = {"usableMfaRegistered": detail["isMfaCapable"]}
            coverage["registration"] = True
        except Exception as exc:
            reasons["registration"] = str(exc)
        try:
            member_rows = _unique(shared["directory_user_group_membership"], "user transitive membership")
            if set(member_rows) != set(users):
                raise ValueError("user membership universe incomplete")
            member = member_rows[uid]
            if member.get("userId", "").casefold() != uid or member.get("_coverage", {}).get("groups", {}).get("status") not in ("collected", "empty"):
                raise ValueError("user transitive membership incomplete")
            principal_ids = {uid}
            for group in member.get("groups", []):
                gid = _id(group.get("id"))
                if "groups_index" not in shared:
                    raise ValueError(failures["groups"])
                if gid not in shared["groups_index"]:
                    raise ValueError("foreign transitive group")
                principal_ids.add(gid)
            coverage["groups"] = True
        except Exception as exc:
            principal_ids = {uid}
            reasons["groups"] = str(exc)
        try:
            if not coverage["groups"] or definitions is None:
                raise ValueError("role/group classification input incomplete")
            # The v1 role inventory is retained as a completeness cross-check;
            # only the documented beta boolean supplies privilege classification.
            v1defs = _unique(shared["directory_role_definition"], "v1 role definition")
            if set(v1defs) != set(definitions):
                raise ValueError("role definition versions disagree")
            role_sources = ("directory_role_assignment", "directory_role_eligibility_schedule",
                            "directory_role_eligibility_instance", "directory_role_assignment_instance")
            privileged = False
            owner_candidates = {gid for gid, group in shared["groups_index"].items()
                                if group.get("isAssignableToRole") is True}
            if any(type(group.get("isAssignableToRole")) is not bool
                   for group in shared["groups_index"].values()):
                raise ValueError("role-assignable group classification incomplete")
            for kind in role_sources:
                _unique(shared[kind], kind, identity=_opaque)
                for assignment in shared[kind]:
                    pid = _id(assignment.get("principalId"))
                    role = _id(assignment.get("roleDefinitionId"))
                    if role not in definitions:
                        raise ValueError("unresolved assigned role definition")
                    if pid in shared["groups_index"] and definitions[role]["isPrivileged"]:
                        owner_candidates.add(pid)
                    if pid not in principal_ids or not definitions[role]["isPrivileged"]:
                        continue
                    if kind == "directory_role_eligibility_schedule":
                        # Schedule lifecycle alone does not prove present eligibility.
                        instance_ids = {v.get("roleEligibilityScheduleId") for v in shared["directory_role_eligibility_instance"]}
                        if assignment["id"] not in instance_ids:
                            raise ValueError("unresolved eligibility schedule")
                    elif kind in ("directory_role_eligibility_instance", "directory_role_assignment_instance"):
                        corroborated = (kind == "directory_role_assignment_instance" and
                                        _same_role_assignment(assignment, shared["directory_role_assignment"]))
                        if _active(assignment, now, current_assignment_proven=corroborated):
                            privileged = True
                    else:
                        privileged = True
            # A group owner can manage membership of a role-assignable group.
            # Ownership is not itself an effective role assignment: leave the
            # signed privileged/nonprivileged decision unresolved for owners.
            for gid in sorted(owner_candidates):
                if gid not in owner_cache:
                    url = GRAPH + "/v1.0/groups/" + quote(gid, safe="") + "/owners?$select=id"
                    owner_cache[gid] = set(_paged(reader, request, url))
                if uid in owner_cache[gid]:
                    raise ValueError("role-assignable or privileged-role group owner unresolved")
            # PIM for Groups may grant future access to a role-assigned group.
            # The principal-filtered inventory is mandatory before a negative.
            for principal in sorted(principal_ids):
                for endpoint in ("eligibilityScheduleInstances", "assignmentScheduleInstances"):
                    url = (GRAPH + "/v1.0/identityGovernance/privilegedAccess/group/" + endpoint
                           + "?" + urlencode({"$filter": "principalId eq '" + principal + "'"}))
                    group_schedules = _paged(reader, request, url, identity=_opaque)
                    for entry in group_schedules.values():
                        gid = _id(entry.get("groupId"))
                        if _id(entry.get("principalId")) != principal or gid not in shared["groups_index"]:
                            raise ValueError("foreign PIM group schedule")
                        current_member = (endpoint == "assignmentScheduleInstances"
                                          and entry.get("accessId") == "member" and gid in principal_ids)
                        if not _active(entry, now, current_assignment_proven=current_member):
                            continue
                        if endpoint == "eligibilityScheduleInstances" or gid not in principal_ids or entry.get("accessId") != "member":
                            raise ValueError("PIM group path requires group role expansion")
            row["privileged"] = privileged
            coverage["directory_roles"] = True
        except Exception as exc:
            reasons["directory_roles"] = _safe_error(exc)[1]["code"] if not isinstance(exc, (ValueError, KeyError)) else str(exc)
        if reasons:
            row["_unresolved"] = reasons
        source_ids = {uid, GRAPH + "/beta/users/" + uid + "/authentication/requirements",
                      GRAPH + "/beta/roleManagement/directory/roleDefinitions?$select=id,isPrivileged"}
        source_ids.update(GRAPH + "/v1.0/groups/" + quote(gid, safe="") + "/owners?$select=id"
                          for gid in owner_cache)
        for kind in ("directory_user_group_membership", "user_registration_detail",
                     "directory_role_assignment", "directory_role_eligibility_schedule",
                     "directory_role_eligibility_instance", "directory_role_assignment_instance"):
            for source in shared.get(kind, []):
                if isinstance(source, dict) and isinstance(source.get("id"), str):
                    source_ids.add(source["id"])
        row["_provenance"]["source_ids"] = sorted(source_ids)
        rows.append(row)
    reader.run([("azure_sw18_evidence", scope, "Microsoft.Graph", lambda: (rows,))])
    reader.collections[-1].setdefault("_provenance", {}).update(proof)

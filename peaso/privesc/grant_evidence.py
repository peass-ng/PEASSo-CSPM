"""Explain the recorded permission match using the exact collected granting definition.

This only decorates evaluator evidence; it never discovers additional authority.
"""
from .effective_permissions import glob_match


def permission_evidence(model, grant):
    cache = model.__dict__.setdefault("_permission_explanation_cache", {})
    output = []
    for pair in grant.permission_refs:
        key = (pair.get("permission"), repr(pair.get("grant")), repr(pair.get("requirement")), pair.get("evaluated_resource"))
        if key not in cache:
            cache[key] = _explain(model, pair)
        value = cache[key]
        if value is not None and value not in output:
            output.append(value)
    return output


def _explain(model, pair):
    ref = pair.get("grant")
    if not isinstance(ref, dict):
        return dict(pair)
    if str(ref.get("effect", "Allow")).lower() == "deny" or "deny_policy" in ref or "bound_resource" in ref:
        return None
    ref = dict(ref)
    permission = str(pair.get("permission", ""))
    if model.provider == "aws":
        policy = model.policies.get(ref.get("policy"))
        index = ref.get("statement")
        if policy is not None and type(index) is int and 0 <= index < len(policy.statements):
            statement = policy.statements[index]
            if statement.effect != "allow" or not statement.action_matches(permission):
                return None
            ref["statement_document"] = {
                "Effect": "Allow",
                "NotAction" if statement.notaction else "Action": list(statement.actions),
                "NotResource" if statement.notresource else "Resource": list(statement.resources),
            }
            if statement.condition:
                ref["statement_document"]["Condition"] = statement.condition
            if ref.get("sid"):
                ref["statement_document"]["Sid"] = ref["sid"]
    elif model.provider == "gcp":
        role = model.roles.get(ref.get("role"))
        if role is not None:
            patterns = _matched_role_permissions(model, role, permission)
            if not patterns:
                return None
            ref["matched_role_permissions"] = patterns
            ref["role_definition_confidence"] = role.confidence
    elif model.provider == "azure" and ref.get("assignment"):
        assignments = model.__dict__.get("_permission_assignment_index")
        if assignments is None:
            assignments = model._permission_assignment_index = {a["id"]: a for rows in model.assignments.values() for a in rows}
        assignment = assignments.get(ref["assignment"])
        definition = model.roles.get(assignment["role"]) if assignment else None
        if definition:
            data_action = pair.get("requirement", {}).get("data_action") is not None
            if not definition.allows(permission.lower(), data_action):
                return None
            ref["role_definition"] = definition.id
            ref["role_permissions"] = {
                "actions": list(definition.actions), "notActions": list(definition.not_actions),
                "dataActions": list(definition.data), "notDataActions": list(definition.not_data),
            }
    return {**pair, "grant": ref}


def _matched_role_permissions(model, role, permission):
    """sorted(p for p in role.native_permissions if glob_match(p, permission)), indexed once per role."""
    indexes = model.__dict__.setdefault("_role_permission_match_index", {})
    entry = indexes.get(id(role))
    if entry is None or entry[0] is not role:
        exact, wildcard = {}, []
        for pattern in role.native_permissions:
            if pattern == "*" or "*" in pattern or "?" in pattern:
                wildcard.append(pattern)
            else:
                exact.setdefault(pattern.lower(), []).append(pattern)
        entry = indexes[id(role)] = (role, exact, wildcard)
    _, exact, wildcard = entry
    return sorted([*exact.get(permission.lower(), ()), *(p for p in wildcard if glob_match(p, permission))])


def administrative_basis(permissions):
    """Name the actual basis of an administrative classification, including its native scope."""
    import json
    if not permissions:
        return "The stored evidence does not record the exact administrative permission match."
    descriptions = []
    for pair in permissions:
        ref = pair["grant"]
        statement = ref.get("statement_document")
        if statement:
            action = "NotAction" if "NotAction" in statement else "Action"
            resource = "NotResource" if "NotResource" in statement else "Resource"
            source = ref.get("policy", ref.get("policy_name", "the recorded policy"))
            descriptions.append(f'Allow {action}: {json.dumps(statement[action])} on {resource}: {json.dumps(statement[resource])} '
                                f'from {ref.get("policy_type", "recorded")} policy {ref.get("policy_name", source)} '
                                f'({source}), statement {ref.get("statement", 0)}')
        elif ref.get("rule"):
            descriptions.append(f'{json.dumps(ref["rule"], sort_keys=True)} from {ref.get("role")} via {ref.get("binding")}')
        else:
            scope = ref.get("scope", ref.get("directory_scope", ref.get("policy", "the recorded scope")))
            descriptions.append(f'{pair["permission"]} from {ref.get("role", "the recorded grant")} on {scope}')
    return "Administrative permission match: " + "; ".join(descriptions) + ". Conditions and guardrails are recorded separately."

"""Read-only, principal-only Unified Catalog governance policy inventory."""
from __future__ import annotations

import re
from urllib.parse import urlencode

from .azure_purview_metadata_policy_native import AUDIENCE, _GUID, _principals

KIND = "purview_unified_policy"
VERSION = "2026-03-20-preview"
BASE = "https://api.purview-service.microsoft.com/datagovernance/catalog/policies"
_ROLE = re.compile(r"^[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$")


def collect(reader, request, wanted, tenant_scope):
    if KIND not in wanted:
        return

    def pages():
        token = None
        seen_tokens = set()
        seen_policies = set()
        page_number = 0
        while reader.budget.max_pages is None or page_number < reader.budget.max_pages:
            reader.check_cancelled()
            params = {"api-version": VERSION}
            if token is not None:
                params["skipToken"] = token
            url = BASE + "?" + urlencode(params)
            response = reader.call(request, url, audience=AUDIENCE)
            page_number += 1
            if not isinstance(response, dict) or not isinstance(response.get("values"), list):
                raise ValueError("malformed Unified Catalog policy page")
            projected = []
            for raw in response["values"]:
                policy_id = raw.get("id") if isinstance(raw, dict) else None
                if not isinstance(policy_id, str) or not _GUID.fullmatch(policy_id) or policy_id.lower() in seen_policies:
                    raise ValueError("Unified Catalog policy identity missing or duplicate")
                seen_policies.add(policy_id.lower())
                props = raw.get("properties")
                if not isinstance(props, dict) or not isinstance(props.get("attributeRules"), list):
                    raise ValueError("Unified Catalog attribute rules missing")
                entity = props.get("entity")
                entity_type = entity.get("type") if isinstance(entity, dict) else None
                entity_id = entity.get("referenceName") if isinstance(entity, dict) else None
                if not isinstance(entity_type, str) or not re.fullmatch(r"[A-Za-z]+Reference", entity_type) or not isinstance(entity_id, str) or not _GUID.fullmatch(entity_id):
                    raise ValueError("Unified Catalog entity identity missing")
                roles = []
                for rule in props["attributeRules"]:
                    role_id = rule.get("id") if isinstance(rule, dict) else None
                    if not isinstance(role_id, str) or not _ROLE.fullmatch(role_id):
                        raise ValueError("Unified Catalog role identity malformed")
                    roles.append({"role": role_id.split(":", 1)[0], **_principals(rule)})
                projected.append({"id": "purview-unified://" + policy_id.lower(),
                                  "entity_type": entity_type, "entity_id": entity_id.lower(), "roles": roles})
            yield projected
            token = response.get("skipToken")
            if token is None or token == "":
                return
            if not isinstance(token, str) or len(token) > 4096 or token in seen_tokens:
                raise ValueError("malformed Unified Catalog continuation token")
            seen_tokens.add(token)
        raise ValueError("Unified Catalog page limit")

    reader.run([(KIND, tenant_scope, "Purview Unified Catalog", pages)])

"""Read existing Identity Platform tenants and their IAM policies."""

import re

from .gcp import ReadError


def collection_pages(collector, scope):
    base = f"https://identitytoolkit.googleapis.com/v2/{scope}/tenants"
    seen = set()
    for page, request_id in collector.pages(base, scope, key="tenants", params={"fields":
            "tenants(name,allowPasswordSignup,enableEmailLinkSignin,disableAuth,enableAnonymousUser,client(permissions(disabledUserSignup))),nextPageToken"}):
        rows = []
        for item in page:
            name = item.get("name") if isinstance(item, dict) else None
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(scope) + r"/tenants/[A-Za-z0-9_-]+", name) or name in seen):
                raise ReadError("malformed", "identityplatform_tenant_identity_unbound")
            seen.add(name)
            rows.append(item)
        def policy(item):
            url = "https://identitytoolkit.googleapis.com/admin/v2/" + item["name"] + ":getIamPolicy"
            return collector.hydrate(item, "iamPolicy", url, scope,
                                     method="POST", body={"options": {"requestedPolicyVersion": 3}})
        yield collector.parallel(policy, rows), request_id

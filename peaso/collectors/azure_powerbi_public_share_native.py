"""Tenant-wide Power BI public and organization-wide link metadata."""
from __future__ import annotations

import re
from urllib.parse import quote, urlsplit, parse_qs

AUDIENCE = "https://analysis.windows.net/powerbi/api"
BASE = "https://api.powerbi.com/v1.0/myorg/admin/widelySharedArtifacts"
PUBLISHED = "powerbi_published_item"
ORGANIZATION = "powerbi_org_link"
KINDS = (PUBLISHED, ORGANIZATION)
_ROUTES = {PUBLISHED: "/publishedToWeb", ORGANIZATION: "/linksSharedToWholeOrganization"}
_GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def allowed_route(url):
    parsed = urlsplit(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return (parsed.scheme == "https" and parsed.netloc == "api.powerbi.com"
            and parsed.username is None and parsed.password is None and not parsed.fragment
            and parsed.path in {"/v1.0/myorg/admin/widelySharedArtifacts" + path for path in _ROUTES.values()}
            and (not params or (set(params) == {"continuationToken"}
                                and len(params["continuationToken"]) == 1
                                and bool(params["continuationToken"][0]))))


def _project(raw, kind):
    if not isinstance(raw, dict):
        raise ValueError("malformed Power BI shared artifact")
    iid = raw.get("artifactId")
    item_type = raw.get("artifactType")
    share_type = raw.get("shareType")
    expected = "PublishToWeb" if kind == PUBLISHED else "Link"
    if (not isinstance(iid, str) or not _GUID.fullmatch(iid)
            or not isinstance(item_type, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", item_type)
            or share_type != expected):
        raise ValueError("malformed Power BI public share identity")
    return {"id": "powerbi-share://" + kind + "/" + iid.lower(),
            "artifact_id": iid.lower(), "artifact_type": item_type,
            "share_type": share_type, "effective_status": "unknown"}


def collect(reader, request, wanted, tenant_scope):
    jobs = []
    for kind in KINDS:
        if kind not in wanted:
            continue
        path = _ROUTES[kind]

        def pages(kind=kind, path=path):
            token = None
            seen = set()
            count = 0
            while reader.budget.max_pages is None or count < reader.budget.max_pages:
                reader.check_cancelled()
                url = BASE + path + ("?continuationToken=" + quote(token, safe="%") if token else "")
                response = reader.call(request, url, audience=AUDIENCE)
                count += 1
                if not isinstance(response, dict) or not isinstance(response.get("artifactAccessEntities"), list):
                    raise ValueError("malformed Power BI shared artifact page")
                yield [_project(item, kind) for item in response["artifactAccessEntities"]]
                token = response.get("continuationToken")
                if not token:
                    return
                if (not isinstance(token, str) or len(token) > 4096
                        or not re.fullmatch(r"[A-Za-z0-9%_=/+\-]+", token) or token in seen):
                    raise ValueError("malformed Power BI continuation token")
                seen.add(token)
            raise ValueError("Power BI page limit")

        jobs.append((kind, tenant_scope, "Power BI", pages))
    reader.run(jobs)

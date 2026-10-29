"""One bounded Activity Log read per selected subscription for IAM usage."""
import copy
from datetime import datetime, timedelta, timezone
import re
from urllib.parse import urlencode, urlsplit

from peaso.snapshot import make_snapshot

SUBSCRIPTION = re.compile(r"/subscriptions/[0-9a-fA-F-]{36}")
SELECT = "eventTimestamp,caller,status,resourceId,eventDataId,authorization,claims"
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
OBJECT_ID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"


def enrich_snapshot(snapshot, connector, *, page_limit=20):
    existing = {(c["type"], c["scope"].casefold()) for c in snapshot["collections"]}
    missing = sorted({scope for scope in snapshot.get("scopes", [])
                      if isinstance(scope, str) and SUBSCRIPTION.fullmatch(scope)
                      and ("iam_usage_activity", scope.casefold()) not in existing})
    if not missing:
        return snapshot
    from .azure import ARM, AzureTransport

    options = connector.get("options") or {}
    days = options.get("activity_days", 90)
    if type(days) is not int or not 1 <= days <= 90:
        days = 90
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    until = end - timedelta(microseconds=1)
    query_window = {"start": start.isoformat(), "end": end.isoformat(), "endExclusive": True,
                    "days": days, "absenceProvesUnused": False}
    collections = copy.deepcopy(snapshot["collections"])
    auth = connector.get("auth") or {}
    # Match the native collector's hosted credential boundary.
    if options.get("hosted") and (any(auth.get(key) for key in ("certificate_path", "token_file"))
            or not any(auth.get(key) for key in ("arm_token", "token", "client_secret", "certificate_data",
                                                   "client_certificate", "federated_token"))):
        for scope in missing:
            collections.append({"type": "iam_usage_activity", "scope": scope, "service": "Microsoft.Insights",
                "status": "denied", "items": [], "queryWindow": query_window,
                "error": {"code": "hosted_credentials_required"}})
        return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                             created_at=snapshot["created_at"], metadata=snapshot.get("metadata"), owned=True)
    transport = None
    try:
        transport = AzureTransport(auth)
        for scope in missing:
            path = scope + "/providers/Microsoft.Insights/eventtypes/management/values"
            filter_value = f"eventTimestamp ge '{start.isoformat()}' and eventTimestamp le '{until.isoformat()}'"
            url = ARM + path + "?" + urlencode({"api-version": "2015-04-01", "$filter": filter_value, "$select": SELECT})
            rows, seen, visited = [], set(), set()
            status, error = "collected", None
            try:
                for _ in range(page_limit):
                    parsed = urlsplit(url)
                    if (parsed.scheme != "https" or parsed.netloc != urlsplit(ARM).netloc or parsed.path != path
                            or parsed.fragment or parsed.username or parsed.password or url in visited):
                        raise ValueError("untrusted_activity_cursor")
                    visited.add(url)
                    response = transport.request(url)
                    if not isinstance(response, dict) or not isinstance(response.get("value"), list):
                        raise ValueError("malformed_activity_page")
                    for event in response["value"]:
                        if not isinstance(event, dict):
                            continue
                        event_id = event.get("eventDataId")
                        if not isinstance(event_id, str) or not event_id or event_id in seen:
                            continue
                        seen.add(event_id)
                        auth_value = event.get("authorization")
                        action = auth_value.get("action") if isinstance(auth_value, dict) else None
                        caller = event.get("caller")
                        claims = event.get("claims") or {}
                        if not isinstance(claims, dict):
                            claims = {}
                        object_id = claims.get(OBJECT_ID_CLAIM)
                        app_id = claims.get("appid")
                        timestamp = event.get("eventTimestamp")
                        resource = event.get("resourceId")
                        event_status = event.get("status")
                        success = isinstance(event_status, dict) and event_status.get("value") == "Succeeded"
                        identities = {"caller": caller} if isinstance(caller, str) and caller else {}
                        if isinstance(object_id, str) and GUID.fullmatch(object_id):
                            identities["principalObjectId"] = object_id
                        if isinstance(app_id, str) and GUID.fullmatch(app_id):
                            identities["appId"] = app_id
                        if (success and identities and all(isinstance(value, str) and value for value in
                                                       (action, timestamp, resource))):
                            rows.append({"eventDataId": event_id, **identities, "eventTimestamp": timestamp,
                                "resourceId": resource, "authorizationAction": action,
                                "status": {"value": "Succeeded"}})
                    url = response.get("nextLink")
                    if not url:
                        break
                if url:
                    status, error = "partial", {"code": "iam_usage_activity_page_limit"}
            except Exception:
                status, error = ("partial" if rows else "unknown"), {"code": "iam_usage_activity_read_failed"}
            result = {"type": "iam_usage_activity", "scope": scope, "service": "Microsoft.Insights",
                      "status": status if rows else ("empty" if status == "collected" else status),
                      "items": rows, "queryWindow": query_window}
            if error:
                result["error"] = error
            collections.append(result)
    except Exception:
        for scope in missing:
            if not any(c["type"] == "iam_usage_activity" and c["scope"] == scope for c in collections):
                collections.append({"type": "iam_usage_activity", "scope": scope,
                    "service": "Microsoft.Insights", "status": "unknown", "items": [],
                    "queryWindow": query_window, "error": {"code": "iam_usage_activity_read_failed"}})
    finally:
        if transport:
            transport.close()
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=snapshot.get("metadata"), owned=True)

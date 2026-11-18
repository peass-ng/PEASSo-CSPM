"""Resolve successful non-home-region emptiness only after native home discovery."""
from threading import Lock
_LOCK = Lock()


def remember(requests, account, region):
    with _LOCK:
        homes = getattr(requests, "identity_center_discovered_regions", None)
        if homes is None:
            homes = requests.identity_center_discovered_regions = {}
        homes.setdefault(account, set()).add(region)


def finalize(requests, collections, metadata):
    homes = getattr(requests, "identity_center_discovered_regions", {})
    metadata["identity_center_discovered_regions"] = {k: sorted(v) for k, v in homes.items()}
    for row in collections:
        account, _, region = row.get("scope", "").partition("/")
        error = row.get("error") or {}
        if (row.get("type") in {"identity_center", "aws_identity_center_permission_set_consumer"}
                and row.get("status") == "not_collected" and not row.get("items")
                and error.get("code") == "identity_center_home_region_unresolved"
                and homes.get(account) and region not in homes[account]):
            row.update(status="empty", home_regions=sorted(homes[account]))
            row.pop("error", None)

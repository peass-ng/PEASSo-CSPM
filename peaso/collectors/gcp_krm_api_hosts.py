"""Read Config Controller hosts and their exact IAM policies."""

import re

from .gcp import ReadError
from .gcp_fanout import fanout_pages


def collection_pages(collector, scope):
    base = f"https://krmapihosting.googleapis.com/v1/{scope}/locations"
    seen_locations = set()
    for locations, _ in collector.pages(base, scope, key="locations"):
        # Location identities are checked in order before any host read; hosts
        # are read per location concurrently and replayed in that order.
        names, failure = [], None
        for location in locations:
            name = location.get("name")
            if (not isinstance(name, str) or not re.fullmatch(
                    re.escape(scope) + r"/locations/[a-z][a-z0-9-]*", name)
                    or name in seen_locations):
                failure = ReadError("malformed", "krm_api_host_location_unbound")
                break
            seen_locations.add(name)
            names.append(name)

        def location_pages(name):
            url = f"https://krmapihosting.googleapis.com/v1/{name}/krmApiHosts"
            seen_hosts = set()  # host names embed their location
            for hosts, request_id in collector.pages(url, scope, key="krmApiHosts"):
                rows = []
                for host in hosts:
                    host_name = host.get("name")
                    if (not isinstance(host_name, str) or not re.fullmatch(
                            re.escape(name) + r"/krmApiHosts/[A-Za-z0-9_-]+", host_name)
                            or host_name in seen_hosts):
                        raise ReadError("malformed", "krm_api_host_identity_unbound")
                    seen_hosts.add(host_name)
                    rows.append(host)
                def policy(host):
                    policy_url = ("https://krmapihosting.googleapis.com/v1/"
                                  + host["name"] + ":getIamPolicy")
                    return collector.hydrate(host, "iamPolicy", policy_url, scope,
                                             params={"options.requestedPolicyVersion": 3})
                yield collector.parallel(policy, rows), request_id
        yield from fanout_pages(collector, names, location_pages)
        if failure is not None:
            raise failure

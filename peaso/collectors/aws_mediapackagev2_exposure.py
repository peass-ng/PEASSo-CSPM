"""MediaPackage v2 ingest and playback listener metadata from owned channels."""

from urllib.parse import urlsplit

KIND = "mediapackagev2_channel_listener"
HARVEST_KIND = "mediapackagev2_harvest_job"
SPECS = {KIND: ("mediapackagev2", "list_channel_groups", "Items"),
         HARVEST_KIND: ("mediapackagev2", "list_channel_groups", "Items")}
NATIVE_IDS = {KIND: "ChannelArn", HARVEST_KIND: "Arn"}
READ_ACTIONS = {("mediapackagev2", operation) for operation in
                ("list_channel_groups", "list_channels", "list_origin_endpoints", "get_channel", "list_harvest_jobs")}


def endpoint_host(url):
    """Discard paths, query strings and userinfo before retaining an endpoint."""
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or 443
    except ValueError:
        return None
    if parsed.scheme != "https" or not host or not 1 <= port <= 65535:
        return None
    return {"Host": host.lower(), "Port": port}


def collect(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    groups = requests.pages(session, "mediapackagev2", region, "list_channel_groups", "Items")
    if groups.status not in {"collected", "empty"}:
        return groups
    partition = session.get_partition_for_region(region)
    rows, failures = [], []
    for group in groups.items:
        group_name = group.get("ChannelGroupName") if isinstance(group, dict) else None
        if not isinstance(group_name, str) or not group_name:
            failures.append("malformed")
            continue
        channels = requests.pages(session, "mediapackagev2", region, "list_channels", "Items",
                                  ChannelGroupName=group_name)
        if channels.status not in {"collected", "empty"}:
            failures.append(channels.status)
        for channel in channels.items:
            channel_name = channel.get("ChannelName") if isinstance(channel, dict) else None
            arn = channel.get("Arn") if isinstance(channel, dict) else None
            expected = (f"arn:{partition}:mediapackagev2:{region}:{account}:"
                        f"channelGroup/{group_name}/channel/{channel_name}")
            if not isinstance(channel_name, str) or arn != expected:
                failures.append("malformed")
                continue
            row = {"ChannelArn": arn, "ChannelGroupName": group_name, "ChannelName": channel_name}
            detail = requests.detail(MetadataSession(session), "mediapackagev2", region, "get_channel",
                                     ChannelGroupName=group_name, ChannelName=channel_name)
            if (detail.get("collection_status") == "collected" and detail.get("Arn") == arn and
                    isinstance(detail.get("Hosts"), list)):
                row["Ingest"] = {"collection_status": "collected", "Hosts": detail["Hosts"]}
            else:
                status = detail.get("collection_status", "malformed")
                row["Ingest"] = {"collection_status": status}
                failures.append(status)
            listed = requests.pages(session, "mediapackagev2", region, "list_origin_endpoints", "Items",
                                    ChannelGroupName=group_name, ChannelName=channel_name)
            if listed.status not in {"collected", "empty"}:
                row["Playback"] = {"collection_status": listed.status}
                failures.append(listed.status)
            else:
                endpoints = []
                valid = True
                for endpoint in listed.items:
                    endpoint_name = endpoint.get("OriginEndpointName") if isinstance(endpoint, dict) else None
                    endpoint_arn = endpoint.get("Arn") if isinstance(endpoint, dict) else None
                    if not isinstance(endpoint_name, str) or endpoint_arn != arn + "/originEndpoint/" + endpoint_name:
                        valid = False
                        break
                    hosts = []
                    for field in ("HlsManifests", "LowLatencyHlsManifests", "DashManifests", "MssManifests"):
                        manifests = endpoint.get(field, [])
                        if not isinstance(manifests, list):
                            valid = False
                            break
                        for manifest in manifests:
                            host = endpoint_host(manifest.get("Url")) if isinstance(manifest, dict) else None
                            if host is None:
                                valid = False
                                break
                            if host not in hosts:
                                hosts.append(host)
                    if not valid:
                        break
                    endpoints.append({"OriginEndpointArn": endpoint_arn, "Hosts": hosts})
                if valid:
                    row["Playback"] = {"collection_status": "collected", "Endpoints": endpoints}
                else:
                    row["Playback"] = {"collection_status": "malformed"}
                    failures.append("malformed")
            rows.append(row)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "mediapackagev2_listener_inventory_incomplete"} if failures else None)


def collect_harvest_jobs(requests, session, region, account):
    """Project the S3 bucket only; harvest paths and manifests stay out of cache."""
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    groups = requests.pages(session, "mediapackagev2", region, "list_channel_groups", "Items")
    if groups.status not in {"collected", "empty"}:
        return groups
    partition = session.get_partition_for_region(region)
    rows, failures = [], []
    for group in groups.items:
        group_name = group.get("ChannelGroupName") if isinstance(group, dict) else None
        if not isinstance(group_name, str) or not group_name:
            failures.append("malformed")
            continue
        listed = requests.pages(MetadataSession(session), "mediapackagev2", region,
                                "list_harvest_jobs", "Items", ChannelGroupName=group_name)
        if listed.status not in {"collected", "empty"}:
            failures.append(listed.status)
        for job in listed.items:
            if not isinstance(job, dict):
                failures.append("malformed")
                continue
            channel, origin, name = (job.get(key) for key in
                                     ("ChannelName", "OriginEndpointName", "HarvestJobName"))
            arn = job.get("Arn")
            expected = (f"arn:{partition}:mediapackagev2:{region}:{account}:channelGroup/{group_name}/"
                        f"channel/{channel}/originEndpoint/{origin}/harvestJob/{name}")
            if (job.get("ChannelGroupName") != group_name or arn != expected or
                    not isinstance(job.get("BucketName"), str) or not isinstance(job.get("Status"), str)):
                failures.append("malformed")
                continue
            rows.append(job)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "mediapackagev2_harvest_inventory_incomplete"} if failures else None)


FETCHERS = {KIND: collect, HARVEST_KIND: collect_harvest_jobs}

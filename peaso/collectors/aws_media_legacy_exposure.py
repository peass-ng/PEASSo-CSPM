"""Bounded MediaPackage V1 and MediaTailor public playback metadata."""

from urllib.parse import urlsplit

SPECS = {
    "mediapackage_origin_endpoint": ("mediapackage", "list_origin_endpoints", "OriginEndpoints"),
    "mediatailor_playback_configuration": ("mediatailor", "list_playback_configurations", "Items"),
}
NATIVE_IDS = {
    "mediapackage_origin_endpoint": "NetworkResourceId",
    "mediatailor_playback_configuration": "NetworkResourceId",
}
READ_ACTIONS = {(service, operation) for service, operation, _ in SPECS.values()}


def _host(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443) and not parsed.username and not parsed.password:
            return parsed.hostname.lower()
    except ValueError:
        pass
    return None


class MetadataClient:
    def __init__(self, native, service):
        self.native, self.service = native, service

    def __getattr__(self, operation):
        native = getattr(self.native, operation)
        spec = next(((kind, root) for kind, (service, read, root) in SPECS.items()
                     if (service, read) == (self.service, operation)), None)
        if spec is None:
            return native

        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            with private_sdk_logs():
                response = native(**arguments)
            kind, root = spec
            items = response.get(root) if isinstance(response, dict) else None
            if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                return {}
            selected = []
            for row in items:
                if kind == "mediapackage_origin_endpoint":
                    entry = {key: row[key] for key in ("Arn", "Id", "Origination")
                             if isinstance(row.get(key), str)}
                    entry["Host"] = _host(row.get("Url"))
                    whitelist = row.get("Whitelist")
                    entry["Whitelist"] = (whitelist if isinstance(whitelist, list) and
                                          all(isinstance(item, str) for item in whitelist) else None)
                    entry["CdnAuthorization"] = isinstance(row.get("Authorization"), dict)
                else:
                    entry = {key: row[key] for key in ("Name", "PlaybackConfigurationArn")
                             if isinstance(row.get(key), str)}
                    entry["PlaybackHosts"] = sorted({host for field in
                        ("PlaybackEndpointPrefix", "DualStackPlaybackEndpointPrefix",
                         "SessionInitializationEndpointPrefix", "DualStackSessionInitializationEndpointPrefix")
                        if (host := _host(row.get(field)))})
                    entry["AdDecisionHost"] = _host(row.get("AdDecisionServerUrl"))
                selected.append(entry)
            token = response.get("NextToken")
            return {root: selected, **({"NextToken": token} if isinstance(token, str) else {})}
        return read


class MetadataSession:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        client = self.native.client(service, **arguments)
        return MetadataClient(client, service) if service in {"mediapackage", "mediatailor"} else client


def collect(kind):
    service, operation, root = SPECS[kind]

    def fetch(requests, session, region, account):
        from .aws import ReadResult

        partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
        read = requests.pages(MetadataSession(session), service, region, operation, root,
                              _tokens=("NextToken", "NextToken"))
        rows, malformed = [], False
        for row in read.items:
            if not isinstance(row, dict):
                malformed = True
                continue
            arn = row.get("Arn") if service == "mediapackage" else row.get("PlaybackConfigurationArn")
            name = row.get("Id") if service == "mediapackage" else row.get("Name")
            prefix = "origin_endpoints" if service == "mediapackage" else "playbackConfiguration"
            if (not isinstance(name, str) or not name or
                    arn != f"arn:{partition}:{service}:{region}:{account}:{prefix}/{name}"):
                malformed = True
                continue
            rows.append(dict(row, NetworkResourceId=arn))
        status = "partial" if rows and (malformed or read.status not in {"collected", "empty"}) else (
            read.status if read.status not in {"collected", "empty"} else "malformed" if malformed else
            "collected" if rows else "empty")
        return ReadResult(rows, status, {"code": "media_playback_inventory_incomplete"} if malformed else read.error)

    return fetch


FETCHERS = {kind: collect(kind) for kind in SPECS}

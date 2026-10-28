"""Project NGINX for Azure public frontends and configured listeners without retaining files.

ARM schema: https://learn.microsoft.com/en-us/azure/templates/nginx.nginxplus/2025-11-01/nginxdeployments
Configuration schema: https://learn.microsoft.com/en-us/azure/templates/nginx.nginxplus/2025-11-01/nginxdeployments/configurations
"""
from __future__ import annotations

import base64
import fnmatch
import posixpath
import re


ARM = "https://management.azure.com"
VERSION = "2025-11-01"
KIND = "nginx_deployment"
TYPE = "Nginx.NginxPlus/nginxDeployments"
PUBLIC_IP = re.compile(r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/publicIPAddresses/[^/]+", re.I)


def _listeners(files, root):
    if not isinstance(files, list) or not isinstance(root, str) or not root.startswith("/"):
        return [], True
    contents = {}
    for row in files:
        if not isinstance(row, dict) or not isinstance(row.get("virtualPath"), str) or not isinstance(row.get("content"), str):
            return [], True
        path = posixpath.normpath(row["virtualPath"])
        if not path.startswith("/") or path in contents:
            return [], True
        try:
            contents[path] = base64.b64decode(row["content"], validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            return [], True
    ports, visited, unresolved = set(), set(), False

    def walk(path):
        nonlocal unresolved
        if path in visited:
            return
        visited.add(path)
        content = contents.get(path)
        if content is None:
            unresolved = True
            return
        # This extracts directives only; all other configuration text is discarded.
        content = re.sub(r"(?m)#.*$", "", content)
        for match in re.finditer(r"(?m)(?:^|[;{}\n])\s*include\s+([^;]+);", content):
            pattern = match.group(1).strip().strip('"\'')
            if not pattern.startswith("/"):
                pattern = posixpath.join(posixpath.dirname(path), pattern)
            matched = [name for name in contents if fnmatch.fnmatchcase(name, posixpath.normpath(pattern))]
            if not matched:
                unresolved = True
            for name in matched:
                walk(name)
        for match in re.finditer(r"(?m)(?:^|[;{}\n])\s*listen\s+([^;]+);", content):
            words = match.group(1).split()
            if not words:
                unresolved = True
                continue
            address = words[0]
            if address.startswith("unix:"):
                continue
            port = address.rsplit(":", 1)[-1]
            if not port.isdecimal() or not 1 <= int(port) <= 65535:
                unresolved = True
                continue
            ports.add(("udp" if "udp" in words[1:] else "tcp", int(port)))

    walk(posixpath.normpath(root))
    return sorted(ports), unresolved


def _project(reader, request, row, scope):
    rid = row.get("id") if isinstance(row, dict) else None
    if (not isinstance(rid, str) or re.fullmatch(
            re.escape(scope) + r"/resourceGroups/[^/]+/providers/Nginx\.NginxPlus/nginxDeployments/[^/]+", rid, re.I) is None
            or str(row.get("type", "")).casefold() != TYPE.casefold()):
        raise ValueError("malformed NGINX deployment identity")
    props = row.get("properties")
    network = props.get("networkProfile") if isinstance(props, dict) else None
    frontend = network.get("frontEndIPConfiguration") if isinstance(network, dict) else None
    addresses = frontend.get("publicIPAddresses") if isinstance(frontend, dict) else None
    if not isinstance(addresses, list):
        raise ValueError("NGINX frontend inventory unavailable")
    public_ids = []
    for address in addresses:
        public_id = address.get("id") if isinstance(address, dict) else None
        if not isinstance(public_id, str) or PUBLIC_IP.fullmatch(public_id) is None:
            raise ValueError("malformed NGINX public IP reference")
        public_ids.append(public_id)
    result = {"publicIpIds": sorted(set(public_ids)), "listeners": [], "listenerCoverage": "collected",
              "provisioningState": props.get("provisioningState")}
    if not public_ids:
        return result
    seen = set()
    url = ARM + rid + "/configurations?api-version=" + VERSION
    for page in reader.pages(request, url):
        for config in page:
            config_id = config.get("id") if isinstance(config, dict) else None
            if (not isinstance(config_id, str) or re.fullmatch(re.escape(rid) + r"/configurations/[^/]+", config_id, re.I) is None
                    or config_id.casefold() in seen):
                raise ValueError("malformed NGINX configuration identity")
            seen.add(config_id.casefold())
            details = config.get("properties") if isinstance(config, dict) else None
            if not isinstance(details, dict) or "files" not in details:
                details = reader.call(request, ARM + config_id + "?api-version=" + VERSION).get("properties")
            if not isinstance(details, dict):
                raise ValueError("NGINX configuration unavailable")
            ports, unknown = _listeners(details.get("files"), details.get("rootFile"))
            result["listeners"].extend(ports)
            if unknown or details.get("package"):
                result["listenerCoverage"] = "unknown"
    if not seen:
        result["listenerCoverage"] = "unknown"
    result["listeners"] = sorted(set(result["listeners"]))
    return result


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    for collection in reader.collections:
        if collection.get("type") != KIND or collection.get("status") not in ("collected", "partial"):
            continue
        for row in collection["items"]:
            try:
                row["nginxExposure"] = _project(reader, request, row, collection["scope"])
                row.setdefault("_coverage", {})["nginxExposure"] = {"status": "collected"}
            except Exception as exc:
                row.pop("nginxExposure", None)
                row.setdefault("_coverage", {})["nginxExposure"] = {
                    "status": "unknown", "error": {"code": str(getattr(exc, "code", "read_failed"))}}

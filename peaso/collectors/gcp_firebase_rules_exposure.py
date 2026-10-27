"""Read active Firebase rules without persisting rule source text."""

import copy
import json
import re
import threading
from urllib.parse import urlsplit

from .gcp import ReadError, Transport, _settle_cache_entry, http_error


def _code(source):
    """Blank comments and quoted strings while preserving rule punctuation."""
    out = []
    index = 0
    state = "code"
    quote = None
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                out.extend("  ")
                index += 2
                state = "line"
                continue
            if char == "/" and next_char == "*":
                out.extend("  ")
                index += 2
                state = "block"
                continue
            if char in ("'", '"'):
                quote = char
                out.append(" ")
                state = "string"
            else:
                out.append(char)
        elif state == "line":
            out.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and next_char == "/":
                out.extend("  ")
                index += 2
                state = "code"
                continue
            out.append("\n" if char == "\n" else " ")
        else:
            if char == "\\" and next_char:
                out.extend("  ")
                index += 2
                continue
            out.append("\n" if char == "\n" else " ")
            if char == quote:
                state = "code"
        index += 1
    return "".join(out)


def summarize(files):
    """Conservative existential read/write declarations, never an effective rules proof."""
    if not isinstance(files, list) or not files:
        raise ReadError("malformed", "firebase_rules_source_missing")
    flags = {"public_read": False, "public_write": False,
             "authenticated_read": False, "authenticated_write": False,
             "conditional_read": False, "conditional_write": False}
    for file in files:
        if not isinstance(file, dict) or not isinstance(file.get("content"), str):
            raise ReadError("malformed", "firebase_rules_source_missing")
        source = _code(file["content"])
        for match in re.finditer(r"\ballow\s+([a-z,\s]+?)\s*(?::\s*if\s*(.*?))?\s*;", source, re.S):
            operations = {part.strip() for part in match.group(1).split(",")}
            condition = (match.group(2) or "").strip()
            read = bool(operations & {"read", "get", "list"})
            write = bool(operations & {"write", "create", "update", "delete"})
            if not read and not write:
                continue
            if condition in ("false", "(false)"):
                continue
            if condition in ("", "true", "(true)") or re.fullmatch(
                    r"\(?\s*request\.auth\s*==\s*null\s*\)?", condition):
                flags["public_read"] |= read
                flags["public_write"] |= write
            elif re.fullmatch(r"\(?\s*request\.auth\s*!=\s*null\s*\)?", condition):
                flags["authenticated_read"] |= read
                flags["authenticated_write"] |= write
            else:
                flags["conditional_read"] |= read
                flags["conditional_write"] |= write
    return flags


def as_services(metadata):
    value = metadata.get("services") if isinstance(metadata, dict) else None
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _project(data, ruleset):
    if not isinstance(data, dict) or data.get("name") != ruleset:
        raise ReadError("malformed", "firebase_ruleset_detail_malformed")
    files = (data.get("source") or {}).get("files")
    return {"name": ruleset, "services": as_services(data.get("metadata")), **summarize(files)}


def _project_list(data):
    if (not isinstance(data, dict) or not isinstance(data.get("releases", []), list) or
        any(not isinstance(row, dict) for row in data.get("releases", []))):
        raise ReadError("malformed", "firebase_rules_release_list_malformed")
    return {"releases": [{"name": row.get("name"), "rulesetName": row.get("rulesetName")}
                         for row in data.get("releases", [])],
            **({"nextPageToken": data["nextPageToken"]} if "nextPageToken" in data else {})}


def _read(collector, url, scope, params, ruleset=None):
    """Exact-host read with the existing scan cache; source is projected before caching."""
    parsed = urlsplit(url)
    allowed = (parsed.scheme == "https" and parsed.hostname == "firebaserules.googleapis.com"
        and parsed.port in (None, 443) and not parsed.query and not parsed.username and not parsed.password
        and (parsed.path == f"/v1/{scope}/releases" or
             ruleset is not None and parsed.path == f"/v1/{ruleset}"))
    if not allowed:
        raise ReadError("unsupported", "unsafe_firebase_rules_endpoint")
    transport = collector.transport
    if not isinstance(transport, Transport):
        # Fixture transports retain their request log, and never hold real credentials.
        data, receipt = collector.read(url, scope, params=params)
        return (_project(data, ruleset) if ruleset else _project_list(data)), receipt
    transport.check_cancelled()
    key = json.dumps(["firebase-rules-projected", url, params], sort_keys=True)
    with transport.lock:
        cached = transport.cache.get(key)
        if cached is not None and hasattr(transport.cache, "touch"):
            transport.cache.touch(key)
        owner = cached is None
        if owner:
            cached = {"event": threading.Event()}
            transport.cache[key] = cached
    if not owner:
        cached["event"].wait()
        transport.check_cancelled()
        if "error" in cached:
            raise cached["error"]
        return copy.deepcopy(cached["data"]), cached["id"]
    evidence = {"id": None, "scope": scope, "method": "GET", "url": url,
                "operation": parsed.path, "query": {k: v for k, v in params.items() if k != "pageToken"},
                "attempts": 1, "http_attempts": 0}
    try:
        transport.check_cancelled()
        with transport.lock:
            if transport.max_calls is not None and transport.calls >= transport.max_calls:
                raise ReadError("unavailable", "call_limit")
            transport.calls += 1
        headers = transport.credentials.headers()
        if transport.options.get("quota_project"):
            headers["X-Goog-User-Project"] = transport.options["quota_project"]
        evidence["http_attempts"] = 1
        response = transport._session().request("GET", url, params=params, headers=headers,
            timeout=transport.timeout, allow_redirects=False)
        evidence["http_status"] = response.status_code
        try:
            data = response.json()
        except Exception:
            raise ReadError("malformed", "firebase_rules_response_malformed") from None
        if response.status_code >= 300:
            raise http_error(response.status_code, data)
        if not isinstance(data, dict):
            raise ReadError("malformed", "firebase_rules_response_malformed")
        cached["data"] = _project(data, ruleset) if ruleset else _project_list(data)
        evidence["status"] = "collected"
    except ReadError as exc:
        cached["error"] = exc
        evidence["status"], evidence["error"] = exc.status, exc.error
    except Exception:
        cached["error"] = ReadError("unavailable", "firebase_rules_read_failed")
        evidence["status"], evidence["error"] = cached["error"].status, cached["error"].error
    finally:
        with transport.lock:
            evidence["id"] = f"request-{len(transport.evidence) + 1}"
            transport.evidence.append(evidence)
            cached["id"] = evidence["id"]
            _settle_cache_entry(transport.cache, key, cached,
                len(json.dumps(cached.get("data", {}), sort_keys=True)))
        cached["event"].set()
    if "error" in cached:
        cached["error"].request_id = cached["id"]
        raise cached["error"]
    return copy.deepcopy(cached["data"]), cached["id"]


def collection_pages(collector, scope):
    base = "https://firebaserules.googleapis.com/v1/"
    rulesets, seen_tokens = {}, set()
    params = {"fields": "releases(name,rulesetName),nextPageToken", "pageSize": min(collector.page_size, 100)}
    for page in range(collector.max_pages or 100000):
        data, receipt = _read(collector, base + scope + "/releases", scope, params)
        releases = data.get("releases", []) if isinstance(data, dict) else None
        if not isinstance(releases, list) or any(not isinstance(row, dict) for row in releases):
            raise ReadError("malformed", "firebase_rules_release_list_malformed")
        yield [], receipt
        for release in releases:
            name, ruleset = release.get("name"), release.get("rulesetName")
            if (not isinstance(name, str) or not name.startswith(scope + "/releases/") or
                not isinstance(ruleset, str) or not re.fullmatch(re.escape(scope) + r"/rulesets/[A-Za-z0-9_-]+", ruleset)):
                raise ReadError("malformed", "firebase_rules_release_identity_unbound")
            if ruleset not in rulesets:
                rulesets[ruleset], detail_receipt = _read(collector, base + ruleset, scope,
                    {"fields": "name,source(files(content)),metadata(services)"}, ruleset)
                yield [], detail_receipt
            yield [{**rulesets[ruleset], "name": name, "rulesetName": ruleset,
                    "source_inspected": True}], receipt
        token = data.get("nextPageToken")
        if not token:
            return
        if not isinstance(token, str) or token in seen_tokens:
            raise ReadError("malformed", "firebase_rules_release_pagination_malformed")
        seen_tokens.add(token)
        params = {**params, "pageToken": token}
    raise ReadError("unavailable", "page_limit")

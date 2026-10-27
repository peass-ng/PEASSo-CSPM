"""Read Realtime Database rules and retain only derived exposure declarations."""

import copy
import json
import re
import threading
from urllib.parse import urlsplit

from .gcp import ReadError, Transport, _settle_cache_entry, http_error


_DATABASE_HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,61}[a-z0-9](?:\.[a-z0-9-]+)*\.(?:firebaseio\.com|firebasedatabase\.app)")


def summarize_rules(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("rules"), dict):
        raise ReadError("malformed", "firebase_database_rules_malformed")
    flags = {"public_read": False, "public_write": False,
             "authenticated_read": False, "conditional_read": False,
             "conditional_write": False}

    def visit(node):
        if not isinstance(node, dict):
            raise ReadError("malformed", "firebase_database_rules_malformed")
        for operation, public_key, conditional_key in (
                (".read", "public_read", "conditional_read"),
                (".write", "public_write", "conditional_write")):
            if operation not in node:
                continue
            value = node[operation]
            if not isinstance(value, (bool, str)):
                raise ReadError("malformed", "firebase_database_rule_expression_malformed")
            expression = str(value).strip().lower() if isinstance(value, bool) else value.strip()
            expression = expression.removeprefix("(").removesuffix(")").strip()
            if expression in {"true", "auth == null", "auth === null"}:
                flags[public_key] = True
            elif expression in {"false"}:
                pass
            elif operation == ".read" and expression in {"auth != null", "auth !== null"}:
                flags["authenticated_read"] = True
            else:
                flags[conditional_key] = True
        for key, child in node.items():
            if not key.startswith("."):
                visit(child)

    visit(payload["rules"])
    return flags


def _rules_url(value):
    if not isinstance(value, str):
        raise ReadError("malformed", "firebase_database_url_missing")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ReadError("malformed", "firebase_database_url_invalid") from None
    if (parsed.scheme != "https" or not parsed.hostname or not _DATABASE_HOST.fullmatch(parsed.hostname)
            or parsed.port not in (None, 443) or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ReadError("malformed", "firebase_database_url_invalid")
    return f"https://{parsed.hostname}/.settings/rules.json"


def _read_rules(collector, url, scope):
    """Use the scan transport cache, storing only projected flags and no rule source."""
    transport = collector.transport
    if not isinstance(transport, Transport):
        payload, receipt = collector.read(url, scope, params={})
        return summarize_rules(payload), receipt
    transport.check_cancelled()
    key = json.dumps(["firebase-database-rules-projected", url], sort_keys=True)
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
                "operation": "/.settings/rules.json", "query": {}, "attempts": 1, "http_attempts": 0}
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
        response = transport._session().request("GET", url, params={}, headers=headers,
            timeout=transport.timeout, allow_redirects=False)
        evidence["http_status"] = response.status_code
        if len(response.content) > 1_048_576:
            raise ReadError("unavailable", "firebase_database_rules_size_limit")
        try:
            payload = response.json()
        except Exception:
            raise ReadError("malformed", "firebase_database_rules_response_malformed") from None
        if response.status_code >= 300:
            raise http_error(response.status_code, payload)
        cached["data"] = summarize_rules(payload)
        evidence["status"] = "collected"
    except ReadError as exc:
        cached["error"] = exc
        evidence["status"], evidence["error"] = exc.status, exc.error
    except Exception:
        cached["error"] = ReadError("unavailable", "firebase_database_rules_read_failed")
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
    binding = collector._data_project_binding(scope, require_alias=True)
    number = binding.get("project_number")
    if not isinstance(number, str) or not number.isdecimal():
        raise ReadError("unavailable", "firebase_database_project_number_unavailable")
    parent = f"projects/{number}/locations/-"
    url = f"https://firebasedatabase.googleapis.com/v1beta/{parent}/instances"
    for instances, receipt in collector.pages(url, scope, key="instances"):
        yield [], receipt
        for instance in instances:
            name = instance.get("name") if isinstance(instance, dict) else None
            if not isinstance(name, str) or not re.fullmatch(
                    rf"projects/{re.escape(number)}/locations/[a-z0-9-]+/instances/[a-z0-9-]+", name):
                raise ReadError("malformed", "firebase_database_instance_identity_invalid")
            if instance.get("state") == "DELETED":
                continue
            rules_url = _rules_url(instance.get("databaseUrl"))
            flags, rules_receipt = _read_rules(collector, rules_url, scope)
            yield [{"name": name, "databaseUrl": instance["databaseUrl"], "state": instance.get("state"),
                    "source_inspected": True, **flags}], rules_receipt

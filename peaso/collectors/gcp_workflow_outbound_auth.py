"""Bounded, transient projection of Workflows authenticated HTTP calls."""
from urllib.parse import urlsplit


def project(source):
    if not isinstance(source, str) or len(source.encode("utf-8")) > 131072:
        return {"status": "unavailable", "routes": []}
    try:
        import yaml
        document = yaml.safe_load(source)
    except (ValueError, UnicodeError, RecursionError, yaml.YAMLError):
        return {"status": "unavailable", "routes": []}
    routes, stack, seen = [], [document], 0
    while stack:
        value = stack.pop()
        seen += 1
        if seen > 10000:
            return {"status": "unavailable", "routes": []}
        if isinstance(value, list):
            stack.extend(value)
            continue
        if not isinstance(value, dict):
            continue
        call, args = value.get("call"), value.get("args")
        if isinstance(call, str) and call.startswith("http.") and isinstance(args, dict):
            auth = args.get("auth")
            kind = auth.get("type") if isinstance(auth, dict) else None
            if (kind in ("OIDC", "OAuth2") or
                    (auth is not None and (not isinstance(auth, dict) or kind not in (None, "NONE")))):
                url = args.get("url")
                try:
                    parsed = urlsplit(url) if isinstance(url, str) and "${" not in url else None
                    origin = (parsed.scheme + "://" + parsed.netloc.rsplit("@", 1)[-1]
                              if parsed and parsed.scheme in ("http", "https") and parsed.hostname else None)
                except ValueError:
                    origin = None
                routes.append({"call": call, "auth_type": kind if kind in ("OIDC", "OAuth2") else "UNRESOLVED",
                               "target_origin": origin,
                               "url_kind": "static" if origin else "dynamic_or_unresolved"})
                if len(routes) > 64:
                    return {"status": "unavailable", "routes": []}
        stack.extend(value.values())
    return {"status": "collected", "routes": routes}

"""Public-by-design client identifiers that secret detectors match.

Some vendors issue a key that every browser sends with each request: it names
the project, it does not authorize reading or changing anything. A detector
may still match it, sometimes under a rule named after the vendor's real
secret, because both share one format. Such a match is not a leaked secret
when all of these hold:

- a detector rule names the vendor (``rules``),
- the value has the public key's format (``value``),
- the file is JavaScript a web server delivers to browsers (``BROWSER_BUNDLE``),
- every occurrence of the value in the scanned content is the argument of the
  vendor SDK's public key setting (``assigned_to``).

A value used anywhere else in the same content (a server-side call, a
``secretKey`` field, an environment file) stays a finding. Add a vendor by
adding one entry to ``PUBLIC_CLIENT_IDENTIFIERS``.
"""
import re

# Client bundles a web server delivers as-is: Next.js static chunks, public/
# and static asset trees, and built client bundles. Server bundles
# (.next/server, server.js) are not browser-delivered.
BROWSER_BUNDLE = re.compile(
    r'(?:^|/)(?:\.next/static|public|static|dist|build|out)/(?:[^/]+/)*[^/]+\.(?:m?js|cjs)$')
_SERVER_BUNDLE = re.compile(r'(?:^|/)(?:\.next/server|server)/')
# How far before a value its key name may sit: `amplitudeApiKey: "` plus spacing.
_PREFIX = 96

PUBLIC_CLIENT_IDENTIFIERS = (
    {'id': 'amplitude_browser_api_key',
     # Kingfisher's betterleaks.amplitude-secret-key matches any 32-hex value
     # near "amplitude"; Amplitude's public API key has that same format.
     'rules': re.compile(r'(?i)amplitude'),
     'value': re.compile(r'[0-9a-f]{32}'),
     # amplitudeApiKey: "<key>", apiKey: "<key>", amplitude.init("<key>").
     'assigned_to': re.compile(
         r'''(?:\b(?:amplitude_?api_?key|api_?key)["'`]?\s*[:=]\s*|\bamplitude(?:\.getInstance\(\s*\))?\.init\(\s*)["'`]$''',
         re.IGNORECASE),
     'reason': 'Amplitude browser SDK API key: public by design, sent by every browser to Amplitude. '
               'It is not the Amplitude secret key, which never belongs in browser code.'},
)


def _every_use_assigned(payload, value, pattern):
    needle = value.encode('utf-8')
    position, found = payload.find(needle), False
    while position != -1:
        before = payload[max(0, position - _PREFIX):position].decode('latin-1')
        if not pattern.search(before):
            return False
        found = True
        position = payload.find(needle, position + len(needle))
    return found


def public_client_identifiers(matches_by_engine, payload, path):
    """{value: entry} for matched values that are public client identifiers here."""
    if not isinstance(path, str) or not BROWSER_BUNDLE.search(path) or _SERVER_BUNDLE.search(path):
        return {}
    rules = {}
    for _, matches in matches_by_engine:
        for value, rule, _ in matches:
            rules.setdefault(value, set()).add(rule if isinstance(rule, str) else '')
    public = {}
    for value, names in rules.items():
        for entry in PUBLIC_CLIENT_IDENTIFIERS:
            if (entry['value'].fullmatch(value) and any(entry['rules'].search(name) for name in names)
                    and _every_use_assigned(payload, value, entry['assigned_to'])):
                public[value] = entry
                break
    return public

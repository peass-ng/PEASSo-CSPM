"""OCI descriptor `data`: content embedded in the descriptor itself.

The image spec allows an optional base64 `data` field and requires it to match
the descriptor's `size` and `digest` (official Debian manifests embed their
config this way). It is accepted only as exact, canonical base64 of those very
bytes; the content is still fetched and verified by digest as before.
"""
import base64
import binascii
import hashlib


def embedded_matches(item):
    data = item['data']
    if type(data) is not str or not data.isascii():
        return False
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return False
    return (base64.b64encode(raw).decode('ascii') == data and len(raw) == item['size']
            and 'sha256:' + hashlib.sha256(raw).hexdigest() == item['digest'])

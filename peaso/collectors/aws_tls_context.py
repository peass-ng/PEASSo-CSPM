"""Load the CA bundle into each botocore TLS context once, not per connection.

botocore sets ``ca_certs`` on its HTTPS connection pool before every request,
and urllib3 then calls ``SSLContext.load_verify_locations(ca_certs)`` on the
client's shared context for every new TLS connection. With OpenSSL 3 that
rewrites the shared X509 store while other threads are verifying server
certificate chains against it. Under the collector's concurrent reads this
showed up as sporadic ``SSLError`` handshake failures (reported as an unknown
inventory) and as a SIGSEGV inside ``X509_STORE_CTX_get1_issuer``.

``install()`` loads the same bundle into a context exactly once, before any
handshake can use it, and then lets each connection reuse the already loaded
store. Trust is unchanged: the bundle path is the one botocore selected
(certifi, ``AWS_CA_BUNDLE`` or a client ``verify`` path), certificate
verification stays ``CERT_REQUIRED`` and urllib3 still checks the hostname.
``verify=False`` and contexts that already carry another bundle keep the
original per-connection behaviour.
"""

from __future__ import annotations

import threading

_INSTALL_LOCK = threading.Lock()
_LOAD_LOCK = threading.Lock()
_MARK = "_peaso_loaded_ca_bundle"


def _context(pool):
    kwargs = getattr(pool, "conn_kw", None)
    return kwargs.get("ssl_context") if isinstance(kwargs, dict) else None


def load_once(context, path):
    """Load ``path`` into ``context`` once; True when it is that context's bundle."""
    if not isinstance(path, str) or not path or context is None:
        return False
    loaded = getattr(context, _MARK, None)
    if loaded is None:
        with _LOAD_LOCK:
            loaded = getattr(context, _MARK, None)
            if loaded is None:
                try:
                    context.load_verify_locations(path)
                    setattr(context, _MARK, path)
                except Exception:
                    # Keep urllib3's own per-connection load and its error.
                    return False
                loaded = path
    return loaded == path


def install():
    """Patch botocore's URLLib3Session once for this process (idempotent)."""
    try:
        from botocore import httpsession
    except Exception:
        return False
    with _INSTALL_LOCK:
        current = httpsession.URLLib3Session._setup_ssl_cert
        if getattr(current, "_peaso_tls_once", False):
            return True

        def _setup_ssl_cert(self, conn, url, verify):
            # Same decision as botocore: HTTPS with verification uses the
            # selected bundle. The pool never carries the path, so no new
            # connection reloads it into the shared context.
            if isinstance(url, str) and url.lower().startswith("https") and verify \
                    and not getattr(conn, "ca_cert_dir", None) and not getattr(conn, "ca_cert_data", None):
                path = httpsession.get_cert_path(verify)
                if load_once(_context(conn), path):
                    conn.cert_reqs = "CERT_REQUIRED"
                    conn.ca_certs = None
                    return
            current(self, conn, url, verify)

        _setup_ssl_cert._peaso_tls_once = True
        _setup_ssl_cert._peaso_original = current
        httpsession.URLLib3Session._setup_ssl_cert = _setup_ssl_cert
        return True

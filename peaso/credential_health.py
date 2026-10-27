"""Recognize connector credentials that the provider rejected outright.

A scan whose connector credential is invalid, revoked or expired reads
nothing from the provider. Such a scan must fail with a clear error code
instead of publishing an assessment made only of DENIED/UNKNOWN rows.
"""

# Provider error codes that name an authentication (not authorization) failure.
GCP_CODES = frozenset({"credential_refresh_failed", "credential_initialization_failed",
                       "gcloud_auth_failed", "explicit_token_required"})
AWS_CODES = frozenset({"InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch",
                       "InvalidAccessKeyId", "AuthFailure", "IncompleteSignature",
                       "MissingAuthenticationToken", "InvalidSignatureException", "NoCredentialsError",
                       "InvalidToken"})
AZURE_CODES = frozenset({"audience_token_unavailable", "CredentialUnavailableError", "InvalidAuthenticationToken",
                         "AuthenticationFailed", "ExpiredAuthenticationToken", "InvalidAuthenticationTokenTenant"})
AUTH_KINDS = frozenset({"ClientAuthenticationError", "CredentialUnavailableError", "NoCredentialsError"})


def _errors(collection):
    error = collection.get("error")
    if not isinstance(error, dict):
        return []
    extra = [item for item in error.get("additional_errors", ()) if isinstance(item, dict)]
    return [error, *extra]


def authentication_failure(error, provider):
    """True when one recorded collection error says the credential itself was refused."""
    code, kind, status = error.get("code"), error.get("kind"), error.get("http_status")
    if status in (401, "401") or code in ("401", 401) or kind in AUTH_KINDS:
        return True
    codes = {"gcp": GCP_CODES, "aws": AWS_CODES, "azure": AZURE_CODES, "k8s": AZURE_CODES}.get(provider, frozenset())
    return code in codes


def provider_read(collection):
    """True when a collection holds evidence returned by the provider itself.

    Derived envelopes built only from local inputs (every source request is
    ``local:``) and partial envelopes without items do not show that the
    connector credentials could read anything.
    """
    status = collection.get("status")
    if status not in ("collected", "empty", "partial"):
        return False
    requests = collection.get("source_requests")
    if (isinstance(requests, list) and requests
            and all(isinstance(r, str) and r.startswith("local:") for r in requests)):
        return False
    return not (status == "partial" and not collection.get("items"))


def nothing_readable(snapshot):
    """True when no collection holds data the provider returned to these credentials."""
    return not any(provider_read(c) for c in snapshot.get("collections", ()))


def credentials_rejected(snapshot):
    """Nothing came back from the provider and at least one read names a credential failure."""
    if not nothing_readable(snapshot):
        return False
    provider = snapshot.get("provider")
    return any(authentication_failure(error, provider)
               for collection in snapshot.get("collections", ())
               for error in _errors(collection))

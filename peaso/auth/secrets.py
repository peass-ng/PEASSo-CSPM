"""Credential encryption and recursive evidence sanitization."""
import json
import os
from pathlib import Path
import re
import uuid
from cryptography.fernet import Fernet

SENSITIVE = re.compile(r"(?i)^(?:.*password|.*passwd|.*clientsecret|.*secretaccesskey|.*secret|secretvalue|(?:access|refresh|id|session|aws.?session|bearer|oauth|api|subject|federated|vault|storage|databricksaccount)?token|authorization|privatekey|clientkey(?:data)?|apikey|keystring|(?:aws)?accesskeyid|credentials|credential|connectionstring|kubeconfig)$")


def private_file(path: Path, factory) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        return path.read_bytes()
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    value = factory()
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        try:
            os.link(temporary, path)
        except FileExistsError:
            value = path.read_bytes()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return value


class CredentialCipher:
    def __init__(self, identity_dir: Path):
        key = os.getenv("PEASO_ENCRYPTION_KEY")
        arn = os.getenv("PEASO_CREDENTIAL_SECRET_ARN")
        if arn:
            import boto3
            key = boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"].strip()
        if os.getenv("PEASO_STORAGE") == "dynamodb" and not key:
            raise ValueError("Hosted storage requires a configured credential encryption key")
        self.fernet = Fernet(key.encode() if key else private_file(identity_dir / "credentials.key", Fernet.generate_key))

    def encrypt(self, value: dict) -> str:
        return self.fernet.encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()

    def decrypt(self, value: str) -> dict:
        return json.loads(self.fernet.decrypt(value.encode()))


def secret_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from secret_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from secret_values(item)
    elif isinstance(value, str) and value:
        yield value


PUBLIC_AUTH_FIELDS = {"provider", "method", "profile", "context", "region_name", "role_arn", "external_id", "target_principal", "impersonate_service_account", "tenant_id", "client_id", "account", "quota_project", "server", "cluster_id", "in_cluster", "session_name", "role_session_name", "token_uri", "client_email", "type", "project_id", "private_key_id", "auth_uri", "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain", "name", "namespace", "current-context", "apiVersion", "kind"}


def _registry_private_fields(entry):
    """Separate routing identities in the exact explicit registry auth schema."""
    if type(entry) is not dict:
        return None
    method = entry.get('method')
    private = {'username', 'password'} if method == 'basic' else {'token'}
    if (method not in ('basic', 'bearer')
            or set(entry) != {'host', 'repository', 'method'} | private
            or any(type(value) is not str or not value for value in entry.values())
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}(?::[0-9]{1,5})?', entry['host'])
            or not re.fullmatch(r'[a-z0-9][a-z0-9._/-]{0,255}', entry['repository'])
            or any(part in {'', '.', '..'} for part in entry['repository'].split('/'))):
        return None  # Unknown documents retain the conservative extraction.
    return private


def credential_values(value, *, _seen=None, _depth=0, _registry_entry=False):
    """Extract credentials without treating provider/method/identity names as secrets."""
    if _seen is None:
        _seen = set()
    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in _seen:
            return
        if _depth > 64 or len(_seen) >= 20_000:
            raise ValueError('credential document structure exceeds limits')
        _seen.add(identity)
    if isinstance(value, dict):
        private = _registry_private_fields(value) if _registry_entry else None
        for key, item in value.items():
            if private is not None and key not in private:
                continue
            if key in PUBLIC_AUTH_FIELDS:
                continue
            if key == 'registry_auth' and type(item) is list:
                yield from credential_values(item, _seen=_seen, _depth=_depth + 1,
                                             _registry_entry=True)
                continue
            if isinstance(item, (dict, list)):
                yield from credential_values(item, _seen=_seen, _depth=_depth + 1)
            elif key in {"sa_json", "external_account_json", "kubeconfig_data"} and isinstance(item, str):
                try:
                    parsed = json.loads(item)
                except (ValueError, TypeError):
                    from .documents import credential_document
                    try:
                        parsed = credential_document(item)
                    except Exception:
                        parsed = None
                if parsed is not None:
                    # Keep the parsed document alive during traversal: object
                    # IDs in _seen must not be reused by another document.
                    yield from credential_values(parsed, _depth=_depth + 1)
            elif isinstance(item, str) and item:
                yield item
    elif isinstance(value, list):
        for item in value:
            yield from credential_values(item, _seen=_seen, _depth=_depth + 1,
                                         _registry_entry=_registry_entry)
    elif isinstance(value, str) and value:
        yield value


_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----")
_FIELD_LABEL = re.compile(r"[^a-zA-Z0-9]")
MAX_PREFILTER_VALUES = 2048
MAX_PREFILTER_CHARS = 128 * 1024
MAX_PREFILTER_TEXT = 64 * 1024


def _literal_matcher(values):
    # re.compile caches patterns process-wide. A pattern containing credentials
    # must remain owned by this call instead. CPython's compiler avoids that
    # cache; other runtimes safely retain the ordered replacement path.
    compiler = getattr(getattr(re, '_compiler', None), 'compile', None)
    if compiler is None:
        return None
    try:
        return compiler('|'.join(re.escape(value) for value in values), 0)
    except (re.error, RecursionError, OverflowError):
        return None


class Redactor:
    """Document-local preparation, also reusable for its keys and aliases.

    A bounded literal matcher only rejects strings containing no long secret.
    Positive matches use the original ordered replacements, preserving overlap
    and replacement-marker cascades. Oversized plans/text use that same path.
    No secret or plaintext is retained outside this caller-owned instance.
    """
    def __init__(self, secrets=(), *, fields=True):
        # fields=False replaces only the given values. Scan publication uses
        # it for the scanner's own connector credentials: secrets found in the
        # customer's resources, including secret-named fields, stay visible.
        self.fields = fields
        self.ordered = sorted(set(secrets), key=len, reverse=True)
        self.short = frozenset(secret for secret in self.ordered if secret and len(secret) < 4)
        long = [secret for secret in self.ordered if len(secret) >= 4]
        self.has_long = bool(long)
        self.matcher = (_literal_matcher(long)
                        if long and len(long) <= MAX_PREFILTER_VALUES
                        and sum(map(len, long)) <= MAX_PREFILTER_CHARS else None)

    def __call__(self, value):
        if isinstance(value, dict) and not self.fields:
            return {str(key): self(child) for key, child in value.items()}
        if isinstance(value, dict):
            labels = [item for key, item in value.items() if str(key).lower() in {'key', 'name'} and isinstance(item, str)]
            paired_secret = any(SENSITIVE.fullmatch(_FIELD_LABEL.sub('', label)) for label in labels)
            return {str(key): '[REDACTED]' if (SENSITIVE.fullmatch(_FIELD_LABEL.sub('', str(key)))
                or (paired_secret and str(key).lower() in {'value', 'content', 'data'}))
                and isinstance(child, (str, dict, list)) else self(child) for key, child in value.items()}
        if isinstance(value, (list, tuple)):
            return [self(child) for child in value]
        if isinstance(value, str):
            if self.fields:
                value = _PRIVATE_KEY.sub('[REDACTED PRIVATE KEY]', value)
            if not self.has_long or (self.matcher is not None and len(value) <= MAX_PREFILTER_TEXT
                                     and self.matcher.search(value) is None):
                return '[REDACTED]' if value in self.short else value
            for secret in self.ordered:
                if secret and (len(secret) >= 4 or value == secret):
                    value = value.replace(secret, '[REDACTED]')
            return value
        return value


def redact(value, secrets=(), *, fields=True):
    """Replace known credential values everywhere; fields=True also drops secret-shaped fields."""
    return Redactor(secrets, fields=fields)(value)

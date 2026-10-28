"""Native, bounded GCP collection. No mutation or managed-secret payload access.

The injectable transport is intentionally below the collector so fixtures exercise
the same pagination, provenance, scope filtering and hydration as real API reads.
"""
from __future__ import annotations

import copy
import json
import math
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from itertools import count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlsplit

from . import gcp_dataproc_source_runtime_20261020 as dataproc_source_runtime
from . import gcp_workbench_source_runtime_20261020 as workbench_source_runtime
from . import gcp_dataflow_batch_source_runtime_20261020 as selected_job_source_runtime
from .gcp_fanout import POOL_PREFIX as LOCATION_POOL_PREFIX, fanout_pages, location_fanout

OAUTH_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
HOSTS = frozenset(f"{s}.googleapis.com" for s in (
    "cloudasset", "cloudresourcemanager", "compute", "storage", "iam", "logging",
    "sqladmin", "container", "cloudkms", "secretmanager", "recommender", "bigquery", "artifactregistry", "analyticshub",
    "run", "cloudfunctions", "cloudidentity", "appengine", "admin", "apikeys", "dataproc", "dns", "monitoring",
    "alloydb", "essentialcontacts", "accessapproval", "securitycenter", "serviceusage", "bigtableadmin", "cloudbilling",
    "networkmanagement", "networkconnectivity", "networksecurity", "networkservices", "datastream", "datamigration", "certificatemanager", "privateca", "orgpolicy", "pubsub", "policyanalyzer", "accesscontextmanager",
    "cloudbuild", "clouddeploy", "composer", "notebooks", "cloudscheduler", "domains", "sourcerepo", "osconfig", "integrations", "policytroubleshooter", "containeranalysis", "datacatalog", "metastore",
    # Groups Settings API (www.googleapis.com/groups/v1), read only with group_settings=true.
    "www", "workflows", "vpcaccess", "file", "redis", "netapp", "servicenetworking", "dataflow", "batch", "aiplatform", "managedkafka", "memorystore", "bigqueryconnection", "cloudprivatecatalogproducer", "krmapihosting", "firebasedatabase",
    "memcache", "looker", "lustre", "ids", "tpu", "backupdr", "vmwareengine", "datafusion", "dataplex", "apigee", "ml", "workstations", "baremetalsolution", "connectors", "contactcenterinsights", "agentidentity", "bigquerydatatransfer", "bigqueryreservation", "developerconnect", "discoveryengine", "iap", "identitytoolkit", "config"))


_ASSET_LIST_PATH = re.compile(r"/v1/(?:projects|folders|organizations)/[^/]+/assets")


def endpoint_page_size(url, method="GET"):
    """Documented per-request maximum for list endpoints read in bulk.

    Used only when the connector does not set page_size. Unknown endpoints
    keep the historical default; items and per-page checks are unchanged."""
    parsed = urlsplit(url)
    host, path = parsed.hostname or "", parsed.path
    if host == "cloudasset.googleapis.com":
        if path.endswith((":searchAllResources", ":searchAllIamPolicies")):
            return 500
        if method == "GET" and _ASSET_LIST_PATH.fullmatch(path):
            return 1000
        return None
    if host == "compute.googleapis.com":
        return 500
    if host == "storage.googleapis.com":
        return 1000
    return None


def _scoped_privesc_read(method, parsed, scope, params, body):
    """Admit only the four documented project-bound inventory API routes."""
    if not isinstance(scope, str) or not re.fullmatch(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]", scope):
        return False
    if not isinstance(params, (dict, type(None))):
        return False
    path = parsed.path
    parent = re.escape(scope)
    segment = r"[A-Za-z0-9_.-]+"
    location = r"[a-z0-9-]+"
    patterns = {
        "biglake.googleapis.com": (
            rf"/iceberg/v1/restcatalog/extensions/{parent}/catalogs",
            rf"/iceberg/v1/restcatalog/v1/{parent}/catalogs/{segment}/namespaces",
            rf"/iceberg/v1/restcatalog/v1/{parent}/catalogs/{segment}/namespaces/{segment}/tables",
            rf"/v1/{parent}/catalogs/{segment}(?:/namespaces/{segment}(?:/tables/{segment})?)?:getIamPolicy",
        ),
        "cloudtasks.googleapis.com": (
            rf"/v2/{parent}/locations",
            rf"/v2/{parent}/locations/{location}/queues",
        ),
        "dataform.googleapis.com": (
            rf"/v1/{parent}/locations",
            rf"/v1/{parent}/locations/{location}/config",
            rf"/v1/{parent}/locations/{location}/repositories",
            rf"/v1/{parent}/locations/{location}/repositories/{segment}:getIamPolicy",
        ),
        "firebaseapphosting.googleapis.com": (
            rf"/v1/{parent}/locations",
            rf"/v1/{parent}/locations/{location}/backends",
        ),
    }
    host = parsed.hostname
    if (host == "cloudtasks.googleapis.com" and method == "POST" and
            re.fullmatch(rf"/v2/{parent}/locations/{location}/queues/{segment}:getIamPolicy", path)):
        return not params and body == {"options": {"requestedPolicyVersion": 3}}
    if method != "GET" or body is not None or host not in patterns:
        return False
    allowed_params = {
        "biglake.googleapis.com": {"view", "page-size", "page-token", "pageSize", "pageToken",
                                    "options.requestedPolicyVersion"},
        "cloudtasks.googleapis.com": {"pageSize", "pageToken"},
        "dataform.googleapis.com": {"pageSize", "pageToken"},
        "firebaseapphosting.googleapis.com": {"pageSize", "pageToken"},
    }
    return (set(params or ()).issubset(allowed_params[host]) and
            any(re.fullmatch(pattern, path) for pattern in patterns[host]))
SAFE_REASONS = frozenset(("SERVICE_DISABLED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "IAM_PERMISSION_DENIED",
    "PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND", "RESOURCE_EXHAUSTED", "INVALID_ARGUMENT",
    "BILLING_DISABLED", "USER_PROJECT_DENIED", "QUOTA_EXCEEDED", "RATE_LIMIT_EXCEEDED", "UNAVAILABLE",
    "LOCATION_POLICY_VIOLATED"))
# BigQuery anonymous (cached query result) datasets: owner-only, ~24h lifetime.
ANONYMOUS_DATASET = re.compile(r"_[0-9a-f]{40}")
SENSITIVE_KEYS = frozenset(("privatekey", "privatekeydata", "publickeydata", "accesstoken", "refreshtoken",
    "idtoken", "clientsecret", "password", "certificate", "clientcertificate", "clientkey", "token",
    "authorization", "secretvalue", "payload", "startupscript", "sshkeys", "userdata", "connectionstring",
    "cert", "servercacert", "sharedsecret", "sharedsecrethash", "environmentvariables",
    "secretenvironmentvariables", "args", "command", "subjecttoken", "apikey", "keystring",
    "authtoken", "oauthtoken", "secretaccesskey", "sessiontoken", "credentials", "authcredentials", "rawkey", "rsawrappedkey"))
TOKEN_CONFIG_KEYS = frozenset(("oidctoken", "oauthtoken"))


def sanitize(value):
    """Keep configuration evidence while dropping credentials, scripts and values."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            # Token *configuration* objects (Pub/Sub push, Scheduler/Tasks HTTP
            # targets) name the identity a Google agent mints tokens for; they
            # never contain a token. Only the identity/audience/scope survive.
            if normalized in TOKEN_CONFIG_KEYS and isinstance(item, dict):
                output[key] = {k: item[k] for k in ("serviceAccountEmail", "audience", "scope")
                               if isinstance(item.get(k), str)}
                continue
            # Inline environment maps keep variable NAMES only (values dropped);
            # secret-backed variables keep their Secret Manager reference.
            if normalized == "environmentvariables" and isinstance(item, (dict, list)):
                names = item if isinstance(item, dict) else [x.get("name") for x in item if isinstance(x, dict)]
                output["environmentVariableNames"] = sorted(str(name) for name in names if isinstance(name, str))
                continue
            if normalized == "secretenvironmentvariables" and isinstance(item, list):
                output[key] = [{k: x[k] for k in ("key", "projectId", "secret", "version") if isinstance(x.get(k), str)}
                               for x in item if isinstance(x, dict)]
                continue
            if normalized in SENSITIVE_KEYS or normalized.endswith(("password", "token", "privatekey", "clientsecret", "secretvalue")):
                continue
            if key == "env" and isinstance(item, list):
                output[key] = []
                for entry in item:
                    if not isinstance(entry, dict):
                        output[key].append(None)  # Retain malformed entries as unavailable evidence.
                        continue
                    projected = {"name": entry.get("name")}
                    # Presence is sufficient to detect invalid literal/reference unions;
                    # the literal value itself never enters the snapshot.
                    if "value" in entry:
                        projected["_literal_value_present"] = True
                        projected["_literal_value_empty"] = entry["value"] == ""
                    elif "_literal_value_present" in entry:
                        for marker in ("_literal_value_present", "_literal_value_empty"):
                            if marker in entry:
                                projected[marker] = entry[marker] if type(entry[marker]) is bool else None
                    if "_coverage" in entry:
                        projected["_coverage"] = sanitize(entry["_coverage"])
                    for source, fields in (("valueSource", ("secret", "version")),
                                           ("valueFrom", ("name", "key"))):
                        if source not in entry:
                            continue
                        body = entry[source]
                        if not isinstance(body, dict):
                            projected[source] = None
                            continue
                        reference = {}
                        if "_coverage" in body:
                            reference["_coverage"] = sanitize(body["_coverage"])
                        if "secretKeyRef" in body:
                            selector = body["secretKeyRef"]
                            reference["secretKeyRef"] = ({field: (sanitize(selector[field])
                                if field == "_coverage" or isinstance(selector[field], str) else None)
                                for field in (*fields, "_coverage") if field in selector}
                                if isinstance(selector, dict) else None)
                        projected[source] = reference
                    output[key].append(projected)
                continue
            if key in ("metadata", "commonInstanceMetadata") and isinstance(item, dict) and isinstance(item.get("items"), list):
                output[key] = {**sanitize({k: v for k, v in item.items() if k != "items"}),
                    "items": [{"key": x.get("key"), **({"value": x.get("value")} if x.get("key") in
                        ("enable-oslogin", "enable-oslogin-2fa", "block-project-ssh-keys", "serial-port-enable", "disable-legacy-endpoints") else {})}
                        for x in item["items"] if isinstance(x, dict)]}
            else:
                output[key] = sanitize(item)
        return output
    if isinstance(value, list):
        return [sanitize(x) for x in value]
    if isinstance(value, str) and ("-----BEGIN " in value or re.search(r"(?i)\b(?:bearer|ya29\.)\s*\S+", value)):
        return "[redacted]"
    return value


class ReadError(Exception):
    def __init__(self, status="unavailable", code="read_failed", *, http_status=None, reason=None):
        super().__init__(code)
        self.status = status
        self.error = {"code": code}
        if http_status is not None:
            self.error["http_status"] = http_status
        if reason in SAFE_REASONS:
            self.error["reason"] = reason


def http_error(status, payload):
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    reason = next((x.get("reason") for x in error.get("details", []) if isinstance(x, dict)
        and x.get("reason") in SAFE_REASONS), None) if isinstance(error, dict) else None
    state = "denied" if status in (401, 403) else "unavailable"
    if reason in ("SERVICE_DISABLED", "BILLING_DISABLED"):
        state = "unavailable"
    if status in (405, 501):
        state = "unsupported"
    result = ReadError(state, "api_error", http_status=status, reason=reason)
    if reason == "SERVICE_DISABLED":
        # ErrorInfo.metadata names the consumer project whose service is off;
        # it can be the caller's quota project rather than the read target.
        info = next((x.get("metadata") for x in error.get("details", []) if isinstance(x, dict)
            and x.get("reason") == reason and isinstance(x.get("metadata"), dict)), {})
        for key in ("consumer", "service"):
            value = info.get(key)
            if isinstance(value, str) and re.fullmatch(r"projects/[a-z0-9-]{1,63}|[a-z0-9.-]{1,100}\.googleapis\.com", value):
                result.error[key] = value
    if status == 404:
        # google.rpc.ResourceInfo names the exact resource that does not exist,
        # distinguishing "no such child resource" from an unknown endpoint.
        name = next((x.get("resourceName") for x in error.get("details", []) if isinstance(x, dict)
            and str(x.get("@type", "")).endswith("google.rpc.ResourceInfo")), None) if isinstance(error, dict) else None
        if isinstance(name, str) and re.fullmatch(r"projects/[a-z0-9-]{1,63}/locations/global/applications/[a-z0-9-]{1,63}", name):
            result.error["resource"] = name
    return result


def bound(options, name, default, low, high):
    value = options.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")
    return value


def optional_bound(options, name, low, high):
    return None if options.get(name) is None else bound(options, name, None, low, high)


def _gcloud(command, env):
    try:
        result = subprocess.run(["gcloud", *command], env=env, capture_output=True, text=True,
                                check=True, timeout=30)
    except Exception:
        raise ReadError("denied", "gcloud_auth_failed") from None
    value = result.stdout.strip()
    if not value or value == "(unset)":
        raise ReadError("denied", "gcloud_identity_missing")
    return value


def validate_external_config(info, *, inline=False):
    """Validate credential destinations before handing config to google-auth."""
    if not isinstance(info, dict) or info.get("type") != "external_account":
        raise ReadError("denied", "external_account_config_required")
    if info.get("token_url") != "https://sts.googleapis.com/v1/token":
        raise ReadError("denied", "unsafe_external_token_endpoint")
    if info.get("token_info_url") not in (None, "https://sts.googleapis.com/v1/introspect"):
        raise ReadError("denied", "unsafe_external_token_endpoint")
    impersonation_url = info.get("service_account_impersonation_url")
    if impersonation_url is not None and (not isinstance(impersonation_url, str) or not re.fullmatch(
        r"https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/[A-Za-z0-9@._%+-]+:generateAccessToken",
        impersonation_url)):
        raise ReadError("denied", "unsafe_external_impersonation_endpoint")
    source = info.get("credential_source", {})
    if not isinstance(source, dict) or "executable" in source:
        raise ReadError("unsupported", "external_executable_source_prohibited")
    if inline:
        # The inline supplier replaces the config's source, so it cannot execute
        # a plugin, read a server file, or make source-directed network requests.
        return
    if source.get("environment_id") == "aws1":
        expected = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "imdsv2_session_token_url": "http://169.254.169.254/latest/api/token"}
        for key, value in expected.items():
            if key in source and (not isinstance(source[key], str) or source[key].rstrip("/") != value):
                raise ReadError("denied", "unsafe_external_credential_source")
        verification = source.get("regional_cred_verification_url", "")
        if not isinstance(verification, str) or not re.fullmatch(r"https://sts\.\{region\}\.amazonaws\.com(?:\.cn)?/\?Action=GetCallerIdentity&Version=2011-06-15", verification):
            raise ReadError("denied", "unsafe_external_credential_source")
    elif source.get("url") or not isinstance(source.get("file"), str):
        raise ReadError("unsupported", "external_source_requires_local_file_or_inline_token")


class GcloudCredentials:
    """Pin account AND impersonation before the first token is requested."""
    def __init__(self, auth):
        self.env = dict(os.environ)
        self.account = auth.get("account") or _gcloud(["config", "get-value", "account"], self.env)
        target = auth.get("target_principal") or auth.get("impersonate_service_account")
        if target is None:
            try:
                target = _gcloud(["config", "get-value", "auth/impersonate_service_account"], self.env)
            except ReadError as exc:
                if exc.error["code"] != "gcloud_identity_missing":
                    raise
                target = ""
        delegates = auth.get("delegates", [])
        if delegates:
            raise ReadError("unsupported", "gcloud_delegates_require_impersonation_method")
        self.env["CLOUDSDK_CORE_ACCOUNT"] = self.account
        self.env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] = target or ""
        self.command = ["auth", "print-access-token", "--account", self.account, "--quiet"]
        if target:
            self.command += ["--impersonate-service-account", target]
        self.token = None
        self.expires = 0.0

    def headers(self):
        if time.monotonic() >= self.expires:
            self.token = _gcloud(self.command, self.env)
            self.expires = time.monotonic() + 240
        return {"Authorization": "Bearer " + self.token}


def selected_auth_method(auth):
    if "token" in auth:
        return "token"
    if "method" in auth:
        method = auth["method"]
    elif any(key in auth for key in ("service_account_file", "sa_json")):
        method = "service-account"
    elif any(key in auth for key in ("external_account_file", "credential_file", "external_account_json")):
        method = "external-account"
    else:
        method = "adc"
    if not isinstance(method, str):
        return "unsupported"
    method = {"auto": "adc", "gcloud-cli": "gcloud", "service_account": "service-account",
              "platform-service-account": "service-account",
              "external_account": "external-account", "wif": "external-account", "impersonate": "impersonation"}.get(method, method)
    return method if method in ("adc", "gcloud", "service-account", "external-account", "metadata", "impersonation") else "unsupported"


class Credentials:
    def __init__(self, auth, *, timeout=20, gke_content=False):
        self.lock = threading.Lock()
        self.oauth_scopes = list(OAUTH_SCOPES) + (["https://www.googleapis.com/auth/userinfo.email"] if gke_content is True else [])
        self.failure = None
        self.timeout = timeout
        self.method = selected_auth_method(auth)
        self.direct_token = auth.get("token")
        self.credential = None
        self.gcloud = None
        self.session = None
        try:
            if "token" in auth:
                if not isinstance(self.direct_token, str) or not self.direct_token.strip():
                    raise ReadError("denied", "explicit_token_required")
                return
            if self.method == "gcloud":
                self.gcloud = GcloudCredentials(auth)
                return
            import google.auth
            import requests
            from google.auth.transport.requests import Request
            self.session = requests.Session()
            self.request = Request(session=self.session)
            if self.method == "adc":
                self.credential, _ = google.auth.default(scopes=self.oauth_scopes, quota_project_id=auth.get("quota_project"))
            elif self.method == "service-account":
                from google.oauth2.service_account import Credentials as SACredentials
                if isinstance(auth.get("sa_json"), dict):
                    self.credential = SACredentials.from_service_account_info(auth["sa_json"], scopes=self.oauth_scopes)
                elif auth.get("sa_json", "").lstrip().startswith("{"):
                    self.credential = SACredentials.from_service_account_info(json.loads(auth["sa_json"]), scopes=self.oauth_scopes)
                else:
                    self.credential = SACredentials.from_service_account_file(auth.get("service_account_file")
                        or auth.get("sa_json"), scopes=self.oauth_scopes)
            elif self.method == "external-account":
                inline = auth.get("external_account_json")
                if inline is not None:
                    from google.auth import identity_pool
                    info = json.loads(inline) if isinstance(inline, str) else copy.deepcopy(inline)
                    validate_external_config(info, inline=True)
                    subject_token = auth.get("subject_token")
                    if not isinstance(subject_token, str) or not subject_token:
                        raise ReadError("denied", "inline_subject_token_required")
                    class Supplier(identity_pool.SubjectTokenSupplier):
                        def get_subject_token(self, context, request):
                            return subject_token
                    info.pop("credential_source", None)
                    # google-auth 2.45 reads this from info and overwrites the
                    # constructor kwarg; newer versions preserve either form.
                    # Replace any input value with our non-executable supplier.
                    info["subject_token_supplier"] = Supplier()
                    # Older external_account.from_info also forwards quota from
                    # info explicitly, so a duplicate kwarg raises TypeError.
                    info["quota_project_id"] = auth.get("quota_project", info.get("quota_project_id"))
                    self.credential = identity_pool.Credentials.from_info(info, scopes=self.oauth_scopes)
                else:
                    path = auth.get("external_account_file") or auth.get("credential_file")
                    with open(path, encoding="utf-8") as stream:
                        info = json.load(stream)
                    validate_external_config(info)
                    # Load the already-validated document to avoid a file-change
                    # race replacing safe config with an executable/url source.
                    self.credential, _ = google.auth.load_credentials_from_dict(info, scopes=self.oauth_scopes,
                        quota_project_id=auth.get("quota_project"))
            elif self.method == "metadata":
                from google.auth.compute_engine import Credentials as MetadataCredentials
                self.credential = MetadataCredentials(scopes=self.oauth_scopes,
                    service_account_email=auth.get("service_account_email", "default"))
            elif self.method == "impersonation":
                from google.auth import impersonated_credentials
                source = auth.get("source_auth")
                if not isinstance(source, dict) or source.get("method") in ("impersonation", "impersonate"):
                    raise ReadError("denied", "explicit_impersonation_source_required")
                source_credentials = Credentials(source, timeout=timeout)
                if source_credentials.gcloud is not None:
                    from google.oauth2.credentials import Credentials as UserCredentials
                    def refresh_handler(request, scopes=None):
                        headers = source_credentials.headers()
                        return headers["Authorization"].removeprefix("Bearer "), (
                            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=240))
                    source_credentials.credential = UserCredentials(token=None, scopes=self.oauth_scopes,
                        refresh_handler=refresh_handler)
                if source_credentials.credential is None:
                    source_credentials.close()
                    raise ReadError("unsupported", "impersonation_source_must_use_google_auth")
                self.source = source_credentials
                target = auth.get("target_principal") or auth.get("impersonate_service_account")
                if not target:
                    raise ReadError("denied", "impersonation_target_required")
                self.credential = impersonated_credentials.Credentials(source_credentials=source_credentials.credential,
                    target_principal=target, target_scopes=self.oauth_scopes, delegates=auth.get("delegates", []),
                    lifetime=bound(auth, "lifetime", 900, 300, 3600), quota_project_id=auth.get("quota_project"))
            else:
                raise ReadError("unsupported", "unsupported_auth_method")
        except ReadError:
            self.close()
            raise
        except Exception:
            self.close()
            raise ReadError("denied", "credential_initialization_failed") from None

    def headers(self):
        with self.lock:
            if self.failure is not None:
                raise self.failure
            try:
                if self.direct_token:
                    return {"Authorization": "Bearer " + self.direct_token}
                if self.gcloud:
                    return self.gcloud.headers()
                headers = {}
                def request(*args, **kwargs):
                    kwargs["timeout"] = min(kwargs.get("timeout", self.timeout), self.timeout)
                    return self.request(*args, **kwargs)
                self.credential.before_request(request, "GET", "https://cloudasset.googleapis.com/", headers)
                authorization_keys = [key for key in headers
                                      if isinstance(key, str) and key.lower() == "authorization"]
                if authorization_keys:
                    authorization = headers[authorization_keys[0]]
                    if any(headers[key] != authorization for key in authorization_keys[1:]):
                        raise ValueError("conflicting authorization headers")
                    for key in authorization_keys:
                        del headers[key]
                    headers["Authorization"] = authorization
                return headers
            except ReadError as exc:
                self.failure = exc
                raise
            except Exception:
                self.failure = ReadError("denied", "credential_refresh_failed")
                raise self.failure from None

    def close(self):
        if self.session:
            self.session.close()
        if getattr(self, "source", None):
            self.source.close()


def _preserve_native_headers(request):
    """Requests must not replace the chosen bearer identity with ambient netrc."""
    return request


def native_header_session(transport):
    session = transport._session()
    session.auth = _preserve_native_headers
    return session


def _unique_data_identity_pairs(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise ReadError("malformed", "duplicate_project_identity_field")
        value[key] = member
    return value


def _response_size(response):
    content = getattr(response, "content", None)
    return len(content) if isinstance(content, (bytes, bytearray, str)) else 0


def _settle_cache_entry(cache, key, entry, response_bytes):
    """Keep a settled read for this scan unless its outcome is transient."""
    from .scan_cache import gcp_error_is_transient, ERROR_ENTRY_BYTES, PARSED_OBJECT_FACTOR
    if "error" in entry:
        if gcp_error_is_transient(entry["error"]):
            # Waiters on this flight share the error; later callers read again.
            if hasattr(cache, "discard"):
                cache.discard(key, entry)
            elif cache.get(key) is entry:
                del cache[key]
            return
        size = ERROR_ENTRY_BYTES
    else:
        # Parsed JSON costs several times its wire size in Python objects.
        size = max(response_bytes * PARSED_OBJECT_FACTOR, ERROR_ENTRY_BYTES)
    if hasattr(cache, "admit"):
        cache.admit(key, entry, size)


class Transport:
    def __init__(self, credentials, options, *, sleep=time.sleep):
        self.credentials, self.options, self.sleep = credentials, options, sleep
        import uuid
        self.ai_context_id = uuid.uuid4().hex
        self.max_calls = optional_bound(options, "max_calls", 1, 100000)
        self.retries = bound(options, "retries", 4, 0, 8)
        self.timeout = bound(options, "timeout", 20, 1, 120)
        self.calls = 0
        self.lock = threading.Lock()
        self.local = threading.local()
        self.sessions = []
        self.evidence = []
        from .scan_cache import BoundedEntries, budget, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRY_BYTES
        # Per-scan single-flight response cache, bounded by settled bytes.
        self.cache = BoundedEntries(budget(options, "response_cache_max_bytes", DEFAULT_MAX_BYTES),
                                    budget(options, "response_cache_max_entry_bytes", DEFAULT_MAX_ENTRY_BYTES), owner=self)
        self.run_sbom_metadata_reads = {}
        self.datafusion_cdap_reads = {}
        self.notebook_airflow_secret_budget = None
        self.started = time.monotonic()
        self.deadline_seconds = optional_bound(options, "deadline_seconds", 1, 86400)
        if self.deadline_seconds is None:
            self.deadline_seconds = optional_bound(options, "collection_deadline_seconds", 1, 86400)
        self.deadline = options.get("deadline")
        if self.deadline is not None and (isinstance(self.deadline, bool) or not isinstance(self.deadline, (int, float))):
            raise ValueError("deadline must be an absolute epoch timestamp")

    def check_cancelled(self):
        event = self.options.get("cancel_event")
        if event is not None and event.is_set():
            raise ReadError("unavailable", "cancelled")
        callback = self.options.get("_cancel_check")
        if callable(callback) and callback():
            raise ReadError("unavailable", "cancelled")
        if self.deadline is not None and time.time() >= self.deadline:
            raise ReadError("unavailable", "execution_deadline")
        if self.deadline_seconds is not None and time.monotonic() - self.started >= self.deadline_seconds:
            raise ReadError("unavailable", "execution_deadline")

    def _session(self):
        if not getattr(self.local, "session", None):
            import requests
            self.local.session = requests.Session()
            self.local.session.auth = _preserve_native_headers
            with self.lock:
                self.sessions.append(self.local.session)
        return self.local.session

    def request(self, method, url, *, params=None, body=None, scope=None, operation=None):
        from . import gcp_additional_literal_secret_indicators as extra
        if operation and operation.startswith(extra.OPERATION):
            return extra.read_projected(self, method, url, params=params, body=body, scope=scope, kind=operation[len(extra.OPERATION):])
        if extra.should_intercept(self, method, url, scope):
            return extra.read_projected(self, method, url, params=params, body=body, scope=scope, kind=extra.SCHEDULER)
        if operation == 'application-log-secret-sample':
            from .gcp_log_secret_indicators import read_page
            return read_page(self, method, url, params=params, body=body, scope=scope)
        self.check_cancelled()
        parsed = urlsplit(url)
        # Exact metadata endpoints registered after native service/traffic joins.
        regional_metadata = (method == "GET" and body is None and
            self.run_sbom_metadata_reads.get(url) == (scope, params) and
            re.fullmatch(r"[a-z0-9-]+-run\.googleapis\.com", parsed.hostname or "") and
            re.fullmatch(r"/apis/serving\.knative\.dev/v1/namespaces/[a-z0-9-]+/(?:services|revisions)/[a-z][a-z0-9-]*", parsed.path))
        cdap_read = (method == "GET" and body is None and
            self.datafusion_cdap_reads.get(url) == (scope, params) and
            re.fullmatch(r"[a-z0-9-]+-dot-[a-z0-9-]+\.datafusion\.googleusercontent\.com", parsed.hostname or "") and
            re.fullmatch(r"/api/v3/namespaces(?:/[A-Za-z0-9_-]+(?:/(?:apps|artifacts|profiles)(?:/[A-Za-z0-9_.-]+)?)?)?", parsed.path)
            or (method == "GET" and body is None and
                self.datafusion_cdap_reads.get(url) == (scope, params) and
                re.fullmatch(r"[a-z0-9-]+-dot-[a-z0-9-]+\.datafusion\.googleusercontent\.com", parsed.hostname or "") and
                (re.fullmatch(r"/api/v3/namespaces/[A-Za-z0-9_-]+/apps/[A-Za-z0-9_.-]+(?:/schedules|/workflows/DataPipelineWorkflow/preferences)", parsed.path)
                 or re.fullmatch(r"/api/v3/namespaces/[A-Za-z0-9_-]+/preferences", parsed.path)
                 or re.fullmatch(r"/api/v3/namespaces/[A-Za-z0-9_-]+/artifacts/[A-Za-z0-9_.-]+/versions/[A-Za-z0-9_.-]+/extensions(?:/[a-z]+)?", parsed.path))))
        privesc_read = _scoped_privesc_read(method, parsed, scope, params, body)
        if parsed.scheme != "https" or (parsed.hostname not in HOSTS and not regional_metadata and not cdap_read and not privesc_read) or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query:
            raise ReadError("unsupported", "unsafe_api_endpoint")
        # POST is used by a few provider read methods. Bind each action to
        # its documented service and resource path before credentials are read.
        read_post = method == "POST" and (
            privesc_read
            or
            (parsed.hostname == "cloudresourcemanager.googleapis.com" and (
                re.fullmatch(r"/v3/(?:projects|folders|organizations)/[^/%:]+:getIamPolicy", parsed.path)
                or re.fullmatch(r"/v1/projects/[^/%:]+:getAncestry", parsed.path)))
            or (parsed.hostname == "bigtableadmin.googleapis.com" and
                re.fullmatch(r"/v2/projects/[^/%:]+/instances/[^/%:]+:getIamPolicy", parsed.path))
            or (parsed.hostname == "dataproc.googleapis.com" and
                re.fullmatch(r"/v1/projects/[^/%:]+/regions/[a-z0-9-]+/clusters/[^/%:]+:getIamPolicy", parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "bigquery.googleapis.com" and
                re.fullmatch(r"/bigquery/v2/projects/[^/%:]+/datasets/[^/%:]+/tables/[^/%:]+:getIamPolicy", parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "bigquery.googleapis.com" and
                re.fullmatch(r"/bigquery/v2/projects/[^/%:]+/datasets/[^/%:]+/tables/[^/%:]+/rowAccessPolicies/[^/%:]+:getIamPolicy", parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "bigqueryconnection.googleapis.com" and
                re.fullmatch(r"/v1/projects/[^/%:]+/locations/[^/%:]+/connections/[^/%:]+:getIamPolicy", parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "bigquery.googleapis.com" and
                re.fullmatch(r"/bigquery/v2/projects/[a-z][a-z0-9-]{4,61}[a-z0-9]/queries", parsed.path)
                and isinstance(body, dict) and set(body) == {"query", "useLegacySql", "location", "maxResults", "timeoutMs"}
                and body.get("useLegacySql") is False and body.get("maxResults") == 2
                and body.get("timeoutMs") == 10000
                and isinstance(body.get("location"), str)
                and re.fullmatch(r"[A-Za-z0-9-]+", body["location"])
                and body.get("query") == (
                    "SELECT COALESCE((SELECT option_value FROM `region-" + body["location"].lower()
                    + "`.INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS "
                    "WHERE option_name = 'enable_fine_grained_dataset_acls_option' LIMIT 1), 'false') AS option_value"))
            or (parsed.hostname == "iam.googleapis.com" and
                re.fullmatch(r"/v1/projects/[^/%:]+/serviceAccounts/[^/%:]+:getIamPolicy", parsed.path))
            or (parsed.hostname == "analyticshub.googleapis.com" and
                re.fullmatch(r"/v1/projects/[^/%:]+/locations/[^/%:]+/dataExchanges/[^/%:]+(?:/listings/[^/%:]+)?:getIamPolicy", parsed.path))
            or (parsed.hostname == "iap.googleapis.com" and
                re.fullmatch(r"/v1/projects/[A-Za-z0-9_-]+/iap_tunnel(?:/zones/[a-z][a-z0-9-]*[0-9]-[a-z]"
                             r"(?:/instances/[A-Za-z0-9_-]+)?)?:getIamPolicy", parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "identitytoolkit.googleapis.com" and
                re.fullmatch(r"/admin/v2/projects/[A-Za-z0-9_-]+/tenants/[A-Za-z0-9_-]+:getIamPolicy",
                             parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "logging.googleapis.com" and
                re.fullmatch(r"/v2/(?:projects|folders|organizations|billingAccounts)/[A-Za-z0-9_-]+/"
                             r"locations/[a-z0-9-]+/buckets/[A-Za-z0-9_.-]+/views/[A-Za-z0-9_-]+:getIamPolicy",
                             parsed.path)
                and isinstance(body, dict) and body == {"options": {"requestedPolicyVersion": 3}})
            or (parsed.hostname == "logging.googleapis.com" and parsed.path == "/v2/entries:list")
            or (parsed.hostname == "policytroubleshooter.googleapis.com" and
                parsed.path == "/v3beta/iam:troubleshoot"))
        if method != "GET" and not read_post:
            raise ReadError("unsupported", "cloud_mutation_prohibited")
        app_version_get = (method == "GET" and parsed.hostname == "appengine.googleapis.com" and
            re.fullmatch(r"/v1/apps/[a-z0-9-]+/services/[a-z0-9-]+/versions/[a-z0-9-]+", parsed.path) and
            params == {"view": "FULL_VIEW", "fields": "name,serviceAccount,runtime,env,servingStatus"})
        if re.search(r"/versions/[^/]+(?::access|$)|/oauthClients/|/keys/[^/]+$", parsed.path) and not app_version_get:
            raise ReadError("unsupported", "sensitive_value_read_prohibited")
        # requests sends the same URL for absent and empty params.
        cache_key = json.dumps([method, url, params or {}, body], sort_keys=True)
        from . import gcp_prefetch
        gcp_prefetch.before_read(self, cache_key, method, url, params, body, scope, operation)
        # Coalesce identical requests, including simultaneous hydration calls.
        with self.lock:
            cached = self.cache.get(cache_key)
            if cached is not None and hasattr(self.cache, "touch"):
                self.cache.touch(cache_key)
            if cached is None:
                cached = {"event": threading.Event()}
                self.cache[cache_key] = cached
                owner = True
            else:
                owner = False
        if not owner:
            if (self.options.get("cancel_event") is not None or
                    callable(self.options.get("_cancel_check")) or
                    self.deadline is not None or self.deadline_seconds is not None):
                # Only the owner may complete the cache entry. A follower can
                # leave independently while the owner's HTTP call is blocked.
                while True:
                    self.check_cancelled()
                    wait = 0.1
                    if self.deadline is not None:
                        wait = min(wait, max(0, self.deadline - time.time()))
                    if self.deadline_seconds is not None:
                        wait = min(wait, max(0, self.deadline_seconds - (time.monotonic() - self.started)))
                    if cached["event"].wait(wait):
                        self.check_cancelled()
                        break
            else:
                cached["event"].wait()
            if "error" in cached:
                raise cached["error"]
            return copy.deepcopy(cached["data"]), cached["id"]
        safe_params = {k: v for k, v in (params or {}).items() if k != "pageToken"}
        evidence = {"id": None, "scope": scope, "method": method, "url": url,
            "operation": operation or parsed.path, "query": sanitize(safe_params), "attempts": 0,
            "http_attempts": 0, "started_at": datetime.now(timezone.utc).isoformat()}
        if body:
            evidence["request"] = sanitize({k: v for k, v in body.items() if k != "pageToken"})
        response_bytes = 0
        try:
            for attempt in range(self.retries + 1):
                self.check_cancelled()
                with self.lock:
                    if self.max_calls is not None and self.calls >= self.max_calls:
                        raise ReadError("unavailable", "call_limit")
                    self.calls += 1
                evidence["attempts"] += 1
                headers = self.credentials.headers()
                from peaso.ai.access import bearer as capture_ai_bearer
                expiry = getattr(getattr(self.credentials, "credential", None), "expiry", None)
                capture_ai_bearer("gcp", "https://www.googleapis.com/",
                    (headers.get("Authorization") or headers.get("authorization") or "").removeprefix("Bearer "),
                    expires_at=expiry.timestamp() if expiry else None, context_id=self.ai_context_id,
                    target_scopes=[scope] if scope else [], quota_project=self.options.get("quota_project"))
                if self.options.get("quota_project"):
                    headers["X-Goog-User-Project"] = self.options["quota_project"]
                try:
                    evidence["http_attempts"] += 1
                    response = self._session().request(method, url, params=params, json=body, headers=headers,
                        timeout=self.timeout, allow_redirects=False)
                except Exception:
                    error = ReadError("unavailable", "network_error")
                    if attempt < self.retries:
                        self.sleep(min(4, 0.25 * 2 ** attempt))
                        continue
                    raise error from None
                evidence["http_status"] = response.status_code
                response_bytes = _response_size(response)
                try:
                    if (method == "GET" and parsed.hostname == "cloudresourcemanager.googleapis.com"
                            and re.fullmatch(r"/v3/projects/[A-Za-z0-9_-]+", parsed.path)):
                        # Canonical alias facts must survive a single cache read
                        # without silently choosing one duplicate JSON identity.
                        data = json.loads(response.content, object_pairs_hook=_unique_data_identity_pairs)
                    else:
                        data = response.json()
                    if extra.scheduler_endpoint(url):
                        data = extra.scheduler_metadata_response(data)
                except ReadError:
                    raise
                except Exception:
                    data = None
                if response.status_code >= 400 or 300 <= response.status_code < 400:
                    error = http_error(response.status_code, data)
                    throttled = response.status_code == 429 or error.error.get("reason") in (
                        "RATE_LIMIT_EXCEEDED", "RESOURCE_EXHAUSTED", "QUOTA_EXCEEDED")
                    if (throttled or response.status_code in (500, 502, 503, 504)) and attempt < self.retries:
                        delay = self.backoff(attempt, response, throttled)
                        # A provider minimum must never be shortened by jitter or
                        # a local wait cap. End incomplete if the next permitted
                        # attempt exceeds this scan's remaining wait budget.
                        if not math.isfinite(delay) or delay > 60:
                            raise ReadError("unavailable", "retry_after_exceeds_budget")
                        if ((self.deadline is not None and time.time() + delay >= self.deadline) or
                                (self.deadline_seconds is not None and
                                 time.monotonic() - self.started + delay >= self.deadline_seconds)):
                            raise ReadError("unavailable", "retry_wait_exceeds_deadline")
                        self.sleep(delay)
                        continue
                    raise error
                # Compute returns an empty 204 when the selected project has no
                # Shared VPC host. Keep this exact documented relationship read
                # distinct from a malformed 204 on any other API operation.
                if (response.status_code != 204 and isinstance(data, dict) and "_noXpnHost" in data):
                    # This marker is private transport state, never provider JSON.
                    raise ReadError("malformed", "malformed_response")
                if response.status_code == 204:
                    if (method == "GET" and parsed.hostname == "compute.googleapis.com"
                            and re.fullmatch(r"/compute/v1/projects/[^/]+/getXpnHost", parsed.path)
                            and not response.content):
                        data = {"_noXpnHost": True}
                    else:
                        raise ReadError("malformed", "malformed_response")
                if cdap_read and isinstance(data, list):
                    data = {"items": data}
                if not isinstance(data, dict):
                    raise ReadError("malformed", "malformed_response")
                if cdap_read:
                    from .gcp_datafusion_privesc import project_cdap_response
                    data = project_cdap_response(data, parsed.path)
                # Projection strips token-like fields from resource evidence.
                # Preserve only the original top-level pagination protocol,
                # including malformed values so pages() can reject them.
                has_native_cursor = 'nextPageToken' in data
                native_cursor = copy.deepcopy(data.get('nextPageToken'))
                from peaso.secret_evidence import native_environment_resources
                native_environment_resources(data, provider='gcp', scope=scope, method=method, url=url, body=body)
                if parsed.hostname in {"appengine.googleapis.com", "artifactregistry.googleapis.com",
                                       "integrations.googleapis.com", "www.googleapis.com"}:
                    from .gcp_facts_v4_holds import project_transport_response
                    data = project_transport_response(method, url, params, data)
                evidence["status"] = "collected"
                if parsed.hostname == "cloudfunctions.googleapis.com" and (
                        parsed.path.endswith('/functions') or re.fullmatch(r'/v2/projects/[^/]+/locations/[^/]+/functions/[A-Za-z0-9_-]+', parsed.path)):
                    from .gcp_function_source_secret_indicators import capture_response
                    data = capture_response(self, data, method=method, url=url, params=params, body=body, scope=scope)
                    from peaso.collectors.gcp_function_secret_pairs_20261020 import project_response
                    data = project_response(data, method=method, url=url, params=params, body=body,
                        scope=scope, enabled=(self.options.get('content_secret_scans') is True
                            and 'function' in self.options.get('_content_secret_scan_kinds', [])),
                        check_cancelled=self.check_cancelled)
                if parsed.hostname in ('compute.googleapis.com', 'run.googleapis.com', 'cloudbuild.googleapis.com'):
                    from peaso.collectors.gcp_configuration_secret_indicators import project_response
                    data = project_response(data, method=method, url=url, params=params, body=body,
                        scope=scope, enabled=self.options.get('content_secret_scans') is True,
                        selected_kinds=self.options.get('_content_secret_scan_kinds', []),
                        check_cancelled=self.check_cancelled)
                if method == 'GET' and parsed.hostname == 'dataproc.googleapis.com' and re.fullmatch(
                        r'/v1/projects/[^/%:]+/regions/[a-z0-9-]+/clusters', parsed.path):
                    from .gcp_job_literal_secret_indicators import cluster_metadata_response
                    data = cluster_metadata_response(data)
                notebook_airflow_endpoint = method == 'GET' and body is None and (
                    parsed.hostname == 'composer.googleapis.com' and re.fullmatch(
                        r'/v1/projects/[^/%:]+/locations/[a-z0-9-]+/environments(?:/[A-Za-z0-9_-]+)?', parsed.path)
                    or parsed.hostname == 'notebooks.googleapis.com' and re.fullmatch(
                        r'/v2/projects/[^/%:]+/locations/[a-z0-9-]+/instances(?:/[A-Za-z0-9_-]+)?', parsed.path))
                if notebook_airflow_endpoint:
                    from .gcp_notebook_airflow_secret_indicators import project_response, new_budget
                    kind = 'composer_environment' if parsed.hostname == 'composer.googleapis.com' else 'workbench_instance'
                    active = self.options.get('content_secret_scans') is True and kind in self.options.get('_content_secret_scan_kinds', [])
                    if active:
                        with self.lock:
                            if self.notebook_airflow_secret_budget is None:
                                self.notebook_airflow_secret_budget = new_budget()
                    data = project_response(data, method=method, url=url, params=params, body=body,
                        scope=scope, enabled=active, selected_kinds=self.options.get('_content_secret_scan_kinds', []),
                        check_cancelled=self.check_cancelled, budget=self.notebook_airflow_secret_budget)
                cached["data"] = sanitize(data)
                # A top-level pagination cursor is protocol state, not an OAuth
                # credential. Keep it inside the transport cache so real REST
                # scans consume every page. pages() never emits it as an item,
                # and request evidence excludes continuation tokens.
                if has_native_cursor:
                    cached['data']['nextPageToken'] = native_cursor
                break
        except ReadError as exc:
            evidence["status"], evidence["error"] = exc.status, exc.error
            # Credential failure is memoized across requests; provenance belongs
            # to this request, so do not mutate that shared exception instance.
            cached["error"] = ReadError(exc.status, exc.error["code"], http_status=exc.error.get("http_status"),
                                        reason=exc.error.get("reason"))
            # Keep the disabled service's consumer/service for collection
            # metadata; neither target nor quota disablement proves absence.
            cached["error"].error.update({key: exc.error[key] for key in ("consumer", "service", "resource") if key in exc.error})
        except Exception:
            error = ReadError("unavailable", "read_failed")
            evidence["status"], evidence["error"], cached["error"] = error.status, error.error, error
        finally:
            with self.lock:
                evidence["id"] = f"request-{len(self.evidence) + 1}"
                self.evidence.append(evidence)
                cached["id"] = evidence["id"]
                _settle_cache_entry(self.cache, cache_key, cached, response_bytes)
            cached["event"].set()
        if "error" in cached:
            cached["error"].request_id = cached["id"]
            raise cached["error"]
        gcp_prefetch.after_read(self, method, url, params, body, scope, operation, cached["data"])
        return copy.deepcopy(cached["data"]), cached["id"]

    @staticmethod
    def backoff(attempt, response=None, throttled=False):
        """Exponential backoff with jitter; quota responses honour Retry-After."""
        import random
        delay = min(32 if throttled else 8, (1.0 if throttled else 0.25) * 2 ** attempt)
        headers = getattr(response, "headers", None) or {}
        jittered = delay * (0.5 + random.random() / 2)
        try:
            value = headers.get("Retry-After")
        except AttributeError:
            value = None
        if isinstance(value, str):
            value = value.strip()
            try:
                if re.fullmatch(r"[0-9]+", value):
                    minimum = float(value)
                else:
                    stamp = parsedate_to_datetime(value)
                    minimum = max(0.0, stamp.timestamp() - time.time()) if stamp.tzinfo else 0.0
                # Infinite numeric minima also abort at the caller's wait budget.
                return max(jittered, minimum)
            except (TypeError, ValueError, OverflowError):
                pass
        return jittered

    def close(self):
        from . import gcp_prefetch
        gcp_prefetch.close(self)
        from .gcp_function_source_secret_indicators import clear_pending
        clear_pending(self)
        for session in self.sessions:
            session.close()
        self.credentials.close()


# (kind, Compute endpoint, list field, aggregated). Full native configuration is
# returned by these list calls; IAM and fields absent from list APIs are hydrated.
COMPUTE = (
    ("network", "global/networks", "items", False),
    ("interconnect", "global/interconnects", "items", False),
    ("interconnect_attachment", "aggregated/interconnectAttachments", "interconnectAttachments", True),
    ("service_attachment", "aggregated/serviceAttachments", "serviceAttachments", True),
    ("network_endpoint_group", "aggregated/networkEndpointGroups", "networkEndpointGroups", True),
    ("network_endpoint_group", "global/networkEndpointGroups", "items", False),
    ("network_attachment", "aggregated/networkAttachments", "networkAttachments", True),
    ("subnetwork", "aggregated/subnetworks", "subnetworks", True),
    ("firewall", "global/firewalls", "items", False),
    ("firewall_policy", "aggregated/firewallPolicies", "firewallPolicies", True),
    ("instance", "aggregated/instances", "instances", True),
    ("disk", "aggregated/disks", "disks", True),
    ("ssl_policy", "aggregated/sslPolicies", "sslPolicies", True),
    ("route", "global/routes", "items", False),
    ("router", "aggregated/routers", "routers", True),
    ("vpn_gateway", "aggregated/vpnGateways", "vpnGateways", True),
    ("vpn_gateway", "aggregated/targetVpnGateways", "targetVpnGateways", True),
    ("vpn_tunnel", "aggregated/vpnTunnels", "vpnTunnels", True),
    ("forwarding_rule", "aggregated/forwardingRules", "forwardingRules", True),
    ("backend_service", "aggregated/backendServices", "backendServices", True),
    ("backend_bucket", "global/backendBuckets", "items", False),
    ("url_map", "aggregated/urlMaps", "urlMaps", True),
    ("health_check", "aggregated/healthChecks", "healthChecks", True),
    ("instance_group", "aggregated/instanceGroups", "instanceGroups", True),
    ("address", "aggregated/addresses", "addresses", True),
    ("image", "global/images", "items", False),
    ("machine_image", "global/machineImages", "items", False),
    ("snapshot", "aggregated/snapshots", "snapshots", True),
    ("instance_template", "aggregated/instanceTemplates", "instanceTemplates", True),
    ("instance_group_manager", "aggregated/instanceGroupManagers", "instanceGroupManagers", True),
    ("node_group", "aggregated/nodeGroups", "nodeGroups", True),
    ("node_template", "aggregated/nodeTemplates", "nodeTemplates", True),
    ("resource_policy", "aggregated/resourcePolicies", "resourcePolicies", True),
    *(("target_proxy", f"aggregated/{name}", name, True) for name in
      ("targetHttpProxies", "targetHttpsProxies", "targetTcpProxies")),
    *(("target_proxy", f"global/{name}", "items", False) for name in ("targetSslProxies", "targetGrpcProxies")),
)
SUPPORTED_TYPES = frozenset({x[0] for x in COMPUTE} | {
    "asset", "iam_policy", "iam_role", "iam_deny_policy", "project", "organization", "folder",
    "service_account", "service_account_key", "service_account_insight", "activity", "recommendation", "insight", "shared_vpc",
    "bucket", "managed_folder", "sql_instance", "gke_cluster", "kms_key_ring", "kms_key", "secret", "log_sink",
    "workload_identity_pool", "workload_identity_provider", "workforce_pool", "workforce_provider",
    "bigquery_dataset", "bigquery_acl_mode", "bigquery_row_policy_inventory", "bigquery_connection", "bigquery_routine_metadata", "bigquery_transfer_config", "bigquery_continuous_assignment", "artifact_repository", "containeranalysis_note", "datacatalog_taxonomy", "datacatalog_policy_tag", "biglake_catalog", "biglake_namespace", "biglake_table", "analyticshub_data_exchange", "analyticshub_listing", "agentidentity_auth_provider", "agentidentity_authorization", "cloudrun_service", "cloudrun_instance", "cloudrun_worker_pool", "function", "group", "group_membership",
    "principal_access_boundary_policy", "policy_binding", "app_engine_application", "app_engine_application_identity", "app_engine_service", "app_engine_version", "app_engine_instance", "app_engine_legacy_constraint", "workspace_user", "workspace_customer", "workspace_role",
    "workspace_role_assignment", "workspace_user_activity", "api_key_usage", "storage_hmac_key_usage", "api_key", "bigquery_table", "dataproc_cluster", "dns_managed_zone", "dns_policy",
    "logging_metric", "monitoring_alert_policy", "alloydb_cluster", "alloydb_instance", "essential_contact",
    "access_approval_settings", "service_usage", "bigtable_instance", "bigtable_table", "bigtable_authorized_view", "bigtable_materialized_view", "bigtable_backup", "billing_account", "cloudrun_job",
    "vpc_flow_logs_config", "policy_based_route", "firewall_policy_association", "effective_firewall", "monitoring_notification_channel", "org_policy_effective",
    "pubsub_topic", "pubsub_subscription", "pubsub_snapshot", "service_perimeter",
    "cloudbuild_trigger", "cloudbuild_default_sa", "cloudbuild_connection", "cloudbuild_repository", "developerconnect_git_repository_link", "discoveryengine_collection", "discoveryengine_data_store", "discoveryengine_engine", "cloudfunctions_location", "workflows_workflow", "workstations_cluster", "workstations_config", "workstations_workstation", "cloudtasks_queue", "storage_hmac_key", "composer_environment", "composer_image_version", "workbench_instance", "scheduler_job",
    "domains_registration", "eventarc_message_bus", "eventarc_enrollment", "firebase_apphosting_backend", "bucket_notification", "kms_key_version", "logging_bucket", "sql_user",
    "certificate", "cloud_asset", "target_https_proxy", "server_tls_policy", "autoscaler",
    "worker_pool", "sql_backup_run", "source_repository", "alert_policy",
    "access_transparency_entry", "audit_log", "os_inventory", "security_policy", "gcp_v4_workload_facts",
    "dns_record", "cloudbuild_build", "clouddeploy_delivery_pipeline", "clouddeploy_target", "clouddeploy_custom_target_type", "sql_operation"})
SUPPORTED_TYPES = SUPPORTED_TYPES | {'vpc_access_connector', 'filestore_instance', 'redis_instance', 'instance_settings', 'recoverable_snapshot', 'instance_effective_firewall'}
from .gcp_network_catalog import TYPES as NETWORK_CATALOG_TYPES
from .gcp_network_catalog import PRIVATE_SERVICES as NETWORK_PRIVATE_SERVICES, SERVICE_ENDPOINTS as NETWORK_SERVICE_ENDPOINTS, REGIONAL as NETWORK_REGIONAL_SERVICES
_NETWORK_API_SERVICES = {plan['service'] for plan in NETWORK_PRIVATE_SERVICES.values()} | {plan[0] for plan in NETWORK_REGIONAL_SERVICES.values()}
HOSTS |= frozenset({service + '.googleapis.com' for service in _NETWORK_API_SERVICES} |
    {host for service in _NETWORK_API_SERVICES
     for host in NETWORK_SERVICE_ENDPOINTS.get(service, {}).values()})
SUPPORTED_TYPES = SUPPORTED_TYPES | NETWORK_CATALOG_TYPES
SUPPORTED_TYPES = SUPPORTED_TYPES | {'artifact_image', 'sbom_occurrence', 'deployed_image', 'log_secret_sample', 'gcs_selected_object'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'app_engine_version_secret', 'workflow_source'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'clouddeploy_release_source', 'cloudbuild_artifact_source', 'gcs_selected_archive', 'composer_dag_source', 'cloudbuild_log_source', 'appengine_deployment_source'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'artifact_selected_file', 'function_source_archive', 'gke_workload_literal', 'dataform_selected_file', 'dataflow_job', 'batch_job', 'dataproc_job'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'gke_exposure_service', 'gke_exposure_ingress', 'gke_exposure_pod'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'dataflow_privesc_job', 'dataflow_privesc_pipeline'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'bucket_acl', 'object_acl', 'bucket_effective_iam', 'os_patch_deployment', 'os_vulnerability_report', 'kms_effective_use'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'osconfig_guest_policy', 'osconfig_project_feature_settings', 'osconfig_os_policy_assignment', 'osconfig_policy_orchestrator', 'ca_pool', 'service_catalog_version'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'dataform_privesc_location'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'datafusion_privesc_instance'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'deployment_manager_deployment'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'iam_role_builtin'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'folder_policy_grant_constraints'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'organization_policy_grant_constraints'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'dataplex_privesc_lake'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'log_entry', 'scc_finding', 'scc_notification_config', 'backup_target', 'asset_service_inventory', 'access_approval_request', 'provider_access_event', 'asset_previous', 'asset_audit_log'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'source_repository_file', 'cloudtasks_selected_task', 'bigquery_selected_routine'}
SUPPORTED_TYPES = SUPPORTED_TYPES | dataproc_source_runtime.KINDS | workbench_source_runtime.KINDS | selected_job_source_runtime.KINDS
SUPPORTED_TYPES = SUPPORTED_TYPES | {'cloudrun_job_declared_image', 'cloudrun_worker_pool_selected_revision_image', 'developerconnect_selected_file'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'cloud_run_selected_job_image_vulnerabilities', 'artifact_selected_image_vulnerabilities', 'gke_selected_pod_image_secrets', 'gke_selected_pod_image_vulnerabilities', 'appengine_flex_selected_version_image_secrets', 'appengine_flex_selected_version_image_vulnerabilities'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'iap_tunnel_policy'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'identityplatform_tenant'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'krm_api_host'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'logging_view'}
SUPPORTED_TYPES = SUPPORTED_TYPES | {'inframanager_location'}
# These inventories represent optional application content, not metadata.
# An unselected read cannot establish that no resources/content exist.
CONTENT_ONLY_TYPES = selected_job_source_runtime.KINDS | dataproc_source_runtime.KINDS | workbench_source_runtime.KINDS | frozenset({
    'cloudtasks_selected_task', 'bigquery_selected_routine',
    'source_repository_file',
    'clouddeploy_release_source',
    'cloudbuild_artifact_source',
    'log_secret_sample', 'gcs_selected_object', 'gcs_selected_archive',
    'dataform_selected_file', 'app_engine_version_secret', 'workflow_source',
    'dataflow_job', 'batch_job', 'dataproc_job', 'gke_workload_literal',
    'gke_selected_pod_image_secrets', 'gke_selected_pod_image_vulnerabilities',
    'function_source_archive', 'composer_dag_source', 'artifact_selected_file', 'cloudbuild_log_source', 'appengine_deployment_source',
})
CONTENT_ONLY_TYPES = CONTENT_ONLY_TYPES | {'cloudrun_job_declared_image', 'cloudrun_worker_pool_selected_revision_image', 'developerconnect_selected_file'}
CONTENT_ONLY_TYPES = CONTENT_ONLY_TYPES | {'cloud_run_selected_job_image_vulnerabilities', 'artifact_selected_image_vulnerabilities', 'appengine_flex_selected_version_image_secrets', 'appengine_flex_selected_version_image_vulnerabilities'}
# Compute kinds whose resource IAM policy is read with the per-kind GET
# {resource}/getIamPolicy method (collection path segment, location kind).
COMPUTE_IAM = {"instance": ("instances", "zone"), "disk": ("disks", "zone"), "snapshot": ("snapshots", "region"), "subnetwork": ("subnetworks", "region"), "image": ("images", None), "machine_image": ("machineImages", None), "node_group": ("nodeGroups", "zone"),
               "node_template": ("nodeTemplates", "region"), "resource_policy": ("resourcePolicies", "region")}
# Service states read per project by services.get (checks name each one).
SERVICE_USAGE_NAMES = ["cloudasset.googleapis.com", "containeranalysis.googleapis.com", "containerscanning.googleapis.com",
                       "generativelanguage.googleapis.com"]
# Org Policy constraints whose evaluated (inherited) policy is read per project.
# Names are the documented constraint names (Organization Policy constraints
# list); an unknown name would fail the read and leave every constraint UNKNOWN.
ORG_POLICY_CONSTRAINTS = ("storage.publicAccessPrevention", "compute.requireOsLogin",
                          "iam.disableCrossProjectServiceAccountUsage", "iam.automaticIamGrantsForDefaultServiceAccounts",
                          "iam.disableServiceAccountKeyCreation", "iam.disableServiceAccountKeyUpload",
                          "iam.allowedPolicyMemberDomains", "essentialcontacts.allowedContactDomains",
                          # Managed successors: when they carry a policy they supersede the legacy twin.
                          "iam.managed.disableServiceAccountKeyCreation", "iam.managed.disableServiceAccountKeyUpload",
                          "iam.managed.disableServiceAccountApiKeyCreation",
                          "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts", "iam.managed.allowedPolicyMembers",
                          "essentialcontacts.managed.allowedContactDomains")
DEPENDENCIES = {"service_account_key": {"service_account"}, "workload_identity_provider": {"workload_identity_pool"},
                "workforce_provider": {"workforce_pool"}, "kms_key": {"kms_key_ring"},
                "group": {"iam_policy", "organization"}, "group_membership": {"group", "iam_policy", "organization"}}
DEPENDENCIES["bigquery_table"] = {"bigquery_dataset"}
DEPENDENCIES["workspace_user_activity"] = {"workspace_user"}
DEPENDENCIES["api_key_usage"] = {"api_key"}
DEPENDENCIES["storage_hmac_key_usage"] = {"storage_hmac_key"}
DEPENDENCIES["bigquery_acl_mode"] = {"bigquery_dataset"}
DEPENDENCIES["bigquery_row_policy_inventory"] = {"bigquery_table", "bigquery_dataset"}
DEPENDENCIES["bigquery_connection"] = {"bigquery_dataset"}
DEPENDENCIES["bigquery_routine_metadata"] = {"bigquery_dataset"}
DEPENDENCIES["bigquery_transfer_config"] = {"bigquery_dataset"}
DEPENDENCIES["bigquery_continuous_assignment"] = {"bigquery_dataset"}
DEPENDENCIES["bigtable_table"] = {"bigtable_instance"}
DEPENDENCIES["bigtable_authorized_view"] = {"bigtable_instance", "bigtable_table"}
DEPENDENCIES["bigtable_materialized_view"] = {"bigtable_instance"}
DEPENDENCIES["bigtable_backup"] = {"bigtable_instance"}
DEPENDENCIES["cloudbuild_repository"] = {"cloudbuild_connection"}
DEPENDENCIES["biglake_namespace"] = {"biglake_catalog"}
DEPENDENCIES["biglake_table"] = {"biglake_catalog", "biglake_namespace"}
DEPENDENCIES["analyticshub_data_exchange"] = {"cloud_asset"}
DEPENDENCIES["analyticshub_listing"] = {"cloud_asset", "analyticshub_data_exchange"}
for _clouddeploy_kind in ("clouddeploy_delivery_pipeline", "clouddeploy_target", "clouddeploy_custom_target_type"):
    DEPENDENCIES[_clouddeploy_kind] = {"project", "iam_policy", "service_account"}
DEPENDENCIES["function"] = {"cloudfunctions_location"}
DEPENDENCIES["cloudbuild_default_sa"] = {"project", "iam_policy"}
DEPENDENCIES["workflows_workflow"] = {"project", "iam_policy", "service_account"}
for _workstations_kind in ("workstations_cluster", "workstations_config", "workstations_workstation"):
    DEPENDENCIES[_workstations_kind] = {"project", "iam_policy", "service_account"}
DEPENDENCIES["workstations_config"].add("workstations_cluster")
DEPENDENCIES["workstations_workstation"].update({"workstations_cluster", "workstations_config"})
DEPENDENCIES["cloudtasks_queue"] = {"project", "iam_policy", "service_account"}
# Dedicated Dataproc source jobs independently GET exact parents; no list dependency.
for _selected_job_source_kind in selected_job_source_runtime.KINDS:
    DEPENDENCIES[_selected_job_source_kind] = set()
for _workbench_source_kind in workbench_source_runtime.KINDS:
    DEPENDENCIES[_workbench_source_kind] = set()
for _dataproc_source_kind in dataproc_source_runtime.KINDS:
    DEPENDENCIES[_dataproc_source_kind] = set()
DEPENDENCIES['composer_dag_source'] = {'project', 'bucket', 'composer_environment'}
DEPENDENCIES['cloudbuild_log_source'] = {'project', 'bucket'}
DEPENDENCIES['source_repository_file'] = {'project'}
DEPENDENCIES['cloudtasks_selected_task'] = {'project'}
DEPENDENCIES['bigquery_selected_routine'] = {'project'}
DEPENDENCIES['clouddeploy_release_source'] = {'project', 'bucket'}
DEPENDENCIES['cloudbuild_artifact_source'] = {'project', 'bucket'}
DEPENDENCIES['appengine_deployment_source'] = {'project', 'bucket'}
DEPENDENCIES['gcs_selected_object'] = {'project', 'bucket'}
DEPENDENCIES['gcs_selected_archive'] = {'project', 'bucket'}
DEPENDENCIES['dataform_selected_file'] = {'project'}
DEPENDENCIES['gke_workload_literal'] = {'gke_cluster'}
DEPENDENCIES['gke_exposure_service'] = {'gke_cluster'}
DEPENDENCIES['gke_exposure_ingress'] = {'gke_cluster'}
DEPENDENCIES['gke_exposure_pod'] = {'gke_cluster'}
DEPENDENCIES['function_source_archive'] = {'function', 'project', 'bucket'}
DEPENDENCIES['artifact_selected_file'] = {'project', 'artifact_repository'}
for _literal_job_kind in ('dataflow_job', 'batch_job', 'dataproc_job'):
    DEPENDENCIES[_literal_job_kind] = {'project'}
DEPENDENCIES["effective_firewall"] = {"network", "subnetwork"}
DEPENDENCIES["instance_effective_firewall"] = {"instance"}
DEPENDENCIES["alloydb_instance"] = {"alloydb_cluster"}
DEPENDENCIES["bucket_notification"] = {"bucket"}
DEPENDENCIES["iam_role"] = {"iam_policy", "project"}
DEPENDENCIES["app_engine_version"] = {"app_engine_service"}
DEPENDENCIES["app_engine_instance"] = {"app_engine_version", "app_engine_service"}
DEPENDENCIES["app_engine_version_secret"] = {"app_engine_version", "app_engine_service"}
DEPENDENCIES["kms_key_version"] = {"kms_key", "kms_key_ring"}
DEPENDENCIES["sql_user"] = {"sql_instance"}
DEPENDENCIES["target_https_proxy"] = {"target_proxy"}
DEPENDENCIES["server_tls_policy"] = {"target_https_proxy", "target_proxy"}
DEPENDENCIES["autoscaler"] = {"instance_group_manager"}
DEPENDENCIES["sql_backup_run"] = {"sql_instance"}
DEPENDENCIES["backup_target"] = {"sql_instance", "sql_backup_run"}
DEPENDENCIES["alert_policy"] = {"monitoring_alert_policy"}
DEPENDENCIES["os_inventory"] = {"instance"}
DEPENDENCIES["instance_settings"] = {"instance"}
DEPENDENCIES["iap_tunnel_policy"] = {"instance"}
DEPENDENCIES["artifact_image"] = {"artifact_repository"}
DEPENDENCIES["datacatalog_policy_tag"] = {"datacatalog_taxonomy"}
DEPENDENCIES["agentidentity_authorization"] = {"agentidentity_auth_provider"}
DEPENDENCIES["sbom_occurrence"] = {"artifact_repository"}
DEPENDENCIES["deployed_image"] = {"artifact_repository", "cloudrun_service", "project"}
DEPENDENCIES["bucket_acl"] = {"bucket"}
DEPENDENCIES["managed_folder"] = {"bucket"}
DEPENDENCIES["composer_image_version"] = {"project", "bucket"}
DEPENDENCIES["object_acl"] = {"bucket"}
DEPENDENCIES["bucket_effective_iam"] = {"bucket", "iam_policy", "project"}
DEPENDENCIES["os_patch_deployment"] = {"instance"}
DEPENDENCIES["os_vulnerability_report"] = {"instance", "project"}
DEPENDENCIES["kms_effective_use"] = {"kms_key", "kms_key_ring", "project", "iam_policy"}
DEPENDENCIES["dns_record"] = {"dns_managed_zone"}
DEPENDENCIES["sql_operation"] = {"sql_instance"}
DEPENDENCIES["gcp_v4_workload_facts"] = {"app_engine_application", "app_engine_service", "app_engine_version",
    "artifact_repository", "cloudrun_service", "cloudrun_job"}


def normalize_scope(value):
    if not isinstance(value, str):
        raise ValueError("GCP scopes must be project, organization or folder names")
    if value == "*":
        return value
    scope = value if "/" in value else "projects/" + value
    if not re.fullmatch(r"(?:projects|organizations|folders)/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", scope):
        raise ValueError("invalid GCP scope")
    return scope


def scope_type(scope):
    return scope.split("/", 1)[0] if "/" in scope else scope


def wire_status(status):
    return "unknown" if status in ("unavailable", "unsupported") else status


def _iam_distinct_root_views(scope, previous, current):
    """The one collision allowed before alias proof: direct root plus CAI view."""
    def view(item):
        provenance = item.get("_provenance", {})
        representation = item.get("_representation", provenance.get("representation")
                                  if isinstance(provenance, dict) else None)
        if representation == "full" and item.get("name") == scope and "assetType" not in item:
            return "direct"
        if (representation == "partial" and
                item.get("name") == "//cloudresourcemanager.googleapis.com/" + scope and
                item.get("assetType") == "cloudresourcemanager.googleapis.com/Project" and
                item.get("project") == scope):
            return "cai"
        return None
    return {view(previous), view(current)} == {"direct", "cai"}


def _iam_identical_direct_root(scope, previous, current):
    """Only a repeated complete direct root can reuse its prior observation."""
    def payload(item):
        provenance = item.get("_provenance", {})
        representation = item.get("_representation", provenance.get("representation")
                                  if isinstance(provenance, dict) else None)
        if representation != "full" or item.get("name") != scope or "assetType" in item:
            return None
        return {key: value for key, value in item.items()
                if key not in {"_resource_id", "native_id", "_provenance", "_relationships",
                               "_representation"}}
    left, right = payload(previous), payload(current)
    return left is not None and left == right


def _validate_iam_policy(policy):
    """Reject provider Policy fields that could replace collector identity or authority."""
    if not isinstance(policy, dict) or set(policy) - {"bindings", "auditConfigs", "etag", "version"}:
        raise ReadError("malformed", "malformed_iam_policy")
    if ("bindings" in policy and not isinstance(policy["bindings"], list)
            or "auditConfigs" in policy and not isinstance(policy["auditConfigs"], list)
            or "etag" in policy and not isinstance(policy["etag"], str)
            or "version" in policy and type(policy["version"]) is not int):
        raise ReadError("malformed", "malformed_iam_policy")
    for binding in policy.get("bindings", []):
        if (not isinstance(binding, dict) or set(binding) - {"role", "members", "condition"}
                or not isinstance(binding.get("role"), str)
                or not isinstance(binding.get("members", []), list)
                or any(not isinstance(member, str) for member in binding.get("members", []))):
            raise ReadError("malformed", "malformed_iam_policy")
        if "condition" in binding:
            condition = binding["condition"]
            if (not isinstance(condition, dict)
                    or set(condition) - {"title", "description", "expression", "location"}
                    or any(not isinstance(value, str) for value in condition.values())):
                raise ReadError("malformed", "malformed_iam_policy")
    for config in policy.get("auditConfigs", []):
        if (not isinstance(config, dict) or set(config) - {"service", "auditLogConfigs"}
                or not isinstance(config.get("service"), str)
                or not isinstance(config.get("auditLogConfigs", []), list)):
            raise ReadError("malformed", "malformed_iam_policy")
        for log in config.get("auditLogConfigs", []):
            if (not isinstance(log, dict) or set(log) - {"logType", "exemptedMembers"}
                    or not isinstance(log.get("logType"), str)
                    or not isinstance(log.get("exemptedMembers", []), list)
                    or any(not isinstance(member, str) for member in log.get("exemptedMembers", []))):
                raise ReadError("malformed", "malformed_iam_policy")
    return policy


def item_identity(kind, scope, item):
    for field in ("selfLink", "resource", "name"):
        name = item.get(field)
        if kind == "iam_policy" and name == scope:
            return "//cloudresourcemanager.googleapis.com/" + scope
        if isinstance(name, str) and (name.startswith(("https://", "//", "projects/", "organizations/", "folders/", "locations/", "groups/", "roles/", "policies/"))):
            return name
    name = str(item.get("name") or item.get("id") or item.get("email") or "")
    location = item.get("zone") or item.get("region") or item.get("location") or item.get("_aggregated_scope") or "global"
    return f"//gcp/{scope}/{location}/{kind}/{name}" if name else None


def relationships(item):
    """Only explicitly declared references; no inferred effective reachability."""
    edges = []
    fields = {"network": "uses_network", "subnetwork": "uses_subnetwork", "peerNetwork": "peers_with",
        "vpnGateway": "uses_vpn_gateway", "targetVpnGateway": "uses_vpn_gateway", "router": "uses_router",
        "target": "forwards_to", "backendService": "uses_backend", "urlMap": "uses_url_map",
        "defaultService": "uses_backend", "service": "uses_backend", "group": "uses_instance_group",
        "healthChecks": "uses_health_check", "kmsKeyName": "encrypted_with", "defaultKmsKeyName": "encrypted_with",
        "destination": "logs_to", "keyRing": "belongs_to_key_ring", "group": "member_of_group", "member": "member_reference"}
    def visit(value, path=""):
        if isinstance(value, dict):
            for field, child in value.items():
                if field.startswith("_"):
                    continue
                if field in fields:
                    for ref in child if isinstance(child, list) else [child]:
                        if isinstance(ref, str) and ref:
                            edges.append({"type": fields[field], "target": ref, "field": path + field})
                visit(child, path + field + ".")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + str(index) + ".")
    visit(item)
    return sorted({(e["type"], e["target"], e["field"]): e for e in edges}.values(),
                  key=lambda e: (e["type"], e["target"], e["field"]))


class GCPCollector:
    def __init__(self, connector, requirements=None, *, transport=None):
        self.options = dict(connector.get("options") or {})
        self.regional_policy_skips = {}
        if 'content_secret_scans' in self.options and type(self.options['content_secret_scans']) is not bool:
            raise ValueError('content_secret_scans must be a boolean')
        from .gcp_appengine_versions import approved_version_maxima
        approved_version_maxima(self.options)
        self.progress_callback = self.options.pop("_progress_callback", None)
        self.collection_callback = self.options.pop("_collection_callback", None)
        self.resume_collection_lookup = self.options.pop("_resume_collection_lookup", None)
        if self.resume_collection_lookup is not None and not callable(self.resume_collection_lookup):
            raise ValueError("Invalid resumed native collection lookup")
        self._resumed_collection_keys = set()
        if self.progress_callback is None:
            from peaso.progress import current_callback
            self.progress_callback = current_callback()
        self.progress_phase = "discovering"
        self.progress_lock = threading.RLock()
        self.auth = connector.get("auth", {})
        if self.auth is None:
            self.auth = {}
        if not isinstance(self.auth, dict):
            raise ValueError("GCP auth must be an object")
        if 'selected_appengine_flex_version_images' in self.options:
            from peaso.gcp_appengine_flex_image_selection_20261021 import selected as selected_flex_images
            selected_flex_images(self.options, connector.get('scopes', []), self.options.get('_appengine_flex_image_named_checks', []))
        if 'selected_gke_pod_images' in self.options:
            from peaso.gcp_gke_image_selection_20261021 import selected as gke_image_selected, kubernetes_auth as gke_image_auth, registry_auth as gke_registry_auth
            selected_gke_images = gke_image_selected(self.options, connector.get('scopes', []), self.options.get('_gke_image_named_checks', []))
            gke_image_auth(self.auth, selected_gke_images)
            gke_registry_auth(self.auth, selected_gke_images, self.options.get('selected_registry_hosts', []))
        if self.auth.get("quota_project"):
            self.options["quota_project"] = self.auth["quota_project"]
        if requirements is not None and (not isinstance(requirements, (list, tuple, set)) or
                                        any(x not in SUPPORTED_TYPES for x in requirements)):
            raise ValueError("requirements must contain supported GCP resource types")
        default_requested = sorted(SUPPORTED_TYPES - CONTENT_ONLY_TYPES - {"composer_dag_source", "audit_log", "log_entry", "log_secret_sample", "gcs_selected_object", "gcs_selected_archive", "dataform_selected_file", "provider_access_event", "asset_previous", "asset_audit_log", "app_engine_version_secret", "workflow_source", "dataflow_job", "batch_job", "dataproc_job", "gke_workload_literal", "function_source_archive", "artifact_selected_file"}) if requirements is None else list(requirements)
        requested = self.options.get("inventories", default_requested)
        if not isinstance(requested, list) or any(x not in SUPPORTED_TYPES for x in requested):
            raise ValueError("inventories must contain supported GCP resource types")
        self.wanted = set(requested) & (set(requirements) if requirements is not None else SUPPORTED_TYPES)
        # Listing subscription rights can be inherited from an exchange policy.
        if "analyticshub_listing" in self.wanted:
            self.wanted.add("analyticshub_data_exchange")
        # The authorization row is meaningful only alongside its provider
        # configuration and policy, including in a focused inventory request.
        if "agentidentity_authorization" in self.wanted:
            self.wanted.update(("agentidentity_auth_provider", "project"))
        # A transfer config is useful only with the exact destination dataset
        # recorded in the exported snapshot, not merely fetched as a hidden
        # supporting inventory during collection.
        if "bigquery_transfer_config" in self.wanted:
            self.wanted.add("bigquery_dataset")
        if "bigtable_authorized_view" in self.wanted:
            self.wanted.update(("bigtable_instance", "bigtable_table"))
        if "bigtable_table" in self.wanted:
            self.wanted.add("bigtable_instance")
        if "bigtable_materialized_view" in self.wanted:
            self.wanted.add("bigtable_instance")
        if "bigtable_backup" in self.wanted:
            self.wanted.add("bigtable_instance")
        if "cloudbuild_repository" in self.wanted:
            self.wanted.add("cloudbuild_connection")
        if 'log_entry' in self.wanted:
            bound(self.options, 'log_entry_minutes', 60, 1, 1440)
        self.needed = set(self.wanted)
        if {"workspace_user", "domains_registration"} <= self.wanted:
            # The domain-to-tenant join needs the Directory customer's primary domain.
            self.wanted.add("workspace_customer")
            self.needed.add("workspace_customer")
        from .gcp_job_literal_secret_indicators import enabled as job_secrets_enabled
        if 'dataproc_cluster' in self.wanted and job_secrets_enabled(self.options, 'dataproc_cluster'):
            self.needed.add('project')
        for kind in self.wanted:
            self.needed.update(DEPENDENCIES.get(kind, set()))
        # The signed active-service restriction predicate joins these two
        # inventories by selected project ID. Both APIs may instead return the
        # numeric project name, which needs independent CRM identity proof.
        self.api_key_alias_mode = {"api_key", "service_usage"} <= self.needed
        if self.api_key_alias_mode:
            self.needed.add("project")
        sw52_types = {"workspace_role_assignment", "workspace_role", "workspace_user", "iam_policy", "group", "group_membership"}
        self.sw52_native_mode = sw52_types <= self.wanted
        self.sw52_only_mode = self.sw52_native_mode and self.wanted == sw52_types
        if self.sw52_native_mode:
            self.needed.update(("project", "folder", "organization"))
        if 'asset_service_inventory' in self.wanted:
            from .gcp_native_evidence import inventory_dependencies
            self.needed.update(inventory_dependencies(self.options))
        locations = self.options.get("integration_locations")
        if locations is not None and (not isinstance(locations, list) or len(locations) > 100 or any(
                not isinstance(location, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location)
                for location in locations)):
            raise ValueError("integration_locations must contain at most 100 explicit locations")
        deploy_locations = self.options.get("clouddeploy_locations")
        if deploy_locations is not None and (not isinstance(deploy_locations, list) or len(deploy_locations) > 100 or any(
                not isinstance(location, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location)
                for location in deploy_locations)):
            raise ValueError("clouddeploy_locations must contain at most 100 explicit locations")
        self.scopes = list(dict.fromkeys(normalize_scope(s) for s in connector.get("scopes", [])))
        self.registry_image_vulnerability_targets = []
        if "artifact_selected_image_vulnerabilities" in self.wanted:
            from .gcp_registry_trivy_runtime_20261021 import prepare as prepare_registry_cves
            self.registry_image_vulnerability_targets = prepare_registry_cves(self.options, self.scopes, self.wanted)
            if not self.registry_image_vulnerability_targets:
                self.needed.discard("artifact_selected_image_vulnerabilities")
        if 'selected_cloudrun_services' in self.options:
            from .gcp_cloudrun_image_inspection import validate_selection
            validate_selection(self.options['selected_cloudrun_services'], self.scopes)
        if 'selected_cloudbuild_builds' in self.options:
            from .gcp_cloudbuild_log_secret_indicators import selected_builds, KIND, Incomplete
            try:
                selected_builds({**self.options, 'content_secret_scans': True,
                    '_content_secret_scan_kinds': [KIND]}, self.scopes)
            except Incomplete:
                raise ValueError('Cloud Build log inspection requires bounded exact same-project Build names') from None
        from .gcp_selected_task_routine_secret_indicators import SPECS as task_routine_specs, selected_targets as task_routine_targets, Incomplete as TaskRoutineIncomplete
        for kind, spec in task_routine_specs.items():
            if spec['option'] in self.options:
                try:
                    task_routine_targets({**self.options, 'content_secret_scans': True,
                        '_content_secret_scan_kinds': [kind]}, self.scopes, kind)
                except TaskRoutineIncomplete:
                    raise ValueError('Task/routine inspection requires 1-8 exact unique names in one matching project-ID scope') from None
        if 'selected_source_repository_files' in self.options:
            from .gcp_sourcerepo_secret_indicators import selected_targets, KIND, Incomplete
            try:
                selected_targets({**self.options, 'content_secret_scans': True,
                    '_content_secret_scan_kinds': [KIND]}, self.scopes)
            except Incomplete:
                raise ValueError('Source Repository inspection requires one exact project, repository, commit and bounded file selection') from None
        if 'selected_clouddeploy_releases' in self.options:
            from .gcp_clouddeploy_source_secret_indicators import selected_releases, KIND, Incomplete
            try:
                selected_releases({**self.options, 'content_secret_scans': True,
                    '_content_secret_scan_kinds': [KIND]}, self.scopes)
            except Incomplete:
                raise ValueError('Cloud Deploy source inspection requires bounded exact same-project Release names') from None
        if 'selected_cloudbuild_artifact_builds' in self.options:
            from .gcp_cloudbuild_artifact_secret_indicators import selected_builds, KIND, Incomplete
            try:
                selected_builds({**self.options, 'content_secret_scans': True,
                    '_content_secret_scan_kinds': [KIND]}, self.scopes)
            except Incomplete:
                raise ValueError('Cloud Build artifact inspection requires bounded exact same-project Build names') from None
        if 'selected_appengine_versions' in self.options:
            from .gcp_appengine_source_secret_indicators import selected_versions, KIND, Incomplete
            try:
                selected_versions({**self.options, 'content_secret_scans': True,
                    '_content_secret_scan_kinds': [KIND]}, self.scopes)
            except Incomplete:
                raise ValueError('App Engine source inspection requires bounded exact same-project Version names') from None
        selected_job_permitted = selected_job_source_runtime.authorize_collector(self.options, self.scopes)
        self.needed.difference_update(selected_job_source_runtime.KINDS - selected_job_permitted)
        workbench_permitted = workbench_source_runtime.authorize_collector(self.options, self.scopes)
        self.needed.difference_update(workbench_source_runtime.KINDS - workbench_permitted)
        dataproc_permitted = dataproc_source_runtime.authorize_collector(self.options, self.scopes)
        self.needed.difference_update(dataproc_source_runtime.KINDS - dataproc_permitted)
        self.requested_scopes = self.scopes[:]
        self.platform_proof_label = None
        if self.auth.get("method") == "platform-service-account":
            from peaso.gcp_platform import PLATFORM_EMAIL, PLATFORM_PROJECT, PROOF_LABEL
            info = self.auth.get("sa_json")
            if isinstance(info, str):
                try:
                    info = json.loads(info)
                except ValueError:
                    raise ValueError("Hosted GCP service account is malformed") from None
            if (not isinstance(info, dict) or info.get("project_id") != PLATFORM_PROJECT
                    or info.get("client_email") != PLATFORM_EMAIL or not info.get("private_key")):
                raise ValueError("Hosted GCP service account identity is invalid")
            if not self.scopes or "*" in self.scopes or any(self.options.get(key) for key in ("all_projects", "discover_projects", "all_hierarchy")):
                raise ValueError("Shared HackTricks GCP identity requires exact project IDs; discovery is unavailable")
            label = self.auth.get("project_proof_label")
            if not isinstance(label, str) or not PROOF_LABEL.fullmatch(label):
                raise ValueError("Hosted GCP project proof is missing")
            if any(not scope.startswith("projects/") or scope == f"projects/{PLATFORM_PROJECT}"
                   for scope in self.scopes if scope != "*"):
                raise ValueError("Hosted GCP can only scan verified customer projects")
            self.platform_proof_label = label
        from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
        self.audit_owner_policy = normalize_owner_policy(self.options[OPTION]) if OPTION in self.options else None
        from peaso.gcp_psc_policy import OPTION as PSC_OPTION, normalize as normalize_psc_policy
        self.psc_owner_policy = normalize_psc_policy(self.options[PSC_OPTION]) if PSC_OPTION in self.options else None
        self.auto_scopes = not self.scopes
        if self.auto_scopes:
            self.scopes = ["*"]
            self.options["all_projects"] = True
            self.options["all_hierarchy"] = True
        if self.platform_proof_label:
            self.options["all_hierarchy"] = False
            self.options["discover_projects"] = False
        self.allowed = self.options.get("project_restrictions", self.options.get("allowed_projects"))
        if self.allowed is not None:
            if not isinstance(self.allowed, list) or any(not isinstance(x, str) for x in self.allowed):
                raise ValueError("project_restrictions must be a project string list")
            self.allowed = set(normalize_scope(x) for x in self.allowed)
            if any(not x.startswith("projects/") for x in self.allowed):
                raise ValueError("project_restrictions must contain only projects")
            if any(s.startswith("projects/") and s not in self.allowed for s in self.scopes):
                raise ValueError("explicit project is outside project_restrictions")
        if not self.scopes or ("*" in self.scopes and not self.options.get("all_projects")):
            raise ValueError("GCP requires explicit scopes; '*' requires all_projects=true")
        self.max_scopes = optional_bound(self.options, "max_scopes", 1, 100000)
        if self.max_scopes is not None and len(self.scopes) > self.max_scopes:
            raise ValueError("scope limit exceeded")
        self.max_pages = optional_bound(self.options, "max_pages", 1, 100000)
        self.max_items = optional_bound(self.options, "max_resources", 1, 10000000)
        self.page_size = bound(self.options, "page_size", 100, 1, 1000)
        self.workers = bound(self.options, "concurrency", 16, 1, 32)
        # Per-item hydration (IAM, dataset/table details) runs on its own bounded
        # pool so nested waits can never starve the scope/type job pool.
        self.hydration_pool = ThreadPoolExecutor(max_workers=bound(self.options, "hydration_concurrency",
            min(32, self.workers * 2), 1, 64), thread_name_prefix="gcp-hydrate")
        # Per-location list reads inside one job fan out on a third bounded
        # pool; its workers use the hydration pool but never wait on their own.
        location_workers = bound(self.options, "location_concurrency", min(32, self.workers * 2), 1, 64)
        self.location_pool = (ThreadPoolExecutor(max_workers=location_workers, thread_name_prefix=LOCATION_POOL_PREFIX)
                              if self.workers > 1 and location_workers > 1 else None)
        self.max_calls = optional_bound(self.options, "max_calls", 1, 100000)
        self.collections = {}
        self.lock = threading.Lock()
        self.total_items = 0
        self.seen_items = set()
        self.scope_errors = []
        self.transport = transport
        self.auth_error = None
        self.read_time = datetime.now(timezone.utc).isoformat()
        self.ancestry = {}
        self.ancestry_source_requests = {}
        self.native_asset_times = {}
        self.native_asset_bindings = {}
        self.data_project_lock = threading.RLock()
        self.data_project_bindings = {}

    def progress(self, phase=None, scope="", *, complete=False):
        if not callable(self.progress_callback):
            return
        from peaso.progress import emit_progress
        with self.progress_lock:
            if phase:
                self.progress_phase = phase
            with self.lock:
                settled = len(self.collections)
                resources = sum(len(collection["items"]) for collection in self.collections.values())
            emit_progress(self.progress_callback, phase=self.progress_phase, provider="gcp", scope=scope,
                completed=settled, total=settled if complete else None, resources=resources, dynamic_total=not complete)

    def read(self, url, scope, *, params=None, body=None, method="GET", operation=None):
        if isinstance(params, dict) and params:
            params = self._bulk_page_params(url, method, params)
        return self.transport.request(method, url, params=params, body=body, scope=scope, operation=operation)

    def _bulk_page_params(self, url, method, params):
        # pages() seeds its historical default page size; raise only that
        # seeded value to the endpoint maximum when page_size is unset.
        seeded = min(self.page_size, 500 if "compute.googleapis.com" in url else 1000)
        target = self.default_page_size(url, method)
        keys = [key for key in ("pageSize", "maxResults") if params.get(key) == seeded]
        if target == seeded or not keys:
            return params
        return {**params, **dict.fromkeys(keys, target)}

    def _data_project_binding(self, scope, *, require_alias=False):
        """Resolve only native CRM-proven aliases; one read/error per scope."""
        token = scope.removeprefix("projects/") if isinstance(scope, str) else ""
        if not re.fullmatch(r"projects/[A-Za-z0-9_-]+", scope or ""):
            raise ReadError("malformed", "data_project_scope_invalid")
        with self.data_project_lock:
            cached = self.data_project_bindings.get(scope)
            if isinstance(cached, ReadError):
                raise cached
            if cached is not None:
                return copy.deepcopy(cached)
            if not token.isdecimal() and not require_alias:
                return {"scope": scope, "status": "scope_bound", "project_id": token,
                        "project_number": None, "source_requests": []}
            request_id = None
            try:
                url = "https://cloudresourcemanager.googleapis.com/v3/" + scope
                value, request_id = self.read(url, scope, params={})
                number = value.get("name", "") if isinstance(value, dict) else ""
                project_id = value.get("projectId") if isinstance(value, dict) else None
                if (not re.fullmatch(r"projects/[1-9][0-9]*", number)
                        or not isinstance(project_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id)
                        or token not in (number.split("/")[1], project_id)
                        or any(k in value for k in ("items", "projects", "nextPageToken", "_coverage"))):
                    raise ReadError("malformed", "data_project_alias_identity_mismatch")
                receipts = [r for r in getattr(self.transport, "evidence", []) if r.get("id") == request_id]
                if (len(receipts) != 1 or receipts[0].get("scope") != scope
                        or receipts[0].get("method") != "GET" or receipts[0].get("url") != url
                        or receipts[0].get("status") != "collected" or receipts[0].get("http_status") != 200
                        or receipts[0].get("query", {}) != {}):
                    raise ReadError("malformed", "data_project_alias_receipt_unbound")
                binding = {"scope": scope, "status": "collected", "project_id": project_id,
                           "project_number": number.split("/")[1], "source_requests": [request_id]}
                self.data_project_bindings[scope] = binding
                return copy.deepcopy(binding)
            except ReadError as exc:
                if request_id and not getattr(exc, "request_id", None):
                    exc.request_id = request_id
                self.data_project_bindings[scope] = exc
                raise

    def _data_project_matches(self, scope, project):
        if not isinstance(project, str) or not project:
            return False
        binding = self._data_project_binding(scope)
        if project in (binding["project_id"], binding["project_number"]):
            return True
        if project.isdecimal():
            binding = self._data_project_binding(scope, require_alias=True)
            return project == binding["project_number"]
        return False

    def _data_sql_identity(self, scope, item):
        """Check raw native parent identity before any users/provenance join."""
        name = item.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,97}", name):
            raise ReadError("malformed", "sql_instance_identity_missing")
        if "kind" in item and item["kind"] != "sql#instance":
            raise ReadError("malformed", "sql_instance_kind_mismatch")
        for field in ("project", "projectId"):
            if field in item and not self._data_project_matches(scope, item[field]):
                raise ReadError("malformed", "sql_instance_project_mismatch")
        if "selfLink" in item:
            link = urlsplit(item["selfLink"]) if isinstance(item["selfLink"], str) else None
            match = re.fullmatch(r"/sql/v1beta4/projects/([^/]+)/instances/([^/]+)", link.path) if link else None
            if (not link or link.scheme != "https" or link.hostname not in ("sqladmin.googleapis.com", "www.googleapis.com")
                    or link.port not in (None, 443) or link.username is not None or link.password is not None
                    or link.query or link.fragment or not match or match[2] != name
                    or not self._data_project_matches(scope, match[1])):
                raise ReadError("malformed", "sql_instance_self_link_mismatch")
        if "connectionName" in item:
            parts = item["connectionName"].split(":") if isinstance(item["connectionName"], str) else []
            if (len(parts) != 3 or not self._data_project_matches(scope, parts[0]) or parts[2] != name
                    or not parts[1] or "region" in item and parts[1] != item["region"]):
                raise ReadError("malformed", "sql_instance_connection_name_mismatch")
        return item

    def _data_bigquery_identity(self, scope, item, dataset_id=None, table_id=None):
        """Bind every present identity component to the exact native GET parent."""
        table = table_id is not None
        ref = item.get("tableReference" if table else "datasetReference")
        if (not isinstance(ref, dict) or not self._data_project_matches(scope, ref.get("projectId"))
                or not isinstance(ref.get("datasetId"), str)
                or not re.fullmatch(r"[A-Za-z0-9_]{1,1024}", ref["datasetId"])):
            raise ReadError("malformed", "bigquery_reference_identity_mismatch")
        for field in ("projectId", "project"):
            if field in item and not self._data_project_matches(scope, item[field]):
                raise ReadError("malformed", "bigquery_project_identity_mismatch")
        dataset_id = dataset_id if dataset_id is not None else ref["datasetId"]
        if ref["datasetId"] != dataset_id:
            raise ReadError("malformed", "bigquery_dataset_parent_mismatch")
        if table and (not isinstance(ref.get("tableId"), str) or not ref["tableId"]
                or len(ref["tableId"]) > 1024 or ref["tableId"] != table_id
                or any(ord(c) < 32 or c in "/?#\\" for c in table_id)):
            raise ReadError("malformed", "bigquery_table_parent_mismatch")
        suffix = "/datasets/" + quote(dataset_id, safe="")
        opaque = dataset_id
        if table:
            suffix += "/tables/" + quote(table_id, safe="")
            opaque += "." + table_id
        if "id" in item:
            ident = item["id"]
            if not isinstance(ident, str) or ":" not in ident:
                raise ReadError("malformed", "bigquery_native_id_mismatch")
            project, native = ident.split(":", 1)
            if native != opaque or not self._data_project_matches(scope, project):
                raise ReadError("malformed", "bigquery_native_id_mismatch")
        for field, expected in (("datasetId", dataset_id), ("tableId", table_id)):
            if field in item and item[field] != expected:
                raise ReadError("malformed", "bigquery_native_parent_mismatch")
        if "name" in item:
            binding = self._data_project_binding(scope)
            if item["name"] not in {"projects/" + p + suffix for p in
                    (binding["project_id"], binding["project_number"]) if p is not None}:
                raise ReadError("malformed", "bigquery_native_name_mismatch")
        if "selfLink" in item:
            link = urlsplit(item["selfLink"]) if isinstance(item["selfLink"], str) else None
            match = re.fullmatch(r"/bigquery/v2/projects/([^/]+)(/.*)", link.path) if link else None
            if (not link or link.scheme != "https" or link.hostname not in ("bigquery.googleapis.com", "www.googleapis.com")
                    or link.port not in (None, 443) or link.username is not None or link.password is not None
                    or link.query or link.fragment or not match or match[2] != suffix
                    or not self._data_project_matches(scope, match[1])):
                raise ReadError("malformed", "bigquery_self_link_mismatch")
        return dataset_id

    def default_page_size(self, url, method="GET"):
        """Explicit page_size keeps its existing bound; otherwise use the
        documented maximum of endpoints known to accept it, else 100."""
        if "page_size" in self.options:
            return min(self.page_size, 500 if "compute.googleapis.com" in url else 1000)
        return endpoint_page_size(url, method) or self.page_size

    def pages(self, url, scope, *, key="items", params=None, body=None, method="GET", aggregate=None,
              single=False, transform=None, operation=None, page_size_key="pageSize", response_validator=None):
        params = dict(params or {})
        if not single and page_size_key:
            params.setdefault(page_size_key, min(self.page_size, 500 if "compute.googleapis.com" in url else 1000))
        seen = set()
        for page in count():
            data, request_id = self.read(url, scope, params=params, body=body, method=method, operation=operation)
            def malformed(code):
                error = ReadError("malformed", code)
                error.request_id = request_id
                return error
            if not isinstance(data, dict):
                raise malformed("malformed_response")
            if response_validator is not None:
                try:
                    response_validator(data)
                except ReadError as exc:
                    exc.request_id = request_id
                    raise
            incomplete = isinstance(data.get("warning"), dict) and data["warning"].get("code") not in (None, "NO_RESULTS_ON_PAGE")
            items = [data] if single else data.get("items" if aggregate else key, {} if aggregate else [])
            if aggregate:
                if not isinstance(items, dict):
                    raise malformed("malformed_aggregated_list")
                flattened = []
                for location, group in sorted(items.items()):
                    if not isinstance(group, dict) or not isinstance(group.get(aggregate, []), list):
                        raise malformed("malformed_aggregated_list")
                    if any(not isinstance(entry, dict) for entry in group.get(aggregate, [])):
                        raise malformed("malformed_aggregated_list")
                    if isinstance(group.get("warning"), dict) and group["warning"].get("code") not in (None, "NO_RESULTS_ON_PAGE"):
                        incomplete = True
                    flattened.extend({**x, "_aggregated_scope": location} for x in group.get(aggregate, []))
                items = flattened
            if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
                raise malformed("malformed_list")
            if transform:
                try:
                    items = [transform(item) for item in items]
                except ReadError as exc:
                    exc.request_id = request_id
                    raise
            yield items, request_id
            if incomplete:
                raise ReadError("unavailable", "partial_api_warning")
            if data.get("unreachables") or data.get("unreachable") or data.get("missingZones") or data.get("failedLocations") or data.get("failedLocation"):
                raise ReadError("unavailable", "unreachable_locations")
            token = data.get("nextPageToken")
            if token is not None and not isinstance(token, str):
                raise ReadError('malformed', 'malformed_pagination_token')
            if single or not token:
                return
            if not isinstance(token, str) or token in seen:
                raise ReadError("malformed", "repeated_pagination_token")
            seen.add(token)
            if self.max_pages is not None and page + 1 >= self.max_pages:
                raise ReadError("unavailable", "page_limit")
            if body is not None:
                body = {**body, "pageToken": token}
            else:
                params["pageToken"] = token

    def envelope(self, kind, scope, service, fetch):
        items, source_requests = {}, []
        iam_by_native_id = {}
        state, error, service_state = "collected", None, None
        try:
            if kind in CONTENT_ONLY_TYPES and not (
                    self.options.get('content_secret_scans') is True
                    and isinstance(self.options.get('_content_secret_scan_kinds'), list)
                    and kind in self.options['_content_secret_scan_kinds']):
                raise ReadError('unavailable', 'content_secret_inspection_not_enabled')
            for page, request_id in fetch():
                source_requests.append(request_id)
                for raw in page:
                    item = sanitize(raw)
                    rid = item_identity(kind, scope, item)
                    if rid is None:
                        from peaso.snapshot import digest
                        rid = digest(item)
                    native_id = rid
                    if kind == "iam_policy":
                        # Keep every observation, but a repeated same-authority
                        # identity is incomplete inventory even when payloads agree.
                        prior = iam_by_native_id.get(native_id, [])
                        if len(prior) == 1 and _iam_identical_direct_root(scope, prior[0], item):
                            refs = prior[0]["_provenance"]["source_requests"]
                            prior[0]["_provenance"]["source_requests"] = sorted(set([*refs, request_id]))
                            continue
                        if prior and not (len(prior) == 1 and
                                          _iam_distinct_root_views(scope, prior[0], item)):
                            error = {"kind": "malformed", "code": "conflicting_iam_policy_identity"}
                        if rid in items:
                            ordinal = 2
                            while f"{rid}#observation-{ordinal}" in items:
                                ordinal += 1
                            rid = f"{rid}#observation-{ordinal}"
                    elif rid in items:
                        if kind == "iam_role":
                            raise ReadError("malformed", "duplicate_iam_role_identity")
                        if kind == "project":
                            raise ReadError("malformed", "duplicate_project_identity")
                        if kind == "bucket":
                            # A repeated list identity makes ACL absence ambiguous.
                            raise ReadError("malformed", "duplicate_bucket_identity")
                        if kind in ("ssl_policy", "service_usage", "monitoring_notification_channel",
                                    "monitoring_alert_policy", "logging_metric"):
                            excluded = {"_resource_id", "native_id", "_provenance", "_relationships",
                                        "_aggregated_scope", "_representation"}
                            previous = {key: value for key, value in items[rid].items() if key not in excluded}
                            current = {key: value for key, value in item.items() if key not in excluded}
                            if previous != current:
                                raise ReadError("malformed", "conflicting_" + kind + "_identity")
                            refs = items[rid]["_provenance"]["source_requests"]
                            items[rid]["_provenance"]["source_requests"] = sorted(set([*refs, request_id]))
                        if kind == 'log_entry':
                            excluded = {'_resource_id', 'native_id', '_provenance', '_relationships'}
                            previous = {key: value for key, value in items[rid].items() if key not in excluded}
                            current = {key: value for key, value in item.items() if key not in excluded}
                            if previous != current:
                                raise ReadError('malformed', 'conflicting_audit_metadata_identity')
                        continue
                    with self.lock:
                        identity = (kind, scope, rid)
                        if identity not in self.seen_items:
                            if self.max_items is not None and self.total_items >= self.max_items:
                                raise ReadError("unavailable", "resource_limit")
                            self.seen_items.add(identity)
                            self.total_items += 1
                    item["_resource_id"] = rid
                    item["native_id"] = native_id
                    details = [ref for detail in item.get("_coverage", {}).values()
                               if isinstance(detail, dict)
                               for ref in detail.get("source_requests", [])]
                    if kind in ("project", "workbench_instance"):
                        source_requests.extend(details)
                    representation = item.pop("_representation", None)
                    item["_provenance"] = {"source_requests": sorted(set([request_id, *details])), "scope": scope,
                                           "collected_at": self.read_time}
                    if kind in selected_job_source_runtime.KINDS:
                        selected_job_source_runtime.preserve_capture(item, raw, self.transport)
                    if kind == workbench_source_runtime.KIND:
                        workbench_source_runtime.preserve_capture(item, raw, self.transport)
                    # "full" asserts that the API returned the complete resource
                    # representation (no field mask/partial projection), so a
                    # documented omitted-when-unset field may be read as unset.
                    if representation in ("full", "partial"):
                        item["_provenance"]["representation"] = representation
                    if kind == "bigquery_table" and item.pop("_schema_full", False) is True:
                        item["_provenance"]["schema_full"] = True
                    item["_relationships"] = relationships(item)
                    items[rid] = item
                    if kind == "iam_policy":
                        iam_by_native_id.setdefault(native_id, []).append(item)
        except ReadError as exc:
            state, error = exc.status, {"kind": exc.status, **exc.error}
            if getattr(exc, "request_id", None):
                source_requests.append(exc.request_id)
            if exc.error.get("reason") == "SERVICE_DISABLED" and exc.error.get("consumer") == scope:
                # A disabled API cannot inventory retained resources (for example,
                # Cloud Storage buckets or BigQuery datasets). Preserve the error.
                service_state = {"state": "disabled", "reason": "SERVICE_DISABLED", "service": exc.error.get("service"),
                    "consumer": scope, "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}
        except Exception:
            state, error = "unavailable", {"kind": "unavailable", "code": "collector_error"}
        if error and items:
            state = "partial"
        if state == "collected" and not items:
            state = "empty"
        result = {"type": kind, "scope": scope, "service": service, "status": wire_status(state),
            "coverage_status": state, "items": list(items.values()), "source_requests": sorted(set(source_requests))}
        if error:
            result["error"] = error
        if service_state:
            result["service_state"] = service_state
        return result

    def add(self, kind, scope, service, fetch):
        saved = None
        lookup = self.resume_collection_lookup
        key = (kind, scope)
        if lookup is not None and scope != "discovery":
            with self.lock:
                if key in self._resumed_collection_keys:
                    return self.collections[key]
                if key not in self.collections:
                    saved = lookup(kind, scope, service)
                    if saved is not None:
                        if (not isinstance(saved, dict) or saved.get("type") != kind
                                or saved.get("scope") != scope or saved.get("service") != service
                                or saved.get("status") not in ("collected", "empty")
                                or saved.get("coverage_status", saved["status"]) != saved["status"]
                                or saved.get("error") or not isinstance(saved.get("items"), list)
                                or not isinstance(saved.get("source_requests", []), list)):
                            raise ValueError("Invalid resumed native collection")
                        saved = copy.deepcopy(saved)
                        self.collections[key] = saved
                        self._resumed_collection_keys.add(key)
        if saved is not None:
            from peaso.collection_events import emit_collection
            emit_collection(self.collection_callback, saved)
            self.progress(scope=scope)
            return saved
        envelope = self.envelope(kind, scope, service, fetch)
        with self.lock:
            if key in self._resumed_collection_keys:
                return self.collections[key]
            previous = self.collections.get(key)
            if previous:
                output = {x["_resource_id"]: x for x in previous["items"]}
                iam_by_native_id = {}
                iam_collision = False
                if kind == "iam_policy":
                    for row in output.values():
                        iam_by_native_id.setdefault(row["native_id"], []).append(row)
                for item in envelope["items"]:
                    rid = item["_resource_id"]
                    if kind == "iam_policy":
                        prior = iam_by_native_id.get(item["native_id"], [])
                        if len(prior) == 1 and _iam_identical_direct_root(scope, prior[0], item):
                            refs = prior[0]["_provenance"]["source_requests"]
                            prior[0]["_provenance"]["source_requests"] = sorted(set(
                                [*refs, *item["_provenance"]["source_requests"]]))
                            continue
                        if prior and not (len(prior) == 1 and
                                          _iam_distinct_root_views(scope, prior[0], item)):
                            iam_collision = True
                        if rid in output:
                            ordinal = 2
                            native_id = item["native_id"]
                            while f"{native_id}#observation-{ordinal}" in output:
                                ordinal += 1
                            rid = f"{native_id}#observation-{ordinal}"
                            item["_resource_id"] = rid
                    if kind == "iam_role" and rid in output:
                        envelope["error"] = {"kind": "malformed", "code": "duplicate_iam_role_identity"}
                    if kind in ("ssl_policy", "service_usage", "monitoring_notification_channel",
                                    "monitoring_alert_policy", "logging_metric") and rid in output:
                        excluded = {"_resource_id", "native_id", "_provenance", "_relationships",
                                    "_aggregated_scope", "_representation"}
                        prior = {key: value for key, value in output[rid].items() if key not in excluded}
                        current = {key: value for key, value in item.items() if key not in excluded}
                        if prior != current:
                            if not previous.get("error"):
                                envelope.setdefault("error", {"kind": "malformed",
                                    "code": "conflicting_" + kind + "_identity"})
                        else:
                            refs = output[rid]["_provenance"]["source_requests"]
                            output[rid]["_provenance"]["source_requests"] = sorted(set(
                                [*refs, *item["_provenance"]["source_requests"]]))
                        continue
                    output[rid] = item
                    if kind == "iam_policy":
                        iam_by_native_id.setdefault(item["native_id"], []).append(item)
                envelope["items"] = list(output.values())
                envelope["source_requests"] = sorted(set(previous["source_requests"] + envelope["source_requests"]))
                if kind == "iam_policy":
                    collision = {"kind": "malformed", "code": "conflicting_iam_policy_identity"}
                    causes = [error for error in (previous.get("error"), envelope.get("error"))
                              if error and error != collision]
                    if causes:
                        # A read, pagination, or resource failure has stronger
                        # authority than identity classification of retained rows.
                        # Keep both substantive causes if separate adds failed.
                        envelope["error"] = copy.deepcopy(causes[0])
                        if len(causes) > 1 and causes[1] != causes[0]:
                            envelope["error"]["additional_errors"] = copy.deepcopy(causes[1:])
                    elif iam_collision or previous.get("error") or envelope.get("error"):
                        envelope["error"] = collision
                if previous.get("error") or envelope.get("error"):
                    envelope["error"] = envelope.get("error") or previous["error"]
                    state = "partial" if output else envelope["error"]["kind"]
                    envelope["status"], envelope["coverage_status"] = wire_status(state), state
                elif output:
                    envelope["status"] = envelope["coverage_status"] = "collected"
            self.collections[key] = envelope
        from peaso.collection_events import emit_collection
        emit_collection(self.collection_callback, envelope)
        self.progress(scope=scope)
        return envelope

    def key_activity(self, scope):
        """Policy Analyzer serviceAccountKeyLastAuthentication keyed by key resource name.

        Returns (activities, coverage). A key listed without lastAuthenticatedTime was
        not used in the observation period; an unlisted key stays unknown."""
        activities, requests = {}, []
        try:
            for items, request_id in self.pages(f"https://policyanalyzer.googleapis.com/v1/{scope}/locations/global/activityTypes/"
                                                "serviceAccountKeyLastAuthentication/activities:query", scope, key="activities"):
                requests.append(request_id)
                for row in items:
                    name, period, body = row.get("fullResourceName"), row.get("observationPeriod"), row.get("activity", {})
                    if not isinstance(name, str) or not isinstance(period, dict) or not isinstance(period.get("endTime"), str) \
                            or not isinstance(body, dict):
                        raise ReadError("malformed", "malformed_activity")
                    from peaso.gcp_iam_usage_contract import project_activity
                    tokens = {scope.split('/')[1]}
                    resource_project = name.removeprefix('//iam.googleapis.com/').split('/')[1]
                    if resource_project not in tokens:
                        binding = self._data_project_binding(scope, require_alias=True)
                        tokens.update(str(binding[key]) for key in ('project_id', 'project_number'))
                    fact = project_activity(row, scope, 'service_account_key', tokens)
                    if body.get("lastAuthenticatedTime") is not None:
                        fact["lastAuthenticatedTime"] = body["lastAuthenticatedTime"]
                    if name.removeprefix("//iam.googleapis.com/") in activities:
                        raise ReadError("malformed", "duplicate_key_activity")
                    activities[name.removeprefix("//iam.googleapis.com/")] = (fact, request_id)
            return activities, {"status": "collected", "collection_status": "collected", "source_requests": requests}
        except ReadError as exc:
            return None, {"status": exc.status, "collection_status": wire_status(exc.status), "error": exc.error,
                "source_requests": requests + ([exc.request_id] if getattr(exc, "request_id", None) else [])}
        except Exception:
            # Activity is supplementary: it never hides the key inventory.
            return None, {"status": "unavailable", "collection_status": "unknown", "error": {"code": "collector_error"},
                "source_requests": requests}

    @staticmethod
    def attach_key_activity(key, activity):
        activities, coverage = activity
        output = {**key, "_coverage": dict(key.get("_coverage", {}))}
        match = activities.get(key.get("name")) if activities is not None else None
        if match:
            output["_activity"] = match[0]
            output["_coverage"]["_activity"] = {**coverage, "source_requests": [match[1]],
                "semantics": "Policy Analyzer key last authentication; listed without lastAuthenticatedTime means unused in the observation period"}
        else:
            output["_coverage"]["_activity"] = {**coverage, "status": coverage["status"] if activities is None else "not_observed",
                "semantics": "Key absent from Policy Analyzer results: usage unknown"}
        return output

    def hydrate(self, item, field, url, scope, *, params=None, body=None, method="GET", identity_validator=None):
        output = dict(item)
        coverage = output.setdefault("_coverage", {})
        try:
            value, request_id = self.read(url, scope, params=params, body=body, method=method)
            if not isinstance(value, dict):
                raise ReadError("malformed", "malformed_response")
            if identity_validator is not None:
                identity_validator(value)
            # An omitted repeated binding field in a successful IAM Policy is
            # the API's empty list, distinct from denied/malformed hydration.
            if field == "iamPolicy":
                value = {"bindings": [], **value}
            output[field] = sanitize(value)
            coverage[field] = {"status": "collected", "collection_status": "collected", "source_requests": [request_id]}
        except ReadError as exc:
            coverage[field] = {"status": exc.status, "collection_status": wire_status(exc.status), "error": exc.error,
                "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}
            output[field] = {"collection_status": wire_status(exc.status), "error": exc.error}
        return output

    def location_fanout(self, locations, fetch_one):
        """Order-preserving per-location fan-out; see gcp_fanout."""
        return location_fanout(self, locations, fetch_one)

    def parallel(self, function, items):
        """Order-preserving bounded fan-out for leaf per-item hydration reads."""
        items = list(items)
        if len(items) <= 1 or self.workers == 1:
            return [function(item) for item in items]
        return list(self.hydration_pool.map(function, items))

    def items(self, kind):
        return [(scope, item) for (item_kind, scope), collection in sorted(self.collections.items())
                if item_kind == kind for item in collection["items"]]

    def run_jobs(self, jobs):
        # Executor.map consumes bounded scope/type jobs, never one future per asset.
        jobs = list(jobs)
        if self.resume_collection_lookup is not None:
            # One complete saved envelope owns the kind/scope even when two
            # native views schedule jobs for it in the same parallel batch.
            for kind, scope, service, fetch in jobs:
                key = (kind, scope)
                if (scope != "discovery" and key not in self.collections
                        and self.resume_collection_lookup(kind, scope, service) is not None):
                    self.add(kind, scope, service, fetch)
            jobs = [job for job in jobs if (job[0], job[1]) not in self._resumed_collection_keys]
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="gcp-read") as pool:
            list(pool.map(lambda job: self.add(*job), jobs))

    def discover(self):
        if "*" in self.scopes or self.options.get("all_projects"):
            def search_projects():
                from peaso.gcp_platform import approved_project
                for page, request_id in self.pages(
                        "https://cloudresourcemanager.googleapis.com/v3/projects:search", "discovery", key="projects",
                        params={"query": "state:ACTIVE"}):
                    if self.platform_proof_label:
                        page = [item for item in page if approved_project(item, self.platform_proof_label)]
                    yield page, request_id
            result = self.add("project", "discovery", "cloudresourcemanager", search_projects)
            if result["coverage_status"] not in ("collected", "empty"):
                self.scope_errors.append({"scope": "discovery", "operation": "projects:search", "status": result["coverage_status"],
                    "error": result.get("error"), "source_requests": result["source_requests"]})
            discovered = [normalize_scope(item.get("projectId") or item["name"]) for item in result["items"]]
            if self.platform_proof_label:
                selected = [scope for scope in self.scopes if scope != "*"]
                if any(scope not in discovered for scope in selected):
                    raise ReadError("denied", "selected_project_not_verified")
                self.scopes = discovered
                if not self.scopes:
                    raise ReadError("denied", "no_verified_customer_projects")
            else:
                self.scopes = [s for s in self.scopes if s != "*"] + discovered
        elif self.platform_proof_label:
            from peaso.gcp_platform import approved_project
            for scope in self.scopes:
                try:
                    project, _ = self.read(f"https://cloudresourcemanager.googleapis.com/v3/{scope}", scope)
                except ReadError:
                    raise ReadError("denied", "selected_project_not_verified") from None
                if not approved_project(project, self.platform_proof_label):
                    raise ReadError("denied", "selected_project_not_verified")
        if self.options.get("discover_projects"):
            for scope in self.scopes[:]:
                if not scope.startswith(("organizations/", "folders/")):
                    continue
                result = self.add("project", scope, "cloudasset", lambda scope=scope: self.pages(
                    f"https://cloudasset.googleapis.com/v1/{scope}/assets", scope, key="assets",
                    params={"assetTypes": ["cloudresourcemanager.googleapis.com/Project"], "contentType": "RESOURCE"},
                    transform=lambda asset: {**asset.get("resource", {}).get("data", {}), "_asset_name": asset.get("name")}))
                for item in result["items"]:
                    project = item.get("projectId") or item.get("project_id")
                    if project:
                        self.scopes.append(normalize_scope(project))
        if self.options.get("all_hierarchy"):
            for kind, key in (("organization", "organizations"), ("folder", "folders")):
                result = self.add(kind, "discovery", "cloudresourcemanager", lambda key=key: self.pages(
                    f"https://cloudresourcemanager.googleapis.com/v3/{key}:search", "discovery", key=key))
                if result["coverage_status"] not in ("collected", "empty"):
                    self.scope_errors.append({"scope": "discovery", "operation": key + ":search", "status": result["coverage_status"],
                        "error": result.get("error"), "source_requests": result["source_requests"]})
                self.scopes.extend(normalize_scope(item["name"]) for item in result["items"])
        self.scopes = list(dict.fromkeys(s for s in self.scopes if not s.startswith("projects/") or
                                        self.allowed is None or s in self.allowed))
        # Remove discovery evidence about projects excluded by restrictions.
        if self.allowed is not None:
            for (kind, _), collection in self.collections.items():
                if kind == "project":
                    collection["items"] = [x for x in collection["items"] if normalize_scope(
                        x.get("projectId") or x.get("project_id") or x.get("name", "excluded")) in self.allowed]
                    if not collection["items"] and collection["status"] == "collected":
                        collection["status"] = collection["coverage_status"] = "empty"
        if self.max_scopes is not None and len(self.scopes) > self.max_scopes:
            self.scopes = self.scopes[:self.max_scopes]
            self.scope_errors.append({"code": "scope_limit", "status": "partial"})

    def alias_identity_only(self):
        return (self.api_key_alias_mode and "project" not in self.wanted and
                self.needed == {"api_key", "service_usage", "project"})

    def scope_jobs(self, scope):
        jobs = []
        from .gcp_additional_literal_secret_indicators import prepare_scope, workflow_jobs, finish_scheduler_scrub
        prepare_scope(self, scope)
        jobs.extend(workflow_jobs(self, scope))
        from .gcp_log_secret_indicators import scope_jobs as log_secret_jobs
        jobs.extend(log_secret_jobs(self, scope))
        from .gcp_native_evidence import scope_jobs as native_evidence_jobs
        jobs.extend(native_evidence_jobs(self, scope))
        from .gcp_os_patch_native import scope_jobs as os_patch_jobs
        jobs.extend(os_patch_jobs(self, scope))
        from .gcp_network_catalog import scope_jobs as network_catalog_jobs
        jobs.extend(network_catalog_jobs(self, scope))
        from .gcp_workstations import scope_jobs as workstations_jobs
        jobs.extend(workstations_jobs(self, scope))
        def add(kind, service, factory):
            if kind in self.needed:
                jobs.append((kind, scope, service, factory))
        crm = "https://cloudresourcemanager.googleapis.com"
        scope_type = {"projects": "project", "organizations": "organization", "folders": "folder"}[scope.split("/")[0]]
        def scope_metadata():
            for items, request_id in self.pages(f"{crm}/v3/{scope}", scope, single=True):
                if scope_type == "project" and not self.alias_identity_only():
                    hydrated = []
                    for item in items:
                        item = self.hydrate(item, "computeConfig", f"https://compute.googleapis.com/compute/v1/{scope}", scope)
                        config = item.get("computeConfig", {})
                        for field in ("commonInstanceMetadata", "defaultServiceAccount", "xpnProjectStatus"):
                            if field in config:
                                item[field] = config[field]
                        if self.options.get("metrics_scopes", True):
                            item = self.metrics_scopes(item, scope)
                        hydrated.append(item)
                    items = hydrated
                yield items, request_id
        add(scope_type, "cloudresourcemanager", scope_metadata)
        def policies():
            failure = None
            try:
                for items, request_id in self.pages(f"{crm}/v3/{scope}:getIamPolicy", scope, single=True, method="POST",
                    body={"options": {"requestedPolicyVersion": 3}}):
                    # getIamPolicy returns the whole Policy: omitted auditConfigs
                    # means the resource itself declares no audit configuration.
                    try:
                        yield [{"name": scope, "bindings": [], **_validate_iam_policy(item),
                                "_representation": "full"} for item in items], request_id
                    except ReadError as exc:
                        exc.request_id = request_id
                        raise
            except ReadError as exc:
                failure = exc
            if self.options.get("resource_iam", True) and not (self.allowed is not None and scope_type != "project"):
                def cai_policy(item):
                    if not isinstance(item, dict):
                        raise ReadError("malformed", "malformed_cai_iam_policy")
                    policy = _validate_iam_policy(item.get("policy"))
                    return {"name": item.get("resource"), **policy,
                        "assetType": item.get("assetType"), "project": item.get("project"),
                        "folders": item.get("folders", []), "_representation": "partial"}
                yield from self.pages(f"https://cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies", scope,
                    key="results", transform=cai_policy)
            if failure:
                raise failure
        add("iam_policy", "iam/cloudasset", policies)
        attachment = quote("cloudresourcemanager.googleapis.com/" + scope, safe="")
        def deny_policies():
            for items, request_id in self.pages(f"https://iam.googleapis.com/v2/policies/{attachment}/denypolicies", scope, key="policies"):
                hydrated = []
                for item in items:
                    if "rules" not in item and item.get("name"):
                        name = item['name']
                        # Attachment point slashes are encoded within the policy
                        # name, not interpreted as extra API path components.
                        item = self.hydrate(item, "policyDetails", f"https://iam.googleapis.com/v2/{name}", scope)
                        if "rules" in item.get("policyDetails", {}):
                            item["rules"] = item["policyDetails"]["rules"]
                    hydrated.append(item)
                yield hydrated, request_id
        add("iam_deny_policy", "iam", deny_policies)
        add("policy_binding", "iam", lambda: self.pages(f"https://iam.googleapis.com/v3/{scope}/locations/global/policyBindings",
            scope, key="policyBindings"))
        if scope_type == "organization":
            add("principal_access_boundary_policy", "iam", lambda: self.pages(
                f"https://iam.googleapis.com/v3/{scope}/locations/global/principalAccessBoundaryPolicies", scope,
                key="principalAccessBoundaryPolicies"))
        if scope_type in ("project", "organization"):
            add("iam_role", "iam", lambda: self.pages(f"https://iam.googleapis.com/v1/{scope}/roles", scope,
                key="roles", params={"view": "FULL", "showDeleted": "true"}))
        if scope_type == "project":
            def selected_builtin_roles():
                for role in ("roles/editor", "roles/resourcemanager.projectDeleter",
                             "roles/deploymentmanager.admin", "roles/domains.editor",
                             "roles/eventarc.serviceAgent", "roles/eventarc.developer",
                             "roles/eventarc.messageBusUser", "roles/eventarc.admin",
                             "roles/eventarc.editor", "roles/iam.serviceAccountTokenCreator",
                             "roles/iam.securityAdmin", "roles/discoveryengine.agentspaceViewer",
                             "roles/discoveryengine.agentspaceAdmin", "roles/krmapihosting.admin",
                             "roles/logging.viewAccessor", "roles/resourcemanager.folderAdmin",
                             "roles/run.developer", "roles/run.jobsExecutorWithOverrides"):
                    yield from self.pages("https://iam.googleapis.com/v1/" + role,
                                          scope, single=True)
            add("iam_role_builtin", "iam", selected_builtin_roles)
        if "asset" in self.needed and not (self.allowed is not None and scope_type != "project"):
            asset_types = self.options.get("asset_types")
            if asset_types is not None and (not isinstance(asset_types, list) or len(asset_types) > 100 or
                                           any(not isinstance(x, str) for x in asset_types)):
                raise ValueError("asset_types must be a list of at most 100 names/patterns")
            params = {"contentType": "RESOURCE", "readTime": self.read_time}
            if asset_types:
                params["assetTypes"] = asset_types
            from .gcp_native_evidence import asset_pages
            add("asset", "cloudasset", lambda: asset_pages(self, scope, 'asset', params))
        add("log_sink", "logging", lambda: self.pages(f"https://logging.googleapis.com/v2/{scope}/sinks", scope, key="sinks",
            transform=lambda item: {**item, "sinkId": item.get("name"), "name": f"{scope}/sinks/{item['name']}"}))
        add("essential_contact", "essentialcontacts", lambda: self.pages(f"https://essentialcontacts.googleapis.com/v1/{scope}/contacts",
            scope, key="contacts", params={"fields": "contacts(name,email,notificationCategorySubscriptions,validationState,languageTag),nextPageToken"}))
        add("access_approval_settings", "accessapproval", lambda: self.pages(f"https://accessapproval.googleapis.com/v1/{scope}/accessApprovalSettings",
            scope, single=True, params={"fields": "name,notificationEmails,enrolledServices,enrolledAncestor,activeKeyVersion,ancestorHasActiveKeyVersion"}))
        def billing_accounts():
            if scope_type == "organization":
                for items, request_id in self.pages("https://cloudbilling.googleapis.com/v1/billingAccounts", scope, key="billingAccounts",
                    params={"parent": scope, "fields": "billingAccounts(name,displayName,open,parent),nextPageToken", "pageSize": min(self.page_size, 100)}):
                    yield self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://cloudbilling.googleapis.com/v1/{item['name']}:getIamPolicy", scope,
                        params={"options.requestedPolicyVersion": 3}), items), request_id
            elif scope_type == "project":
                info, request_id = self.read(f"https://cloudbilling.googleapis.com/v1/{scope}/billingInfo", scope,
                    params={"fields": "name,projectId,billingAccountName,billingEnabled"})
                name = info.get("billingAccountName")
                if not name:
                    yield [], request_id
                    return
                if not isinstance(name, str) or not re.fullmatch(r"billingAccounts/[A-Za-z0-9-]+", name):
                    raise ReadError("malformed", "invalid_billing_account_reference")
                item = self.hydrate({"name": name, "linkedProject": scope, "billingEnabled": info.get("billingEnabled")}, "accountDetails",
                    f"https://cloudbilling.googleapis.com/v1/{name}", scope, params={"fields": "name,displayName,open,parent"})
                if item["_coverage"]["accountDetails"]["status"] == "collected":
                    item.update(item.pop("accountDetails"))
                yield [self.hydrate(item, "iamPolicy", f"https://cloudbilling.googleapis.com/v1/{name}:getIamPolicy", scope,
                    params={"options.requestedPolicyVersion": 3})], request_id
        if scope_type in ("project", "organization"):
            add("billing_account", "cloudbilling", billing_accounts)
        if scope_type == "organization":
            add("workforce_pool", "iam", lambda: self.pages("https://iam.googleapis.com/v1/locations/global/workforcePools",
                scope, key="workforcePools", params={"parent": scope, "showDeleted": "true"}))
        if scope_type in ("organization", "folder"):
            def hierarchical_firewalls():
                yield from self.pages("https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies",
                    scope, params={"parentId": scope}, page_size_key="maxResults")
            add("firewall_policy", "compute", hierarchical_firewalls)
            def firewall_associations():
                def validate_response(data):
                    # The public REST schema names the first value; the live v1
                    # endpoint returns the second for an empty association list.
                    if data.get("kind") not in {
                        "compute#FirewallPoliciesListAssociations",
                        "compute#firewallPoliciesListAssociationsResponse",
                    }:
                        raise ReadError("malformed", "malformed_firewall_association_list")
                yield from self.pages("https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies/listAssociations",
                    scope, key="associations", params={"targetResource": scope}, page_size_key=None,
                    response_validator=validate_response)
            add("firewall_policy_association", "compute", firewall_associations)
        if scope_type == "folder":
            add("iam_role_builtin", "iam", lambda: self.pages(
                "https://iam.googleapis.com/v1/roles/resourcemanager.folderAdmin",
                scope, single=True))
            def folder_grant_constraints():
                for constraint in ("iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"):
                    url = f"https://orgpolicy.googleapis.com/v2/{scope}/policies/{constraint}:getEffectivePolicy"
                    for policies, request_id in self.pages(url, scope, single=True):
                        for policy in policies:
                            if policy.get("name") != f"{scope}/policies/{constraint}":
                                raise ReadError("malformed", "folder_effective_policy_name_mismatch")
                            yield [{**policy, "constraint": constraint}], request_id
            add("folder_policy_grant_constraints", "orgpolicy", folder_grant_constraints)
        if scope_type == "organization":
            def organization_grant_roles():
                for role in ("roles/orgpolicy.policyAdmin", "roles/iam.denyAdmin",
                             "roles/iam.organizationRoleAdmin",
                             "roles/resourcemanager.organizationAdmin"):
                    yield from self.pages("https://iam.googleapis.com/v1/" + role,
                                          scope, single=True)
            add("iam_role_builtin", "iam", organization_grant_roles)
            def organization_grant_constraints():
                for constraint in ("iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"):
                    url = f"https://orgpolicy.googleapis.com/v2/{scope}/policies/{constraint}:getEffectivePolicy"
                    for policies, request_id in self.pages(url, scope, single=True):
                        for policy in policies:
                            if policy.get("name") != f"{scope}/policies/{constraint}":
                                raise ReadError("malformed", "organization_effective_policy_name_mismatch")
                            yield [{**policy, "constraint": constraint}], request_id
            add("organization_policy_grant_constraints", "orgpolicy", organization_grant_constraints)
        for kind, suffix, key in (("recommendation", "recommenders/google.iam.policy.Recommender/recommendations", "recommendations"),
                                 ("insight", "insightTypes/google.iam.policy.Insight/insights", "insights")):
            def rec_pages(suffix=suffix, key=key):
                locations = self.options.get("recommender_locations", ["global"])
                if not isinstance(locations, list) or len(locations) > 50 or any(not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                    raise ValueError("invalid recommender_locations")
                for location in locations:
                    for rows, request_id in self.pages(f"https://recommender.googleapis.com/v1/{scope}/locations/{location}/{suffix}", scope, key=key):
                        if key == "insights":
                            for row in rows:
                                match = re.fullmatch(r"((?:projects|folders|organizations)/[^/]+)/locations/" + re.escape(location) +
                                    r"/insightTypes/google\.iam\.policy\.Insight/insights/[^/?#]+", row.get("name", ""))
                                if not match:
                                    raise ReadError("malformed", "invalid_policy_insight_identity")
                                authorities = {scope}
                                if scope_type == "project" and match[1] not in authorities:
                                    binding = self._data_project_binding(scope, require_alias=True)
                                    authorities.update("projects/" + str(binding[field]) for field in ("project_id", "project_number"))
                                if match[1] not in authorities:
                                    raise ReadError("malformed", "foreign_policy_insight_identity")
                        yield rows, request_id
            add(kind, "recommender", rec_pages)
        if scope_type != "project":
            return jobs
        def unused_account_insights():
            suffix = '/locations/global/insightTypes/google.iam.serviceAccount.Insight/insights'
            for rows, request_id in self.pages('https://recommender.googleapis.com/v1/' + scope + suffix,
                                               scope, key='insights'):
                for row in rows:
                    name = row.get('name') if isinstance(row, dict) else None
                    match = re.fullmatch(r'projects/([^/]+)/locations/global/insightTypes/google\.iam\.serviceAccount\.Insight/insights/[^/?#]+', name or '')
                    if not match:
                        raise ReadError('malformed', 'malformed_service_account_insight')
                    tokens = {scope.split('/')[1]}
                    if match.group(1) not in tokens:
                        binding = self._data_project_binding(scope, require_alias=True)
                        tokens.update(str(binding[key]) for key in ('project_id', 'project_number'))
                    if match.group(1) not in tokens:
                        raise ReadError('malformed', 'foreign_service_account_insight')
                yield rows, request_id
        add('service_account_insight', 'recommender', unused_account_insights)
        project = quote(scope.split("/", 1)[1], safe="")
        compute = f"https://compute.googleapis.com/compute/v1/projects/{project}"
        add("service_usage", "serviceusage", lambda: self.pages(
            f"https://serviceusage.googleapis.com/v1/{scope}/services", scope, key="services",
            params={"pageSize": min(self.page_size if "page_size" in self.options else 200, 200)}))
        def bigtable_instances():
            for items, request_id in self.pages(f"https://bigtableadmin.googleapis.com/v2/{scope}/instances", scope,
                key="instances", page_size_key=None, params={"fields": "instances(name,displayName,state,type,labels),failedLocations"}):
                yield self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://bigtableadmin.googleapis.com/v2/{item['name']}:getIamPolicy", scope,
                    method="POST", body={"options": {"requestedPolicyVersion": 3}}), items), request_id
        add("bigtable_instance", "bigtableadmin", bigtable_instances)
        def alloydb_clusters():
            locations = self.options.get("alloydb_locations", self.options.get("regions"))
            if locations is None:
                locations = []
                for items, request_id in self.pages(f"https://alloydb.googleapis.com/v1/{scope}/locations", scope, key="locations"):
                    locations.extend(item.get("locationId") or item["name"].rsplit("/", 1)[1] for item in items)
                    yield [], request_id
            if not isinstance(locations, list) or any(not isinstance(location, str) or not re.fullmatch(r"[a-z0-9-]+", location) for location in locations):
                raise ValueError("alloydb_locations must contain valid location IDs")
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), lambda location: self.pages(
                    f"https://alloydb.googleapis.com/v1/{scope}/locations/{location}/clusters", scope,
                    key="clusters", params={"fields": "clusters(name,uid,state,databaseVersion,encryptionInfo,encryptionConfig,networkConfig,labels),nextPageToken,unreachable"})):
                yield from pages
                if exc is not None:
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise failures[0] if failures else exc  # project-wide
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("alloydb_cluster", "alloydb", alloydb_clusters)
        add("logging_metric", "logging", lambda: self.pages(f"https://logging.googleapis.com/v2/{scope}/metrics",
            scope, key="metrics", params={"fields": "metrics(name,filter,disabled,bucketName,labelExtractors,metricDescriptor(type,metricKind,valueType)),nextPageToken"},
            transform=lambda item: {**item, "metricId": item.get("name"), "name": f"{scope}/metrics/{item['name']}"}))
        add("monitoring_alert_policy", "monitoring", lambda: self.pages(f"https://monitoring.googleapis.com/v3/{scope}/alertPolicies",
            scope, key="alertPolicies", params={"fields": "alertPolicies(name,enabled,validity,conditions,notificationChannels,combiner),nextPageToken"}))
        if scope_type == "project":
            add("monitoring_notification_channel", "monitoring", lambda: self.pages(
                f"https://monitoring.googleapis.com/v3/{scope}/notificationChannels", scope, key="notificationChannels",
                params={"fields": "notificationChannels(name,type,enabled,verificationStatus),nextPageToken"}))
            def effective_org_policies():
                # The response name may use the project's numeric name even when
                # the request uses projectId. Resolve that alias once from an
                # independent, read-only CRM projects.get response, never from
                # the policy payload or its requested-scope wrapper.
                alias_checked, alias_name, alias_error, alias_request = False, None, None, None

                def numeric_project_alias():
                    nonlocal alias_checked, alias_name, alias_error, alias_request
                    if not alias_checked:
                        alias_checked = True
                        try:
                            project, project_request = self.read(f"{crm}/v3/{scope}", scope,
                                                                 operation="projects.get")
                        except ReadError as exc:
                            alias_error = exc
                        else:
                            name = project.get("name") if isinstance(project, dict) else None
                            if (not isinstance(project, dict) or project.get("projectId") != scope.split("/", 1)[1]
                                    or not isinstance(name, str) or not re.fullmatch(r"projects/[1-9][0-9]*", name)):
                                alias_error = ReadError("malformed", "effective_policy_project_alias_mismatch")
                                alias_error.request_id = project_request
                            else:
                                alias_name, alias_request = name, project_request
                    if alias_error is not None:
                        raise alias_error
                    return alias_name

                # getEffectivePolicy evaluates the project's policy merged with
                # its folder/organization ancestors (read-only, orgpolicy.policies.get).
                failures = []
                for constraint in ORG_POLICY_CONSTRAINTS:
                    try:
                        for items, request_id in self.pages(f"https://orgpolicy.googleapis.com/v2/{scope}/policies/"
                                                            f"{constraint}:getEffectivePolicy", scope, single=True):
                            validated = []
                            suffix = "/policies/" + constraint
                            for item in items:
                                name = item.get("name")
                                if not isinstance(name, str) or not name.endswith(suffix):
                                    error = ReadError("malformed", "effective_policy_name_mismatch")
                                    error.request_id = request_id
                                    raise error
                                parent = name[:-len(suffix)]
                                alias = None
                                if parent != scope:
                                    if not re.fullmatch(r"projects/[1-9][0-9]*", parent) or parent != numeric_project_alias():
                                        error = ReadError("malformed", "effective_policy_project_mismatch")
                                        error.request_id = request_id
                                        raise error
                                    alias = {"requested_scope": scope, "project_id": scope.split("/", 1)[1],
                                             "canonical_name": alias_name, "source_operation": "projects.get",
                                             "source_request": alias_request}
                                # Replace any body-supplied alias with this producer-owned CRM proof.
                                safe = {key: value for key, value in item.items() if key != "project_alias"}
                                if alias is not None:
                                    safe["project_alias"] = alias
                                validated.append({**safe, "constraint": constraint, "_representation": "full"})
                            yield validated, request_id
                    except ReadError as exc:
                        failures.append(exc)
                if failures:
                    raise failures[0]
            add("org_policy_effective", "orgpolicy", effective_org_policies)
        def vpc_flow_logs_configs():
            # Network Management VPC Flow Logs configs are a second, independent
            # enablement path beside subnet logConfig. queryOrg returns the
            # organization configs that apply to this project's networks.
            base = f"https://networkmanagement.googleapis.com/v1/{scope}/locations/global/vpcFlowLogsConfigs"
            for items, request_id in self.pages(base, scope, key="vpcFlowLogsConfigs"):
                yield [{**item, "configLevel": "project"} for item in items], request_id
            for items, request_id in self.pages(base + ":queryOrgVpcFlowLogsConfigs", scope, key="vpcFlowLogsConfigs"):
                yield [{**item, "configLevel": "organization"} for item in items], request_id
        add("vpc_flow_logs_config", "networkmanagement", vpc_flow_logs_configs)
        def compute_policy(kind, item):
            # e.g. subnetworks.getIamPolicy (GET, compute.subnetworks.getIamPolicy):
            # a Policy whose empty bindings list is omitted.
            segment, location_field = COMPUTE_IAM[kind]
            if kind == "snapshot":
                link = item.get("selfLink")
                match = re.fullmatch(
                    rf"https://(?:www|compute)\.googleapis\.com/compute/v1/{re.escape(scope)}/"
                    r"(global|regions/[a-z0-9-]+)/snapshots/([a-z][a-z0-9-]*)",
                    link) if isinstance(link, str) else None
                if (not match or item.get("name") != match.group(2)
                        or (match.group(1) == "global" and item.get("region"))
                        or (match.group(1).startswith("regions/") and
                            str(item.get("region") or "").rsplit("/", 1)[-1] != match.group(1).split("/", 1)[1])):
                    return item
                return self.hydrate(item, "iamPolicy", link + "/getIamPolicy", scope,
                                    params={"optionsRequestedPolicyVersion": 3})
            if kind == "disk" and item.get("region") and not item.get("zone"):
                location_field = "region"
            location = "global"
            if location_field:
                value = str(item.get(location_field, "")).rsplit("/", 1)[-1]
                if not re.fullmatch(r"[a-z0-9-]+", value):
                    return item
                location = f"{location_field}s/{value}"
            if not isinstance(item.get("name"), str):
                return item
            return self.hydrate(item, "iamPolicy", f"{compute}/{location}/{segment}/{quote(item['name'], safe='')}/getIamPolicy",
                scope, params={"optionsRequestedPolicyVersion": 3})
        for kind, endpoint, key, aggregated in COMPUTE:
            def compute_list(kind=kind, endpoint=endpoint, key=key, aggregated=aggregated):
                def backend_health(item):
                    output = dict(item)
                    link = item.get("selfLink")
                    expected = (rf"https://(?:www|compute)\.googleapis\.com/compute/v1/projects/"
                        rf"{re.escape(project)}/(?:global|regions/[a-z0-9-]+)/backendServices/[A-Za-z0-9_-]+")
                    if not isinstance(link, str) or not re.fullmatch(expected, link):
                        output["BackendHealth"] = {"collection_status": "unknown", "groups": [],
                            "error": {"code": "backend_service_identity_missing"}}
                        return output
                    groups = []
                    for backend in item.get("backends") or []:
                        group = backend.get("group") if isinstance(backend, dict) else None
                        if not isinstance(group, str) or not re.fullmatch(
                            r"https://(?:www|compute)\.googleapis\.com/compute/v1/projects/"
                            r"[A-Za-z0-9_-]+/(?:zones|regions)/[a-z0-9-]+/"
                            r"(?:instanceGroups|networkEndpointGroups)/[A-Za-z0-9_-]+", group):
                            groups.append({"group": group, "collection_status": "unknown",
                                "error": {"code": "backend_group_identity_missing"}})
                            continue
                        try:
                            result, request_id = self.read(link + "/getHealth", scope,
                                method="POST", body={"group": group})
                            if (not isinstance(result, dict) or not isinstance(result.get("healthStatus", []), list)
                                    or any(not isinstance(status, dict) for status in result.get("healthStatus", []))):
                                raise ReadError("malformed", "backend_health_malformed")
                            groups.append({"group": group, "collection_status": "collected",
                                "source_requests": [request_id], "healthStatus": [
                                    {field: status.get(field) for field in ("instance", "healthState", "ipAddress", "port")
                                     if field in status}
                                    for status in result.get("healthStatus", [])]})
                        except ReadError as exc:
                            groups.append({"group": group, "collection_status": wire_status(exc.status),
                                "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else [],
                                "error": exc.error})
                    status = "collected" if all(group["collection_status"] == "collected" for group in groups) else "partial"
                    output["BackendHealth"] = {"collection_status": status, "groups": groups}
                    output.setdefault("_coverage", {})["BackendHealth"] = {"status": status,
                        "collection_status": status, "source_requests": [request_id for group in groups
                            for request_id in group.get("source_requests", [])]}
                    return output
                for items, request_id in self.pages(
                    f"{compute}/{endpoint}", scope, key=key, aggregate=key if aggregated else None,
                    params={"returnPartialSuccess": "true"} if aggregated else None, page_size_key="maxResults",
                    # Compute list calls carry no field mask: each item is the full resource.
                    transform=lambda item: {**item, "_representation": "full",
                        **({"_proxy_type": endpoint.rsplit("/", 1)[-1]} if kind == "target_proxy" else {})}):
                    if kind in COMPUTE_IAM and self.options.get("compute_resource_iam", True):
                        items = self.parallel(lambda item, kind=kind: compute_policy(kind, item), items)
                    if kind == "backend_service":
                        items = self.parallel(backend_health, items)
                    yield items, request_id
            add(kind, "compute", compute_list)
        def recoverable_snapshots():
            base = f"https://compute.googleapis.com/compute/beta/{scope}/global/recoverableSnapshots"
            for page, request_id in self.pages(base, scope, page_size_key="maxResults"):
                if self.options.get("compute_resource_iam", True):
                    def policy(item):
                        name = item.get("name")
                        if not isinstance(name, str) or not re.fullmatch(r"[a-z]([-a-z0-9]*[a-z0-9])?", name):
                            return item
                        return self.hydrate(item, "iamPolicy", f"{base}/{quote(name, safe='')}/getIamPolicy",
                                            scope, params={"optionsRequestedPolicyVersion": 3})
                    page = self.parallel(policy, page)
                yield [{**item, "_representation": "full"} for item in page], request_id
        if scope_type == "project":
            add("recoverable_snapshot", "compute", recoverable_snapshots)
        def policy_based_routes():
            path = f"https://networkconnectivity.googleapis.com/v1/{scope}/locations/global/policyBasedRoutes"
            for items, request_id in self.pages(path, scope, key="policyBasedRoutes"):
                yield [{**item, "_representation": "full"} for item in items], request_id
        add("policy_based_route", "networkconnectivity", policy_based_routes)
        def security_policies():
            regions = self.options.get("security_policy_regions")
            if regions is None:
                regions = []
                for page, request_id in self.pages(f"{compute}/regions", scope, page_size_key="maxResults",
                                                   params={"fields": "items(name),nextPageToken"}):
                    for region in page:
                        name = region.get("name")
                        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
                            raise ReadError("malformed", "security_policy_region_identity_missing")
                        regions.append(name)
                    yield [], request_id
            if (not isinstance(regions, list) or len(regions) > 100 or
                    any(not isinstance(region, str) or not re.fullmatch(r"[a-z0-9-]+", region) for region in regions)):
                raise ReadError("unavailable", "security_policy_region_coverage_unresolved")
            def checked(item, location):
                link = item.get("selfLink")
                pattern = (r"https://(?:www|compute)\.googleapis\.com/compute/v1/projects/" +
                           re.escape(project) + "/" + re.escape(location) + r"/securityPolicies/[^/]+")
                if not isinstance(link, str) or not re.fullmatch(pattern, link) or not isinstance(item.get("rules"), list):
                    raise ReadError("malformed", "security_policy_full_resource_missing")
                return {**item, "_representation": "full"}
            yield from self.pages(f"{compute}/global/securityPolicies", scope, page_size_key="maxResults",
                                  transform=lambda item: checked(item, "global"))
            failures = []
            for region, pages, exc in self.location_fanout(dict.fromkeys(regions), lambda region: self.pages(
                    f"{compute}/regions/{region}/securityPolicies", scope, page_size_key="maxResults",
                    transform=lambda item: checked(item, f"regions/{region}"))):
                yield from pages
                if exc is not None:
                    if getattr(exc, "request_id", None):
                        yield [], exc.request_id
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise failures[0] if failures else exc  # project-wide
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("security_policy", "compute", security_policies)
        def buckets():
            for items, request_id in self.pages("https://storage.googleapis.com/storage/v1/b", scope,
                params={"project": project, "projection": "full"}, page_size_key="maxResults"):
                # projection=full returns every bucket property; unset logging,
                # versioning and lifecycle are then omitted from the resource.
                yield self.parallel(lambda item: {**self.hydrate(item, "iamPolicy", "https://storage.googleapis.com/storage/v1/b/" +
                    quote(item["name"], safe="") + "/iam", scope, params={"optionsRequestedPolicyVersion": 3}),
                    "_representation": "full"}, items), request_id
        add("bucket", "storage", buckets)
        from .gcp_compliance_wave import sql_instances
        add("sql_instance", "sqladmin", lambda: sql_instances(self, scope, project))
        from .gcp_gke_literal_secret_indicators import validate_cluster_source
        add("gke_cluster", "container", lambda: self.pages(f"https://container.googleapis.com/v1/{scope}/locations/-/clusters",
            scope, key="clusters", page_size_key=None,
            response_validator=(lambda data: validate_cluster_source(data, scope))
                if "gke_workload_literal" in self.needed and self.options.get('content_secret_scans') is True
                    and 'gke_workload_literal' in self.options.get('_content_secret_scan_kinds', []) else None))
        def app_engine_application():
            # apps.get answers 404 NOT_FOUND naming this project's application in
            # ResourceInfo when no App Engine app was ever created: an empty set.
            try:
                yield from self.pages(f"https://appengine.googleapis.com/v1/apps/{project}", scope, single=True)
            except ReadError as exc:
                if not (exc.error.get("http_status") == 404
                        and exc.error.get("resource") == f"projects/{project}/locations/global/applications/{project}"):
                    raise
        add("app_engine_application", "appengine", app_engine_application)
        if "app_engine_application_identity" in self.needed:
            def app_engine_application_identity():
                try:
                    for page, request_id in self.pages(
                            f"https://appengine.googleapis.com/v1beta/apps/{project}", scope,
                            params={"fields": "name,serviceAccount"}, single=True):
                        item, = page
                        if item.get("name") != f"apps/{project}" or set(item) - {"name", "serviceAccount"}:
                            raise ReadError("malformed", "appengine_application_identity_mismatch")
                        account = item.get("serviceAccount")
                        if account is not None and (not isinstance(account, str) or "@" not in account):
                            raise ReadError("malformed", "appengine_default_service_account_malformed")
                        yield [{**item, "_field_mask": "name,serviceAccount",
                                "_representation": "partial"}], request_id
                except ReadError as exc:
                    if not (exc.error.get("http_status") == 404
                            and exc.error.get("resource") == f"projects/{project}/locations/global/applications/{project}"):
                        raise
            add("app_engine_application_identity", "appengine", app_engine_application_identity)
        if "app_engine_legacy_constraint" in self.needed:
            from .gcp_appengine_legacy_constraint import list_constraint
            add("app_engine_legacy_constraint", "orgpolicy", lambda: list_constraint(self, scope))
        if "app_engine_service" in self.needed:
            from .gcp_appengine_versions import list_services
            add("app_engine_service", "appengine", lambda: list_services(self, scope))
        def api_key(item):
            # The existing fields mask selects all of restrictions. ProtoJSON
            # may omit an empty repeated allowlist from a present caller mode.
            # Do not fill an absent mode or override explicit unreadability.
            fields = {"serverKeyRestrictions": "allowedIps",
                "browserKeyRestrictions": "allowedReferrers",
                "androidKeyRestrictions": "allowedApplications",
                "iosKeyRestrictions": "allowedBundleIds"}
            restrictions = item.get("restrictions")
            if ("_coverage" in item or not isinstance(restrictions, dict)
                    or "_coverage" in restrictions):
                return item
            modes = [mode for mode in fields if mode in restrictions]
            if len(modes) != 1:
                return item
            mode = modes[0]
            body = restrictions[mode]
            field = fields[mode]
            if not isinstance(body, dict) or "_coverage" in body or field in body:
                return item
            return {**item, "restrictions": {**restrictions, mode: {**body,
                field: [], "_coverage": {field: {"status": "empty"}}}}}
        add("api_key", "apikeys", lambda: self.pages(f"https://apikeys.googleapis.com/v2/{scope}/locations/global/keys",
            scope, key="keys", params={"fields": "keys(name,uid,displayName,createTime,updateTime,deleteTime,restrictions),nextPageToken"},
            transform=api_key))
        add("dns_managed_zone", "dns", lambda: self.pages(f"https://dns.googleapis.com/dns/v1/projects/{project}/managedZones",
            scope, key="managedZones", page_size_key="maxResults"))
        add("dns_policy", "dns", lambda: self.pages(f"https://dns.googleapis.com/dns/v1/projects/{project}/policies",
            scope, key="policies", page_size_key="maxResults"))
        def clouddeploy_inventory(collection, key):
            def complete_page(data):
                if data.get("unreachable"):
                    raise ReadError("unavailable", "clouddeploy_unreachable_locations")
            locations = self.options.get("clouddeploy_locations")
            if locations is None:
                locations = []
                for found, request_id in self.pages(f"https://clouddeploy.googleapis.com/v1/{scope}/locations",
                                                    scope, key="locations"):
                    for item in found:
                        name = item.get("name") if isinstance(item, dict) else None
                        location = name.rsplit("/", 1)[-1] if isinstance(name, str) else None
                        if not location or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location):
                            raise ReadError("unavailable", "malformed_clouddeploy_location")
                        locations.append(location)
                    yield [], request_id
            def location_pages(location):
                for page, request_id in self.pages(
                        f"https://clouddeploy.googleapis.com/v1/{scope}/locations/{location}/{collection}",
                        scope, key=key, response_validator=complete_page):
                    if collection != "deliveryPipelines":
                        yield page, request_id
                        continue
                    parent = f"{scope}/locations/{location}/deliveryPipelines/"
                    for item in page:
                        name = item.get("name") if isinstance(item, dict) else None
                        if (not isinstance(name, str) or not name.startswith(parent)
                                or not name[len(parent):] or "/" in name[len(parent):]):
                            raise ReadError("malformed", "clouddeploy_pipeline_identity_unbound")
                    yield self.parallel(lambda item: self.hydrate(item, "iamPolicy",
                        f"https://clouddeploy.googleapis.com/v1/{item['name']}:getIamPolicy",
                        scope, params={"options.requestedPolicyVersion": 3},
                        identity_validator=_validate_iam_policy), page), request_id
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), location_pages):
                yield from pages
                if exc is not None:
                    if exc.error.get("reason") == "LOCATION_POLICY_VIOLATED":
                        continue
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise failures[0] if failures else exc  # project-wide
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("clouddeploy_delivery_pipeline", "clouddeploy", lambda: clouddeploy_inventory("deliveryPipelines", "deliveryPipelines"))
        add("clouddeploy_target", "clouddeploy", lambda: clouddeploy_inventory("targets", "targets"))
        add("clouddeploy_custom_target_type", "clouddeploy", lambda: clouddeploy_inventory("customTargetTypes", "customTargetTypes"))
        def workflows_inventory():
            def complete_page(data):
                if data.get("unreachable"):
                    raise ReadError("unavailable", "workflows_unreachable_locations")
            locations = []
            for found, request_id in self.pages(f"https://workflows.googleapis.com/v1/{scope}/locations",
                                                scope, key="locations"):
                for item in found:
                    name = item.get("name") if isinstance(item, dict) else None
                    location = name.rsplit("/", 1)[-1] if isinstance(name, str) else None
                    if not location or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location):
                        raise ReadError("unavailable", "malformed_workflows_location")
                    locations.append(location)
                yield [], request_id
            def location_pages(location):
                def project_workflow(item):
                    if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].startswith(
                            f"{scope}/locations/{location}/workflows/"):
                        raise ReadError("malformed", "workflows_identity_missing")
                    return {key: item[key] for key in ("name", "serviceAccount", "state") if key in item}
                return self.pages(f"https://workflows.googleapis.com/v1/{scope}/locations/{location}/workflows",
                                  scope, key="workflows", transform=project_workflow,
                                  response_validator=complete_page)
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), location_pages):
                yield from pages
                if exc is not None:
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise failures[0] if failures else exc  # project-wide
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("workflows_workflow", "workflows", workflows_inventory)
        def dataproc_clusters():
            regions = self.options.get("dataproc_regions", self.options.get("regions"))
            if regions is None:
                regions = []
                for locations, request_id in self.pages(f"https://compute.googleapis.com/compute/v1/{scope}/regions", scope,
                    page_size_key="maxResults"):
                    regions.extend(location["name"] for location in locations)
                    yield [], request_id
            if not isinstance(regions, list) or any(not isinstance(region, str) or not re.fullmatch(r"[a-z0-9-]+", region) for region in regions):
                raise ValueError("dataproc_regions must contain valid region names")
            def region_pages(region):
                for clusters, request_id in self.pages(
                        f"https://dataproc.googleapis.com/v1/{scope}/regions/{region}/clusters", scope,
                        key="clusters", transform=lambda cluster: {**cluster, "_region": region}):
                    def policy(cluster):
                        name = cluster.get("clusterName")
                        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", name):
                            raise ReadError("malformed", "dataproc_cluster_name_invalid")
                        resource = f"{scope}/regions/{region}/clusters/{name}"
                        result = self.hydrate(cluster, "iamPolicy",
                            f"https://dataproc.googleapis.com/v1/{resource}:getIamPolicy", scope,
                            method="POST", body={"options": {"requestedPolicyVersion": 3}})
                        from .gcp_dataproc_init_objects import collect as init_objects
                        result["_initObjectMetadata"] = init_objects(self, cluster, scope)
                        return result
                    yield self.parallel(policy, clusters), request_id
            failures = []
            for region, pages, exc in self.location_fanout(dict.fromkeys(regions), region_pages):
                yield from pages
                if exc is not None:
                    # A region the project cannot use at all (restricted/opt-in
                    # location) holds none of its clusters; not a permission gap.
                    if exc.error.get("reason") == "LOCATION_POLICY_VIOLATED":
                        continue
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise exc  # project-wide; every other region would repeat it
                    failures.append(exc)
            if failures:
                raise failures[0]
        from .gcp_job_literal_secret_indicators import enabled as job_secrets_enabled
        if not job_secrets_enabled(self.options, 'dataproc_cluster'):
            add("dataproc_cluster", "dataproc", dataproc_clusters)
        def deployment_manager_deployments():
            from .gcp_deploymentmanager_deployments import collection_pages
            yield from collection_pages(self, scope)
        add("deployment_manager_deployment", "deploymentmanager",
            deployment_manager_deployments)
        def account_activity():
            """Policy Analyzer serviceAccountLastAuthentication, keyed by account resource name.

            Returns (activities, coverage). An account listed without lastAuthenticatedTime
            was never used in the observation period; an unlisted account stays unknown."""
            activities, requests = {}, []
            try:
                for items, request_id in self.pages(f"https://policyanalyzer.googleapis.com/v1/{scope}/locations/global/activityTypes/"
                                                    "serviceAccountLastAuthentication/activities:query", scope, key="activities"):
                    requests.append(request_id)
                    for row in items:
                        name = row.get("fullResourceName")
                        period = row.get("observationPeriod")
                        body = row.get("activity", {})
                        if not isinstance(name, str) or not isinstance(period, dict) or not isinstance(period.get("endTime"), str) \
                                or not isinstance(body, dict):
                            raise ReadError("malformed", "malformed_activity")
                        from peaso.gcp_iam_usage_contract import project_activity
                        tokens = {scope.split('/')[1]}
                        resource_project = name.removeprefix('//iam.googleapis.com/').split('/')[1]
                        if resource_project not in tokens:
                            binding = self._data_project_binding(scope, require_alias=True)
                            tokens.update(str(binding[key]) for key in ('project_id', 'project_number'))
                        fact = project_activity(row, scope, 'service_account', tokens)
                        if body.get("lastAuthenticatedTime") is not None:
                            fact["lastAuthenticatedTime"] = body["lastAuthenticatedTime"]
                        if name.removeprefix("//iam.googleapis.com/") in activities:
                            raise ReadError("malformed", "duplicate_account_activity")
                        activities[name.removeprefix("//iam.googleapis.com/")] = (fact, request_id)
                        account_id = body.get("serviceAccount", {}).get("serviceAccountId") if isinstance(body.get("serviceAccount"), dict) else None
                        if isinstance(account_id, str):
                            activities["id:" + account_id] = (fact, request_id)
                return activities, {"status": "collected", "collection_status": "collected", "source_requests": requests}
            except ReadError as exc:
                return None, {"status": exc.status, "collection_status": wire_status(exc.status), "error": exc.error,
                    "source_requests": requests + ([exc.request_id] if getattr(exc, "request_id", None) else [])}
            except Exception:
                # Activity is supplementary: it never hides the account inventory.
                return None, {"status": "unavailable", "collection_status": "unknown", "error": {"code": "collector_error"},
                    "source_requests": requests}
        def service_accounts():
            activity = account_activity() if self.options.get("service_account_activity", True) else None
            def detail(item):
                item = self.hydrate(item, "iamPolicy", f"https://iam.googleapis.com/v1/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}, method="POST")
                if activity is None:
                    return item
                activities, coverage = activity
                match = None
                if activities is not None:
                    match = activities.get(item.get("name")) or activities.get("id:" + str(item.get("uniqueId")))
                    if match is None and isinstance(item.get("email"), str):
                        match = activities.get(f"{scope}/serviceAccounts/{item['email']}")
                if match:
                    item["_activity"] = match[0]
                    item["_coverage"]["_activity"] = {**coverage, "source_requests": [match[1]],
                        "semantics": "Policy Analyzer last authentication; listed without lastAuthenticatedTime means never used in the observation period"}
                else:
                    item["_coverage"]["_activity"] = {**coverage, "status": coverage["status"] if activities is None else "not_observed",
                        "semantics": "Account absent from Policy Analyzer results: usage unknown"}
                return item
            # IAM serviceAccounts.list rejects pageSize above 100 even when the
            # connector's general page size is larger.
            for items, request_id in self.pages(f"https://iam.googleapis.com/v1/{scope}/serviceAccounts", scope,
                                                key="accounts", params={"pageSize": min(self.page_size, 100)}):
                yield self.parallel(detail, items), request_id
        add("service_account", "iam", service_accounts)
        add("workload_identity_pool", "iam", lambda: self.pages(f"https://iam.googleapis.com/v1/{scope}/locations/global/workloadIdentityPools",
            scope, key="workloadIdentityPools", params={"showDeleted": "true"}))
        def key_rings():
            selected_locations = self.options.get("kms_locations")
            if selected_locations is not None:
                if not isinstance(selected_locations, list) or len(selected_locations) > 100 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in selected_locations):
                    raise ValueError("kms_locations must contain at most 100 region names")
                locations = [f"{scope}/locations/{x}" for x in dict.fromkeys(selected_locations)]
            else:
                locations = []
                for items, request_id in self.pages(f"https://cloudkms.googleapis.com/v1/{scope}/locations", scope, key="locations"):
                    locations.extend(item["name"] for item in items)
                    yield [], request_id
            def location_pages(location):
                for items, request_id in self.pages(f"https://cloudkms.googleapis.com/v1/{location}/keyRings", scope, key="keyRings"):
                    # keyRings.getIamPolicy (GET) returns an empty Policy when none is set.
                    yield self.parallel(lambda item: self.hydrate(item, "iamPolicy",
                        f"https://cloudkms.googleapis.com/v1/{item['name']}:getIamPolicy", scope,
                        params={"options.requestedPolicyVersion": 3}), items), request_id
            # The first failing location ends the listing, as before.
            yield from fanout_pages(self, locations, location_pages)
        add("kms_key_ring", "cloudkms", key_rings)
        for kind, segment in (("pubsub_topic", "topics"), ("pubsub_subscription", "subscriptions"), ("pubsub_snapshot", "snapshots")):
            def pubsub(segment=segment):
                # {resource}:getIamPolicy (GET) returns an empty Policy when none is set.
                for items, request_id in self.pages(f"https://pubsub.googleapis.com/v1/{scope}/{segment}", scope, key=segment,
                    # topics.list returns Topic resources without a field mask.
                    # Its optional kmsKeyName can be absent on a complete Topic.
                    transform=(lambda item: {**item, "_representation": "full"}) if segment == "topics" else None):
                    yield self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://pubsub.googleapis.com/v1/{item['name']}:getIamPolicy",
                        scope, params={"options.requestedPolicyVersion": 3}), items), request_id
            add(kind, "pubsub", pubsub)
        def secrets():
            for items, request_id in self.pages(f"https://secretmanager.googleapis.com/v1/{scope}/secrets", scope, key="secrets"):
                yield self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://secretmanager.googleapis.com/v1/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}), items), request_id
        add("secret", "secretmanager", secrets)
        def datasets():
            binding = self._data_project_binding(scope)
            api_scope = "projects/" + binding["project_id"]
            for items, request_id in self.pages(f"https://bigquery.googleapis.com/bigquery/v2/{api_scope}/datasets", scope,
                key="datasets", params={"all": "true"}, page_size_key="maxResults"):
                def detail(item):
                    dataset_id = self._data_bigquery_identity(scope, item)
                    name = f"{scope}/datasets/{dataset_id}"
                    item = self.hydrate({**item, "name": name}, "datasetDetails",
                        f"https://bigquery.googleapis.com/bigquery/v2/{api_scope}/datasets/{quote(dataset_id, safe='')}", scope,
                        params={"accessPolicyVersion": 3, "datasetView": "FULL"},
                        identity_validator=lambda value: self._data_bigquery_identity(scope, value, dataset_id))
                    if item["_coverage"]["datasetDetails"]["status"] == "collected":
                        item.update(item.pop("datasetDetails"))
                        item["_representation"] = "full"
                    else:
                        item["_representation"] = "partial"
                        # A denied ACL read does not invalidate the list identity
                        # for independent tables.get. Contradictory detail identity
                        # invalidates the object itself before provenance stamping.
                        if item["_coverage"]["datasetDetails"]["status"] == "malformed":
                            raise ReadError("malformed", "bigquery_dataset_detail_identity_unbound")
                    return item
                yield self.parallel(detail, items), request_id
        add("bigquery_dataset", "bigquery", datasets)
        def region_metadata(service, version, segment, key, location_option, *, locations_version=None, with_iam=True):
            def policy(page):
                return self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://{service}.googleapis.com/{version}/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}), page)
            locations = self.options.get(location_option, self.options.get("regions"))
            if locations is not None:
                if not isinstance(locations, list) or len(locations) > 100 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                    raise ValueError("regional metadata locations must contain at most 100 region names")
                locations = list(dict.fromkeys(locations))
            else:
                locations = []
                for items, request_id in self.pages(f"https://{service}.googleapis.com/{locations_version or version}/{scope}/locations",
                    scope, key="locations"):
                    locations.extend(item.get("locationId") or item["name"].rsplit("/", 1)[1] for item in items)
                    yield [], request_id
            def location_pages(location):
                for items, request_id in self.pages(f"https://{service}.googleapis.com/{version}/{scope}/locations/{location}/{segment}",
                    scope, key=key):
                    yield [{**item, "_representation": "full"} for item in (policy(items) if with_iam else items)], request_id
            failures = []
            for location, pages, exc in self.location_fanout(locations, location_pages):
                yield from pages
                if exc is not None:
                    # Same semantics as Dataproc: an org-policy restricted region
                    # is unusable by the project; a disabled service is project-wide.
                    if exc.error.get("reason") == "LOCATION_POLICY_VIOLATED":
                        self.regional_policy_skips.setdefault(service, {}).setdefault(scope, set()).add(location)
                        continue
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise exc
                    failures.append(exc)
            if failures:
                raise failures[0]
        def cloudtasks_queues():
            for page, request_id in region_metadata("cloudtasks", "v2", "queues", "queues",
                                                    "cloudtasks_locations", with_iam=False):
                def queue_metadata(item):
                    name = item.get("name") if isinstance(item, dict) else None
                    if not isinstance(name, str) or not name.startswith(scope + "/locations/") or "/queues/" not in name:
                        raise ReadError("malformed", "cloudtasks_queue_identity_missing")
                    target = item.get("httpTarget") or {}
                    projected = {"name": name, "state": item.get("state"),
                                 "hasTargetOverride": bool(target), "_representation": "full"}
                    return self.hydrate(projected, "iamPolicy",
                        f"https://cloudtasks.googleapis.com/v2/{name}:getIamPolicy", scope,
                        method="POST", body={"options": {"requestedPolicyVersion": 3}})
                yield self.parallel(queue_metadata, page), request_id
        add("cloudtasks_queue", "cloudtasks", cloudtasks_queues)
        add("artifact_repository", "artifactregistry", lambda: region_metadata("artifactregistry", "v1", "repositories",
            "repositories", "artifactregistry_locations"))
        def containeranalysis_notes():
            base = "https://containeranalysis.googleapis.com/v1/"
            def note_pages(parent):
                for page, request_id in self.pages(base + parent + "/notes", scope, key="notes"):
                    def policy(item):
                        name = item.get("name")
                        pattern = (re.escape(scope) + r"/(?:locations/[^/]+/)?notes/[^/]+"
                                   if parent == scope else re.escape(parent) + r"/notes/[^/]+")
                        if not isinstance(name, str) or not re.fullmatch(pattern, name):
                            raise ReadError("malformed", "containeranalysis_note_identity_missing")
                        return self.hydrate({**item, "_representation": "full"}, "iamPolicy",
                            base + name + ":getIamPolicy", scope, method="POST",
                            body={"options": {"requestedPolicyVersion": 3}})
                    yield self.parallel(policy, page), request_id
            yield from note_pages(scope)
            locations = self.options.get("containeranalysis_locations", self.options.get("regions"))
            if locations is None:
                locations = []
                for page, request_id in self.pages(
                        f"https://artifactregistry.googleapis.com/v1/{scope}/locations", scope,
                        key="locations"):
                    locations.extend(item.get("locationId") or item["name"].rsplit("/", 1)[1]
                                      for item in page)
                    yield [], request_id
            if (not isinstance(locations, list) or len(locations) > 100
                    or any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x)
                           for x in locations)):
                raise ValueError("containeranalysis_locations must contain at most 100 locations")
            yield from fanout_pages(self, dict.fromkeys(locations),
                                    lambda location: note_pages(f"{scope}/locations/{location}"))
        add("containeranalysis_note", "containeranalysis", containeranalysis_notes)
        def datacatalog_taxonomy_pages():
            locations = self.options.get("datacatalog_locations", self.options.get("regions"))
            if locations is None:
                locations = []
                for page, request_id in self.pages(
                        f"https://artifactregistry.googleapis.com/v1/{scope}/locations", scope,
                        key="locations"):
                    locations.extend(item.get("locationId") or item["name"].rsplit("/", 1)[1]
                                      for item in page)
                    yield [], request_id
            if (not isinstance(locations, list) or len(locations) > 100
                    or any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x)
                           for x in locations)):
                raise ValueError("datacatalog_locations must contain at most 100 locations")
            def location_pages(location):
                url = f"https://datacatalog.googleapis.com/v1/{scope}/locations/{location}/taxonomies"
                for page, request_id in self.pages(url, scope, key="taxonomies"):
                    for item in page:
                        name = item.get("name")
                        if (not isinstance(name, str) or not re.fullmatch(
                                r"projects/[^/]+/locations/" + re.escape(location)
                                + r"/taxonomies/[^/]+", name)):
                            raise ReadError("malformed", "datacatalog_taxonomy_identity_missing")
                    yield page, request_id
            yield from fanout_pages(self, dict.fromkeys(locations), location_pages)
        def datacatalog_taxonomies():
            for page, request_id in datacatalog_taxonomy_pages():
                yield self.parallel(lambda item: self.hydrate(
                    {**item, "_representation": "full"}, "iamPolicy",
                    f"https://datacatalog.googleapis.com/v1/{item['name']}:getIamPolicy",
                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}}), page), request_id
        add("datacatalog_taxonomy", "datacatalog", datacatalog_taxonomies)
        def datacatalog_policy_tags():
            for page, request_id in datacatalog_taxonomy_pages():
                yield [], request_id
                for taxonomy in page:
                    parent = taxonomy["name"]
                    url = f"https://datacatalog.googleapis.com/v1/{parent}/policyTags"
                    for tags, tag_request in self.pages(url, scope, key="policyTags"):
                        def policy(item):
                            name = item.get("name")
                            if (not isinstance(name, str) or not re.fullmatch(
                                    re.escape(parent) + r"/policyTags/[^/]+", name)):
                                raise ReadError("malformed", "datacatalog_policy_tag_identity_missing")
                            raw_parent = item.get("parentPolicyTag")
                            if raw_parent and (not isinstance(raw_parent, str) or not re.fullmatch(
                                    re.escape(parent) + r"/policyTags/[^/]+", raw_parent)
                                    or raw_parent == name):
                                raise ReadError("malformed", "datacatalog_policy_tag_parent_invalid")
                            return self.hydrate({**item, "_representation": "full"}, "iamPolicy",
                                f"https://datacatalog.googleapis.com/v1/{name}:getIamPolicy",
                                scope, method="POST", body={"options": {"requestedPolicyVersion": 3}})
                        yield self.parallel(policy, tags), tag_request
        add("datacatalog_policy_tag", "datacatalog", datacatalog_policy_tags)
        def biglake_catalogs():
            if not scope.startswith("projects/"):
                return
            url = f"https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/{scope}/catalogs"
            params = {"view": "CATALOG_VIEW_BASIC", "page-size": min(self.page_size, 1000)}
            seen_names, seen_tokens = set(), set()
            for page in count():
                data, request_id = self.read(url, scope, params=params)
                if not isinstance(data, dict) or set(data) - {"iceberg-catalogs", "next-page-token", "unreachable"}:
                    raise ReadError("malformed", "biglake_catalog_list_shape")
                rows = data.get("iceberg-catalogs", [])
                if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
                    raise ReadError("malformed", "biglake_catalog_list_shape")
                if data.get("unreachable"):
                    raise ReadError("unavailable", "biglake_catalog_unreachable")
                for item in rows:
                    name = item.get("name")
                    if (not isinstance(name, str) or not re.fullmatch(
                            re.escape(scope) + r"/catalogs/[^/]+", name) or name in seen_names):
                        raise ReadError("malformed", "biglake_catalog_identity")
                    seen_names.add(name)
                def hydrate(item):
                    name = item["name"]
                    return self.hydrate({"name": name, "catalogType": item.get("catalog-type"),
                                         "_representation": "full"}, "iamPolicy",
                        f"https://biglake.googleapis.com/v1/{name}:getIamPolicy", scope,
                        params={"options.requestedPolicyVersion": 3},
                        identity_validator=_validate_iam_policy)
                yield self.parallel(hydrate, rows), request_id
                token = data.get("next-page-token")
                if token is None or token == "":
                    break
                if (not isinstance(token, str) or token in seen_tokens or
                        self.max_pages is not None and page + 1 >= self.max_pages):
                    raise ReadError("unavailable", "biglake_catalog_pagination")
                seen_tokens.add(token)
                params["page-token"] = token
        add("biglake_catalog", "biglake", biglake_catalogs)
        def biglake_namespaces():
            seen_names = set()
            for catalog_page, _ in biglake_catalogs():
                for catalog in catalog_page:
                    parent = catalog["name"]
                    url = f"https://biglake.googleapis.com/iceberg/v1/restcatalog/v1/{parent}/namespaces"
                    params = {"pageSize": min(self.page_size, 1000)}
                    seen_tokens = set()
                    for page in count():
                        data, request_id = self.read(url, scope, params=params)
                        if (not isinstance(data, dict) or
                                set(data) - {"namespaces", "next-page-token", "unreachable"} or
                                not isinstance(data.get("namespaces", []), list)):
                            raise ReadError("malformed", "biglake_namespace_list_shape")
                        if data.get("unreachable"):
                            raise ReadError("unavailable", "biglake_namespace_unreachable")
                        rows = []
                        for parts in data.get("namespaces", []):
                            if (not isinstance(parts, list) or len(parts) != 1 or
                                    not isinstance(parts[0], str) or not re.fullmatch(r"[^/\x00-\x1f]+", parts[0])):
                                raise ReadError("malformed", "biglake_namespace_identity")
                            name = parent + "/namespaces/" + parts[0]
                            if name in seen_names:
                                raise ReadError("malformed", "biglake_namespace_duplicate")
                            seen_names.add(name)
                            rows.append({"name": name})
                        def hydrate(item):
                            name = item["name"]
                            return self.hydrate({**item, "_representation": "full"}, "iamPolicy",
                                f"https://biglake.googleapis.com/v1/{name}:getIamPolicy", scope,
                                params={"options.requestedPolicyVersion": 3},
                                identity_validator=_validate_iam_policy)
                        yield self.parallel(hydrate, rows), request_id
                        token = data.get("next-page-token")
                        if token is None or token == "":
                            break
                        if (not isinstance(token, str) or token in seen_tokens or
                                self.max_pages is not None and page + 1 >= self.max_pages):
                            raise ReadError("unavailable", "biglake_namespace_pagination")
                        seen_tokens.add(token)
                        params["pageToken"] = token
        add("biglake_namespace", "biglake", biglake_namespaces)
        def biglake_tables():
            seen_names = set()
            for namespace_page, _ in biglake_namespaces():
                for namespace in namespace_page:
                    parent = namespace["name"]
                    expected_namespace = parent.rsplit("/namespaces/", 1)[1]
                    url = f"https://biglake.googleapis.com/iceberg/v1/restcatalog/v1/{parent}/tables"
                    params = {"pageSize": min(self.page_size, 1000)}
                    seen_tokens = set()
                    for page in count():
                        data, request_id = self.read(url, scope, params=params)
                        if (not isinstance(data, dict) or
                                set(data) - {"identifiers", "next-page-token"} or
                                not isinstance(data.get("identifiers", []), list)):
                            raise ReadError("malformed", "biglake_table_list_shape")
                        rows = []
                        for ident in data.get("identifiers", []):
                            if (not isinstance(ident, dict) or
                                    ident.get("namespace") != [expected_namespace] or
                                    not isinstance(ident.get("name"), str) or
                                    not re.fullmatch(r"[^/\x00-\x1f]+", ident["name"])):
                                raise ReadError("malformed", "biglake_table_identity")
                            name = parent + "/tables/" + ident["name"]
                            if name in seen_names:
                                raise ReadError("malformed", "biglake_table_duplicate")
                            seen_names.add(name)
                            rows.append({"name": name})
                        def hydrate(item):
                            name = item["name"]
                            return self.hydrate({**item, "_representation": "full"}, "iamPolicy",
                                f"https://biglake.googleapis.com/v1/{name}:getIamPolicy", scope,
                                params={"options.requestedPolicyVersion": 3},
                                identity_validator=_validate_iam_policy)
                        yield self.parallel(hydrate, rows), request_id
                        token = data.get("next-page-token")
                        if token is None or token == "":
                            break
                        if (not isinstance(token, str) or token in seen_tokens or
                                self.max_pages is not None and page + 1 >= self.max_pages):
                            raise ReadError("unavailable", "biglake_table_pagination")
                        seen_tokens.add(token)
                        params["pageToken"] = token
        add("biglake_table", "biglake", biglake_tables)
        add("agentidentity_auth_provider", "agentidentity", lambda: region_metadata(
            "agentidentity", "v1", "authProviders", "authProviders", "agentidentity_locations"))
        # Cloud Run v2 has no locations.list (404); v1 projects.locations.list is
        # the documented region list. v2 list parents cannot be the "-" wildcard.
        add("cloudrun_service", "run", lambda: region_metadata("run", "v2", "services", "services", "cloudrun_locations",
            locations_version="v1"))
        add("cloudrun_job", "run", lambda: region_metadata("run", "v2", "jobs", "jobs", "cloudrun_locations", locations_version="v1"))
        add("cloudrun_instance", "run", lambda: region_metadata("run", "v2", "instances", "instances",
            "cloudrun_locations", locations_version="v1"))
        add("cloudrun_worker_pool", "run", lambda: region_metadata("run", "v2", "workerPools", "workerPools",
            "cloudrun_locations", locations_version="v1"))
        add("vpc_access_connector", "vpcaccess", lambda: region_metadata("vpcaccess", "v1", "connectors",
            "connectors", "vpcaccess_locations", with_iam=False))
        add("filestore_instance", "file", lambda: region_metadata("file", "v1", "instances",
            "instances", "filestore_locations", with_iam=False))
        add("redis_instance", "redis", lambda: region_metadata("redis", "v1", "instances",
            "instances", "redis_locations", with_iam=False))
        def functions():
            def env_names(function):
                # functions.list returns the full Function: an absent inline
                # environment map is none; sanitize keeps the names only.
                if (isinstance(function.get("serviceConfig"), dict)
                        and "environmentVariables" not in function["serviceConfig"]
                        and "environmentVariableNames" not in function["serviceConfig"]):
                    function = {**function, "serviceConfig": {**function["serviceConfig"], "environmentVariables": {}}}
                return function
            for items, request_id in self.pages(f"https://cloudfunctions.googleapis.com/v2/{scope}/locations/-/functions",
                scope, key="functions", transform=env_names):
                yield self.parallel(lambda item: self.hydrate(item, "iamPolicy", f"https://cloudfunctions.googleapis.com/v2/{item['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}), items), request_id
        add("function", "cloudfunctions", functions)
        def cloudfunctions_locations():
            parent = f"{scope}/locations/"
            def project_location(item):
                name = item.get("name") if isinstance(item, dict) else None
                if (not isinstance(name, str) or not name.startswith(parent)
                        or not re.fullmatch(r"[a-z][a-z0-9-]*", name[len(parent):])):
                    raise ReadError("malformed", "cloudfunctions_location_identity_unbound")
                return {"name": name, "locationId": item.get("locationId")}
            yield from self.pages(f"https://cloudfunctions.googleapis.com/v2/{scope}/locations",
                                  scope, key="locations", transform=project_location)
        add("cloudfunctions_location", "cloudfunctions", cloudfunctions_locations)
        def located(option, discover, url_for, key, transform):
            """Bounded per-location list: explicit `option`/`regions` list or the
            service's documented location enumeration (at most 100 locations)."""
            locations = self.options.get(option, self.options.get("regions"))
            if locations is None:
                locations = []
                yield from discover(locations)
            if not isinstance(locations, list) or len(locations) > 100 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                raise ValueError(option + " must contain at most 100 location names")
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), lambda location: self.pages(
                    url_for(location), scope, key=key, transform=transform)):
                yield from pages
                if exc is not None:
                    if exc.error.get("reason") == "LOCATION_POLICY_VIOLATED":
                        continue
                    if exc.error.get("reason") == "SERVICE_DISABLED":
                        raise exc
                    failures.append(exc)
            if failures:
                raise failures[0]
        def service_locations(service, version):
            def discover(locations):
                for items, request_id in self.pages(f"https://{service}.googleapis.com/{version}/{scope}/locations", scope, key="locations"):
                    locations.extend(item.get("locationId") or str(item.get("name", "")).rsplit("/", 1)[-1] for item in items)
                    yield [], request_id
            return discover
        def eventarc_resources(kind, segment, key):
            def fetch():
                locations = self.options.get("eventarc_locations", self.options.get("regions"))
                if locations is None:
                    locations = []
                    yield from service_locations("eventarc", "v1")(locations)
                if not isinstance(locations, list) or len(locations) > 100 or any(
                        not isinstance(location, str) or not re.fullmatch(r"[a-z0-9-]+", location)
                        for location in locations):
                    raise ValueError("eventarc_locations must contain at most 100 location names")
                def location_pages(location):
                    for rows, request_id in self.pages(
                            f"https://eventarc.googleapis.com/v1/{scope}/locations/{location}/{segment}",
                            scope, key=key):
                        def projected(row):
                            fields = ("name", "messageBus", "destination") if kind == "eventarc_enrollment" else ("name",)
                            item = {field: row[field] for field in fields if field in row}
                            name = item.get("name")
                            if not isinstance(name, str) or not re.fullmatch(
                                    re.escape(scope) + r"/locations/" + re.escape(location)
                                    + r"/" + re.escape(segment) + r"/[^/]+", name):
                                return item
                            return self.hydrate(item, "iamPolicy",
                                f"https://eventarc.googleapis.com/v1/{name}:getIamPolicy", scope,
                                params={"options.requestedPolicyVersion": 3})
                        yield self.parallel(projected, rows), request_id
                failures = []
                for location, pages, exc in self.location_fanout(dict.fromkeys(locations), location_pages):
                    yield from pages
                    if exc is not None:
                        if exc.error.get("reason") == "SERVICE_DISABLED":
                            raise failures[0] if failures else exc  # project-wide
                        failures.append(exc)
                if failures:
                    raise failures[0]
            add(kind, "eventarc", fetch)
        eventarc_resources("eventarc_message_bus", "messageBuses", "messageBuses")
        eventarc_resources("eventarc_enrollment", "enrollments", "enrollments")
        def firebase_apphosting_backends():
            locations = []
            yield from service_locations("firebaseapphosting", "v1")(locations)
            if len(locations) > 100 or any(not isinstance(location, str) or not re.fullmatch(
                    r"[a-z0-9-]+", location) for location in locations):
                raise ReadError("malformed", "firebase_apphosting_locations_unbound")
            def location_pages(location):
                for rows, request_id in self.pages(
                        f"https://firebaseapphosting.googleapis.com/v1/{scope}/locations/{location}/backends",
                        scope, key="backends"):
                    projected = []
                    for row in rows:
                        name = row.get("name") if isinstance(row, dict) else None
                        if not isinstance(name, str) or not re.fullmatch(
                                re.escape(scope) + r"/locations/" + re.escape(location)
                                + r"/backends/[^/]+", name):
                            raise ReadError("malformed", "firebase_apphosting_backend_identity_unbound")
                        projected.append({field: row[field] for field in
                                          ("name", "serviceAccount", "codebase", "deleteTime", "reconciling")
                                          if field in row})
                    yield projected, request_id
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), location_pages):
                yield from pages
                if exc is not None:
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("firebase_apphosting_backend", "firebaseapphosting", firebase_apphosting_backends)
        def compute_regions(locations):
            for items, request_id in self.pages(f"{compute}/regions", scope, page_size_key="maxResults"):
                locations.extend(str(item.get("name", "")) for item in items)
                yield [], request_id
        from .gcp_compliance_wave import located as compliance_located
        add("logging_bucket", "logging", lambda: compliance_located(self, scope, "logging", "v2",
            "buckets", "buckets", "logging_locations"))
        add("certificate", "certificatemanager", lambda: compliance_located(self, scope, "certificatemanager", "v1",
            "certificates", "certificates", "certificate_locations"))
        add("worker_pool", "cloudbuild", lambda: compliance_located(self, scope, "cloudbuild", "v1",
            "workerPools", "workerPools", "worker_pool_locations"))
        def source_repositories():
            failures = []
            base = f"https://sourcerepo.googleapis.com/v1/{scope}/repos"
            for items, request_id in self.pages(base, scope, key="repos"):
                def policy(repo):
                    name = repo.get("name")
                    if (not isinstance(name, str) or not name.startswith(scope + "/repos/") or
                            any(not re.fullmatch(r"[A-Za-z0-9._-]+", part) or part in (".", "..")
                                for part in name.split("/")[3:])):
                        raise ReadError("malformed", "source_repository_identity_mismatch")
                    row = self.hydrate(repo, "iamPolicy", f"https://sourcerepo.googleapis.com/v1/{name}:getIamPolicy", scope,
                                       params={"options.requestedPolicyVersion": 3})
                    row["_representation"] = "full"
                    return row
                rows = self.parallel(policy, items)
                yield rows, request_id
                if any(row["_coverage"]["iamPolicy"]["status"] != "collected" for row in rows):
                    failures.append(ReadError("unavailable", "source_repository_policy_incomplete"))
            if failures:
                raise failures[0]
        add("source_repository", "sourcerepo", source_repositories)
        def access_transparency_entries():
            end = datetime.fromisoformat(self.read_time)
            start = end - timedelta(days=30)
            log_name = f"{scope}/logs/cloudaudit.googleapis.com%2Faccess_transparency"
            body = {"resourceNames": [scope], "filter":
                f'logName="{log_name}" AND timestamp>="{start.isoformat()}" AND timestamp<"{end.isoformat()}"'}
            def project_entry(item):
                if item.get("logName") != log_name or not isinstance(item.get("timestamp"), str):
                    raise ReadError("malformed", "access_transparency_event_scope_mismatch")
                insert_id = item.get("insertId")
                if not isinstance(insert_id, str) or not insert_id:
                    raise ReadError("malformed", "access_transparency_event_identity_missing")
                return {"name": f"{log_name}/entries/{quote(insert_id, safe='')}",
                    "project": scope, "logName": log_name,
                    "timestamp": item["timestamp"], "_representation": "full"}
            yield from self.pages("https://logging.googleapis.com/v2/entries:list", scope,
                key="entries", method="POST", page_size_key=None, body=body, transform=project_entry)
        add("access_transparency_entry", "logging", access_transparency_entries)
        from .gcp_compliance_wave import event_jobs
        jobs.extend(event_jobs(self, scope))
        add("cloud_asset", "cloudasset", lambda: self.pages(
            f"https://cloudasset.googleapis.com/v1/{scope}:searchAllResources", scope, key="results",
            transform=lambda item: {**item, "labels": item.get("labels", {}), "_representation": "full"}))
        def autoscalers():
            locations = self.options.get("autoscaler_regions", self.options.get("regions"))
            if locations is None:
                locations = []
                yield from compute_regions(locations)
            if (not isinstance(locations, list) or not locations or len(locations) > 100 or
                    any(not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations)):
                raise ReadError("unavailable", "region_coverage_unresolved")
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), lambda location: self.pages(
                    f"{compute}/regions/{location}/autoscalers", scope,
                    page_size_key="maxResults", transform=lambda item: {**item, "_representation": "full"})):
                yield from pages
                if exc is not None:
                    if getattr(exc, "request_id", None):
                        yield [], exc.request_id
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("autoscaler", "compute", autoscalers)
        def cloudbuild_connections():
            from .gcp_history import cloudbuild_locations
            locations = []
            for found, request_id in cloudbuild_locations(self, scope):
                locations.extend(found)
                if request_id:
                    yield [], request_id
            def location_pages(location):
                parent = f"{scope}/locations/{location}"
                for page, request_id in self.pages(
                        f"https://cloudbuild.googleapis.com/v2/{parent}/connections",
                        scope, key="connections"):
                    rows = []
                    for item in page:
                        name = item.get("name")
                        if (not isinstance(name, str) or not re.fullmatch(
                                re.escape(parent) + r"/connections/[^/]+", name)):
                            raise ReadError("malformed", "cloudbuild_connection_identity_unbound")
                        rows.append({"name": name,
                                     "installationStage": (item.get("installationState") or {}).get("stage")})
                    yield self.parallel(lambda projected: self.hydrate(projected, "iamPolicy",
                        f"https://cloudbuild.googleapis.com/v2/{projected['name']}:getIamPolicy",
                        scope, params={"options.requestedPolicyVersion": 3},
                        identity_validator=_validate_iam_policy), rows), request_id
            failures = []
            for location, pages, exc in self.location_fanout(
                    [location for location in dict.fromkeys(locations) if location != "global"], location_pages):
                yield from pages
                if exc is not None:
                    if getattr(exc, "request_id", None):
                        yield [], exc.request_id
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("cloudbuild_connection", "cloudbuild", cloudbuild_connections)
        def cloudbuild_triggers():
            # projects.locations.triggers.list returns full BuildTrigger
            # resources (no field mask). Inline build steps, substitution values
            # and scripts are dropped; names and identities remain.
            from peaso.collectors.gcp_cloudbuild_projection import project_trigger
            from .gcp_history import cloudbuild_locations
            locations = []
            for found, request_id in cloudbuild_locations(self, scope):
                locations.extend(found)
                if request_id:
                    yield [], request_id
            yield from _cloudbuild(locations, project_trigger)
        def _cloudbuild(locations, scrub):
            if not isinstance(locations, list) or len(locations) > 101 or any(
                    not isinstance(x, str) or not re.fullmatch(r"[a-z0-9-]+", x) for x in locations):
                raise ValueError("cloudbuild_locations must contain at most 100 location names")
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), lambda location: self.pages(
                    f"https://cloudbuild.googleapis.com/v1/{scope}/locations/{location}/triggers",
                    scope, key="triggers", transform=scrub)):
                yield from pages
                if exc is not None:
                    if getattr(exc, "request_id", None):
                        yield [], exc.request_id
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("cloudbuild_trigger", "cloudbuild", cloudbuild_triggers)
        from .gcp_developerconnect_links import collection_pages as developerconnect_links
        add("developerconnect_git_repository_link", "developerconnect",
            lambda: developerconnect_links(self, scope))
        from .gcp_discoveryengine_collections import (
            collection_pages as discoveryengine_collections,
            data_store_pages as discoveryengine_data_stores,
            engine_pages as discoveryengine_engines)
        add("discoveryengine_collection", "discoveryengine",
            lambda: discoveryengine_collections(self, scope))
        add("discoveryengine_data_store", "discoveryengine",
            lambda: discoveryengine_data_stores(self, scope))
        add("discoveryengine_engine", "discoveryengine",
            lambda: discoveryengine_engines(self, scope))
        def cloudbuild_default_accounts():
            from .gcp_history import cloudbuild_locations
            locations = []
            for found, request_id in cloudbuild_locations(self, scope):
                locations.extend(found)
                if request_id:
                    yield [], request_id
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), lambda location: self.pages(
                    f"https://cloudbuild.googleapis.com/v1/{scope}/locations/{location}/defaultServiceAccount",
                    scope, single=True)):
                yield from pages
                if exc is not None:
                    if getattr(exc, "request_id", None):
                        yield [], exc.request_id
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("cloudbuild_default_sa", "cloudbuild", cloudbuild_default_accounts)
        from .gcp_history import cloudbuild_builds
        add("cloudbuild_build", "cloudbuild", lambda: cloudbuild_builds(self, scope))
        # Cloud Domains registrations are global resources (projects/*/locations/global).
        # Only the domain name and state are requested: contactSettings carry
        # registrant personal data and are never read.
        def domains_registrations():
            for registrations, request_id in self.pages(
                    f"https://domains.googleapis.com/v1/{scope}/locations/global/registrations", scope,
                    key="registrations",
                    params={"fields": "registrations(name,domainName,state,expireTime),nextPageToken"}):
                def hydrate_registration(registration):
                    item = {k: registration[k] for k in ("name", "domainName", "state", "expireTime") if k in registration}
                    name = item.get("name")
                    if not isinstance(name, str) or not re.fullmatch(
                            re.escape(scope) + r"/locations/global/registrations/[^/]+", name):
                        return item
                    return self.hydrate(item, "iamPolicy",
                        f"https://domains.googleapis.com/v1/{name}:getIamPolicy", scope,
                        params={"options.requestedPolicyVersion": 3})
                yield self.parallel(hydrate_registration, registrations), request_id
        add("domains_registration", "domains", domains_registrations)
        add("storage_hmac_key", "storage", lambda: self.pages(
            f"https://storage.googleapis.com/storage/v1/projects/{project}/hmacKeys", scope, page_size_key="maxResults",
            # HMAC key metadata only: the secret is returned solely by create.
            transform=lambda key: {k: key[k] for k in ("id", "selfLink", "accessId", "projectId", "serviceAccountEmail",
                                                     "state", "timeCreated", "updated") if k in key}))
        def composer_scrub(environment):
            output = copy.deepcopy(environment)
            software = output.get("config", {}).get("softwareConfig") if isinstance(output.get("config"), dict) else None
            if isinstance(software, dict):
                for field, names in (("envVariables", "envVariableNames"), ("airflowConfigOverrides", "airflowConfigOverrideNames")):
                    if isinstance(software.get(field), dict):
                        software[names] = sorted(software.pop(field))
                    else:
                        software.pop(field, None)
            return output
        add("composer_environment", "composer", lambda: located("composer_locations", compute_regions,
            lambda location: f"https://composer.googleapis.com/v1/{scope}/locations/{location}/environments", "environments",
            composer_scrub))
        def composer_image_versions():
            locations = self.options.get("composer_image_locations", self.options.get("regions"))
            if locations is None:
                locations = []
                yield from compute_regions(locations)
            if not isinstance(locations, list) or len(locations) > 100 or any(
                    not isinstance(location, str) or not re.fullmatch(r"[a-z0-9-]+", location)
                    for location in locations):
                raise ValueError("composer_image_locations must contain at most 100 location names")
            def location_pages(location):
                for rows, request_id in self.pages(
                        f"https://composer.googleapis.com/v1/{scope}/locations/{location}/imageVersions",
                        scope, key="imageVersions"):
                    if any(not isinstance(row.get("imageVersionId"), str) or
                           not row["imageVersionId"].startswith("composer-") or
                           row.get("creationDisabled") not in (None, True, False)
                           for row in rows):
                        raise ReadError("malformed", "composer_image_version_identity_unbound")
                    yield [{**row, "location": location} for row in rows], request_id
            failures = []
            for location, pages, exc in self.location_fanout(dict.fromkeys(locations), location_pages):
                yield from pages
                if exc is not None:
                    if exc.error.get("http_status") == 404 or exc.error.get("reason") == "LOCATION_POLICY_VIOLATED":
                        continue
                    failures.append(exc)
            if failures:
                raise failures[0]
        add("composer_image_version", "composer", composer_image_versions)
        WORKBENCH_METADATA = ("notebook-disable-root", "notebook-disable-downloads", "notebook-disable-terminal",
                              "notebook-disable-nbconvert", "serial-port-enable", "enable-oslogin", "proxy-mode")
        def workbench_scrub(instance):
            output = copy.deepcopy(instance)
            setup = output.get("gceSetup")
            if isinstance(setup, dict) and isinstance(setup.get("metadata"), dict):
                setup["metadata"] = {k: (copy.deepcopy(v) if k == '_coverage' and isinstance(v, dict)
                    else v if k in WORKBENCH_METADATA else None) for k, v in setup["metadata"].items()}
                from .gcp_workbench_head3_projection_20261020 import project_upgrade_schedule
                setup["metadata"] = project_upgrade_schedule(instance["gceSetup"]["metadata"], setup["metadata"])
            # This list request has no fields mask. The retained security keys
            # can use documented omitted-field defaults; redacted values stay
            # present as None and cannot be treated as missing/default values.
            output['_representation'] = 'full'
            return output
        # Workbench Instances are zonal; notebooks v2 instances.list documents
        # parent projects/{p}/locations/- "to list instances in all locations"; an
        # `unreachable` location list makes the read unavailable, never empty.
        def workbench_instances():
            for listed, request_id in self.pages(
                    f"https://notebooks.googleapis.com/v2/{scope}/locations/-/instances",
                    scope, key="instances", transform=workbench_scrub):
                yield self.parallel(lambda instance: self.hydrate(
                    instance, "iamPolicy", f"https://notebooks.googleapis.com/v2/{instance['name']}:getIamPolicy",
                    scope, params={"options.requestedPolicyVersion": 3}), listed), request_id
        add("workbench_instance", "notebooks", workbench_instances)
        def scheduler_scrub(job):
            output = {k: v for k, v in job.items() if k not in ("httpTarget", "pubsubTarget", "appEngineHttpTarget")}
            for field in ("httpTarget", "pubsubTarget", "appEngineHttpTarget"):
                target = job.get(field)
                if not isinstance(target, dict):
                    continue
                kept = {k: target[k] for k in ("httpMethod", "topicName", "relativeUri", "appEngineRouting", "oauthToken", "oidcToken")
                        if k in target}
                if isinstance(target.get("uri"), str):
                    # Query strings can carry API keys: keep scheme, host and path.
                    parts = urlsplit(target["uri"])
                    kept["uri"] = f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}{parts.path}"
                for map_field in ("headers", "attributes"):
                    if isinstance(target.get(map_field), dict):
                        kept[map_field[:-1] + "Names"] = sorted(target[map_field])
                output[field] = kept
            return output
        add("scheduler_job", "cloudscheduler", lambda: located("cloudscheduler_locations",
            service_locations("cloudscheduler", "v1"),
            lambda location: f"https://cloudscheduler.googleapis.com/v1/{scope}/locations/{location}/jobs", "jobs",
            lambda row: finish_scheduler_scrub(scheduler_scrub(row), row)))
        def shared_vpc():
            # projects.get distinguishes HOST from the only other documented
            # status. Do not infer host applicability from a getXpnResources 400.
            project_data, project_request = self.read(compute, scope)
            if not isinstance(project_data, dict) or project_data.get("kind") != "compute#project" or \
                    project_data.get("name") != project or \
                    ("selfLink" in project_data and project_data["selfLink"] not in (
                        f"https://www.googleapis.com/compute/v1/projects/{project}", compute)):
                raise ReadError("malformed", "malformed_xpn_project_identity")
            role = project_data.get("xpnProjectStatus")
            if role not in ("HOST", "UNSPECIFIED_XPN_PROJECT_STATUS"):
                raise ReadError("unavailable", "unknown_xpn_project_status")
            yield [], project_request
            data, request_id = self.read(f"{compute}/getXpnHost", scope)
            if data == {"_noXpnHost": True}:
                yield [], request_id
            elif isinstance(data, dict) and isinstance(data.get("name"), str) and data["name"]:
                yield [{"name": f"{scope}/getXpnHost", "relationshipType": "getXpnHost", "host": data,
                    "hostProject": data["name"], "serviceProject": scope}], request_id
            else:
                raise ReadError("malformed", "malformed_xpn_host")
            if role == "HOST":
                for items, request_id in self.pages(f"{compute}/getXpnResources", scope, key="resources", page_size_key="maxResults"):
                    yield [{"name": f"{scope}/getXpnResources/{item.get('id')}", "relationshipType": "getXpnResources",
                        "hostProject": scope, "serviceProject": item.get("id"), "resources": [item]} for item in items], request_id
        add("shared_vpc", "compute", shared_vpc)
        if "activity" in self.needed:
            days = bound(self.options, "activity_days", 30, 1, 365)
            since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            def activity(item):
                auth = item.get("protoPayload", {}).get("authenticationInfo", {})
                return {"name": item.get("insertId") or item.get("timestamp"), "timestamp": item.get("timestamp"),
                    "principalEmail": auth.get("principalEmail"), "serviceAccountKeyName": auth.get("serviceAccountKeyName"),
                    "serviceName": item.get("protoPayload", {}).get("serviceName"),
                    "methodName": item.get("protoPayload", {}).get("methodName"), "logName": item.get("logName"),
                    "coverageWindow": {"since": since, "days": days, "absenceProvesUnused": False}}
            add("activity", "logging", lambda: self.pages("https://logging.googleapis.com/v2/entries:list", scope,
                key="entries", method="POST", page_size_key=None,
                body={"resourceNames": [scope], "filter": f'logName:"cloudaudit.googleapis.com" AND timestamp>="{since}" '
                    'AND protoPayload.authenticationInfo.principalEmail:"gserviceaccount.com"',
                    "orderBy": "timestamp desc", "pageSize": min(self.page_size, 1000)}, transform=activity))
        return jobs

    def inherited(self):
        if self.alias_identity_only():
            return
        if not self.options.get("include_inherited", True) or not self.needed.intersection(
            {"iam_policy", "iam_deny_policy", "iam_role", "project", "folder", "organization", "firewall_policy", "firewall_policy_association"}):
            return
        parents = set()
        for scope in self.scopes[:]:
            if not scope.startswith("projects/"):
                continue
            try:
                data, request_id = self.read(f"https://cloudresourcemanager.googleapis.com/v1/{scope}:getAncestry",
                    scope, method="POST", body={})
                ancestors = data.get("ancestor")
                def malformed_ancestry():
                    exc = ReadError("malformed", "malformed_ancestry")
                    exc.request_id = request_id
                    return exc
                if not isinstance(ancestors, list) or not ancestors:
                    raise malformed_ancestry()
                # Older parent-only responses can still select ancestor reads,
                # but never establish the project's complete hierarchy chain.
                first = ancestors[0]
                first_resource = first.get("resourceId") if isinstance(first, dict) else None
                if isinstance(first_resource, dict) and first_resource.get("type") in ("folder", "organization"):
                    parent_only, seen, organization_seen = set(), set(), False
                    for ancestor in ancestors:
                        resource = ancestor.get("resourceId") if isinstance(ancestor, dict) else None
                        kind = resource.get("type") if isinstance(resource, dict) else None
                        identifier = resource.get("id") if isinstance(resource, dict) else None
                        if (kind not in ("folder", "organization") or not isinstance(identifier, str)
                                or not re.fullmatch(r"[1-9][0-9]*", identifier)
                                or organization_seen or (kind, identifier) in seen):
                            raise malformed_ancestry()
                        seen.add((kind, identifier))
                        parent_only.add(f"{kind}s/{identifier}")
                        if kind == "organization":
                            organization_seen = True
                    parents.update(parent_only)
                    raise malformed_ancestry()
                seen_ancestors, organization_seen, verified_parents = set(), False, set()
                for position, ancestor in enumerate(ancestors):
                    if not isinstance(ancestor, dict) or not isinstance(ancestor.get("resourceId"), dict):
                        raise malformed_ancestry()
                    resource = ancestor["resourceId"]
                    kind, identifier = resource.get("type"), resource.get("id")
                    if (kind not in ("project", "folder", "organization")
                            or not isinstance(identifier, str) or not identifier
                            or position == 0 and kind != "project"
                            or position > 0 and kind == "project"
                            or organization_seen or (kind, identifier) in seen_ancestors):
                        raise malformed_ancestry()
                    if kind in ("folder", "organization") and not re.fullmatch(r"[1-9][0-9]*", identifier):
                        raise malformed_ancestry()
                    if kind == "project" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identifier):
                        raise malformed_ancestry()
                    seen_ancestors.add((kind, identifier))
                    if kind == "organization":
                        organization_seen = True
                    if kind in ("folder", "organization"):
                        verified_parents.add(f"{kind}s/{identifier}")
                project = self.collections.get(("project", scope))
                if project and project.get("coverage_status") == "collected" and len(project.get("items", [])) == 1:
                    row = project["items"][0]
                    expected = {scope.split("/", 1)[1]}
                    if isinstance(row.get("name"), str) and row["name"].startswith("projects/"):
                        expected.add(row["name"].split("/", 1)[1])
                    if isinstance(row.get("projectNumber"), str):
                        expected.add(row["projectNumber"])
                    if ancestors[0]["resourceId"]["id"] not in expected:
                        raise malformed_ancestry()
                parents.update(verified_parents)
                self.ancestry[scope] = sanitize(ancestors)
                self.ancestry_source_requests[scope] = request_id
                if ("project", scope) in self.collections:
                    for item in self.collections[("project", scope)]["items"]:
                        item["_ancestry"] = sanitize(ancestors)
                        item["_provenance"]["source_requests"].append(request_id)
                    self.collections[("project", scope)]["source_requests"] = sorted(set(
                        self.collections[("project", scope)]["source_requests"] + [request_id]))
            except ReadError as exc:
                self.scope_errors.append({"scope": scope, "operation": "getAncestry", "status": exc.status,
                    "error": exc.error, "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []})
        self.inherited_scopes = sorted(parents - set(self.scopes))
        remaining = self.max_scopes - len(self.scopes) if self.max_scopes is not None else None
        if remaining is not None and len(self.inherited_scopes) > remaining:
            self.inherited_scopes = self.inherited_scopes[:max(0, remaining)]
            self.scope_errors.append({"code": "inherited_scope_limit", "status": "partial"})
        jobs = []
        for scope in self.inherited_scopes:
            # Ancestors supply inheritance evidence, never select sibling projects
            # or broad ancestor asset searches through implicit scope expansion.
            for kind, scope, service, fetch in self.scope_jobs(scope):
                # Ancestor sinks feed project._inherited_sinks (aggregated sinks).
                if kind in ("iam_policy", "iam_deny_policy", "iam_role", "folder", "organization", "principal_access_boundary_policy", "policy_binding", "log_sink", "firewall_policy", "firewall_policy_association"):
                    if kind == "iam_policy":
                        def fetch(scope=scope):
                            for items, request_id in self.pages(f"https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy",
                                scope, method="POST", body={"options": {"requestedPolicyVersion": 3}}, single=True):
                                yield [{"name": scope, "bindings": [], **item, "_representation": "full"} for item in items], request_id
                    jobs.append((kind, scope, service, fetch))
        self.run_jobs(jobs)

    def perimeter_jobs(self):
        """VPC Service Controls perimeters that can apply to each project.

        Access policies are organization resources (accessPolicies.list with
        parent=organizations/N, including scoped policies), so every perimeter of
        the project's organization is listed at the project scope. A project with
        complete ancestry and no organization cannot be inside any perimeter."""
        if "service_perimeter" not in self.needed:
            return
        def perimeters(scope):
            chain = self.hierarchy_chain(scope)
            if chain is None:
                raise ReadError("unavailable", "ancestry_unavailable")
            organizations = [x for x in chain if x.startswith("organizations/")]
            if not organizations:
                return
            for policies, request_id in self.pages("https://accesscontextmanager.googleapis.com/v1/accessPolicies", scope,
                                                   key="accessPolicies", params={"parent": organizations[-1]}):
                yield [], request_id
                for policy in policies:
                    name = policy.get("name")
                    if not isinstance(name, str) or not re.fullmatch(r"accessPolicies/[0-9]+", name):
                        raise ReadError("malformed", "malformed_access_policy")
                    for items, page_id in self.pages(f"https://accesscontextmanager.googleapis.com/v1/{name}/servicePerimeters",
                                                     scope, key="servicePerimeters"):
                        # servicePerimeters.list has no field mask: full perimeters.
                        yield [{**item, "accessPolicy": name, "organization": organizations[-1], "_representation": "full"}
                               for item in items], page_id
        self.run_jobs([("service_perimeter", scope, "accesscontextmanager", lambda scope=scope: perimeters(scope))
                       for scope in self.scopes if scope.startswith("projects/")])

    def independent_jobs(self):
        """Jobs that read no other collection, run with the main batch instead
        of in their own later single-job phases (results are unchanged)."""
        jobs = []
        projects = [scope for scope in self.scopes if scope.startswith("projects/")]
        if "identityplatform_tenant" in self.needed:
            from .gcp_identityplatform_tenants import collection_pages as identityplatform_tenants
            jobs += [("identityplatform_tenant", scope, "identitytoolkit",
                      lambda scope=scope: identityplatform_tenants(self, scope)) for scope in projects]
        if "krm_api_host" in self.needed:
            from .gcp_krm_api_hosts import collection_pages as krm_api_hosts
            jobs += [("krm_api_host", scope, "krmapihosting",
                      lambda scope=scope: krm_api_hosts(self, scope)) for scope in projects]
        if "logging_view" in self.needed:
            from .gcp_logging_views import collection_pages as logging_views
            jobs += [("logging_view", scope, "logging", lambda scope=scope: logging_views(self, scope))
                     for scope in self.scopes if scope.startswith(("projects/", "folders/", "organizations/"))]
        if "inframanager_location" in self.needed:
            from .gcp_inframanager_locations import collection_pages as inframanager_locations
            jobs += [("inframanager_location", scope, "config",
                      lambda scope=scope: inframanager_locations(self, scope)) for scope in projects]
        from . import gcp_dataform_privesc, gcp_datafusion_privesc, gcp_dataplex_privesc, gcp_privateca_pool
        for module in (gcp_privateca_pool, gcp_dataform_privesc, gcp_datafusion_privesc, gcp_dataplex_privesc):
            jobs += [job for scope in self.scopes for job in module.scope_jobs(self, scope)]
        self._independent_jobs_scheduled = True
        return jobs

    def dependent_jobs(self):
        if "instance_effective_firewall" in self.needed:
            def instance_effective_firewalls(scope):
                parent = self.collections.get(("instance", scope))
                if not parent or parent.get("status") not in ("collected", "empty"):
                    raise ReadError("unavailable", "instance_inventory_incomplete")
                for instance in parent.get("items", []):
                    link = instance.get("selfLink")
                    if not isinstance(link, str):
                        raise ReadError("malformed", "instance_effective_firewall_identity_missing")
                    short = "projects/" + link.split("/projects/", 1)[1] if "/projects/" in link else link
                    if not re.fullmatch(re.escape(scope) + r"/zones/[^/]+/instances/[^/]+", short):
                        raise ReadError("malformed", "instance_effective_firewall_identity_invalid")
                    for interface in instance.get("networkInterfaces", []):
                        if not isinstance(interface, dict):
                            raise ReadError("malformed", "instance_effective_firewall_interface_invalid")
                        name = interface.get("name")
                        if not isinstance(name, str) or not name:
                            raise ReadError("malformed", "instance_effective_firewall_interface_missing")
                        external = any(isinstance(row, dict) and row.get("natIP") for row in interface.get("accessConfigs", [])) or any(
                            isinstance(row, dict) and row.get("externalIpv6") for row in interface.get("ipv6AccessConfigs", []))
                        if not external:
                            continue
                        url = f"https://compute.googleapis.com/compute/v1/{short}/getEffectiveFirewalls"
                        def validate(response):
                            if (not isinstance(response.get("firewalls", []), list) or
                                not isinstance(response.get("firewallPolicys", []), list) or
                                any(not isinstance(row, dict) for row in response.get("firewalls", [])) or
                                any(not isinstance(row, dict) for row in response.get("firewallPolicys", []))):
                                raise ReadError("malformed", "instance_effective_firewall_response_invalid")
                        for page, request_id in self.pages(url, scope, single=True,
                                params={"networkInterface": name}, response_validator=validate):
                            response = page[0]
                            yield [{"name": f"{short}/interfaces/{name}/effectiveFirewalls",
                                    "instance": short, "networkInterface": name,
                                    "firewalls": response.get("firewalls", []),
                                    "firewallPolicys": response.get("firewallPolicys", []),
                                    "effective_source_operation": "instances.getEffectiveFirewalls"}], request_id
            self.run_jobs([("instance_effective_firewall", scope, "compute",
                lambda scope=scope: instance_effective_firewalls(scope))
                for scope in self.scopes if scope.startswith("projects/")])
        if self.needed & {"analyticshub_data_exchange", "analyticshub_listing"}:
            def analytics_resources(scope, *, kind, asset_type, suffix):
                discovered = self.collections.get(("cloud_asset", scope))
                if not discovered or discovered.get("coverage_status") not in ("collected", "empty"):
                    state = discovered.get("coverage_status") if discovered else None
                    raise ReadError("denied" if state == "denied" else "unavailable",
                                    "cloud_asset_analyticshub_inventory_incomplete")
                prefix = "//analyticshub.googleapis.com/"
                resources = set()
                for item in discovered.get("items", []):
                    if item.get("assetType") != asset_type:
                        continue
                    raw = item.get("name")
                    if not isinstance(raw, str) or not raw.startswith(prefix):
                        raise ReadError("malformed", "analyticshub_resource_identity_missing")
                    name = raw.removeprefix(prefix)
                    if not re.fullmatch(re.escape(scope) + suffix, name):
                        raise ReadError("malformed", "analyticshub_resource_identity_mismatch")
                    resources.add(name)
                for item in self.parallel(lambda name: self.hydrate({"name": name, "_representation": "full"}, "iamPolicy",
                        f"https://analyticshub.googleapis.com/v1/{name}:getIamPolicy", scope,
                        method="POST", body={"options": {"requestedPolicyVersion": 3}},
                        identity_validator=_validate_iam_policy), sorted(resources)):
                    refs = ((item.get("_coverage", {}).get("iamPolicy") or {}).get("source_requests")
                            or discovered.get("source_requests") or [])
                    if not refs:
                        raise ReadError("unavailable", "analyticshub_policy_request_provenance_missing")
                    yield [item], refs[0]
            specs = (("analyticshub_data_exchange", "analyticshub.googleapis.com/DataExchange",
                      r"/locations/[^/]+/dataExchanges/[^/]+"),
                     ("analyticshub_listing", "analyticshub.googleapis.com/Listing",
                      r"/locations/[^/]+/dataExchanges/[^/]+/listings/[^/]+"))
            self.run_jobs([(kind, scope, "analyticshub/cloudasset",
                lambda scope=scope, kind=kind, asset_type=asset_type, suffix=suffix:
                    analytics_resources(scope, kind=kind, asset_type=asset_type, suffix=suffix))
                for kind, asset_type, suffix in specs if kind in self.needed
                for scope in self.scopes if scope.startswith("projects/")])
        if self.registry_image_vulnerability_targets:
            from .gcp_registry_trivy_runtime_20261021 import enrich as registry_image_cves
            registry_image_cves(self)
        from .gcp_composer_source_secret_indicators import collection_pages as composer_source_pages, enabled as composer_source_enabled
        if 'composer_dag_source' in self.needed and composer_source_enabled(self.options):
            self.run_jobs([('composer_dag_source', scope, 'storage',
                lambda scope=scope: composer_source_pages(self, scope))
                for scope in self.scopes if scope.startswith('projects/')])
        from .gcp_gke_literal_secret_indicators import dependent_jobs as gke_literal_jobs
        self.run_jobs(gke_literal_jobs(self))
        from .gcp_gke_exposure_services import dependent_jobs as gke_exposure_jobs, INGRESS_KIND, POD_KIND
        self.run_jobs(gke_exposure_jobs(self) + gke_exposure_jobs(self, INGRESS_KIND)
                      + gke_exposure_jobs(self, POD_KIND))
        if self.needed & {'appengine_flex_selected_version_image_secrets', 'appengine_flex_selected_version_image_vulnerabilities'}:
            from .gcp_appengine_flex_image_runtime_20261021 import collect as collect_flex_images
            collect_flex_images(self)
        if self.needed & {'gke_selected_pod_image_secrets', 'gke_selected_pod_image_vulnerabilities'}:
            from .gcp_gke_selected_pod_image_20261021 import collect as collect_gke_images
            collect_gke_images(self)
        if "app_engine_version" in self.needed:
            from .gcp_appengine_versions import list_versions
            version_jobs = []
            for scope in self.scopes:
                if not scope.startswith("projects/"):
                    continue
                def versions(scope=scope):
                    services = self.collections.get(("app_engine_service", scope))
                    if not services or services["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "app_engine_service_inventory_incomplete")
                    yield from list_versions(self, scope, services["items"])
                version_jobs.append(("app_engine_version", scope, "appengine", versions))
            self.run_jobs(version_jobs)
        if "app_engine_instance" in self.needed:
            from .gcp_appengine_versions import list_instances
            instance_jobs = []
            for scope in self.scopes:
                if not scope.startswith("projects/"):
                    continue
                def instances(scope=scope):
                    versions = self.collections.get(("app_engine_version", scope))
                    if not versions or versions["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "app_engine_version_inventory_incomplete")
                    yield from list_instances(self, scope, versions["items"])
                instance_jobs.append(("app_engine_instance", scope, "appengine", instances))
            self.run_jobs(instance_jobs)
        from .gcp_additional_literal_secret_indicators import appengine_jobs
        self.run_jobs(appengine_jobs(self))
        if "gcp_v4_workload_facts" in self.needed:
            from .gcp_facts_v4_holds import collect_supplemental, normalize_facts
            fact_jobs = []
            for scope in self.scopes:
                if not scope.startswith("projects/"):
                    continue
                def facts(scope=scope):
                    supplemental = collect_supplemental(self, scope,
                        integration_regions=self.options.get("integration_locations") or ())
                    item = normalize_facts(self.collections, supplemental, scope)
                    item["name"] = scope
                    # This is a local projection. Its nested coverage carries
                    # the actual read IDs and partial/denied/missing states.
                    yield [item], "local:gcp_v4_workload_facts"
                fact_jobs.append(("gcp_v4_workload_facts", scope, "derived-gcp-metadata", facts))
            self.run_jobs(fact_jobs)
        if "alloydb_instance" in self.needed:
            alloy_jobs = []
            for scope in self.scopes:
                if not scope.startswith("projects/"):
                    continue
                def instances(scope=scope):
                    clusters = self.collections.get(("alloydb_cluster", scope))
                    if not clusters or clusters["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "alloydb_cluster_inventory_incomplete")
                    for cluster in clusters["items"]:
                        yield from self.pages(f"https://alloydb.googleapis.com/v1/{cluster['name']}/instances", scope,
                            key="instances", params={"fields": "instances(name,uid,state,instanceType,databaseFlags,networkConfig,clientConnectionConfig,dataApiAccess,labels),nextPageToken,unreachable"})
                alloy_jobs.append(("alloydb_instance", scope, "alloydb", instances))
            self.run_jobs(alloy_jobs)
        jobs = []
        def add(kind, scope, service, fetch):
            jobs.append((kind, scope, service, fetch))
        from .gcp_job_literal_secret_indicators import collection_pages as job_literal_pages, enabled as job_secrets_enabled
        if "dataflow_privesc_job" in self.needed:
            from .gcp_dataflow_privesc_jobs import collection_pages as dataflow_privesc_pages
            for scope in self.scopes:
                if scope.startswith("projects/"):
                    add("dataflow_privesc_job", scope, "dataflow",
                        lambda scope=scope: dataflow_privesc_pages(self, scope))
        if "dataflow_privesc_pipeline" in self.needed:
            from .gcp_dataflow_privesc_jobs import pipeline_pages
            for scope in self.scopes:
                if scope.startswith("projects/"):
                    add("dataflow_privesc_pipeline", scope, "datapipelines",
                        lambda scope=scope: pipeline_pages(self, scope))
        for kind in ('dataflow_job', 'batch_job', 'dataproc_job', 'dataproc_cluster'):
            if kind in self.needed and job_secrets_enabled(self.options, kind):
                for scope in self.scopes:
                    if scope.startswith('projects/'):
                        service = {'dataflow_job': 'dataflow', 'batch_job': 'batch',
                                   'dataproc_job': 'dataproc', 'dataproc_cluster': 'dataproc'}[kind]
                        add(kind, scope, service,
                            lambda kind=kind, scope=scope: job_literal_pages(self, scope, kind))
        if 'artifact_selected_file' in self.needed:
            from .gcp_artifact_file_secret_indicators import collection_pages as artifact_file_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('artifact_selected_file', scope, 'artifactregistry',
                        lambda scope=scope: artifact_file_pages(self, scope))
        if 'dataform_selected_file' in self.needed:
            from .gcp_dataform_secret_indicators import collection_pages as dataform_file_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('dataform_selected_file', scope, 'dataform',
                        lambda scope=scope: dataform_file_pages(self, scope))
        if 'gcs_selected_object' in self.needed:
            from .gcp_selected_object_secret_indicators import collection_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('gcs_selected_object', scope, 'storage',
                        lambda scope=scope: collection_pages(self, scope))
        if 'gcs_selected_archive' in self.needed:
            from .gcp_selected_archive_secret_indicators import collection_pages as archive_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('gcs_selected_archive', scope, 'storage',
                        lambda scope=scope: archive_pages(self, scope))
        if 'function_source_archive' in self.needed:
            from .gcp_function_source_secret_indicators import collection_pages as function_source_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('function_source_archive', scope, 'cloudfunctions',
                        lambda scope=scope: function_source_pages(self, scope))
        if 'cloudbuild_log_source' in self.needed:
            from .gcp_cloudbuild_log_secret_indicators import jobs as cloudbuild_log_jobs
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    jobs.extend(cloudbuild_log_jobs(self, scope))
        if self.needed & selected_job_source_runtime.KINDS:
            for scope in self.scopes:
                jobs.extend(selected_job_source_runtime.jobs(self, scope))
        if workbench_source_runtime.KIND in self.needed:
            for scope in self.scopes:
                jobs.extend(workbench_source_runtime.jobs(self, scope))
        for profile, spec in dataproc_source_runtime.source.PROFILES.items():
            if spec['kind'] in self.needed:
                for scope in self.scopes:
                    jobs.extend(dataproc_source_runtime.source.jobs(self, scope, profile))
        from .gcp_selected_task_routine_secret_indicators import SPECS as task_routine_specs, jobs as task_routine_jobs
        for kind in task_routine_specs:
            if kind in self.needed:
                for scope in self.scopes:
                    if scope.startswith('projects/'):
                        jobs.extend(task_routine_jobs(self, scope, kind))
        if 'source_repository_file' in self.needed:
            from .gcp_sourcerepo_secret_indicators import jobs as sourcerepo_jobs
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    jobs.extend(sourcerepo_jobs(self, scope))
        if 'clouddeploy_release_source' in self.needed:
            from .gcp_clouddeploy_source_secret_indicators import jobs as clouddeploy_release_source_jobs
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    jobs.extend(clouddeploy_release_source_jobs(self, scope))
        if 'cloudbuild_artifact_source' in self.needed:
            from .gcp_cloudbuild_artifact_secret_indicators import jobs as cloudbuild_artifact_source_jobs
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    jobs.extend(cloudbuild_artifact_source_jobs(self, scope))
        if 'appengine_deployment_source' in self.needed:
            from .gcp_appengine_source_secret_indicators import jobs as appengine_source_jobs
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    jobs.extend(appengine_source_jobs(self, scope))
        if "effective_firewall" in self.needed:
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def regional_effective_firewalls(scope=scope):
                    networks = self.collections.get(("network", scope))
                    subnets = self.collections.get(("subnetwork", scope))
                    if (not networks or networks["status"] not in ("collected", "empty") or
                        not subnets or subnets["status"] not in ("collected", "empty")):
                        raise ReadError("unavailable", "effective_firewall_network_inventory_incomplete")
                    def identity(value):
                        if not isinstance(value, str):
                            return None
                        return "projects/" + value.split("/projects/", 1)[1] if "/projects/" in value else (
                            value if value.startswith("projects/") else None)
                    by_network = {}
                    for network in networks["items"]:
                        link = network.get("selfLink")
                        key = identity(link)
                        if not key or not re.fullmatch(re.escape(scope) + r"/global/networks/[^/]+", key) or key in by_network:
                            raise ReadError("malformed", "effective_firewall_network_identity_invalid")
                        by_network[key] = link
                    pairs = set()
                    for subnet in subnets["items"]:
                        link = identity(subnet.get("selfLink"))
                        network_key = identity(subnet.get("network"))
                        match = re.fullmatch(re.escape(scope) + r"/regions/([a-z0-9-]+)/subnetworks/[^/]+", link or "")
                        if not match or network_key not in by_network:
                            raise ReadError("malformed", "effective_firewall_subnet_identity_invalid")
                        pairs.add((network_key, match.group(1)))
                    for network_key, region in sorted(pairs):
                        path = (f"https://compute.googleapis.com/compute/v1/{scope}/regions/{region}"
                            "/firewallPolicies/getEffectiveFirewalls")
                        def validate_response(data):
                            if (not isinstance(data.get("firewallPolicys", []), list) or
                                any(not isinstance(item, dict) for item in data.get("firewallPolicys", [])) or
                                not isinstance(data.get("firewalls", []), list) or data.get("nextPageToken")):
                                raise ReadError("malformed", "effective_firewall_response_invalid")
                        for page, request_id in self.pages(path, scope, single=True,
                                params={"network": by_network[network_key]}, response_validator=validate_response):
                            response = page[0]
                            yield [{"id": f"{network_key}/regions/{region}/effectiveFirewalls",
                                "network": by_network[network_key], "region": region,
                                "firewallPolicys": response.get("firewallPolicys", []),
                                "effective_source_operation": "regionNetworkFirewallPolicies.getEffectiveFirewalls"}], request_id
                add("effective_firewall", scope, "compute", regional_effective_firewalls)
        if "service_account_key" in self.needed:
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def keys(scope=scope):
                    accounts = self.collections.get(("service_account", scope))
                    if not accounts or accounts["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "service_account_inventory_incomplete")
                    activity = None
                    if self.options.get("service_account_activity", True) and accounts["items"]:
                        activity = self.key_activity(scope)
                    for item in accounts["items"]:
                        name = item.get("name") or f"{scope}/serviceAccounts/{quote(item['email'], safe='')}"
                        for page, request_id in self.pages(f"https://iam.googleapis.com/v1/{name}/keys", scope, key="keys", page_size_key=None,
                                transform=lambda key, name=name: {**{k: v for k, v in key.items() if k not in ("privateKeyData", "publicKeyData")},
                                    "serviceAccount": name}):
                            yield ([self.attach_key_activity(key, activity) for key in page] if activity else page), request_id
                add("service_account_key", scope, "iam", keys)
        if "agentidentity_authorization" in self.needed:
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def authorizations(scope=scope):
                    providers = self.collections.get(("agentidentity_auth_provider", scope))
                    if not providers or providers["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "agentidentity_provider_inventory_incomplete")
                    for provider in providers["items"]:
                        name = provider.get("name")
                        if (not isinstance(name, str) or not re.fullmatch(
                                r"projects/[^/]+/locations/[^/]+/authProviders/[^/]+", name)
                                or (not name.startswith(scope + "/")
                                    and not self._data_project_matches(scope, name.split("/")[1]))):
                            raise ReadError("malformed", "agentidentity_provider_identity_missing")
                        def validate(data):
                            if data.get("unreachable"):
                                raise ReadError("unavailable", "agentidentity_authorizations_incomplete")
                        def attach_parent(item, parent=name):
                            authorization = item.get("name")
                            if (not isinstance(authorization, str)
                                    or not authorization.startswith(parent + "/authorizations/")
                                    or "/" in authorization[len(parent + "/authorizations/"):]):
                                raise ReadError("malformed", "agentidentity_authorization_parent_mismatch")
                            return {**item, "authProvider": parent, "_representation": "full"}
                        yield from self.pages(f"https://agentidentity.googleapis.com/v1/{name}/authorizations",
                                              scope, key="authorizations", transform=attach_parent,
                                              response_validator=validate)
                add("agentidentity_authorization", scope, "agentidentity", authorizations)
        for child, parent, segment, key in (
            ("workload_identity_provider", "workload_identity_pool", "providers", "workloadIdentityPoolProviders"),
            ("workforce_provider", "workforce_pool", "providers", "workforcePoolProviders"),
            ("kms_key", "kms_key_ring", "cryptoKeys", "cryptoKeys")):
            if child not in self.needed:
                continue
            scopes = [s for s in self.scopes if s.startswith("organizations/" if parent == "workforce_pool" else "projects/")]
            for scope in scopes:
                def children(scope=scope, parent=parent, segment=segment, key=key):
                    collection = self.collections.get((parent, scope))
                    if not collection or collection["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", f"{parent}_inventory_incomplete")
                    for item in collection["items"]:
                        service = "cloudkms" if parent == "kms_key_ring" else "iam"
                        def transform(key, ring=item['name'], scope=scope):
                            # cryptoKeys.list has no field mask: each key is the full
                            # CryptoKey, where an unset rotationPeriod is omitted.
                            output = {**key, "keyRing": ring, "_representation": "full"}
                            return self.hydrate(output, "iamPolicy", f"https://cloudkms.googleapis.com/v1/{key['name']}:getIamPolicy",
                                scope, params={"options.requestedPolicyVersion": 3})
                        params = {"showDeleted": "true"} if child in ("workload_identity_provider", "workforce_provider") else None
                        for page, request_id in self.pages(f"https://{service}.googleapis.com/v1/{item['name']}/{segment}", scope,
                                                           key=key, params=params):
                            yield (self.parallel(transform, page) if parent == "kms_key_ring" else page), request_id
                add(child, scope, "cloudkms" if parent == "kms_key_ring" else "iam", children)
        if "bucket_notification" in self.needed:
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def notifications(scope=scope):
                    # storage notifications.list (GET b/{bucket}/notificationConfigs,
                    # storage.buckets.get): one unpaginated read per collected bucket.
                    # custom_attributes are dropped; topic and event filters remain.
                    buckets = self.collections.get(("bucket", scope))
                    if not buckets or buckets["coverage_status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "bucket_inventory_incomplete")
                    for bucket in buckets["items"]:
                        name = bucket.get("name")
                        if not isinstance(name, str) or not name:
                            raise ReadError("malformed", "invalid_bucket_reference")
                        def keep(config, name=name):
                            return {**{k: config[k] for k in ("id", "topic", "event_types", "payload_format", "object_name_prefix")
                                       if k in config}, "name": f"b/{name}/notificationConfigs/{config.get('id')}", "bucket": name,
                                    "bucketProject": scope.split("/", 1)[1], "customAttributeNames": sorted(config.get("custom_attributes") or {})}
                        yield from self.pages("https://storage.googleapis.com/storage/v1/b/" + quote(name, safe="") + "/notificationConfigs",
                                              scope, page_size_key=None, transform=keep)
                add("bucket_notification", scope, "storage", notifications)
        self.run_jobs(jobs)
        from .gcp_osconfig_guest_policy import collect as guest_policy_collect
        guest_policy_collect(self)
        from .gcp_osconfig_policy_orchestrator import collect as orchestrator_collect
        orchestrator_collect(self)
        if not getattr(self, "_independent_jobs_scheduled", False):
            from .gcp_privateca_pool import collect as privateca_pool_collect
            privateca_pool_collect(self)
        from .gcp_privatecatalog_versions import collect as privatecatalog_versions_collect
        privatecatalog_versions_collect(self)
        if not getattr(self, "_independent_jobs_scheduled", False):
            from .gcp_dataform_privesc import collect as dataform_privesc_collect
            dataform_privesc_collect(self)
            from .gcp_datafusion_privesc import collect as datafusion_privesc_collect
            datafusion_privesc_collect(self)
            from .gcp_dataplex_privesc import collect as dataplex_privesc_collect
            dataplex_privesc_collect(self)
        from .gcp_compliance_wave import dependent as compliance_dependent
        compliance_dependent(self)
        from .gcp_native_evidence import dependent as native_evidence_dependent
        native_evidence_dependent(self)
        from .gcp_os_patch_native import collect as os_patch_collect
        os_patch_collect(self)
        if "bigquery_acl_mode" in self.needed:
            mode_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def acl_modes(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    locations = {item.get("location") for item in datasets["items"]}
                    if any(not isinstance(location, str) or not re.fullmatch(r"[A-Za-z0-9-]+", location)
                           for location in locations):
                        raise ReadError("malformed", "dataset_location_missing")
                    binding = self._data_project_binding(scope)
                    def location_pages(location):
                        query = ("SELECT COALESCE((SELECT option_value FROM `region-" + location.lower()
                                 + "`.INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS "
                                 "WHERE option_name = 'enable_fine_grained_dataset_acls_option' LIMIT 1), 'false') AS option_value")
                        data, request_id = self.read(
                            f"https://bigquery.googleapis.com/bigquery/v2/projects/{binding['project_id']}/queries",
                            scope, method="POST", body={"query": query, "useLegacySql": False,
                                "location": location, "maxResults": 2, "timeoutMs": 10000})
                        if not isinstance(data, dict) or data.get("jobComplete") is not True:
                            raise ReadError("unavailable", "bigquery_acl_mode_query_incomplete")
                        rows = data.get("rows")
                        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                            raise ReadError("malformed", "bigquery_acl_mode_rows_invalid")
                        fields = rows[0].get("f")
                        raw = fields[0].get("v") if isinstance(fields, list) and len(fields) == 1 and isinstance(fields[0], dict) else None
                        if not isinstance(raw, str) or raw.lower() not in ("true", "false"):
                            raise ReadError("malformed", "bigquery_acl_mode_value_invalid")
                        yield [{"name": f"{scope}/locations/{location}/bigqueryAclMode",
                                "location": location, "enabled": raw.lower() == "true"}], request_id
                    yield from fanout_pages(self, sorted(locations), location_pages)
                mode_jobs.append(("bigquery_acl_mode", scope, "bigquery", acl_modes))
            self.run_jobs(mode_jobs)
        if "bigquery_connection" in self.needed:
            extra_connection_locations = self.options.get(
                "bigquery_connection_locations", self.options.get("regions", []))
            if (not isinstance(extra_connection_locations, list)
                    or len(extra_connection_locations) > 100
                    or any(not isinstance(location, str)
                           or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", location)
                           for location in extra_connection_locations)):
                raise ValueError("bigquery_connection_locations must contain at most 100 explicit locations")
            connection_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def connections(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    locations = {item.get("location") for item in datasets["items"]}
                    locations.update(extra_connection_locations)
                    if any(not isinstance(location, str) or not re.fullmatch(r"[A-Za-z0-9-]+", location)
                           for location in locations):
                        raise ReadError("malformed", "dataset_location_missing")
                    binding = self._data_project_binding(scope)
                    def location_pages(location):
                        parent = f"projects/{binding['project_id']}/locations/{location}"
                        base = f"https://bigqueryconnection.googleapis.com/v1/{parent}/connections"
                        for page, request_id in self.pages(base, scope, key="connections", page_size_key="pageSize"):
                            def detail(item):
                                native = item.get("name")
                                match = re.fullmatch(
                                    re.escape(parent) + r"/connections/([A-Za-z0-9_-]+)", native or "")
                                if not match:
                                    raise ReadError("malformed", "bigquery_connection_identity_unbound")
                                def exact(value):
                                    if not isinstance(value, dict) or value.get("name") != native:
                                        raise ReadError("malformed", "bigquery_connection_detail_identity_unbound")
                                item = self.hydrate(item, "connectionDetails",
                                    "https://bigqueryconnection.googleapis.com/v1/" + native, scope,
                                    identity_validator=exact)
                                if item["_coverage"]["connectionDetails"]["status"] == "collected":
                                    item.update(item.pop("connectionDetails"))
                                    item["_representation"] = "full"
                                else:
                                    item["_representation"] = "partial"
                                if self.options.get("resource_iam", True):
                                    item = self.hydrate(item, "iamPolicy",
                                        "https://bigqueryconnection.googleapis.com/v1/" + native + ":getIamPolicy",
                                        scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                        identity_validator=_validate_iam_policy)
                                return item
                            yield self.parallel(detail, page), request_id
                    yield from fanout_pages(self, sorted(locations), location_pages)
                connection_jobs.append(("bigquery_connection", scope, "bigqueryconnection", connections))
            self.run_jobs(connection_jobs)
        if "bigquery_routine_metadata" in self.needed:
            routine_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def routine_metadata(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    binding = self._data_project_binding(scope)
                    def dataset_pages(dataset):
                        dataset_id = self._data_bigquery_identity(scope, dataset)
                        if ANONYMOUS_DATASET.fullmatch(dataset_id):
                            return
                        base = ("https://bigquery.googleapis.com/bigquery/v2/projects/"
                                + binding["project_id"] + "/datasets/" + quote(dataset_id, safe="") + "/routines")
                        for page, request_id in self.pages(base, scope, key="routines",
                                                           page_size_key="maxResults"):
                            rows = []
                            for item in page:
                                ref = item.get("routineReference")
                                if (not isinstance(ref, dict) or ref.get("projectId") != binding["project_id"]
                                        or ref.get("datasetId") != dataset_id
                                        or not isinstance(ref.get("routineId"), str)
                                        or not re.fullmatch(r"[A-Za-z0-9_]{1,256}", ref["routineId"])):
                                    raise ReadError("malformed", "bigquery_routine_identity_unbound")
                                rows.append({"name": f"{scope}/datasets/{dataset_id}/routines/{ref['routineId']}",
                                             "routineType": item.get("routineType"),
                                             "language": item.get("language"),
                                             "datasetLocation": dataset.get("location")})
                            if self.options.get("resource_iam", True):
                                rows = self.parallel(lambda item: self.hydrate(item, "iamPolicy",
                                    "https://bigquery.googleapis.com/bigquery/v2/" + item["name"] + ":getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                    identity_validator=_validate_iam_policy), rows)
                            yield rows, request_id
                    yield from fanout_pages(self, datasets["items"], dataset_pages)
                routine_jobs.append(("bigquery_routine_metadata", scope, "bigquery", routine_metadata))
            self.run_jobs(routine_jobs)
        if "bigquery_transfer_config" in self.needed:
            transfer_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def transfer_configs(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    binding = self._data_project_binding(scope)
                    locations = {item.get("location") for item in datasets["items"]}
                    if any(not isinstance(location, str) or not re.fullmatch(r"[A-Za-z0-9-]+", location)
                           for location in locations):
                        raise ReadError("malformed", "dataset_location_missing")
                    def location_pages(location):
                        parent = f"projects/{binding['project_id']}/locations/{location}"
                        base = f"https://bigquerydatatransfer.googleapis.com/v1/{parent}/transferConfigs"
                        for page, request_id in self.pages(base, scope, key="transferConfigs"):
                            rows = []
                            for item in page:
                                if item.get("dataSourceId") != "scheduled_query":
                                    continue
                                native = item.get("name")
                                regional = isinstance(native, str) and re.fullmatch(
                                    re.escape(parent) + r"/transferConfigs/[A-Za-z0-9_-]+", native)
                                legacy_us = (location.upper() == "US" and isinstance(native, str)
                                             and re.fullmatch(re.escape("projects/" + binding["project_id"])
                                                              + r"/transferConfigs/[A-Za-z0-9_-]+", native))
                                if not (regional or legacy_us):
                                    raise ReadError("malformed", "bigquery_transfer_config_identity_unbound")
                                options = item.get("scheduleOptions")
                                if options is not None and not isinstance(options, dict):
                                    raise ReadError("malformed", "bigquery_transfer_schedule_invalid")
                                rows.append({"name": native, "dataSourceId": "scheduled_query",
                                             "location": location,
                                             "destinationDatasetId": item.get("destinationDatasetId"),
                                             "disabled": item.get("disabled"),
                                             "scheduleOptions": {"disableAutoScheduling":
                                                 (options or {}).get("disableAutoScheduling")}})
                            yield rows, request_id
                    yield from fanout_pages(self, sorted(locations), location_pages)
                transfer_jobs.append(("bigquery_transfer_config", scope, "bigquerydatatransfer",
                                      transfer_configs))
            self.run_jobs(transfer_jobs)
        if "bigquery_continuous_assignment" in self.needed:
            assignment_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def continuous_assignments(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    binding = self._data_project_binding(scope)
                    locations = {item.get("location") for item in datasets["items"]}
                    if any(not isinstance(location, str) or not re.fullmatch(r"[A-Za-z0-9-]+", location)
                           for location in locations):
                        raise ReadError("malformed", "dataset_location_missing")
                    def location_pages(location):
                        parent = f"projects/-/locations/{location}"
                        base = f"https://bigqueryreservation.googleapis.com/v1/{parent}:searchAllAssignments"
                        for page, request_id in self.pages(base, scope, key="assignments",
                                page_size_key="pageSize",
                                params={"query": "assignee=projects/" + binding["project_id"]}):
                            rows = []
                            for item in page:
                                if item.get("jobType") != "CONTINUOUS":
                                    continue
                                name = item.get("name")
                                if (not isinstance(name, str) or not re.fullmatch(
                                        r"projects/[^/]+/locations/" + re.escape(location)
                                        + r"/reservations/[A-Za-z0-9_-]+/assignments/[A-Za-z0-9_-]+", name)):
                                    raise ReadError("malformed", "continuous_assignment_identity_unbound")
                                reservation = name.rsplit("/assignments/", 1)[0]
                                projected = {key: item.get(key) for key in
                                             ("name", "assignee", "jobType", "state", "principal")}
                                projected["sourceLocation"] = location
                                def exact(value, reservation=reservation):
                                    if value.get("name") != reservation:
                                        raise ReadError("malformed", "continuous_reservation_identity_unbound")
                                projected = self.hydrate(projected, "reservationDetails",
                                    f"https://bigqueryreservation.googleapis.com/v1/{reservation}", scope,
                                    identity_validator=exact)
                                if projected["_coverage"]["reservationDetails"]["status"] == "collected":
                                    detail = projected.pop("reservationDetails")
                                    projected["reservationEdition"] = detail.get("edition")
                                    projected["reservationSlotCapacity"] = detail.get("slotCapacity")
                                rows.append(projected)
                            yield rows, request_id
                    yield from fanout_pages(self, sorted(locations), location_pages)
                assignment_jobs.append(("bigquery_continuous_assignment", scope, "bigqueryreservation",
                                        continuous_assignments))
            self.run_jobs(assignment_jobs)
        if "bigquery_table" in self.needed:
            table_jobs = []
            for scope in [scope for scope in self.scopes if scope.startswith("projects/")]:
                def tables(scope=scope):
                    datasets = self.collections.get(("bigquery_dataset", scope))
                    if not datasets or datasets["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "dataset_inventory_incomplete")
                    binding = self._data_project_binding(scope)
                    api_scope = "projects/" + binding["project_id"]
                    def dataset_pages(dataset):
                        dataset_id = self._data_bigquery_identity(scope, dataset)
                        if ANONYMOUS_DATASET.fullmatch(dataset_id):
                            return  # owner-only cached query results, not customer tables
                        base = f"https://bigquery.googleapis.com/bigquery/v2/{api_scope}/datasets/{quote(dataset_id, safe='')}/tables"
                        def detail(item, base=base):
                            reference = item.get("tableReference", {})
                            table_id = reference.get("tableId") if isinstance(reference, dict) else None
                            self._data_bigquery_identity(scope, item, dataset_id, table_id if isinstance(table_id, str) else "")
                            resource = f"{scope}/datasets/{dataset_id}/tables/{table_id}"
                            item = {**item, "name": resource}
                            item = self.hydrate(item, "tableDetails", base + "/" + quote(table_id, safe=""), scope,
                                params={"fields": "id,tableReference,type,encryptionConfiguration,timePartitioning,rangePartitioning,expirationTime,creationTime,lastModifiedTime,labels,requirePartitionFilter,resourceTags,schema(fields(name,type,mode,fields,policyTags(names)))"},
                                identity_validator=lambda value: self._data_bigquery_identity(scope, value, dataset_id, table_id))
                            if item["_coverage"]["tableDetails"]["status"] == "malformed":
                                raise ReadError("malformed", "bigquery_table_detail_identity_unbound")
                            if item["_coverage"]["tableDetails"]["status"] == "collected":
                                item.update(item.pop("tableDetails"))
                                if isinstance(item.get("schema"), dict) and isinstance(item["schema"].get("fields"), list):
                                    item["_schema_full"] = True
                            if self.options.get("resource_iam", True):
                                item = self.hydrate(item, "iamPolicy",
                                    f"https://bigquery.googleapis.com/bigquery/v2/{resource}:getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                    identity_validator=_validate_iam_policy)
                            return item
                        for items, request_id in self.pages(base, scope, key="tables", page_size_key="maxResults"):
                            yield self.parallel(detail, items), request_id
                    yield from fanout_pages(self, datasets["items"], dataset_pages)
                table_jobs.append(("bigquery_table", scope, "bigquery", tables))
            self.run_jobs(table_jobs)
        if "bigquery_row_policy_inventory" in self.needed:
            policy_jobs = []
            for scope in [s for s in self.scopes if s.startswith("projects/")]:
                def row_policies(scope=scope):
                    tables = self.collections.get(("bigquery_table", scope))
                    if not tables or tables["status"] not in ("collected", "empty"):
                        raise ReadError("unavailable", "bigquery_table_inventory_incomplete")
                    binding = self._data_project_binding(scope)
                    api_scope = "projects/" + binding["project_id"]
                    def table_pages(table):
                        resource = table.get("name")
                        if table.get("type") != "TABLE" or not isinstance(resource, str):
                            return
                        match = re.fullmatch(r"projects/[^/]+/datasets/([A-Za-z0-9_]+)/tables/([A-Za-z0-9_]+)", resource)
                        if not match or not resource.startswith(scope + "/"):
                            raise ReadError("malformed", "bigquery_row_policy_table_identity_unbound")
                        dataset_id, table_id = match.groups()
                        base = (f"https://bigquery.googleapis.com/bigquery/v2/{api_scope}/datasets/"
                                f"{quote(dataset_id, safe='')}/tables/{quote(table_id, safe='')}/rowAccessPolicies")
                        record = {"name": resource + "/rowAccessPolicyInventory", "table": resource,
                                  "status": "collected", "policies": []}
                        refs = []
                        seen = set()
                        try:
                            for policies, request_id in self.pages(base, scope, key="rowAccessPolicies", page_size_key="pageSize"):
                                refs.append(request_id)
                                # Policies before the first invalid one are kept,
                                # as when each was read in turn.
                                valid, failure = [], None
                                for policy in policies:
                                    ref = policy.get("rowAccessPolicyReference")
                                    if not isinstance(ref, dict) or not self._data_project_matches(scope, ref.get("projectId")) \
                                            or ref.get("datasetId") != dataset_id or ref.get("tableId") != table_id \
                                            or not isinstance(ref.get("policyId"), str) \
                                            or not re.fullmatch(r"[A-Za-z0-9_]{1,256}", ref["policyId"]):
                                        failure = ReadError("malformed", "bigquery_row_policy_identity_unbound")
                                        break
                                    policy_id = ref["policyId"]
                                    if policy_id in seen:
                                        failure = ReadError("malformed", "duplicate_bigquery_row_policy")
                                        break
                                    seen.add(policy_id)
                                    valid.append(policy_id)
                                hydrated_policies = self.parallel(lambda policy_id: self.hydrate(
                                    {"name": resource + "/rowAccessPolicies/" + policy_id}, "iamPolicy",
                                    base + "/" + quote(policy_id, safe="") + ":getIamPolicy", scope,
                                    method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                    identity_validator=_validate_iam_policy), valid)
                                for policy_id, hydrated in zip(valid, hydrated_policies):
                                    policy_name = resource + "/rowAccessPolicies/" + policy_id
                                    coverage = hydrated.get("_coverage", {}).get("iamPolicy", {})
                                    refs.extend(coverage.get("source_requests", []))
                                    if coverage.get("status") != "collected":
                                        record["status"] = coverage.get("status") or "unavailable"
                                    record["policies"].append({"name": policy_name,
                                        "iamPolicy": hydrated.get("iamPolicy"), "_coverage": {"iamPolicy": coverage}})
                                if failure is not None:
                                    raise failure
                        except ReadError as error:
                            record["status"] = error.status
                            if getattr(error, "request_id", None):
                                refs.append(error.request_id)
                        record["_coverage"] = {"rowAccessPolicies": {"status": record["status"],
                            "source_requests": sorted(set(refs))}}
                        source_ref = (refs[0] if refs else
                                      next(iter((table.get("_provenance") or {}).get("source_requests", [])), ""))
                        yield [record], source_ref
                    yield from fanout_pages(self, tables["items"], table_pages)
                policy_jobs.append(("bigquery_row_policy_inventory", scope, "bigquery", row_policies))
            self.run_jobs(policy_jobs)
        if self.needed.intersection({"group", "group_membership"}):
            self.directory_groups()
        if "workspace_user" in self.needed:
            from .gcp_unused_iam_directory_completion_20261021 import collect_users
            collect_users(self)
        if self.needed.intersection({"workspace_user", "workspace_customer", "workspace_role", "workspace_role_assignment"}):
            self.workspace_directory()
        if "iam_role" in self.needed:
            role_scopes = {}
            for scope, policy in self.items("iam_policy"):
                for binding in policy.get("bindings", []):
                    role = binding.get("role")
                    if isinstance(role, str) and re.fullmatch(r"(?:roles/[\w.]+|(?:projects|organizations)/[\w.-]+/roles/[\w.]+)", role):
                        role_scopes.setdefault(role, set()).add(scope)
            for kind in ("bucket", "bigquery_table", "bigquery_routine_metadata", "secret", "pubsub_topic", "pubsub_subscription", "kms_key_ring", "kms_key",
                         "integration_connection", "contact_center_authorized_view"):
                for scope, resource in self.items(kind):
                    if ((resource.get("_coverage") or {}).get("iamPolicy") or {}).get("status") != "collected":
                        continue
                    for binding in (resource.get("iamPolicy") or {}).get("bindings", []):
                        role = binding.get("role")
                        if isinstance(role, str) and re.fullmatch(r"(?:roles/[\w.]+|(?:projects|organizations)/[\w.-]+/roles/[\w.]+)", role):
                            role_scopes.setdefault(role, set()).add(scope)
            for scope, _ in self.items("recoverable_snapshot"):
                role_scopes.setdefault("roles/compute.storageAdmin", set()).add(scope)
            for scope, _ in self.items("snapshot"):
                role_scopes.setdefault("roles/compute.storageAdmin", set()).add(scope)
            for scope, _ in self.items("machine_image"):
                role_scopes.setdefault("roles/compute.admin", set()).add(scope)
            for scope, _ in self.items("integration_connection"):
                role_scopes.setdefault("roles/connectors.invoker", set()).add(scope)
            for scope, _ in self.items("contact_center_authorized_view"):
                role_scopes.setdefault("roles/contactcenterinsights.authorizedViewer", set()).add(scope)
            known = {(scope, item.get("name")) for scope, item in self.items("iam_role")}
            from .gcp_unused_directory_20261021 import known_role_aliases
            known.update(known_role_aliases(self, role_scopes, known))
            selected_projects = set(self.scopes)
            for _, project in self.items("project"):
                if isinstance(project.get("name"), str):
                    selected_projects.add(project["name"])
                if isinstance(project.get("projectId"), str):
                    selected_projects.add("projects/" + project["projectId"])
            jobs = []
            for role, scope in sorted((role, scope) for role, scopes in role_scopes.items() for scope in scopes
                                      if (scope, role) not in known):
                # Cross-project custom roles stay references unless their owning
                # project was selected; project restrictions apply to reads too.
                if role.startswith("projects/") and "/".join(role.split("/")[:2]) not in selected_projects:
                    self.scope_errors.append({"scope": scope, "role": role, "status": "unavailable", "code": "role_owner_not_selected"})
                    continue
                if role.startswith("organizations/") and "/".join(role.split("/")[:2]) not in set(self.scopes) | set(getattr(self, "inherited_scopes", [])):
                    self.scope_errors.append({"scope": scope, "role": role, "status": "unavailable", "code": "role_owner_not_selected"})
                    continue
                jobs.append(("iam_role", scope, "iam", lambda role=role, scope=scope: self.pages(
                    f"https://iam.googleapis.com/v1/{role}", scope, single=True)))
            self.run_jobs(jobs)

    def hierarchy_chain(self, scope):
        """Ancestors of `scope`, nearest first, or None when ancestry is unknown."""
        if scope.startswith("organizations/"):
            return []
        if scope.startswith("projects/"):
            ancestry = self.ancestry.get(scope)
            if not isinstance(ancestry, list):
                return None
            chain = []
            for ancestor in ancestry:
                resource = ancestor.get("resourceId", {}) if isinstance(ancestor, dict) else {}
                if resource.get("type") in ("folder", "organization") and resource.get("id"):
                    chain.append(f"{resource['type']}s/{resource['id']}")
            return chain
        parents = {}
        for _, folder in self.items("folder"):
            if isinstance(folder.get("name"), str) and isinstance(folder.get("parent"), str):
                parents[folder["name"]] = folder["parent"]
        chain, current = [], scope
        while current.startswith("folders/"):
            parent = parents.get(current)
            if parent is None or parent in chain or len(chain) > 20:
                return None
            chain.append(parent)
            current = parent
        return chain

    def derive_sw52_native(self):
        """Bind one project's Directory realm and exact CRM root policies to native reads."""
        self.sw52_native = {}
        if not self.sw52_native_mode:
            return
        if len([scope for scope in self.scopes if scope.startswith("projects/")]) != 1 or len(self.scopes) != 1:
            self.sw52_native = {scope: {"status": "unknown", "scope": scope, "reason": "multi_scope_directory_binding_unavailable"}
                for scope in self.scopes if scope.startswith("projects/")}
            return
        for scope in self.scopes:
            if not scope.startswith("projects/"):
                continue
            record = {"status": "unknown", "scope": scope, "reason": "hierarchy_unavailable"}
            self.sw52_native[scope] = record
            ancestry = self.ancestry.get(scope)
            request = self.ancestry_source_requests.get(scope)
            chain = self.hierarchy_chain(scope)
            if not isinstance(ancestry, list) or not request or chain is None or not chain or not chain[-1].startswith("organizations/"):
                continue
            if chain.count(chain[-1]) != 1 or any(not name.startswith("folders/") for name in chain[:-1]):
                continue
            names = [scope, *chain]
            project = self.collections.get(("project", scope))
            if not project or project.get("status") != "collected" or len(project.get("items", [])) != 1:
                record["reason"] = "project_identity_unavailable"
                continue
            project_row = project["items"][0]
            if (project_row.get("projectId") != scope.split("/", 1)[1] or
                    project_row.get("parent") != chain[0] or
                    not project.get("source_requests")):
                record["reason"] = "stale_project_parent"
                continue
            hierarchy_requests = {scope: project["source_requests"]}
            for position, name in enumerate(chain[:-1]):
                folder = self.collections.get(("folder", name))
                if (not folder or folder.get("status") != "collected" or
                        len(folder.get("items", [])) != 1 or
                        folder["items"][0].get("name") != name or
                        folder["items"][0].get("parent") != chain[position + 1] or
                        not folder.get("source_requests")):
                    record["reason"] = "stale_folder_parent"
                    break
                hierarchy_requests[name] = folder["source_requests"]
            if record["reason"] == "stale_folder_parent":
                continue
            organization = self.collections.get(("organization", chain[-1]))
            if not organization or organization.get("status") != "collected" or len(organization.get("items", [])) != 1:
                record["reason"] = "organization_identity_unavailable"
                continue
            org = organization["items"][0]
            if org.get("name") != chain[-1] or not isinstance(org.get("directoryCustomerId"), str) or not re.fullmatch(r"C[A-Za-z0-9_-]+", org["directoryCustomerId"]):
                record["reason"] = "organization_directory_customer_unavailable"
                continue
            policy_requests, policy_roots = {}, []
            for name in names:
                collection = self.collections.get(("iam_policy", name))
                roots = [row for row in (collection or {}).get("items", []) if row.get("name") == name and row.get("_provenance", {}).get("representation") == "full"]
                if (not collection or collection.get("status") not in ("collected", "empty") or
                        len(roots) != 1 or not collection.get("source_requests") or
                        not roots[0].get("_provenance", {}).get("source_requests") or
                        not isinstance(roots[0].get("bindings"), list)):
                    record["reason"] = "iam_root_read_incomplete"
                    break
                policy_requests[name] = roots[0]["_provenance"]["source_requests"]
                policy_roots.append({"origin_scope": name, "name": roots[0]["name"],
                    "bindings": copy.deepcopy(roots[0]["bindings"]),
                    "representation": "full", "source_requests": copy.deepcopy(policy_requests[name]),
                    "collection_source_requests": copy.deepcopy(collection["source_requests"])})
            else:
                record.update({"status": "collected", "reason": "", "organization": chain[-1],
                    "directory_customer": org["directoryCustomerId"], "iam_policy_resource_names": names,
                    "iam_policy_levels": [name.split("/", 1)[0][:-1] for name in names],
                    "ancestry_source_requests": [request], "iam_policy_source_requests": policy_requests,
                    "iam_policy_roots": policy_roots,
                    "organization_source_requests": organization.get("source_requests", []),
                    "hierarchy_source_requests": hierarchy_requests})

    def annotate_effective_audit(self):
        """Attach the inherited (organization -> folders -> resource) audit
        configuration to each hierarchy root policy. Cloud Audit Logs takes the
        union of the resource's and its ancestors' auditConfigs, and checks see
        only same-scope collections, so the chain is materialized here."""
        if "iam_policy" not in self.needed:
            return
        from peaso.checks.facts import Unavailable, get, guard

        roots, ambiguous_scopes = {}, set()
        proven_alias_positions = {}
        self.proven_project_alias_scopes = set()
        if getattr(self, "transport", None) is not None:
            from peaso.gcp_project_alias import AliasUnavailable, prove_project_alias
            for (kind, scope), policy_envelope in self.collections.items():
                if kind != "iam_policy" or not scope.startswith("projects/"):
                    continue
                project_envelope = self.collections.get(("project", scope))
                if project_envelope is None:
                    continue
                try:
                    binding = prove_project_alias(scope, project_envelope, policy_envelope,
                        getattr(self.transport, "evidence", []))
                except AliasUnavailable:
                    continue
                if (policy_envelope.get("status"), policy_envelope.get("coverage_status")) == ("partial", "partial"):
                    # Only the exact root collision proved above is repaired.
                    # Its request ledger and all retained rows remain intact.
                    policy_envelope["status"] = policy_envelope["coverage_status"] = "collected"
                    policy_envelope.pop("error", None)
                proven_alias_positions[scope] = binding.alias_position
                self.proven_project_alias_scopes.add(scope)
        from peaso.gcp_project_alias import root_candidate

        def representation(item):
            guard(item)
            coverage = item.get("_coverage", {})
            if "_representation" in item or "_representation" in coverage:
                return get(item, "_representation", str)
            if "_provenance" in item or "_provenance" in coverage:
                provenance = get(item, "_provenance", dict)
                if "representation" in provenance or "representation" in provenance.get("_coverage", {}):
                    return get(provenance, "representation", str)
            return None

        def audit_configs(policy):
            guard(policy)
            coverage = policy.get("_coverage", {})
            marker = coverage.get("auditConfigs")
            provenance = policy.get("_provenance", {})
            if not isinstance(provenance, dict):
                raise Unavailable("malformed IAM policy provenance")
            if "auditConfigs" in policy:
                return get(policy, "auditConfigs")
            if "auditConfigs" in coverage:
                if (isinstance(marker, dict) and marker.get("status") == "empty"
                        and representation(policy) == "full"):
                    return []
                raise Unavailable("IAM policy auditConfigs omission unavailable")
            # The direct getIamPolicy read is a full API response. Older
            # unmarked root fixtures also encode the native omitted default.
            if representation(policy) == "full" or (
                    "assetType" not in policy and "_representation" not in policy
                    and "representation" not in provenance):
                return []
            raise Unavailable("IAM policy auditConfigs omission lacks full source")

        for (kind, scope), collection in self.collections.items():
            if kind != "iam_policy":
                continue
            try:
                guard(collection)
                inventory = get(collection, "items", list)
            except Unavailable:
                ambiguous_scopes.add(scope)
                continue
            # Retained readable roots still need an explicit partial annotation.
            # Inventory status can invalidate authority without hiding those rows.
            try:
                collection_coverage = collection.get("_coverage", {})
                for field in ("status", "coverage_status"):
                    if field in collection or field in collection_coverage:
                        if get(collection, field, str) != "collected":
                            raise Unavailable("incomplete IAM inventory")
            except Unavailable:
                ambiguous_scopes.add(scope)
            for position, item in enumerate(inventory):
                if position == proven_alias_positions.get(scope):
                    continue
                try:
                    name = get(item, "name", str)
                    if name == scope:
                        roots.setdefault(scope, []).append(item)
                        continue
                    if root_candidate(item):
                        ambiguous_scopes.add(scope)
                except Unavailable:
                    # A denied identity marker can hide a hierarchy root.
                    ambiguous_scopes.add(scope)
        for scope, policies in roots.items():
            chain = self.hierarchy_chain(scope)
            for item in policies:
                entries, missing, malformed = [], [], []
                for ancestor in [scope, *(chain or [])]:
                    source = self.collections.get(("iam_policy", ancestor))
                    candidates = roots.get(ancestor, [])
                    if not candidates:
                        missing.append(ancestor)
                        continue
                    if len(candidates) > 1 or ancestor in ambiguous_scopes:
                        malformed.append(ancestor)
                        continue
                    if (not isinstance(source, dict) or any(
                            source.get(field, "collected") != "collected"
                            for field in ("status", "coverage_status"))):
                        malformed.append(ancestor)
                        continue
                    policy = candidates[0]
                    try:
                        configs = audit_configs(policy)
                        provenance = policy.get("_provenance", {})
                        requests = list(provenance.get("source_requests", []))
                    except (Unavailable, AttributeError, TypeError):
                        malformed.append(ancestor)
                        continue
                    if not isinstance(configs, list):
                        malformed.append(ancestor)
                    entries.append({"scope": ancestor, "auditConfigs": copy.deepcopy(configs),
                        "source_requests": requests})
                complete = chain is not None and not missing and not malformed
                item["effectiveAuditConfigs"] = entries
                item.setdefault("_coverage", {})["effectiveAuditConfigs"] = {
                    "status": "collected" if complete else "partial", "collection_status": "collected" if complete else "partial",
                    "ancestry_known": chain is not None, "missing_scopes": missing, "malformed_scopes": malformed,
                    "ancestor_scopes": list(chain) if chain is not None else [],
                    "ancestry_source_requests": ([self.ancestry_source_requests[scope]]
                        if scope in self.ancestry_source_requests else []),
                    "source_requests": sorted({ref for entry in entries for ref in entry["source_requests"]}),
                    "semantics": "Union of resource and ancestor auditConfigs (organization, folders, resource)"}

    def metrics_scopes(self, item, scope):
        """Attach the metrics scopes that monitor this project (an alert may
        live in a scoping host project). Absent when the read fails."""
        output = dict(item)
        coverage = output.setdefault("_coverage", {})
        try:
            names, requests = [], []
            for page, request_id in self.pages("https://monitoring.googleapis.com/v1/locations/global/metricsScopes:"
                                               "listMetricsScopesByMonitoredProject", scope, key="metricsScopes",
                                               params={"monitoredResourceContainer": scope}, page_size_key=None):
                if any(not isinstance(row.get("name"), str) for row in page):
                    raise ReadError("malformed", "malformed_metrics_scope")
                names.extend(row["name"] for row in page)
                requests.append(request_id)
            output["_monitoring_metrics_scopes"] = sorted(set(names))
            coverage["_monitoring_metrics_scopes"] = {"status": "collected", "collection_status": "collected",
                                                     "source_requests": requests}
        except ReadError as exc:
            output.pop("_monitoring_metrics_scopes", None)
            coverage["_monitoring_metrics_scopes"] = {"status": exc.status, "collection_status": wire_status(exc.status),
                "error": exc.error, "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}
        return output

    def annotate_inherited_sinks(self):
        """Attach every folder/organization ancestor's sinks to each project as
        `_inherited_sinks`. Absent unless the ancestry and every ancestor's
        sinks.list were completely collected."""
        if "log_sink" not in self.needed or "project" not in self.needed:
            return
        fields = ("name", "destination", "filter", "disabled", "includeChildren", "interceptChildren", "exclusions")
        for (kind, scope), collection in self.collections.items():
            if kind != "project" or not scope.startswith("projects/"):
                continue
            chain = self.hierarchy_chain(scope)
            if chain is None:
                continue
            sinks, requests, complete = [], set(), True
            for ancestor in chain:
                source = self.collections.get(("log_sink", ancestor))
                if source is None or source.get("coverage_status") not in ("collected", "empty"):
                    complete = False
                    break
                requests.update(source.get("source_requests", []))
                for sink in source["items"]:
                    sinks.append({**{key: copy.deepcopy(sink[key]) for key in fields if key in sink}, "ancestor": ancestor})
            if not complete:
                continue
            for item in collection["items"]:
                item["_inherited_sinks"] = copy.deepcopy(sinks)
                provenance = item.setdefault("_provenance", {})
                provenance["source_requests"] = sorted(set(provenance.get("source_requests", [])) | requests)
                item.setdefault("_coverage", {})["_inherited_sinks"] = {"status": "collected", "collection_status": "collected",
                    "ancestors": list(chain), "source_requests": sorted(requests),
                    "semantics": "sinks.list of every folder/organization ancestor (aggregated sinks need includeChildren)"}

    def annotate_inherited_policies(self):
        """Attach each folder/organization ancestor's own root IAM policy to the
        project as `_inherited_iam_policies`. Absent unless the ancestry is known
        and every ancestor's getIamPolicy document was collected."""
        if "iam_policy" not in self.needed or "project" not in self.needed:
            return
        for (kind, scope), collection in self.collections.items():
            if kind != "project" or not scope.startswith("projects/"):
                continue
            chain = self.hierarchy_chain(scope)
            if chain is None:
                continue
            policies, requests = [], set()
            for ancestor in chain:
                source = self.collections.get(("iam_policy", ancestor))
                roots = [x for x in (source or {}).get("items", []) if x.get("name") == ancestor]
                if source is None or source.get("coverage_status") not in ("collected", "empty") or len(roots) != 1:
                    break
                requests.update(roots[0].get("_provenance", {}).get("source_requests", []))
                policies.append({**{key: copy.deepcopy(roots[0][key]) for key in ("name", "bindings", "etag", "version")
                                    if key in roots[0]}, "ancestor": ancestor})
            else:
                for item in collection["items"]:
                    item["_inherited_iam_policies"] = copy.deepcopy(policies)
                    provenance = item.setdefault("_provenance", {})
                    provenance["source_requests"] = sorted(set(provenance.get("source_requests", [])) | requests)
                    item.setdefault("_coverage", {})["_inherited_iam_policies"] = {"status": "collected",
                        "collection_status": "collected", "ancestors": list(chain), "source_requests": sorted(requests),
                        "semantics": "getIamPolicy root policy of every folder/organization ancestor (declared grants)"}

    def directory_groups(self):
        """Resolve declared group references and selected directory group realms."""
        if not self.scopes:
            return
        scope = self.scopes[0]
        references = set()
        for (kind, _), collection in self.collections.items():
            if collection.get("status") not in ("collected", "partial"):
                continue
            for item in collection.get("items", []):
                if not isinstance(item, dict):
                    continue
                policy = item if kind == "iam_policy" else item.get("iamPolicy")
                if isinstance(policy, dict):
                    for binding in policy.get("bindings") or []:
                        if not isinstance(binding, dict):
                            continue
                        references.update(member[len("group:"):] for member in binding.get("members") or []
                            if isinstance(member, str) and member.startswith("group:") and len(member) > len("group:"))
                if kind == "bigquery_dataset":
                    references.update(access["groupByEmail"] for access in item.get("access") or []
                        if isinstance(access, dict) and isinstance(access.get("groupByEmail"), str)
                        and access["groupByEmail"])
        references = sorted(references)
        customers = set(self.options.get("cloud_identity_customers", []))
        if "workspace_user" in self.needed:
            binding = self.workspace_project_binding()
            if binding["status"] == "collected":
                customers.add(binding["customer"])
        if self.sw52_only_mode:
            customers = {entry["directory_customer"] for entry in getattr(self, "sw52_native", {}).values()
                if entry.get("status") == "collected"}
        for _, organization in ([] if self.sw52_only_mode else self.items("organization")):
            owner = organization.get("owner", {})
            customer = organization.get("directoryCustomerId") or (owner.get("directoryCustomerId") if isinstance(owner, dict) else None)
            if customer:
                customers.add(customer)
        if any(not isinstance(customer, str) or not re.fullmatch(r"C[A-Za-z0-9_-]+", customer) for customer in customers):
            raise ValueError("cloud_identity_customers must contain Google directory customer IDs")
        def groups():
            failures = []
            listed_emails = set()
            for customer in sorted(customers):
                try:
                    for rows, request_id in self.pages("https://cloudidentity.googleapis.com/v1/groups", scope, key="groups",
                        params={"parent": "customers/" + customer, "view": "FULL", "pageSize": min(self.page_size, 500)}):
                        for row in rows:
                            key = row.get("groupKey") if isinstance(row, dict) else None
                            if isinstance(key, dict) and isinstance(key.get("id"), str):
                                listed_emails.add(key["id"].lower())
                        yield [{**row, "_representation": "full"} for row in rows], request_id
                except ReadError as exc:
                    failures.append(exc)
            for email in references:
                if email.lower() in listed_emails:
                    continue
                try:
                    resolved, request_id = self.read("https://cloudidentity.googleapis.com/v1/groups:lookup", scope,
                        params={"groupKey.id": email})
                    name = resolved.get("name")
                    if not isinstance(name, str) or not re.fullmatch(r"groups/[A-Za-z0-9_-]+", name):
                        raise ReadError("malformed", "invalid_group_reference")
                    item = self.hydrate({"name": name, "groupKey": {"id": email}, "referencedPrincipal": "group:" + email},
                        "groupDetails", f"https://cloudidentity.googleapis.com/v1/{name}", scope)
                    if item["_coverage"]["groupDetails"]["status"] == "collected":
                        item.update(item.pop("groupDetails"))
                        item["_representation"] = "full"
                    yield [item], request_id
                except ReadError as exc:
                    failures.append(exc)
            # Without a known customer realm, reference resolution cannot claim
            # a complete directory inventory, even if all referenced groups read.
            if not customers:
                failures.append(ReadError("unavailable", "directory_customer_scope_unknown"))
            if failures:
                raise failures[0]
        group_collection = self.add("group", scope, "cloudidentity", groups)
        if self.options.get("group_settings") is True:
            self.group_settings(group_collection, scope)
        if "group_membership" not in self.needed:
            return
        def memberships():
            failures = []
            for group in group_collection["items"]:
                name = group.get("name")
                if not isinstance(name, str) or not re.fullmatch(r"groups/[A-Za-z0-9_-]+", name):
                    failures.append(ReadError("malformed", "invalid_group_reference"))
                    continue
                for relation, endpoint in (("direct", "memberships"), ("transitive", "memberships:searchTransitiveMemberships")):
                    member_names, member_requests = [], []
                    try:
                        for items, request_id in self.pages(f"https://cloudidentity.googleapis.com/v1/{name}/{endpoint}", scope,
                            key="memberships", params={"view": "FULL", "pageSize": min(self.page_size, 500)} if relation == "direct" else None):
                            member_requests.append(request_id)
                            if relation == "direct":
                                for member in items:
                                    native_name = member.get("name")
                                    if (not isinstance(native_name, str) or not re.fullmatch(re.escape(name) + r"/memberships/[A-Za-z0-9_-]+", native_name)
                                            or native_name in member_names):
                                        raise ReadError("malformed", "invalid_direct_membership_identity")
                                    member_names.append(native_name)
                            transformed = []
                            for index, member in enumerate(items):
                                identifier = member.get("name") or member.get("member") or str(member.get("preferredMemberKey") or member.get("memberKey"))
                                transformed.append({**member, "name": f"{name}/{relation}/{identifier}", "group": name,
                                    "membershipKind": relation, "groupKey": group.get("groupKey"),
                                    "membershipCoverage": {"status": "observed", "completeTransitiveClosure": False}})
                            yield transformed, request_id
                        group.setdefault("_coverage", {})[relation + "Memberships"] = {
                            "status": "collected", "scope": scope, "group": name,
                            "collected_at": self.read_time, "source_requests": member_requests}
                    except ReadError as exc:
                        failures.append(exc)
                        group.setdefault("_coverage", {})[relation + "Memberships"] = {
                            "status": exc.status, "error": exc.error,
                            "scope": scope, "group": name, "collected_at": self.read_time,
                            "source_requests": sorted(set(member_requests + ([exc.request_id] if getattr(exc, "request_id", None) else [])))}
                    finally:
                        if relation == "direct":
                            group["_direct_membership_names"] = member_names
                            group["_direct_membership_requests"] = member_requests
            if group_collection["status"] not in ("collected", "empty"):
                failures.append(ReadError("unavailable", "group_inventory_incomplete"))
            if failures:
                raise failures[0]
        collected = self.add("group_membership", scope, "cloudidentity", memberships)
        if collected["status"] in ("collected", "empty"):
            for member in collected["items"]:
                member["membershipCoverage"] = {"status": "collected", "completeTransitiveClosure": True,
                    "semantics": "Cloud Identity membership visibility, not effective cloud permissions"}

    GROUP_SETTINGS_FIELDS = ("whoCanJoin", "allowExternalMembers")

    def group_settings(self, group_collection, scope):
        """Optional Groups Settings (whoCanJoin, allowExternalMembers) per collected group.

        groups.get needs the https://www.googleapis.com/auth/apps.groups.settings
        OAuth scope and a Workspace administrator caller, which the default
        cloud-platform credential does not carry. A denied/insufficient-scope read is
        recorded per group in _coverage.groupSettings and never treated as a setting."""
        for group in group_collection["items"]:
            email = (group.get("groupKey") or {}).get("id") if isinstance(group.get("groupKey"), dict) else None
            coverage = group.setdefault("_coverage", {})
            if not isinstance(email, str) or not re.fullmatch(r"[^@/\s]+@[A-Za-z0-9.-]+", email):
                coverage["groupSettings"] = {"status": "malformed", "collection_status": "malformed",
                                             "error": {"code": "invalid_group_email"}, "source_requests": []}
                continue
            try:
                value, request_id = self.read("https://www.googleapis.com/groups/v1/groups/" + quote(email, safe="@"), scope,
                                              params={"alt": "json"})
                if not isinstance(value, dict):
                    raise ReadError("malformed", "malformed_response")
                group["groupSettings"] = {k: value[k] for k in self.GROUP_SETTINGS_FIELDS if isinstance(value.get(k), str)}
                coverage["groupSettings"] = {"status": "collected", "collection_status": "collected", "source_requests": [request_id]}
                provenance = group.setdefault("_provenance", {})
                provenance["source_requests"] = sorted(set(provenance.get("source_requests", [])) | {request_id})
            except ReadError as exc:
                coverage["groupSettings"] = {"status": exc.status, "collection_status": wire_status(exc.status), "error": exc.error,
                                             "source_requests": [exc.request_id] if getattr(exc, "request_id", None) else []}

    def workspace_project_binding(self):
        """Independent CRM parent reads bind one selected project to its Directory customer."""
        if hasattr(self, "_workspace_binding"):
            return self._workspace_binding
        record = {"status": "unknown", "scope": self.scopes[0] if len(self.scopes) == 1 else "",
                  "chain": [], "reason": "single_project_directory_binding_required"}
        self._workspace_binding = record
        if len(self.scopes) != 1 or not self.scopes[0].startswith("projects/"):
            return record
        scope = self.scopes[0]
        current, seen = scope, set()
        try:
            for _ in range(32):
                if current in seen:
                    raise ReadError("malformed", "directory_hierarchy_cycle")
                seen.add(current)
                row, request_id = self.read("https://cloudresourcemanager.googleapis.com/v3/" + current, scope)
                if not isinstance(row, dict):
                    raise ReadError("malformed", "directory_hierarchy_response")
                if current == scope:
                    if (not isinstance(row.get("name"), str) or not re.fullmatch(r"projects/[1-9][0-9]*", row["name"])
                            or current not in (row["name"], "projects/" + str(row.get("projectId", "")))):
                        raise ReadError("malformed", "directory_project_identity_mismatch")
                elif row.get("name") != current:
                    raise ReadError("malformed", "directory_hierarchy_identity_mismatch")
                record["chain"].append({"requested": current, "name": row["name"],
                    "projectId": row.get("projectId"), "parent": row.get("parent"),
                    "directoryCustomerId": row.get("directoryCustomerId"), "source_request": request_id})
                if current.startswith("organizations/"):
                    customer = row.get("directoryCustomerId")
                    if not isinstance(customer, str) or not re.fullmatch(r"C[A-Za-z0-9_-]+", customer):
                        raise ReadError("malformed", "directory_customer_unavailable")
                    record.update(status="collected", reason="", organization=current, customer=customer)
                    return record
                parent = row.get("parent")
                if not isinstance(parent, str) or not re.fullmatch(r"(?:folders|organizations)/[1-9][0-9]*", parent):
                    raise ReadError("unavailable", "directory_project_parent_unavailable")
                current = parent
            raise ReadError("unavailable", "directory_hierarchy_depth_limit")
        except ReadError as exc:
            record.update(status=exc.status, reason=exc.error.get("code", "directory_binding_unavailable"))
        return record

    def workspace_directory(self):
        scope = self.scopes[0] if self.scopes else "directory"
        customers = self.options.get("workspace_customers", self.options.get("cloud_identity_customers", []))
        if not isinstance(customers, list) or any(not isinstance(customer, str) or not re.fullmatch(r"C[A-Za-z0-9_-]+|my_customer", customer) for customer in customers):
            raise ValueError("workspace_customers must contain directory customer IDs")
        customers = set(customers)
        binding = self.workspace_project_binding() if "workspace_user" in self.needed else None
        if binding and binding["status"] == "collected" and not customers:
            customers = {binding["customer"]}
        if self.sw52_only_mode:
            customers = {entry["directory_customer"] for entry in getattr(self, "sw52_native", {}).values()
                if entry.get("status") == "collected"}
        for _, organization in ([] if self.sw52_only_mode else self.items("organization")):
            owner = organization.get("owner", {})
            customer = organization.get("directoryCustomerId") or (owner.get("directoryCustomerId") if isinstance(owner, dict) else None)
            if customer and re.fullmatch(r"C[A-Za-z0-9_-]+", str(customer)):
                customers.add(customer)
        if not customers and not self.sw52_only_mode:
            customers = {"my_customer"}
        def pages(kind):
            if not customers:
                raise ReadError("unavailable", "organization_directory_customer_unavailable")
            failures = []
            seen = set()
            for customer in sorted(customers):
                if kind == "workspace_user":
                    url = "https://admin.googleapis.com/admin/directory/v1/users"
                    params = {"customer": customer, "projection": "full", "viewType": "admin_view",
                        "fields": "users(id,customerId,primaryEmail,isAdmin,isDelegatedAdmin,suspended,archived,isEnrolledIn2Sv,isEnforcedIn2Sv,recoveryEmail),nextPageToken"}
                    key, size_key = "users", "maxResults"
                elif kind == "workspace_role":
                    url = f"https://admin.googleapis.com/admin/directory/v1/customer/{customer}/roles"
                    params = {"fields": "items(roleId,roleName,isSuperAdminRole,isSystemRole,rolePrivileges),nextPageToken"}
                    key, size_key = "items", "maxResults"
                else:
                    url = f"https://admin.googleapis.com/admin/directory/v1/customer/{customer}/roleassignments"
                    params = {"fields": "items(roleAssignmentId,roleId,assignedTo,scopeType,orgUnitId,condition),nextPageToken"}
                    key, size_key = "items", "maxResults"
                try:
                    for items, request_id in self.pages(url, scope, key=key, params=params, page_size_key=size_key):
                        transformed = []
                        for item in items:
                            identifier = item.get("id") or (item.get("roleId") if kind == "workspace_role" else item.get("roleAssignmentId"))
                            if not isinstance(identifier, str) or not identifier or (customer, identifier) in seen:
                                raise ReadError("malformed", "directory_identity_missing_or_duplicate")
                            seen.add((customer, identifier))
                            output = {**item, "name": f"customers/{item.get('customerId', customer)}/{kind}/{identifier}",
                                "directoryCustomer": item.get("customerId", customer), "scopeSelection": "existing selected identity; read-only Directory API"}
                            if kind == "workspace_user":
                                output["_directoryBinding"] = copy.deepcopy(binding)
                                output["_coverage"] = {"directoryProjection": {"status": "collected",
                                    "fields": ["id", "customerId", "primaryEmail", "isAdmin", "isDelegatedAdmin", "suspended", "archived",
                                               "isEnrolledIn2Sv", "isEnforcedIn2Sv", "recoveryEmail"],
                                    "source_requests": [request_id], "projection": "full", "viewType": "admin_view"}}
                            transformed.append(output)
                        yield transformed, request_id
                except ReadError as exc:
                    failures.append(exc)
            if failures:
                raise failures[0]
        for kind in sorted(self.needed.intersection({"workspace_role", "workspace_role_assignment"})):
            self.add(kind, scope, "workspace-directory", lambda kind=kind: pages(kind))
        if "workspace_customer" in self.needed:
            def customer_pages():
                if not customers:
                    raise ReadError("unavailable", "organization_directory_customer_unavailable")
                failures = []
                for customer in sorted(customers):
                    try:
                        yield from self.pages(
                            f"https://admin.googleapis.com/admin/directory/v1/customers/{customer}",
                            scope, single=True, params={"fields": "id,customerDomain"},
                            transform=lambda item: {"name": f"customers/{item['id']}", "id": item["id"],
                                                    "customerDomain": item["customerDomain"]})
                    except (ReadError, KeyError) as exc:
                        failures.append(exc)
                if failures:
                    error = failures[0]
                    if isinstance(error, ReadError):
                        raise error
                    raise ReadError("malformed", "directory_customer_identity_missing")
            self.add("workspace_customer", scope, "workspace-directory", customer_pages)

    def remember_selected_image_matches(self, matches):
        values = getattr(self, 'gcp_selected_image_redactions', None)
        if values is None:
            values = self.gcp_selected_image_redactions = set()
        if getattr(self, 'gcp_selected_image_redaction_overflow', False):
            return
        if (not isinstance(matches, (set, frozenset)) or
                any(type(value) is not str or not value or len(value.encode('utf-8')) > 4096
                    for value in matches)):
            self.gcp_selected_image_redaction_overflow = True
            values.clear()
            return
        combined = values | matches
        if len(combined) > 256 or sum(len(value.encode('utf-8')) for value in combined) > 65536:
            self.gcp_selected_image_redaction_overflow = True
            values.clear()
            return
        values.update(matches)

    def finish(self):
        from peaso.snapshot import make_snapshot
        envelopes, hierarchy_discovery = [], []
        for key, collection in sorted(self.collections.items()):
            if key[1] == "discovery":
                # Search results only resolve scopes; each project/folder/org is
                # inventoried and evaluated once, in its own scope.
                hierarchy_discovery.append({"type": key[0], "status": collection.get("status"),
                    "coverage_status": collection.get("coverage_status"), "resource_count": len(collection["items"]),
                    "error": collection.get("error"), "source_requests": collection.get("source_requests", [])})
                continue
            if (key[0] in self.wanted or key[0] == "gke_cluster" and self.wanted & {"gke_workload_literal", "gke_exposure_service", "gke_exposure_ingress", "gke_exposure_pod"} or key[0] == "project" and
                    (self.options.get("all_projects") or key[1] in getattr(self, "proven_project_alias_scopes", set())
                     or key[1] in getattr(self, "proven_api_key_alias_scopes", set()))):
                collection["items"].sort(key=lambda item: item["_resource_id"])
                envelopes.append(collection)
        metadata = {"collection": "read-only", "collector": "native-gcp", "requested_scopes": self.requested_scopes,
            "resolved_scopes": self.scopes, "inherited_scopes": getattr(self, "inherited_scopes", []),
            "auth_method": getattr(getattr(self.transport, "credentials", None), "method", selected_auth_method(self.auth)),
            "calls": getattr(self.transport, "calls", 0), "max_calls": self.max_calls, "max_pages": self.max_pages,
            "max_resources": self.max_items, "max_scopes": self.max_scopes, "concurrency": self.workers, "asset_read_time": self.read_time,
            "intentional_limits": {key: self.options[key] for key in ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds")
                                   if self.options.get(key) is not None},
            "collection_mode": "intentionally_limited" if any(self.options.get(key) is not None for key in
                ("max_calls", "max_pages", "max_resources", "max_scopes", "deadline_seconds")) else "full",
            "omitted_inventories": sorted(SUPPORTED_TYPES - self.wanted), "supporting_inventories": sorted(self.needed - self.wanted),
            "source_requests": getattr(self.transport, "evidence", []), "scope_coverage": self.scope_errors,
            "data_service_project_bindings": {scope: copy.deepcopy(value) for scope, value in self.data_project_bindings.items()
                if isinstance(value, dict) and value.get("status") == "collected"},
            "hierarchy_discovery": hierarchy_discovery,
            "scope_type_omissions": {kind: sorted(types) for kind, types in sorted(getattr(self, "scope_type_omissions", {}).items())},
            "project_restrictions": sorted(self.allowed) if self.allowed is not None else None,
            "trusted_scope_ids": self.options.get("trusted_scope_ids", []),
            "trusted_domains": self.options.get("trusted_domains", []),
            "trusted_domains_explicit": "trusted_domains" in self.options,
            "trusted_users": self.options.get("trusted_users"),
            "trusted_groups": self.options.get("trusted_groups"),
            "trusted_service_accounts": self.options.get("trusted_service_accounts"),
            "service_usage_selection": ["*"],
            "service_usage_mode": "complete_list",
            "bigquery_connection_location_mode": "dataset_and_selected",
            "bigquery_connection_extra_locations": self.options.get(
                "bigquery_connection_locations", self.options.get("regions", [])),
            "integration_connection_location_mode": "selected" if "connectors_network_locations" in self.options or "regions" in self.options else "discovered",
            "contact_center_authorized_view_location_mode": "selected" if "contactcenterinsights_network_locations" in self.options or "regions" in self.options else "discovered",
            "cloudbuild_location_selection": self.options.get("cloudbuild_locations"),
            "cloudbuild_location_mode": "selected" if "cloudbuild_locations" in self.options else "discovered",
            "artifactregistry_location_selection": self.options.get("artifactregistry_locations", self.options.get("regions")),
            "artifactregistry_location_mode": "selected" if "artifactregistry_locations" in self.options or "regions" in self.options else "discovered",
            "regional_policy_skips": {service: {scope: sorted(locations)
                                                   for scope, locations in sorted(scopes.items())}
                                      for service, scopes in sorted(self.regional_policy_skips.items())},
            "limitations": ["CAI is eventually consistent; direct API reads are collected at their request time",
                "Audit absence never proves inactivity; disabled/denied Data Access logging limits activity evidence",
                "IAM policies and conditions are declared grants, not an effective-access decision",
                "Shared VPC references outside selected projects are not traversed"]}
        if {"firewall_policy", "firewall_policy_association"} <= self.wanted:
            projects = [scope for scope in self.scopes if scope.startswith("projects/")]
            evidence = []
            unaffected_projects = []
            project_ancestors = {}
            for project_scope in projects:
                ancestry = self.ancestry.get(project_scope)
                ancestry_request = self.ancestry_source_requests.get(project_scope)
                if (not isinstance(ancestry, list) or not ancestry or not ancestry_request or
                    not isinstance(ancestry[0], dict) or not isinstance(ancestry[0].get("resourceId"), dict) or
                    ancestry[0]["resourceId"].get("type") != "project" or
                    any(not isinstance(item, dict) or not isinstance(item.get("resourceId"), dict) or
                        item["resourceId"].get("type") not in ("folder", "organization") or
                        not isinstance(item["resourceId"].get("id"), str) or
                        not item["resourceId"]["id"].isdigit() for item in ancestry[1:]) or
                    any(item["resourceId"]["type"] == "organization" for item in ancestry[1:-1])):
                    continue
                project_evidence = [{"path": f"projects/{project_scope.split('/', 1)[1]}:getAncestry",
                    "source_requests": [ancestry_request]}]
                ancestors = [f"{item['resourceId']['type']}s/{item['resourceId']['id']}"
                    for item in ancestry if item["resourceId"]["type"] in ("folder", "organization")]
                complete = True
                for policy_scope in [project_scope, *ancestors]:
                    kind = "firewall_policy" if policy_scope == project_scope else "firewall_policy_association"
                    inventory = self.collections.get((kind, policy_scope))
                    if (not inventory or inventory["status"] not in ("collected", "empty") or
                        not inventory.get("source_requests")):
                        complete = False
                        break
                    if kind == "firewall_policy_association" and inventory["items"]:
                        complete = False
                        break
                    if kind == "firewall_policy" and any(
                        item.get("_provenance", {}).get("representation") != "full" or
                        not isinstance(item.get("associations", []), list) or item.get("associations")
                        for item in inventory["items"]):
                        complete = False
                        break
                    project_evidence.append({"path": f"collections.{kind}[{policy_scope}]",
                        "source_requests": inventory["source_requests"]})
                networks = self.collections.get(("network", project_scope))
                if networks and any(item.get("firewallPolicy") not in (None, "") for item in networks["items"]):
                    complete = False
                if complete:
                    unaffected_projects.append(project_scope)
                    project_ancestors[project_scope] = ancestors
                    evidence.extend(project_evidence)
            if unaffected_projects:
                metadata["network_context"] = {"gcp": {"firewall_hierarchy": {
                    "status": "collected", "complete": True, "policies": [],
                    "unaffected_projects": unaffected_projects, "project_ancestors": project_ancestors,
                    "source_evidence": evidence}}}
        from .gcp_appengine_versions import approved_version_maxima
        appengine_policy = approved_version_maxima(self.options, self.scopes)
        if appengine_policy is not None:
            metadata["appengine_version_policy"] = appengine_policy
        from .gcp_compliance_wave import policy_metadata
        metadata.update(policy_metadata(self.options, self.scopes))
        if self.sw52_native_mode:
            metadata["sw52_native"] = self.sw52_native
        if self.psc_owner_policy is not None:
            from peaso.gcp_psc_policy import OPTION as PSC_OPTION, normalize as normalize_psc_policy
            metadata[PSC_OPTION] = normalize_psc_policy(self.psc_owner_policy, self.scopes)
        if self.audit_owner_policy is not None:
            from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
            metadata[OPTION] = normalize_owner_policy(self.audit_owner_policy, self.scopes)
        # Preserve exactly the user's selection; resolved scopes and ancestry are
        # separately explicit and every collection is individually scoped.
        snapshot_scopes = (self.scopes or ["*"]) if self.auto_scopes else self.requested_scopes
        from .gcp_gke_literal_secret_indicators import selection_metadata
        if "gke_workload_literal" in self.needed:
            metadata.update(selection_metadata(self))
        metadata.update(getattr(self, 'appengine_flex_image_metadata', {}))
        metadata.update(getattr(self, 'workerpool_image_metadata', {}))
        metadata.update(getattr(self, 'gke_selected_image_metadata', {}))
        from .gcp_function_source_secret_indicators import selection_metadata as function_source_selection
        if 'function_source_archive' in self.needed:
            metadata.update(function_source_selection(self))
        if 'cloudbuild_log_source' in self.needed:
            from .gcp_cloudbuild_log_secret_indicators import selection_metadata as cloudbuild_log_selection
            metadata.update(cloudbuild_log_selection(self))
        if self.needed & {'cloudtasks_selected_task', 'bigquery_selected_routine'}:
            from .gcp_selected_task_routine_secret_indicators import selection_metadata as task_routine_selection
            metadata.update(task_routine_selection(self))
        if 'source_repository_file' in self.needed:
            from .gcp_sourcerepo_secret_indicators import selection_metadata as sourcerepo_selection
            metadata.update(sourcerepo_selection(self))
        if 'clouddeploy_release_source' in self.needed:
            from .gcp_clouddeploy_source_secret_indicators import selection_metadata as clouddeploy_release_source_selection
            metadata.update(clouddeploy_release_source_selection(self))
        if 'cloudbuild_artifact_source' in self.needed:
            from .gcp_cloudbuild_artifact_secret_indicators import selection_metadata as cloudbuild_artifact_source_selection
            metadata.update(cloudbuild_artifact_source_selection(self))
        if 'appengine_deployment_source' in self.needed:
            from .gcp_appengine_source_secret_indicators import selection_metadata as appengine_source_selection
            metadata.update(appengine_source_selection(self))
        if self.registry_image_vulnerability_targets:
            from .gcp_registry_trivy_runtime_20261021 import finish_metadata as registry_cve_metadata
            registry_cve_metadata(self, metadata)
        snapshot = make_snapshot("gcp", snapshot_scopes, envelopes, metadata=sanitize(metadata))
        if self.needed & selected_job_source_runtime.KINDS:
            snapshot = selected_job_source_runtime.final_snapshot(self, snapshot)
        if self.needed & workbench_source_runtime.KINDS:
            snapshot = workbench_source_runtime.final_snapshot(self, snapshot)
        if self.needed & dataproc_source_runtime.KINDS:
            snapshot = dataproc_source_runtime.final_snapshot(self, snapshot)
        gke_values = getattr(self, 'gke_selected_image_redactions', set())
        image_values = getattr(self, 'gcp_selected_image_redactions', set())
        try:
            values = gke_values | image_values
            if (getattr(self, 'gcp_selected_image_redaction_overflow', False)
                    or len(values) > 256
                    or sum(len(value.encode('utf-8')) for value in values) > 65536):
                raise ValueError('gcp_selected_image_redaction_bound')
            if values:
                from peaso.secret_scanning import redact_matches
                snapshot = redact_matches(snapshot, values)
                self.collections = redact_matches(self.collections, values)
                self.options = redact_matches(self.options, values)
                if self.transport is not None:
                    self.transport.cache = redact_matches(self.transport.cache, values)
                    self.transport.evidence = redact_matches(self.transport.evidence, values)
                    self.transport.options = redact_matches(self.transport.options, values)
        finally:
            gke_values.clear()
            image_values.clear()
        self.progress("error" if self.auth_error else "completed", complete=True)
        return snapshot

    def collect(self):
        owned_transport = self.transport is None
        self.progress("discovering")
        try:
            if not self.needed:
                return self.finish()
            if self.transport is None:
                from .gcp_gke_literal_secret_indicators import auth_requested
                credentials = Credentials(self.auth, timeout=bound(self.options, "timeout", 20, 1, 120),
                    gke_content=auth_requested(self) or bool({"gke_exposure_service", "gke_exposure_ingress", "gke_exposure_pod"} & self.needed))
                self.transport = Transport(credentials, self.options)
            self.discover()
            self.progress("collecting")
            self.run_jobs([job for scope in self.scopes for job in self.scope_jobs(scope)] + self.independent_jobs())
            from .gcp_network_forwarding_completion_20261021 import collect as collect_global_forwarding_rules
            collect_global_forwarding_rules(self)
            if "iap_tunnel_policy" in self.needed:
                from .gcp_iap_tunnel_policies import collection_pages as iap_policy_pages
                self.run_jobs([("iap_tunnel_policy", scope, "iap",
                                lambda scope=scope: iap_policy_pages(self, scope))
                               for scope in self.scopes if scope.startswith("projects/")])
            if "instance_settings" in self.needed:
                settings_jobs = []
                for scope in (s for s in self.scopes if s.startswith("projects/")):
                    def zonal_settings(scope=scope):
                        instances = self.collections.get(("instance", scope))
                        if not instances or instances["coverage_status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "instance_inventory_incomplete")
                        zones = set()
                        for vm in instances["items"]:
                            zone = str(vm.get("zone") or "").rsplit("/", 1)[-1]
                            if not re.fullmatch(r"[a-z][a-z0-9-]*[0-9]-[a-z]", zone):
                                raise ReadError("malformed", "instance_zone_unbound")
                            zones.add(zone)
                        for zone in sorted(zones):
                            url = f"https://compute.googleapis.com/compute/v1/{scope}/zones/{zone}/instanceSettings"
                            for rows, request_id in self.pages(url, scope, single=True):
                                if len(rows) != 1 or (rows[0].get("zone") and
                                        str(rows[0]["zone"]).rsplit("/", 1)[-1] != zone):
                                    raise ReadError("malformed", "instance_settings_zone_mismatch")
                                metadata = rows[0].get("metadata", {})
                                values = metadata.get("items", {}) if isinstance(metadata, dict) else None
                                if not isinstance(values, dict) or any(not isinstance(key, str) for key in values):
                                    raise ReadError("malformed", "instance_settings_metadata_malformed")
                                # The API uses a map, while snapshot metadata uses
                                # key-only rows so script content is never retained.
                                safe_metadata = {**metadata, "items": [{"key": key} for key in values]}
                                yield [{**rows[0], "metadata": safe_metadata,
                                        "_zone": zone, "_representation": "full"}], request_id
                    settings_jobs.append(("instance_settings", scope, "compute", zonal_settings))
                self.run_jobs(settings_jobs)
            if "bigtable_table" in self.needed:
                table_jobs = []
                for scope in [s for s in self.scopes if s.startswith("projects/")]:
                    def bigtable_tables(scope=scope):
                        instances = self.collections.get(("bigtable_instance", scope))
                        if not instances or instances["status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "bigtable_instance_inventory_incomplete")
                        def table_row(name):
                            def validate_details(body, expected=name):
                                if body.get("name") != expected:
                                    raise ReadError("malformed", "bigtable_table_details_unbound")
                            detailed = self.hydrate({"name": name}, "details",
                                f"https://bigtableadmin.googleapis.com/v2/{name}?view=FULL",
                                scope, identity_validator=validate_details)
                            if ((detailed.get("_coverage") or {}).get("details") or {}).get("status") == "collected":
                                detailed["clusterStates"] = detailed["details"].get("clusterStates")
                            return self.hydrate(detailed, "iamPolicy",
                                f"https://bigtableadmin.googleapis.com/v2/{name}:getIamPolicy",
                                scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                identity_validator=_validate_iam_policy)
                        def instance_pages(instance):
                            parent = instance.get("name")
                            if (not isinstance(parent, str) or not re.fullmatch(
                                    re.escape(scope) + r"/instances/[^/]+", parent)):
                                raise ReadError("malformed", "bigtable_instance_identity_unbound")
                            url = f"https://bigtableadmin.googleapis.com/v2/{parent}/tables"
                            for page, request_id in self.pages(url, scope, key="tables"):
                                names = []
                                for item in page:
                                    name = item.get("name")
                                    if (not isinstance(name, str) or not re.fullmatch(
                                            re.escape(parent) + r"/tables/[^/]+", name)):
                                        raise ReadError("malformed", "bigtable_table_identity_unbound")
                                    names.append(name)
                                yield self.parallel(table_row, names), request_id
                        yield from fanout_pages(self, instances["items"], instance_pages)
                    table_jobs.append(("bigtable_table", scope, "bigtableadmin", bigtable_tables))
                self.run_jobs(table_jobs)
            if "bigtable_authorized_view" in self.needed:
                view_jobs = []
                for scope in [s for s in self.scopes if s.startswith("projects/")]:
                    def authorized_views(scope=scope):
                        tables = self.collections.get(("bigtable_table", scope))
                        if not tables or tables["status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "bigtable_table_inventory_incomplete")
                        def table_pages(table):
                            table_name = table.get("name")
                            if (not isinstance(table_name, str) or not re.fullmatch(
                                    re.escape(scope) + r"/instances/[^/]+/tables/[^/]+", table_name)):
                                raise ReadError("malformed", "bigtable_table_identity_unbound")
                            url = f"https://bigtableadmin.googleapis.com/v2/{table_name}/authorizedViews"
                            for page, request_id in self.pages(url, scope, key="authorizedViews"):
                                names = []
                                for item in page:
                                    name = item.get("name")
                                    if (not isinstance(name, str) or not re.fullmatch(
                                            re.escape(table_name) + r"/authorizedViews/[^/]+", name)):
                                        raise ReadError("malformed", "bigtable_authorized_view_identity_unbound")
                                    names.append(name)
                                yield self.parallel(lambda name: self.hydrate({"name": name}, "iamPolicy",
                                    f"https://bigtableadmin.googleapis.com/v2/{name}:getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                    identity_validator=_validate_iam_policy), names), request_id
                        yield from fanout_pages(self, tables["items"], table_pages)
                    view_jobs.append(("bigtable_authorized_view", scope, "bigtableadmin", authorized_views))
                self.run_jobs(view_jobs)
            if "bigtable_materialized_view" in self.needed:
                materialized_jobs = []
                for scope in [s for s in self.scopes if s.startswith("projects/")]:
                    def materialized_views(scope=scope):
                        instances = self.collections.get(("bigtable_instance", scope))
                        if not instances or instances["status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "bigtable_instance_inventory_incomplete")
                        def view_row(name):
                            def validate_details(body, expected=name):
                                if body.get("name") != expected:
                                    raise ReadError("malformed", "bigtable_materialized_view_details_unbound")
                            detailed = self.hydrate({"name": name}, "details",
                                f"https://bigtableadmin.googleapis.com/v2/{name}?view=FULL",
                                scope, identity_validator=validate_details)
                            if ((detailed.get("_coverage") or {}).get("details") or {}).get("status") == "collected":
                                detailed.update({key: detailed["details"].get(key)
                                                 for key in ("query", "clusterStates")})
                            return self.hydrate(detailed, "iamPolicy",
                                f"https://bigtableadmin.googleapis.com/v2/{name}:getIamPolicy",
                                scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                identity_validator=_validate_iam_policy)
                        def instance_pages(instance):
                            parent = instance.get("name")
                            if (not isinstance(parent, str) or not re.fullmatch(
                                    re.escape(scope) + r"/instances/[^/]+", parent)):
                                raise ReadError("malformed", "bigtable_instance_identity_unbound")
                            url = f"https://bigtableadmin.googleapis.com/v2/{parent}/materializedViews"
                            for page, request_id in self.pages(url, scope, key="materializedViews"):
                                names = []
                                for item in page:
                                    name = item.get("name")
                                    if (not isinstance(name, str) or not re.fullmatch(
                                            re.escape(parent) + r"/materializedViews/[^/]+", name)):
                                        raise ReadError("malformed", "bigtable_materialized_view_identity_unbound")
                                    names.append(name)
                                yield self.parallel(view_row, names), request_id
                        yield from fanout_pages(self, instances["items"], instance_pages)
                    materialized_jobs.append(("bigtable_materialized_view", scope, "bigtableadmin", materialized_views))
                self.run_jobs(materialized_jobs)
            if "bigtable_backup" in self.needed:
                backup_jobs = []
                for scope in [s for s in self.scopes if s.startswith("projects/")]:
                    def bigtable_backups(scope=scope):
                        instances = self.collections.get(("bigtable_instance", scope))
                        if not instances or instances["status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "bigtable_instance_inventory_incomplete")
                        def instance_pages(instance):
                            parent = instance.get("name")
                            if (not isinstance(parent, str) or not re.fullmatch(
                                    re.escape(scope) + r"/instances/[^/]+", parent)):
                                raise ReadError("malformed", "bigtable_instance_identity_unbound")
                            url = f"https://bigtableadmin.googleapis.com/v2/{parent}/clusters/-/backups"
                            for page, request_id in self.pages(url, scope, key="backups"):
                                projected_rows = []
                                for item in page:
                                    name = item.get("name")
                                    if (not isinstance(name, str) or not re.fullmatch(
                                            re.escape(parent) + r"/clusters/[^/]+/backups/[^/]+", name)):
                                        raise ReadError("malformed", "bigtable_backup_identity_unbound")
                                    projected_rows.append({key: item.get(key) for key in
                                                           ("name", "sourceTable", "state", "expireTime", "encryptionInfo")})
                                yield self.parallel(lambda projected: self.hydrate(projected, "iamPolicy",
                                    f"https://bigtableadmin.googleapis.com/v2/{projected['name']}:getIamPolicy",
                                    scope, method="POST", body={"options": {"requestedPolicyVersion": 3}},
                                    identity_validator=_validate_iam_policy), projected_rows), request_id
                        yield from fanout_pages(self, instances["items"], instance_pages)
                    backup_jobs.append(("bigtable_backup", scope, "bigtableadmin", bigtable_backups))
                self.run_jobs(backup_jobs)
            if "cloudbuild_repository" in self.needed:
                repo_jobs = []
                for scope in [s for s in self.scopes if s.startswith("projects/")]:
                    def cloudbuild_repositories(scope=scope):
                        connections = self.collections.get(("cloudbuild_connection", scope))
                        if not connections or connections["status"] not in ("collected", "empty"):
                            raise ReadError("unavailable", "cloudbuild_connection_inventory_incomplete")
                        for connection in connections["items"]:
                            parent = connection.get("name")
                            if (not isinstance(parent, str) or not re.fullmatch(
                                    re.escape(scope) + r"/locations/[^/]+/connections/[^/]+", parent)):
                                raise ReadError("malformed", "cloudbuild_connection_identity_unbound")
                            url = f"https://cloudbuild.googleapis.com/v2/{parent}/repositories"
                            for page, request_id in self.pages(url, scope, key="repositories"):
                                rows = []
                                for item in page:
                                    name = item.get("name")
                                    if (not isinstance(name, str) or not re.fullmatch(
                                            re.escape(parent) + r"/repositories/[^/]+", name)):
                                        raise ReadError("malformed", "cloudbuild_repository_identity_unbound")
                                    rows.append({"name": name, "remoteUri": item.get("remoteUri")})
                                yield rows, request_id
                    repo_jobs.append(("cloudbuild_repository", scope, "cloudbuild", cloudbuild_repositories))
                self.run_jobs(repo_jobs)
            if self.api_key_alias_mode:
                from .gcp_api_key_alias_native import materialize
                self.proven_api_key_alias_scopes = materialize(self)
            # Fetch independent project identity only where an observed CAI
            # hierarchy view could alias a direct project root.
            alias_scopes = []
            if "iam_policy" in self.needed:
                for scope in self.scopes:
                    collection = self.collections.get(("iam_policy", scope))
                    if (scope.startswith("projects/") and collection and
                            ("project", scope) not in self.collections and
                            any(item.get("name") == scope and
                                item.get("_provenance", {}).get("representation") == "full"
                                for item in collection["items"]) and
                            any(item.get("assetType") == "cloudresourcemanager.googleapis.com/Project"
                                for item in collection["items"])):
                        alias_scopes.append(scope)
            if alias_scopes:
                self.needed.add("project")
                # Supporting identity needs only CRM metadata; do not hydrate
                # compute settings or monitoring scopes that were not requested.
                self.run_jobs([("project", scope, "cloudresourcemanager",
                    lambda scope=scope: self.pages(
                        f"https://cloudresourcemanager.googleapis.com/v3/{scope}", scope, single=True))
                    for scope in alias_scopes])
            self.inherited()
            self.derive_sw52_native()
            self.perimeter_jobs()
            self.dependent_jobs()
            from .gcp_unused_directory_20261021 import collect as collect_unused_directory
            collect_unused_directory(self)
            from .gcp_key_usage_20261021 import collect as collect_key_usage
            collect_key_usage(self)
            if "managed_folder" in self.needed:
                def managed_folders(scope):
                    parent = self.collections.get(("bucket", scope))
                    if not parent or parent.get("status") not in ("collected", "empty"):
                        raise ReadError("unavailable", "bucket_inventory_incomplete")
                    for bucket in parent.get("items", []):
                        bucket_name = bucket.get("name")
                        ubla = ((bucket.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}).get("enabled")
                        if not isinstance(bucket_name, str) or not bucket_name:
                            raise ReadError("malformed", "bucket_name_missing")
                        if ubla is not True:
                            continue
                        url = "https://storage.googleapis.com/storage/v1/b/" + quote(bucket_name, safe="") + "/managedFolders"
                        for folders, request_id in self.pages(url, scope, page_size_key="maxResults"):
                            out = []
                            for folder in folders:
                                name = folder.get("name")
                                if not isinstance(name, str) or not name or folder.get("bucket") != bucket_name:
                                    raise ReadError("malformed", "managed_folder_identity_missing")
                                folder_url = url + "/" + quote(name, safe="")
                                hydrated = self.hydrate(folder, "iamPolicy", folder_url + "/iam", scope,
                                                        params={"optionsRequestedPolicyVersion": 3})
                                out.append({**hydrated, "project": scope,
                                            "resource": f"//storage.googleapis.com/projects/_/buckets/{bucket_name}/managedFolders/{name}"})
                            yield out, request_id
                self.run_jobs([("managed_folder", scope, "storage", lambda scope=scope: managed_folders(scope))
                               for scope in self.scopes if scope.startswith("projects/")])
            self.annotate_effective_audit()
            self.annotate_inherited_sinks()
            self.annotate_inherited_policies()
            from .gcp_storage_acl_native import collect as collect_storage_acl
            collect_storage_acl(self)
            from .gcp_kms_effective_native import collect as collect_kms_effective
            collect_kms_effective(self)
            from .gcp_sbom_native import collect as collect_sbom_native
            collect_sbom_native(self)
            from .gcp_image_stream_inspection_20261021 import enrich as enrich_image_secrets
            enrich_image_secrets(self)
            # Types lacking a service-level API at this scope are explicitly
            # unsupported, instead of silently looking like an empty collection.
            # A kind collected at its native scope type (for example buckets at
            # projects, essential contacts at organizations) is not evaluated
            # again at other scope types: that would duplicate every check as
            # UNKNOWN. The omission is recorded in snapshot metadata instead.
            native = defaultdict(set)
            for kind, scope in list(self.collections):
                native[kind].add(scope_type(scope))
            self.scope_type_omissions = {}
            for scope in self.scopes:
                for kind in sorted(self.wanted):
                    if (kind, scope) not in self.collections:
                        if native[kind] - {scope_type(scope), "discovery"}:
                            self.scope_type_omissions.setdefault(kind, set()).add(scope_type(scope))
                            continue
                        self.add(kind, scope, kind, lambda: (_ for _ in ()).throw(
                            ReadError("unsupported", "inventory_not_supported_at_scope")))
            return self.finish()
        except ReadError as exc:
            for scope in self.scopes:
                for kind in sorted(self.wanted):
                    if (kind, scope) not in self.collections:
                        self.add(kind, scope, kind, lambda exc=exc: (_ for _ in ()).throw(exc))
            return self.finish()
        finally:
            getattr(self, 'gcp_selected_image_redactions', set()).clear()
            self.hydration_pool.shutdown(wait=True)
            if self.location_pool is not None:
                self.location_pool.shutdown(wait=True, cancel_futures=True)
            if self.transport is not None:
                selected_job_source_runtime.clear_pending(self.transport)
                workbench_source_runtime.source.clear_pending(self.transport)
                dataproc_source_runtime.source.clear_pending(self.transport)
            if owned_transport and self.transport is not None:
                self.transport.close()


def collect(connector: dict, requirements: list[str] | None = None) -> dict:
    """Collect the selected native facts, sealed in the engine's snapshot schema."""
    options = connector.get("options") or {}
    inventories = options.get("inventories", [])
    selected = inventories if requirements is None else requirements
    if 'cloud_run_selected_job_image_vulnerabilities' in selected:
        from .gcp_job_image_vulnerability_runtime_20261021 import collect_connector
        return collect_connector(connector, requirements)
    if 'developerconnect_selected_file' in selected:
        from .gcp_developerconnect_file_runtime_20261021 import collect_connector
        return collect_connector(connector, requirements)
    if 'cloudrun_worker_pool_selected_revision_image' in selected:
        from .gcp_workerpool_image_runtime_20261021 import collect_connector
        return collect_connector(connector, requirements)
    if 'cloudrun_job_declared_image' in selected:
        from .gcp_cloudrun_job_image_runtime_20261020 import collect_connector
        return collect_connector(connector, requirements)
    if isinstance(inventories, list) and "audit_log" in inventories and "audit_log" in selected:
        from .gcp_audit_native import AuditGCPCollector
        return AuditGCPCollector(connector, selected).collect()
    return GCPCollector(connector, requirements).collect()



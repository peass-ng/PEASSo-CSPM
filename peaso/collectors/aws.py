"""AWS configuration inventory with scoped temporary Access Analyzer lifecycle.

General requests remain read-only; scan-owned analyzers are created and cleaned
up by a dedicated handler. The legacy scanner is never imported.
"""
from __future__ import annotations

import copy
import base64
import csv
import hashlib
import io
import json
import re
import threading
import time
import math
from concurrent.futures import Future, ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import unquote


def _bound(options, key, default, minimum=1, maximum=10000):
    value = options.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer between {minimum} and {maximum}")
    return value


def _optional_limit(options, key):
    value = options.get(key)
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
        raise ValueError(f"{key} must be a positive integer or null")
    return value


class ReadFailure(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


# Provider-documented service/region state replies, matched on the exact
# operation, error code and full message. They are facts about the account or
# region (service not enabled, no/not the administrator, operation not offered
# in the region), not IAM denials, so they become a structured empty read with
# the state as its code. Anything that does not match exactly is unchanged.
_EMPTY_MESSAGE = r"(?:None)?"
_SERVICE_STATES = (
    ({"GetMacieSession", "ListClassificationJobs"}, "AccessDeniedException", r"Macie is not enabled\.?", "service_not_enabled"),
    ({"ListPolicies"}, "AccessDeniedException", r"No default admin could be found for account [0-9]{12} in Region [a-z]{2}(?:-[a-z]+)+-[0-9]\.?", "no_service_administrator"),
    ({"DescribeOrganizationConfiguration"}, "AccessDeniedException", r"Invoking account does not have access to describe the organization configuration\.?", "not_delegated_administrator"),
    ({"GetDelegatedAdminAccount"}, "ResourceNotFoundException", r"No delegated admin found for caller account\.?", "no_delegated_administrator"),
    ({"GetDevEndpoints"}, "AccessDeniedException", r"GetDevEndpoints operation is currently disabled\.?", "operation_disabled_for_account"),
    ({"GetDevEndpoints"}, "InvalidInputException", r"Operation is not supported in <[a-z]{2}(?:-[a-z]+)+-[0-9]> region\.?", "region_operation_unsupported"),
    ({"ListCustomModels"}, "ValidationException", r"Unknown operation\.?", "region_operation_unsupported"),
    (None, "UnknownOperationException", r"Unknown Operation\.?|Operation is disabled in this region\.?|" + _EMPTY_MESSAGE, "region_operation_unsupported"),
    ({"GetInstances", "GetRelationalDatabases", "GetStaticIps"}, "RegionSetupInProgressException",
     r"Lightsail is setting up this region for your account, please try again later\.?", "region_setup_in_progress"),
)
# Transient documented states: an exact code, never completeness. Lightsail
# "setting up this region" says nothing about whether resources exist.
TRANSIENT_SERVICE_STATES = frozenset({"region_setup_in_progress"})
SERVICE_STATE_CODES = frozenset(state for *_, state in _SERVICE_STATES) - TRANSIENT_SERVICE_STATES


def _service_state(exc, code):
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    message = error.get("Message") if isinstance(error, dict) else None
    message = "" if message is None else message
    operation = getattr(exc, "operation_name", None)
    if not isinstance(message, str) or len(message) > 300:
        return None
    for operations, expected_code, pattern, state in _SERVICE_STATES:
        if code == expected_code and (operations is None or operation in operations) and re.fullmatch(pattern, message.strip()):
            return state
    return None


def _failure(exc):
    if isinstance(exc, ReadFailure):
        return exc
    response = getattr(exc, "response", None)
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    code = error.get("Code", "") if isinstance(error, dict) else ""
    # Never serialize exception messages: providers sometimes echo request data.
    code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", code) else "read_failed"
    state = _service_state(exc, code)
    if state is not None:
        return ReadFailure("unknown" if state in TRANSIENT_SERVICE_STATES else "empty", state)
    if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "ForbiddenException", "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException"}:
        status = "denied"
    elif "timeout" in type(exc).__name__.lower() or isinstance(exc, TimeoutError):
        status = "timeout"
    elif isinstance(exc, (ValueError, TypeError, KeyError)):
        status, code = "malformed", "malformed_response"
    else:
        status = "unknown"
    return ReadFailure(status, code)


def _retry_after_minimum(exc):
    """Return a valid provider minimum in seconds, without retaining headers."""
    response = getattr(exc, "response", None)
    metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
    headers = metadata.get("HTTPHeaders", {}) if isinstance(metadata, dict) else {}
    for source in (headers, getattr(exc, "headers", None)):
        if not hasattr(source, "items"):
            continue
        for name, value in source.items():
            if str(name).lower() != "retry-after" or not isinstance(value, str):
                continue
            value = value.strip()
            try:
                if re.fullmatch(r"[0-9]+", value):
                    return float(value)
                stamp = parsedate_to_datetime(value)
                if stamp.tzinfo is not None:
                    return max(0.0, stamp.timestamp() - time.time())
            except (TypeError, ValueError, OverflowError):
                pass
    return None


_SECRET_FIELDS = {"SecretAccessKey", "SessionToken", "Token", "WebIdentityToken", "SecretString", "SecretBinary", "Password", "MasterUserPassword", "PreSharedKey", "CustomerGatewayConfiguration", "ClientSecret", "clientSecret", "PrivateKey", "Base32StringSeed", "QRCodePNG", "aws_secret_access_key", "aws_session_token", "aws_access_key_id", "Credentials", "Environment", "UserData", "Code", "ResponseMetadata", "NextToken", "Marker", "ContinuationToken", "NextContinuationToken"}
_LABEL_CONTAINERS = {"Tags", "tags", "TagSet", "tagSet", "TagList", "tagList", "Labels", "labels", "Annotations", "annotations"}
_ENVIRONMENT_CONTAINERS = {"environment", "environmentVariables", "EnvironmentVariables"}
_SECRET_FIELDS |= {"RuntimeEnvironmentVariables", "RuntimeEnvironmentSecrets", "PipelineConfigurationBody"}
_PROHIBITED_VALUE_OPERATIONS = {"get_secret_value", "batch_get_secret_value", "get_object", "get_log_events", "filter_log_events", "get_parameter", "get_parameters", "get_parameters_by_path", "get_password_data", "get_authorization_token"}


def _credential_label(label):
    if not isinstance(label, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", label.lower())
    fragments = ("password", "passwd", "dbpass", "apikey", "apitoken", "accesskey", "accesstoken", "refreshtoken", "sessiontoken", "securitytoken", "idtoken", "clientsecret", "secretaccesskey", "privatekey", "sshkey", "authorization", "bearer", "credentials")
    return normalized in {"token", "secret", "credential"} or normalized.endswith("secret") or any(fragment in normalized for fragment in fragments)


def _variable_count_only(value):
    return isinstance(value, dict) and set(value) <= {"VariableCount"} and all(
        isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value.values())


def _safe(value, *, _labels=False, _environment=False, _status=False):
    if isinstance(value, dict):
        result = {}
        label = next((value[k] for k in ("Key", "key", "Name", "name", "HeaderName", "headerName") if isinstance(value.get(k), str)), None)
        sensitive_record = _environment or _credential_label(label)
        redacted_fields = []
        for key, val in value.items():
            if key == "Environment" and _variable_count_only(val):
                # Count-only projection (no names/values); its absence would read as "no variables".
                result[key] = dict(val)
                continue
            # A scalar Environment tag is classification metadata, unlike a
            # service's Environment block containing runtime variables.
            ordinary_environment_tag = key == "Environment" and _labels and isinstance(val, str)
            if key in _SECRET_FIELDS and not (ordinary_environment_tag or
                    key == "Code" and _status and isinstance(val, str)):
                continue
            typed_value = key in {"Value", "value", "HeaderValue", "headerValue"} and sensitive_record
            sensitive_map_value = _labels and _credential_label(key)
            if (typed_value or sensitive_map_value) and not isinstance(val, bool):
                result[key] = "[redacted]"
                redacted_fields.append(key)
                continue
            if key == "AccessKeyId":
                result["AccessKeyFingerprint"] = hashlib.sha256(str(val).encode()).hexdigest()
            else:
                result[key] = _safe(val, _labels=key in _LABEL_CONTAINERS or _labels,
                    _environment=key in _ENVIRONMENT_CONTAINERS or _environment, _status=key == "Status")
        if redacted_fields:
            coverage = result.setdefault("_coverage", {})
            if not isinstance(coverage, dict):
                coverage = result["_coverage"] = {}
            for key in redacted_fields:
                coverage[key] = {"status": "not_collected", "reason": "credential_metadata_redacted"}
        return result
    if isinstance(value, (list, tuple)):
        return [_safe(x, _labels=_labels, _environment=_environment) for x in value]
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return "[omitted binary]"
    return value


def _project_activity_response(response):
    if not isinstance(response, dict) or not isinstance(response.get("Events"), list):
        raise ReadFailure("malformed", "malformed_activity_response")
    events = []
    for event in response["Events"]:
        if not isinstance(event, dict) or not isinstance(event.get("CloudTrailEvent"), str):
            raise ReadFailure("malformed", "missing_activity_projection_payload")
        try:
            payload = json.loads(event["CloudTrailEvent"])
        except (ValueError, TypeError):
            raise ReadFailure("malformed", "malformed_activity_projection_payload") from None
        identity = payload.get("userIdentity") if isinstance(payload, dict) else None
        if not isinstance(identity, dict):
            raise ReadFailure("malformed", "missing_activity_identity")
        actor = identity.get("arn")
        if actor is None:
            # Pinned source ignores AWS service events without an actor ARN.
            continue
        actor_type = identity.get("type")
        name, when, event_id = event.get("EventName"), event.get("EventTime"), event.get("EventId")
        if not all(isinstance(v, str) and v for v in (actor, actor_type, name, event_id)) or not isinstance(when, datetime):
            raise ReadFailure("malformed", "malformed_activity_metadata")
        events.append({"ActorArn": actor, "ActorType": actor_type, "EventName": name,
            "EventTime": when.isoformat(), "EventId": event_id})
    projected = {"Events": events}
    if "NextToken" in response:
        if not isinstance(response["NextToken"], str):
            raise ReadFailure("malformed", "malformed_activity_next_token")
        projected["NextToken"] = response["NextToken"]
    return projected


def _project_user_data_indicators(response, instance_id, *, dual_scanner=False):
    """Ephemeral source-pattern review, never retain script/value bytes."""
    from .aws_user_data_secret_indicators import project as project_secret_indicators, scan_selected_content
    def indicators(text):
        projected = project_secret_indicators(text, instance_id)
        return scan_selected_content(projected, text) if dual_scanner else projected
    if not isinstance(response, dict) or response.get("InstanceId") != instance_id:
        raise ReadFailure("malformed", "malformed_user_data_response")
    block = response.get("UserData")
    if block is None or (isinstance(block, dict) and block.get("Value") is None):
        return {"InstanceId": instance_id, "UserDataIndicators": {"KeywordMatch": False, "PasswordShapeMatch": False, "Present": False},
                "UserDataSecretIndicators": indicators("")}
    if not isinstance(block, dict) or not isinstance(block.get("Value"), str):
        raise ReadFailure("malformed", "malformed_user_data_encoding")
    try:
        encoded = block["Value"].replace("\r", "").replace("\n", "")
        if len(encoded) > 32768:
            raise ReadFailure("malformed", "user_data_size_exceeds_documented_limit")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 16384:
            raise ReadFailure("malformed", "user_data_size_exceeds_documented_limit")
        from .aws_user_data_payload_20261021 import decoded_text
        value = decoded_text(raw)
    except (ValueError, UnicodeError):
        raise ReadFailure("malformed", "malformed_user_data_encoding") from None
    keyword = any(word in value for word in ("pass", "secret", "token", "key"))
    # The source's four dot-star lookaheads plus its one-character final class
    # are exactly existence of lower/upper/digit/special somewhere in the text:
    # choose the earliest such character as the matching start. This linear
    # test avoids quadratic lookahead retries over a 16KiB configuration.
    shape = bool(re.search("[a-z]", value) and re.search("[A-Z]", value) and re.search(r"\d", value) and re.search(r"[@$!%*?&]", value))
    return {"InstanceId": instance_id, "UserDataIndicators": {"KeywordMatch": keyword, "PasswordShapeMatch": shape, "Present": bool(value)},
            "UserDataSecretIndicators": indicators(value)}


_CONTINUATION_KEYS = ("NextToken", "nextToken", "NextPageToken", "nextPageToken", "NextMarker", "nextMarker", "Marker", "PaginationToken")


@dataclass
class ReadResult:
    items: list = field(default_factory=list)
    status: str = "collected"
    error: dict | None = None


class Requests:
    """Scan-local, single-flight request cache with one global attempt budget."""
    def __init__(self, options, *, sleep=time.sleep):
        self.collect_all = options.get('collect_all') is True
        # AWS classifies these two report APIs as Read. Only selected checks
        # enable them; direct Requests callers remain generation-free by default.
        self.iam_report_generation_requested = options.get('_iam_report_generation_requested', False)
        self.iam_service_access_reports_requested = options.get(
            '_iam_service_access_reports_requested', self.iam_report_generation_requested)
        self.iam_credential_report_generation_requested = options.get(
            '_iam_credential_report_generation_requested', self.iam_report_generation_requested)
        for value in (self.iam_report_generation_requested, self.iam_service_access_reports_requested,
                      self.iam_credential_report_generation_requested):
            if type(value) is not bool:
                raise ValueError('internal IAM report selection must be boolean')
        if not self.iam_report_generation_requested and (
                self.iam_service_access_reports_requested or self.iam_credential_report_generation_requested):
            raise ValueError('IAM report selection requires its master selection')
        self.content_secret_scans = options.get('content_secret_scans', False)
        if type(self.content_secret_scans) is not bool:
            raise ValueError('content_secret_scans must be a boolean')
        self.max_calls = _optional_limit(options, "max_calls")
        self.max_pages = _optional_limit(options, "max_pages")
        self.max_items = _optional_limit(options, "max_resources")
        # Reads are latency-bound across ~90 services x every enabled Region;
        # 4 workers could not finish a full-account scan in bounded time.
        self.workers = _bound(options, "service_concurrency", 12, maximum=16)
        self.attempts = _bound(options, "retry_attempts", 3, maximum=5)
        self.timeout = _bound(options, "read_timeout", 15, maximum=120)
        self.connect_timeout = _bound(options, "connect_timeout", 5, maximum=30)
        self.calls = 0
        self.cache_hits = 0
        self._cache, self._clients, self._sessions = {}, {}, {}
        from .aws_request_pool import RawReadCache
        # Native reads shared below projections for this scan only.
        self.raw_reads = RawReadCache()
        # One later recovery read per key after a transient failure.
        self._transient_refreshes = set()
        self._lock = threading.RLock()
        self._sleep = sleep
        deadline = options.get("deadline_seconds")
        if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline) or deadline <= 0):
            raise ValueError("deadline_seconds must be a finite positive number")
        self.deadline = time.monotonic() + deadline if deadline is not None else None
        self.cancel_event = options.get("cancel_event")
        if self.cancel_event is not None and not callable(getattr(self.cancel_event, "is_set", None)):
            raise ValueError("cancel_event must expose is_set()")
        self.evidence_generation_wait = _bound(options, "credential_report_wait_seconds", 60, maximum=300)
        self.evidence_generations = 0
        self.service_last_accessed_wait = _bound(options, "service_last_accessed_wait_seconds", 120, maximum=600)
        self.service_last_accessed_workers = _bound(options, "service_last_accessed_concurrency", 4, maximum=8)
        self.service_last_accessed_generations = 0
        # IAM access-report APIs throttle aggressively; one adaptive pacing
        # interval per session (doubles on throttling, decays on success).
        self._report_interval, self._report_next = {}, {}
        self.activity_lookup_calls = 0
        self._activity_next_read = {}
        self.observed_at = datetime.now(timezone.utc)
        self.activity_minutes = _bound(options, "activity_minutes", 1440, maximum=129600)

    def check_deadline(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ReadFailure("not_collected", "collection_cancelled")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise ReadFailure("timeout", "intentional_scan_deadline")

    def client(self, session, service, region, *, _metadata_profile=None):
        from botocore.config import Config
        from .aws_request_pool import canonical_wrapper
        session = canonical_wrapper(self, session)
        key = (id(session), service, region)

        def cached_client(create):
            # SDK sessions lazily mutate state while constructing clients. Keep
            # creation serialized per session, outside the lock used for API
            # budgets, rate limiting and response-cache lookups. Warm clients
            # need neither that creation lock nor another SDK construction.
            with self._lock:
                self._sessions[id(session)] = session
                if key in self._clients:
                    return self._clients[key]
                locks = getattr(self, "_client_creation_locks", None)
                if locks is None:
                    locks = self._client_creation_locks = {}
                creation_lock = locks.setdefault(id(session), threading.RLock())
            with creation_lock:
                with self._lock:
                    if key in self._clients:
                        return self._clients[key]
                client = create()
                with self._lock:
                    self._clients[key] = client
                return client
        s3_bootstrap = (_metadata_profile is None and service == 'sts' and self.content_secret_scans
            and bool({'s3_selected_source_content', 'ecs_selected_environment_file_content', 'workload_referenced_source_content', 'build_deployment_referenced_source_content'} & set(getattr(self, 'content_secret_scan_kinds', ()))))
        if s3_bootstrap:
            key += ('aws-selected-s3-bootstrap-v1',)
            return cached_client(
                lambda: session.client(service, region_name=region, config=Config(
                        connect_timeout=min(3, self.connect_timeout), read_timeout=min(5, self.timeout),
                        retries={'total_max_attempts': 1, 'mode': 'standard'},
                        ignore_configured_endpoint_urls=True, use_fips_endpoint=False, use_dualstack_endpoint=False)))
        if _metadata_profile == 'aws-selected-s3-source-content-v1':
            from .aws_s3_selected_source_secret_indicators import client_config
            key += (_metadata_profile,)
            return cached_client(
                lambda: session.client(service, region_name=region, config=client_config(self)))
        lambda_environment_profile = _metadata_profile in ('aws-lambda-environment-content-v1', 'aws-selected-configuration-content-v1')
        if _metadata_profile is not None and not lambda_environment_profile:
            raise ReadFailure('not_collected', 'undeclared_client_profile')
        if lambda_environment_profile:
            key += (_metadata_profile,)
        def create():
            client = session.client(service, region_name=region, config=Config(
                    connect_timeout=min(3, self.connect_timeout) if lambda_environment_profile else self.connect_timeout,
                    read_timeout=min(5, self.timeout) if lambda_environment_profile else self.timeout,
                    retries={"total_max_attempts": 1, "mode": "standard"},
                    max_pool_connections=self.workers,
                    **({'ignore_configured_endpoint_urls': True, 'use_fips_endpoint': False, 'use_dualstack_endpoint': False}
                       if _metadata_profile == 'aws-selected-configuration-content-v1' else {})))
            raw_reads = getattr(self, 'raw_reads', None)
            if _metadata_profile is None and raw_reads is not None:
                from botocore.client import BaseClient
                if isinstance(client, BaseClient):
                    raw_reads.install(client, session)
            return client
        return cached_client(create)

    def call(self, session, service, region, operation, *, _cache_refresh=False, _uncached_credential_exchange=False, _metadata_profile=None, _projection_context=None, _codecommit_routes=None, **arguments):
        from .aws_request_pool import SHARED_PROFILES, canonical_wrapper, shared_reads
        session = canonical_wrapper(self, session)
        if _metadata_profile == 'aws-build-deployment-referenced-source-v1':
            if _cache_refresh or _uncached_credential_exchange or _codecommit_routes is not None:
                raise ReadFailure('not_collected', 'invalid_build_deployment_source_controls')
            from .aws_build_deployment_referenced_source_indicators import profile_call
            return profile_call(self, session, service, region, operation, _projection_context=_projection_context, **arguments)
        if _metadata_profile == 'aws-workload-referenced-source-v1':
            if _cache_refresh or _uncached_credential_exchange or _codecommit_routes is not None:
                raise ReadFailure('not_collected', 'invalid_workload_source_controls')
            from .aws_workload_referenced_source_indicators import profile_call
            return profile_call(self, session, service, region, operation, _projection_context=_projection_context, **arguments)
        if _metadata_profile == 'aws-ecs-selected-environment-file-v1':
            if _cache_refresh or _uncached_credential_exchange or _codecommit_routes is not None:
                raise ReadFailure('not_collected', 'invalid_ecs_environment_file_controls')
            from .aws_ecs_environment_file_secret_indicators import profile_call
            return profile_call(self, session, service, region, operation, _projection_context=_projection_context, **arguments)
        if _metadata_profile == 'aws-selected-s3-source-content-v1':
            if (self.content_secret_scans is not True
                    or not {'s3_selected_source_content', 'ecs_selected_environment_file_content', 'workload_referenced_source_content', 'build_deployment_referenced_source_content'} & set(getattr(self, 'content_secret_scan_kinds', ()))
                    or not hasattr(self, 's3_source_io_lock')):
                raise ReadFailure('not_collected', 'selected_s3_profile_uninitialized')
            if _cache_refresh or _uncached_credential_exchange or _codecommit_routes is not None:
                raise ReadFailure('not_collected', 'invalid_selected_s3_controls')
            from .aws_s3_selected_source_secret_indicators import profile_call
            return profile_call(self, session, service, region, operation,
                _projection_context=_projection_context, **arguments)
        if _codecommit_routes is not None and (
                service != 'codecommit' or operation != 'get_folder'
                or _metadata_profile != 'aws-code-log-content-indicators-v1'
                or not isinstance(_codecommit_routes, dict) or set(_codecommit_routes) != {'files', 'folders'}
                or any(not isinstance(v, list) or v for v in _codecommit_routes.values())):
            raise ReadFailure('malformed', 'content_route_sink_invalid')
        credential_exchange = service == "sts" and operation == "assume_role"
        if _uncached_credential_exchange and not credential_exchange:
            raise ReadFailure("not_collected", "uncached_exchange_requires_assume_role")
        metadata_lookup = service == "cloudtrail" and operation == "lookup_events"
        metadata_simulation = (service, operation) == ("iam", "simulate_principal_policy")
        # Report-job generation only: it creates an IAM access-report job and
        # changes no IAM configuration, principal, credential or policy.
        metadata_report = (service == 'iam' and self.iam_report_generation_requested and (
            operation == 'generate_credential_report' and self.iam_credential_report_generation_requested or
            operation == 'generate_service_last_accessed_details' and self.iam_service_access_reports_requested))
        readonly_name = operation.startswith(("get_", "list_", "describe_", "batch_get_", "batch_describe_")) or (service, operation) in {("ec2", "search_transit_gateway_routes"), ("braket", "search_devices")}
        content_profiles = {'aws-code-log-content-indicators-v1', 'aws-package-content-indicators-v1', 'aws-lambda-environment-content-v1', 'aws-selected-configuration-content-v1'}
        content_profile = isinstance(_metadata_profile, str) and _metadata_profile in content_profiles
        content_log = (service, operation) == ('logs', 'filter_log_events') and _metadata_profile == 'aws-code-log-content-indicators-v1'
        if content_profile and self.content_secret_scans is not True:
            raise ReadFailure('not_collected', 'content_secret_scans_disabled')
        if (service, operation) in {('lambda', 'get_function'), ('lambda', 'get_layer_version')} and _metadata_profile != 'aws-package-content-indicators-v1':
            raise ReadFailure('not_collected', 'package_content_requires_safe_projection')
        if (service, operation) == ('codecommit', 'get_file') and _metadata_profile != 'aws-code-log-content-indicators-v1':
            raise ReadFailure('not_collected', 'repository_content_requires_safe_projection')
        if (service, operation) in {('apigateway', 'get_stage'), ('ssm', 'describe_document')} and _metadata_profile != 'aws-selected-configuration-content-v1':
            raise ReadFailure('not_collected', 'selected_configuration_requires_safe_projection')
        if (operation in _PROHIBITED_VALUE_OPERATIONS and not content_log) or (service, operation) not in READ_ACTIONS or not (readonly_name or credential_exchange or metadata_lookup or metadata_simulation or content_log or metadata_report):
            raise ReadFailure("not_collected", "non_read_operation")
        if _projection_context is not None and _metadata_profile != 'aws-code-log-content-indicators-v1':
            raise ReadFailure('not_collected', 'undeclared_projection_context')
        if (service, operation) == ('securityhub', 'get_finding_history') and _metadata_profile != 'securityhub-workflow-history-metadata-v1':
            raise ReadFailure('not_collected', 'securityhub_history_requires_safe_projection')
        profile_projector = None
        if _metadata_profile is not None:
            if _metadata_profile == 'bedrock-agent-reasoning-metadata-v1':
                from . import aws_bedrock_reasoning_native as projection_contract
            elif _metadata_profile == 'fms-managed-web-acl-metadata-v1':
                from . import aws_fms_rule_metadata_native as projection_contract
            elif _metadata_profile == 'securityhub-workflow-history-metadata-v1':
                from . import aws_wave_semantics_native as projection_contract
            elif _metadata_profile == 'securityhub-findings-metadata-v1':
                from . import aws_securityhub_finding_metadata_native as projection_contract
            elif _metadata_profile == 'bedrock-security-role-metadata-v1':
                from . import aws_bedrock_security_metadata as projection_contract
            elif _metadata_profile == 'aws-cloudtrail-s3-delivery-metadata-v1':
                from . import aws_cloudtrail_s3_delivery_metadata as projection_contract
            elif _metadata_profile == 'aws-code-log-content-indicators-v1':
                from . import aws_code_log_content_indicators as projection_contract
            elif _metadata_profile == 'aws-package-content-indicators-v1':
                from . import aws_package_content_indicators as projection_contract
            elif _metadata_profile == 'aws-lambda-environment-content-v1':
                from . import aws_lambda_environment_secret_indicators as projection_contract
            elif _metadata_profile == 'aws-selected-configuration-content-v1':
                from . import aws_selected_configuration_secret_indicators as projection_contract
            else:
                raise ReadFailure('not_collected', 'undeclared_metadata_profile')
            if (service, operation) not in projection_contract.PROJECTION_OPERATIONS:
                raise ReadFailure('not_collected', 'metadata_profile_operation_not_allowed')
            profile_projector = projection_contract.project_response
            if content_profile:
                projection_context = (self, session) if _metadata_profile in ('aws-package-content-indicators-v1', 'aws-lambda-environment-content-v1', 'aws-selected-configuration-content-v1') else _projection_context
                validator = getattr(projection_contract, 'validate_request', None)
                if validator is not None:
                    validator(service, operation, dict(arguments), request_context=projection_context, region=region)
        if metadata_simulation:
            from .aws_cloudtrail_delivery_native import validate_simulation_query
            if not validate_simulation_query(arguments):
                raise ReadFailure("not_collected", "undeclared_cloudtrail_delivery_simulation")
        if service == "ec2" and operation == "describe_instance_attribute":
            if arguments.get("Attribute") not in {"userData", "disableApiTermination"} or not isinstance(arguments.get("InstanceId"), str) or arguments.get("DryRun"):
                raise ReadFailure("not_collected", "undeclared_instance_attribute_query")
        if service == "cloudtrail" and operation == "lookup_events":
            attributes = arguments.get("LookupAttributes")
            names = {name for values in ACTIVITY_ACTIONS.values() for name in values}
            from .aws_kms_enclave_native import is_enclave_query
            from .aws_ssm_inventory_events_native import is_inventory_query
            activity_query = (isinstance(attributes, list) and len(attributes) == 1 and isinstance(attributes[0], dict)
                and attributes[0].get("AttributeKey") == "EventName" and attributes[0].get("AttributeValue") in names)
            if not activity_query and not is_enclave_query(attributes) and not is_inventory_query(attributes):
                raise ReadFailure("not_collected", "undeclared_activity_event_query")
            if not isinstance(arguments.get("StartTime"), datetime) or not isinstance(arguments.get("EndTime"), datetime) or arguments["StartTime"].tzinfo is None or arguments["EndTime"].tzinfo is None or arguments["StartTime"] > arguments["EndTime"]:
                raise ReadFailure("not_collected", "invalid_activity_window")
        cache_arguments = arguments
        if service == 'codecommit' and (operation in ('get_folder', 'get_file')
                or _metadata_profile == 'aws-code-log-content-indicators-v1'):
            from .aws_code_log_content_indicators import opaque_arguments
            cache_arguments = opaque_arguments(arguments)
        if _metadata_profile == 'aws-lambda-environment-content-v1':
            from .aws_lambda_environment_secret_indicators import opaque_arguments as lambda_environment_arguments
            cache_arguments = lambda_environment_arguments(arguments)
        if _metadata_profile == 'aws-selected-configuration-content-v1':
            from .aws_selected_configuration_secret_indicators import opaque_arguments as configuration_arguments
            cache_arguments = configuration_arguments(arguments)
        key = (id(session), service, region, operation, json.dumps(cache_arguments, sort_keys=True, default=lambda v: v.isoformat() if isinstance(v, (date, datetime)) else str(v)))
        if _metadata_profile is not None:
            # Keep the existing cache schema for legacy callers. Profiles share
            # Futures only with callers using the same reviewed projection.
            key += (_metadata_profile,)
            if _projection_context is not None:
                key += (json.dumps(_projection_context, sort_keys=True, allow_nan=False),)
        if _codecommit_routes is not None:
            # A cached folder cannot replay raw routing paths. Read afresh and
            # project safe metadata without retaining a Future or route sink.
            future, owner = None, True
        elif _uncached_credential_exchange:
            # Trust probes must neither retain a successful STS response in a
            # Future nor consume a cached response from another call.
            future, owner = None, True
        else:
            with self._lock:
                if _cache_refresh and key in self._cache and self._cache[key].done():
                    self._cache.pop(key)
                future = self._cache.get(key)
                owner = future is None
                if owner:
                    future = self._cache[key] = Future()
                else:
                    self.cache_hits += 1
        if not owner:
            # Inspect without raising the stored exception: Future.result()
            # would attach each consumer traceback to the shared failure.
            failure = future.exception()
            if isinstance(failure, ReadFailure):
                raise ReadFailure(failure.status, failure.code) from None
            return copy.deepcopy(future.result())
        evict_retryable_failure = False
        try:
            self.check_deadline()
            with self._lock:
                if self.max_calls is not None and self.calls >= self.max_calls:
                    raise ReadFailure("not_collected", "call_limit")
            client = self.client(session, service, region, _metadata_profile=_metadata_profile) if _metadata_profile in ('aws-lambda-environment-content-v1', 'aws-selected-configuration-content-v1') else self.client(session, service, region)
            if _metadata_profile == 'aws-selected-configuration-content-v1':
                projection_contract.validate_native_client(client, service, region)
            if (service == 'sts' and self.content_secret_scans
                    and bool({'s3_selected_source_content', 'ecs_selected_environment_file_content', 'workload_referenced_source_content', 'build_deployment_referenced_source_content'} & set(getattr(self, 'content_secret_scan_kinds', ())))):
                from .aws_s3_selected_source_secret_indicators import validate_native_client
                validate_native_client(client, service, region)
            for attempt in range(self.attempts):
                if service == "cloudtrail" and operation == "lookup_events":
                    rate_key = (id(session), region)
                    with self._lock:
                        now = time.monotonic()
                        ready = max(now, self._activity_next_read.get(rate_key, now))
                        self._activity_next_read[rate_key] = ready + 0.5
                    if ready > now:
                        from peaso.runtime_metrics import span as _runtime_span
                        with _runtime_span("aws.rate_limit.cloudtrail"):
                            self._sleep(ready - now)
                report_key = (id(session), "iam-access-report") if service == "iam" and operation in {"generate_service_last_accessed_details", "get_service_last_accessed_details"} else None
                if report_key:
                    with self._lock:
                        now = time.monotonic()
                        ready = max(now, self._report_next.get(report_key, now))
                        self._report_next[report_key] = ready + self._report_interval.get(report_key, 0.1)
                    if ready > now:
                        from peaso.runtime_metrics import span as _runtime_span
                        with _runtime_span("aws.rate_limit.iam"):
                            self._sleep(ready - now)
                self.check_deadline()
                with self._lock:
                    if self.max_calls is not None and self.calls >= self.max_calls:
                        raise ReadFailure("not_collected", "call_limit")
                    self.calls += 1
                    if service == "cloudtrail" and operation == "lookup_events":
                        self.activity_lookup_calls += 1
                try:
                    if _metadata_profile == 'aws-lambda-environment-content-v1':
                        projection_contract._remaining(self)
                    if _metadata_profile == 'aws-selected-configuration-content-v1':
                        projection_contract.before_request(self)
                    if content_profile or service == 'sts' or _uncached_credential_exchange:
                        from .aws_content_sdk_logging import private_sdk_logs
                        with private_sdk_logs():
                            response = getattr(client, operation)(**arguments)
                    else:
                        with shared_reads(not _cache_refresh and _metadata_profile in SHARED_PROFILES and _codecommit_routes is None):
                            response = getattr(client, operation)(**arguments)
                    if metadata_report:
                        with self._lock:
                            if operation == 'generate_credential_report':
                                self.evidence_generations += 1
                            else:
                                self.service_last_accessed_generations += 1
                    if profile_projector is not None:
                        if content_profile:
                            if _codecommit_routes is not None:
                                response = profile_projector(response, service, operation, dict(arguments),
                                    request_context=projection_context, region=region, routing=_codecommit_routes)
                            else:
                                response = profile_projector(response, service, operation, dict(arguments), request_context=projection_context, region=region)
                        else:
                            response = profile_projector(response, service, operation, dict(arguments))
                    if _metadata_profile == 'aws-selected-configuration-content-v1':
                        # This profile has already discarded all native content
                        # and free text. Never re-project it as legacy metadata.
                        response = _safe(response)
                        if future is not None:
                            future.set_result(response)
                        return copy.deepcopy(response)
                    from . import aws_additional_secret_indicators
                    if (service, operation) in aws_additional_secret_indicators.OPERATIONS:
                        if service == "amplify":
                            # The projector removes buildSpec content. Preserve only
                            # whether it was present for the downstream inventory.
                            raw_apps = response.get("apps") if operation == "list_apps" else [response.get("app")]
                            if isinstance(raw_apps, list):
                                for raw_app in raw_apps:
                                    if isinstance(raw_app, dict):
                                        raw_app["AppBuildSpecPresent"] = bool(raw_app.get("buildSpec"))
                        response = aws_additional_secret_indicators.project_response(
                            response, service=service, operation=operation, arguments=arguments, region=region)
                    from . import aws_configuration_payload_secret_indicators
                    if (service, operation) in aws_configuration_payload_secret_indicators.OPERATIONS:
                        response = aws_configuration_payload_secret_indicators.project_response(
                            response, service=service, operation=operation, arguments=arguments, region=region)
                    from . import aws_launch_template_instance_metadata
                    if (service, operation) in aws_launch_template_instance_metadata.OPERATIONS:
                        response = aws_launch_template_instance_metadata.project_response(
                            response, service=service, operation=operation, arguments=arguments, region=region)
                    if (service, operation) in {("ec2", "describe_tags"), ("lambda", "list_tags")}:
                        from .aws_priority_tags_native import project_tag_response
                        response = project_tag_response(response, service=service)
                    if service == 'autoscaling' and operation == 'describe_launch_configurations':
                        from .aws_launch_configuration_redaction import project_response
                        response = project_response(response)
                    if service == "cloudtrail" and operation == "lookup_events":
                        # Payload is projected before any cache, future, copy or
                        # snapshot sees request/response/token/content fields.
                        from .aws_kms_enclave_native import is_enclave_query, project
                        from .aws_ssm_inventory_events_native import is_inventory_query, project as project_inventory
                        if is_inventory_query(arguments.get("LookupAttributes")):
                            response = project_inventory(response, arguments["LookupAttributes"][0]["AttributeValue"])
                        else:
                            response = project(response, arguments["LookupAttributes"][0]["AttributeValue"]) if is_enclave_query(arguments.get("LookupAttributes")) else _project_activity_response(response)
                    if service == 'controltower' or (service == 'organizations'
                            and operation == 'describe_organization'
                            and getattr(self, 'controltower_policy', None) is not None):
                        from .aws_controltower_native import project_response
                        response = project_response(response, operation)
                    if service == "codecommit" and _metadata_profile != 'aws-code-log-content-indicators-v1':
                        from .aws_codecommit_review_native import project_response
                        response = project_response(response, operation)
                    if service == "codepipeline" and operation == "get_pipeline":
                        # Project allowlisted action metadata before a Future/cache
                        # can retain configuration literals such as secret tokens.
                        from .aws_facts_v4_holds import project_pipeline_response
                        response = project_pipeline_response(response)
                    if service == "codebuild" and operation == "batch_get_projects":
                        # Project executable/credential literals before the shared Future.
                        from .aws_codebuild_redaction import project_batch_get_projects
                        response = project_batch_get_projects(response)
                    if service == "codebuild" and operation == "batch_get_sandboxes":
                        from .aws_codebuild_redaction import project_batch_get_sandboxes
                        response = project_batch_get_sandboxes(response)
                    if service == 'lambda' and operation in {'list_functions', 'get_function_configuration'} and _metadata_profile != 'aws-lambda-environment-content-v1':
                        from .aws_lambda_environment_metadata import project_response
                        response = project_response(response, operation)
                    if service == 'cloudformation' and operation == 'describe_stacks':
                        from .aws_configuration_secret_indicators import project_cloudformation_response
                        response = project_cloudformation_response(response, region=region)
                    if (service == 'organizations' and operation == 'describe_policy'
                            and isinstance(response, dict)
                            and isinstance(response.get('Policy'), dict)
                            and isinstance(response['Policy'].get('PolicySummary'), dict)
                            and response['Policy']['PolicySummary'].get('Type') == 'TAG_POLICY'):
                        from .aws_attached_tag_policy_native import project_response
                        response = project_response(response)
                    if (service == 'organizations' and operation == 'describe_effective_policy'
                            and arguments.get('PolicyType') == 'TAG_POLICY'):
                        from .aws_effective_tag_policy_native import project_response
                        response = project_response(response)
                    if (service == 'resourcegroupstaggingapi' and operation == 'get_resources'
                            and arguments.get('IncludeComplianceDetails') is True):
                        from .aws_resource_tag_compliance_native import project_response
                        response = project_response(response, exclude_compliant_resources=arguments.get('ExcludeCompliantResources', False))
                    if service == "ec2" and operation == "describe_instance_attribute":
                        if arguments["Attribute"] == "userData":
                            response = _project_user_data_indicators(response, arguments["InstanceId"],
                                dual_scanner=(self.content_secret_scans is True and
                                              "instance" in getattr(self, "content_secret_scan_kinds", ())))
                        else:
                            flag = response.get("DisableApiTermination") if isinstance(response, dict) else None
                            if not isinstance(flag, dict) or not isinstance(flag.get("Value"), bool):
                                raise ReadFailure("malformed", "malformed_instance_termination_protection")
                            response = {"InstanceId": arguments["InstanceId"], "DisableApiTermination": {"Value": flag["Value"]}}
                    if service == "cognito-idp" and operation == "describe_user_pool_client" and isinstance(response, dict):
                        client_metadata = response.get("UserPoolClient")
                        if isinstance(client_metadata, dict):
                            client_metadata["ClientSecretPresent"] = bool(client_metadata.pop("ClientSecret", None))
                    if service == "lightsail" and operation == "get_bucket_access_keys":
                        from .aws_facts_swc import project_access_keys
                        response = project_access_keys(response)
                    if service == 'macie2' and operation == 'get_findings':
                        # Retain only classification metadata before shared
                        # caching; finding samples and object paths are omitted.
                        from .aws_macie_findings_native import project_response
                        response = project_response(response)
                    if not isinstance(response, dict):
                        raise ReadFailure("malformed", "malformed_response")
                    if report_key:
                        with self._lock:
                            self._report_interval[report_key] = max(0.1, self._report_interval.get(report_key, 0.1) * 0.9)
                    if future is not None:
                        future.set_result(response)
                    return copy.deepcopy(response)
                except Exception as exc:
                    failure = _failure(exc)
                    if report_key and failure.code in {"Throttling", "ThrottlingException"}:
                        with self._lock:
                            self._report_interval[report_key] = min(1.0, self._report_interval.get(report_key, 0.1) + 0.25)
                    # Amazon Connect answers ListInstances with a message-less
                    # InvalidRequestException in Regions where the service is
                    # not offered (the endpoint resolves); with the SDK support
                    # list excluding the Region it is the same unsupported state.
                    connect_unsupported = (service, operation, failure.code) == ("connect", "list_instances", "InvalidRequestException") and \
                        not ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Message")
                    if type(exc).__name__ in {"EndpointConnectionError", "ConnectTimeoutError"} or connect_unsupported:
                        # A failed endpoint connection plus an explicit SDK
                        # support list that excludes this region is unsupported
                        # endpoint evidence, not a successful empty inventory.
                        try:
                            partition = session.get_partition_for_region(region)
                            supported = session.get_available_regions(service, partition_name=partition)
                            if supported and region not in supported:
                                failure = ReadFailure("not_collected", "unsupported_region_service")
                        except Exception:
                            pass
                    transient_transport = type(exc).__name__ in {"ReadTimeoutError", "ConnectTimeoutError", "EndpointConnectionError", "ConnectionClosedError", "HTTPClientError"}
                    response_meta = getattr(exc, "response", None)
                    response_meta = response_meta.get("ResponseMetadata", {}) if isinstance(response_meta, dict) else {}
                    http_status = response_meta.get("HTTPStatusCode") if isinstance(response_meta, dict) else None
                    retryable = transient_transport or http_status == 429 or failure.code in {"Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "SlowDown", "ServiceUnavailable", "ServiceUnavailableException", "InternalError", "InternalServerError", "InternalServerException"}
                    if failure.code == "unsupported_region_service" or not retryable or attempt + 1 == self.attempts:
                        evict_retryable_failure = retryable and failure.code != "unsupported_region_service"
                        raise failure from None
                    fallback = min(0.2 * (2 ** attempt), 2)
                    provider_minimum = _retry_after_minimum(exc)
                    delay = max(fallback, provider_minimum or 0.0)
                    if self.deadline is not None and time.monotonic() + delay >= self.deadline:
                        raise ReadFailure("timeout", "retry_wait_exceeds_deadline")
                    from peaso.runtime_metrics import span as _runtime_span
                    with _runtime_span("aws.retry_wait"):
                        if self.cancel_event is not None and self._sleep is time.sleep and callable(getattr(self.cancel_event, "wait", None)):
                            self.cancel_event.wait(delay)
                        else:
                            self._sleep(delay)
                    self.check_deadline()
        except Exception as exc:
            failure = _failure(exc)
            if _metadata_profile in ('aws-lambda-environment-content-v1', 'aws-selected-configuration-content-v1'):
                # Unknown provider error codes can echo a selected name/value.
                if (getattr(self, 'automatic_workload_environment_active', False) is not True
                        or failure.status != 'denied' or failure.code not in {
                        'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation', 'ForbiddenException'}):
                    failure = ReadFailure(failure.status, 'selected_configuration_read_unavailable' if _metadata_profile == 'aws-selected-configuration-content-v1' else 'lambda_environment_read_unavailable')
            # A failed projection's traceback can retain raw provider payload
            # in frame locals. Cache a fresh code/status-only exception that
            # has never been raised, and raise a separate sanitized instance.
            if future is not None:
                future.set_exception(ReadFailure(failure.status, failure.code))
                if evict_retryable_failure:
                    with self._lock:
                        if key not in self._transient_refreshes and self._cache.get(key) is future:
                            self._transient_refreshes.add(key)
                            self._cache.pop(key)
            raise ReadFailure(failure.status, failure.code) from None

    def pages(self, session, service, region, operation, expression, _tokens=None, _page_limit=None, **arguments):
        """Complete list read. `_tokens=(input_name, output_name)` paginates an
        operation that botocore declares without a paginator; an unpaginated
        response carrying a continuation token is never reported complete."""
        import jmespath
        from .aws_request_pool import canonical_wrapper
        session = canonical_wrapper(self, session)
        items, seen = [], set()
        try:
            with self._lock:
                if self.max_calls is not None and self.calls >= self.max_calls and not any(key[:4] == (id(session), service, region, operation) for key in self._cache):
                    raise ReadFailure("not_collected", "call_limit")
            client = self.client(session, service, region)
            # SDK pagination metadata handles IAM Marker, S3 continuation,
            # CloudWatch nextToken, ELB NextMarker and multi-token APIs correctly.
            cfg = client.get_paginator(operation)._pagination_cfg if client.can_paginate(operation) else {}
            if not cfg and _tokens:
                cfg = {"input_token": _tokens[0], "output_token": _tokens[1]}
            unpaginated = not cfg
            input_tokens = cfg.get("input_token", [])
            output_tokens = cfg.get("output_token", [])
            input_tokens = [input_tokens] if isinstance(input_tokens, str) else input_tokens
            output_tokens = [output_tokens] if isinstance(output_tokens, str) else output_tokens
            params = dict(arguments)
            page_number = 0
            while (self.max_pages is None or page_number < self.max_pages) and (_page_limit is None or page_number < _page_limit):
                page_number += 1
                response = self.call(session, service, region, operation, **params)
                if operation == "describe_instances":
                    reservations = response.get("Reservations")
                    if not isinstance(reservations, list) or any(not isinstance(r, dict) or not isinstance(r.get("Instances"), list) for r in reservations):
                        raise ReadFailure("malformed", "malformed_response")
                batch = jmespath.search(expression, response)
                if not isinstance(batch, list):
                    raise ReadFailure("malformed", "malformed_response")
                if unpaginated and any(response.get(key) for key in _CONTINUATION_KEYS):
                    items.extend(batch)
                    raise ReadFailure("not_collected", "unhandled_pagination_token")
                remaining = self.max_items - len(items) if self.max_items is not None else None
                items.extend(batch[:remaining])
                more = cfg.get("more_results")
                tokens = tuple(jmespath.search(token, response) for token in output_tokens)
                if more and jmespath.search(more, response) and not any(tokens):
                    raise ReadFailure("malformed", "missing_pagination_token")
                has_more = any(tokens) and (not more or jmespath.search(more, response))
                if remaining is not None and (len(batch) > remaining or (len(items) == self.max_items and has_more)):
                    raise ReadFailure("not_collected", "resource_limit")
                if (service, operation) == ("ec2", "search_transit_gateway_routes"):
                    # Older SDK models have no paginator; newer ones expose
                    # NextToken. In either case an explicit truncation marker
                    # cannot establish completeness without a usable next page.
                    additional = response.get("AdditionalRoutesAvailable")
                    if additional is not None and type(additional) is not bool:
                        raise ReadFailure("malformed", "malformed_route_search_completion")
                    if additional is True and not has_more:
                        raise ReadFailure("not_collected", "missing_pagination_token")
                if not has_more:
                    return ReadResult(items, "collected" if items else "empty")
                token_key = json.dumps(tokens)
                if token_key in seen:
                    raise ReadFailure("malformed", "repeated_pagination_token")
                seen.add(token_key)
                for name, token in zip(input_tokens, tokens):
                    if token is not None:
                        params[name] = token
            raise ReadFailure("not_collected", "page_limit")
        except Exception as exc:
            failure = _failure(exc)
            return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})

    def detail(self, session, service, region, operation, *, absent=(), **arguments):
        try:
            response = _safe(self.call(session, service, region, operation, **arguments))
            response["collection_status"] = "collected"
            return response
        except Exception as exc:
            failure = _failure(exc)
            if failure.code in absent or (failure.status == "empty" and failure.code in SERVICE_STATE_CODES):
                return {"collection_status": "empty", "absent": True, "error": {"code": failure.code}}
            return {"collection_status": failure.status, "error": {"code": failure.code}}


def _session(auth, region):
    """Resolve precisely the selected boto3 chain; never recover via default."""
    import boto3
    key_fields = ("aws_access_key_id", "aws_secret_access_key", "aws_session_token")
    selected_keys = any(auth.get(k) for k in key_fields)
    method = auth.get("method", "default")
    if method == "assume_role":
        if not any(auth.get(key) for key in ("role_arn", "assume_roles", "role_chain")):
            raise ValueError("assume_role requires a target role")
        method = "profile" if auth.get("profile") else "access_keys" if selected_keys else "default"
    if method not in {"default", "auto", "sdk", "profile", "sso", "access_keys", "web_identity", "container", "instance", "task_role"}:
        raise ValueError("unsupported AWS authentication method")
    if method in {"profile", "sso"} and not auth.get("profile"):
        raise ValueError("selected profile authentication requires profile")
    if method == "access_keys" and not selected_keys:
        raise ValueError("selected access_keys authentication requires explicit credentials")
    if selected_keys and not all(auth.get(k) for k in key_fields[:2]):
        raise ValueError("explicit credentials require access key and secret key")
    if selected_keys and auth.get("profile"):
        raise ValueError("select profile or explicit credentials")
    kwargs = {"region_name": region}
    if selected_keys:
        kwargs.update({k: auth[k] for k in key_fields if auth.get(k)})
    elif auth.get("profile"):
        kwargs["profile_name"] = auth["profile"]
    session = boto3.Session(**kwargs)
    # Freeze the selected context for this bounded scan. This prevents provider
    # refresh/chain changes in concurrently constructed clients.
    provider_names = {"web_identity": "assume-role-with-web-identity", "container": "container-role", "instance": "iam-role"}
    if method == "task_role" and (selected_keys or auth.get("profile")):
        raise ValueError("task_role selects the platform runtime credential context")
    if method in provider_names:
        if selected_keys or auth.get("profile"):
            raise ValueError("selected metadata/web identity provider cannot be combined with keys or profile")
        credentials = session._session.get_component("credential_provider").get_provider(provider_names[method]).load()
    else:
        credentials = session.get_credentials()
    if credentials is None:
        raise ReadFailure("denied", "credentials_unavailable")
    if method == "task_role" and getattr(credentials, "method", None) not in {"env", "container-role", "iam-role", "assume-role-with-web-identity"}:
        raise ReadFailure("denied", "platform_role_credentials_unavailable")
    frozen = credentials.get_frozen_credentials()
    if not frozen.access_key or not frozen.secret_key:
        raise ReadFailure("denied", "credentials_unavailable")
    if method == "task_role" and not frozen.token:
        raise ReadFailure("denied", "platform_role_session_token_required")
    pinned = boto3.Session(aws_access_key_id=frozen.access_key,
        aws_secret_access_key=frozen.secret_key, aws_session_token=frozen.token,
        region_name=region or session.region_name or "us-east-1")
    return pinned, getattr(credentials, "method", "selected")


def _assume(requests, session, region, target, defaults):
    import boto3
    target = {"role_arn": target} if isinstance(target, str) else dict(target)
    arn = target.get("role_arn")
    if not isinstance(arn, str) or not re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}", arn):
        raise ValueError("role_arn must be an IAM role ARN")
    name = target.get("role_session_name", defaults.get("role_session_name", "peaso-read-only"))
    if not isinstance(name, str) or not re.fullmatch(r"[\w+=,.@-]{2,64}", name):
        raise ValueError("invalid role_session_name")
    params = {"RoleArn": arn, "RoleSessionName": name}
    external = target.get("external_id", defaults.get("external_id"))
    if external:
        params["ExternalId"] = external
    response = requests.call(session, "sts", region, "assume_role", **params)
    credentials = response.get("Credentials", {})
    if not all(credentials.get(k) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise ReadFailure("malformed", "malformed_assume_role")
    return boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"], region_name=region)


def _reject_unprotected_hosted_role(requests, session, region, target, defaults):
    """Require denial with absent and unrelated workspace External IDs."""
    arn = target if isinstance(target, str) else target["role_arn"]
    name = (target.get("role_session_name") if isinstance(target, dict) else None) or defaults.get("role_session_name", "peaso-read-only")
    if not isinstance(name, str) or not re.fullmatch(r"[\w+=,.@-]{2,64}", name):
        raise ValueError("invalid role_session_name")
    from peaso.auth.aws_trust import require_external_id_boundary, UnsafeRoleTrust
    def probe(external_id):
        # A successful response contains disposable STS credentials. Never
        # construct a session or perform a read with them.
        params = {"RoleArn": arn, "RoleSessionName": name}
        if external_id is not None:
            params["ExternalId"] = external_id
        return requests.call(session, "sts", region, "assume_role",
            _uncached_credential_exchange=True, **params)
    try:
        external = target.get("external_id", defaults.get("external_id")) if isinstance(target, dict) else defaults.get("external_id")
        require_external_id_boundary(probe, external)
    except UnsafeRoleTrust as exc:
        raise ReadFailure("denied", str(exc)) from None


# type -> (service, list operation, native result path). No resource contents,
# database records, secret values, log events or function code are read.
ACTIVITY_ACTIONS = {'enumeration': ['CreateIndex', 'DescribeAccessEntry', 'DescribeAccountAttributes', 'DescribeAvailabilityZones', 'DescribeBundleTasks', 'DescribeCarrierGateways', 'DescribeClientVpnRoutes', 'DescribeCluster', 'DescribeDhcpOptions', 'DescribeFlowLogs', 'DescribeImages', 'DescribeInstanceAttribute', 'DescribeInstanceInformation', 'DescribeInstanceTypes', 'DescribeInstances', 'DescribeInstances', 'DescribeKeyPairs', 'DescribeLogGroups', 'DescribeLogStreams', 'DescribeOrganization', 'DescribeRegions', 'DescribeSecurityGroups', 'DescribeSnapshotAttribute', 'DescribeSnapshotTierStatus', 'DescribeSubscriptionFilters', 'DescribeTransitGatewayMulticastDomains', 'DescribeVolumes', 'DescribeVolumesModifications', 'DescribeVpcEndpointConnectionNotifications', 'DescribeVpcs', 'GetAccount', 'GetAccountAuthorizationDetails', 'GetAccountSendingEnabled', 'GetBucketAcl', 'GetBucketLogging', 'GetBucketPolicy', 'GetBucketReplication', 'GetBucketVersioning', 'GetCallerIdentity', 'GetCertificate', 'GetConsoleScreenshot', 'GetCostAndUsage', 'GetDetector', 'GetEbsDefaultKmsKeyId', 'GetEbsEncryptionByDefault', 'GetFindings', 'GetFlowLogsIntegrationTemplate', 'GetIdentityVerificationAttributes', 'GetInstances', 'GetIntrospectionSchema', 'GetLaunchTemplateData', 'GetLaunchTemplateData', 'GetLogRecord', 'GetParameters', 'GetPolicyVersion', 'GetPublicAccessBlock', 'GetQueryResults', 'GetRegions', 'GetSMSAttributes', 'GetSMSSandboxAccountStatus', 'GetSendQuota', 'GetTransitGatewayRouteTableAssociations', 'GetUserPolicy', 'HeadObject', 'ListAccessKeys', 'ListAccounts', 'ListAllMyBuckets', 'ListAssociatedAccessPolicies', 'ListAttachedUserPolicies', 'ListClusters', 'ListDetectors', 'ListDomains', 'ListFindings', 'ListHostedZones', 'ListIPSets', 'ListIdentities', 'ListInstanceProfiles', 'ListObjects', 'ListOrganizationalUnitsForParent', 'ListOriginationNumbers', 'ListPolicyVersions', 'ListResources', 'ListRoles', 'ListRoles', 'ListRules', 'ListServiceQuotas', 'ListSubscriptions', 'ListTargetsByRule', 'ListTopics', 'ListUsers', 'LookupEvents', 'Search'], 'llm_jacking': ['PutUseCaseForModelAccess', 'PutFoundationModelEntitlement', 'PutModelInvocationLoggingConfiguration', 'CreateFoundationModelAgreement', 'InvokeModel', 'InvokeModelWithResponseStream', 'GetUseCaseForModelAccess', 'GetModelInvocationLoggingConfiguration', 'GetFoundationModelAvailability', 'ListFoundationModelAgreementOffers', 'ListFoundationModels', 'ListProvisionedModelThroughputs', 'SearchAgreements', 'AcceptAgreementRequest'], 'privilege_escalation': ['AddPermission', 'AddRoleToInstanceProfile', 'AddUserToGroup', 'AssociateAccessPolicy', 'AssumeRole', 'AttachGroupPolicy', 'AttachRolePolicy', 'AttachUserPolicy', 'ChangePassword', 'CreateAccessEntry', 'CreateAccessKey', 'CreateDevEndpoint', 'CreateEventSourceMapping', 'CreateFunction', 'CreateGroup', 'CreateJob', 'CreateKeyPair', 'CreateLoginProfile', 'CreatePipeline', 'CreatePolicyVersion', 'CreateRole', 'CreateStack', 'DeleteRolePermissionsBoundary', 'DeleteRolePolicy', 'DeleteUserPermissionsBoundary', 'DeleteUserPolicy', 'DetachRolePolicy', 'DetachUserPolicy', 'GetCredentialsForIdentity', 'GetId', 'GetPolicyVersion', 'GetUserPolicy', 'Invoke', 'ModifyInstanceAttribute', 'PassRole', 'PutGroupPolicy', 'PutPipelineDefinition', 'PutRolePermissionsBoundary', 'PutRolePolicy', 'PutUserPermissionsBoundary', 'PutUserPolicy', 'ReplaceIamInstanceProfileAssociation', 'RunInstances', 'SetDefaultPolicyVersion', 'UpdateAccessKey', 'UpdateAssumeRolePolicy', 'UpdateDevEndpoint', 'UpdateEventSourceMapping', 'UpdateFunctionCode', 'UpdateJob', 'UpdateLoginProfile']}

SPECS = {
    "vpc_account_inventory": ("ec2", "describe_vpcs", "Vpcs"),
    "ssm_managed_instance": ("ssm", "describe_instance_information", "InstanceInformationList"),
    "autoscaling_group": ("autoscaling", "describe_auto_scaling_groups", "AutoScalingGroups"),
    "config_aggregator": ("config", "describe_configuration_aggregators", "ConfigurationAggregators"),
    "config_account_aggregator_inventory": ("config", "describe_configuration_aggregators", "ConfigurationAggregators"),
    "config_delegated_administrator": ("organizations", "list_delegated_administrators", "DelegatedAdministrators"),
    "log_resource_policy": ("logs", "describe_resource_policies", "resourcePolicies"),
    "config_aggregate_authorization": ("config", "describe_aggregation_authorizations", "AggregationAuthorizations"),
    "dlm_policy": ("dlm", "get_lifecycle_policies", "Policies"),
    "gameliftstreams_stream_session": ("gameliftstreams", "list_stream_groups", "Items"),
    "cloudtrail_account_inventory": ("cloudtrail", "describe_trails", "trailList"),
    # One row per enabled Region (Macie jobs are regional, buckets account-global).
    "macie2_account_classification_job_inventory": ("macie2", "list_classification_jobs", "items"),
    "ec2_image": ("ec2", "describe_images", "Images"),
    "ebs_snapshot": ("ec2", "describe_snapshots", "Snapshots"),
    "flow_log": ("ec2", "describe_flow_logs", "FlowLogs"),
    "aws_account_configuration": ("account", "get_alternate_contact", None),
    "access_analyzer": ("accessanalyzer", "list_analyzers", "analyzers"),
    "ec2_regional_settings": ("ec2", "get_ebs_encryption_by_default", None),
    "iam_virtual_mfa_device": ("iam", "list_virtual_mfa_devices", "VirtualMFADevices"),
    "iam_server_certificate": ("iam", "list_server_certificates", "ServerCertificateMetadataList"),
    "aws_cloudtrail_activity": ("cloudtrail", "lookup_events", "Events"),
    "aws_identity_center_user": ("identitystore", "list_users", "Users"),
    "aws_identity_center_permission_set": ("sso-admin", "list_permission_sets", "PermissionSets"),
    "vpc": ("ec2", "describe_vpcs", "Vpcs"),
    "subnet": ("ec2", "describe_subnets", "Subnets"),
    "route_table": ("ec2", "describe_route_tables", "RouteTables"),
    "security_group": ("ec2", "describe_security_groups", "SecurityGroups"),
    "network_acl": ("ec2", "describe_network_acls", "NetworkAcls"),
    "network_interface": ("ec2", "describe_network_interfaces", "NetworkInterfaces"),
    "instance": ("ec2", "describe_instances", "Reservations[].Instances[]"),
    "ebs_volume": ("ec2", "describe_volumes", "Volumes"),
    "internet_gateway": ("ec2", "describe_internet_gateways", "InternetGateways"),
    "nat_gateway": ("ec2", "describe_nat_gateways", "NatGateways"),
    "vpc_endpoint": ("ec2", "describe_vpc_endpoints", "VpcEndpoints"),
    "vpc_peering": ("ec2", "describe_vpc_peering_connections", "VpcPeeringConnections"),
    "transit_gateway": ("ec2", "describe_transit_gateways", "TransitGateways"),
    "transit_gateway_attachment": ("ec2", "describe_transit_gateway_attachments", "TransitGatewayAttachments"),
    "transit_gateway_vpc_attachment": ("ec2", "describe_transit_gateway_vpc_attachments", "TransitGatewayVpcAttachments"),
    "transit_gateway_route_table": ("ec2", "describe_transit_gateway_route_tables", "TransitGatewayRouteTables"),
    "vpn_connection": ("ec2", "describe_vpn_connections", "VpnConnections"),
    "vpn_gateway": ("ec2", "describe_vpn_gateways", "VpnGateways"),
    "load_balancer": ("elbv2", "describe_load_balancers", "LoadBalancers"),
    "classic_load_balancer": ("elb", "describe_load_balancers", "LoadBalancerDescriptions"),
    "target_group": ("elbv2", "describe_target_groups", "TargetGroups"),
    "kms_key": ("kms", "list_keys", "Keys"),
    "cloudtrail": ("cloudtrail", "describe_trails", "trailList"),
    "config_recorder": ("config", "describe_configuration_recorders", "ConfigurationRecorders"),
    "config_delivery_channel": ("config", "describe_delivery_channels", "DeliveryChannels"),
    "guardduty_detector": ("guardduty", "list_detectors", "DetectorIds"),
    "synthetics_canary": ("synthetics", "describe_canaries", "Canaries"),
    "rds_instance": ("rds", "describe_db_instances", "DBInstances"),
    "rds_cluster": ("rds", "describe_db_clusters", "DBClusters"),
    "rds_snapshot": ("rds", "describe_db_snapshots", "DBSnapshots"),
    "eks_cluster": ("eks", "list_clusters", "clusters"),
    "lambda_function": ("lambda", "list_functions", "Functions"),
    "ecr_repository": ("ecr", "describe_repositories", "repositories"),
    "log_group": ("logs", "describe_log_groups", "logGroups"),
    "cloudwatch_alarm": ("cloudwatch", "describe_alarms", "MetricAlarms"),
    "secret": ("secretsmanager", "list_secrets", "SecretList"),
    "sns_topic": ("sns", "list_topics", "Topics"),
    "sqs_queue": ("sqs", "list_queues", "QueueUrls || `[]`"),
    "rest_api": ("apigateway", "get_rest_apis", "items"),
    "http_api": ("apigatewayv2", "get_apis", "Items"),
    "opensearch_domain": ("opensearch", "list_domain_names", "DomainNames"),
    "dynamodb_table": ("dynamodb", "list_tables", "TableNames"),
}
GLOBAL_TYPES = {"iam_customer_policy", "iam_managed_policy", "aws_account", "aws_account_configuration", "cloudtrail_account_inventory", "config_account_region_coverage", "config_account_aggregator_inventory", "config_delegated_administrator", "iam_user", "iam_group", "iam_role", "iam_policy", "iam_account_summary", "iam_password_policy", "iam_credential_report", "iam_access_key", "iam_virtual_mfa_device", "iam_server_certificate", "bucket", "s3_account_public_access_block", "organization_account", "organization_parent", "scp_policy"}
AWS_TYPES = sorted(set(SPECS) | GLOBAL_TYPES)
GLOBAL_SCOPE = "global"
FETCHERS = {}
GLOBAL_TYPES.add("vpc_account_inventory")
GLOBAL_TYPES.add("macie2_account_classification_job_inventory")
ENRICHERS = {}

# Auditable operation allowlist. In particular, GetSecretValue, logs/objects,
# secret/content reads and Access Analyzer creation are absent.
_DETAIL_ACTIONS = {
    "sts": "get_caller_identity assume_role",
    "iam": "list_policies get_policy_version get_account_authorization_details get_account_summary get_account_password_policy get_credential_report get_service_last_accessed_details generate_credential_report generate_service_last_accessed_details list_users list_access_keys list_ssh_public_keys get_access_key_last_used get_login_profile list_mfa_devices",
    "sso-admin": "list_instances list_permission_sets describe_permission_set get_inline_policy_for_permission_set list_managed_policies_in_permission_set get_permissions_boundary_for_permission_set",
    "identitystore": "list_users",
    "ec2": "describe_regions get_snapshot_block_public_access_state get_image_block_public_access_state get_instance_metadata_defaults describe_snapshot_attribute describe_instance_attribute search_transit_gateway_routes get_transit_gateway_route_table_associations",
    "s3": "list_buckets get_bucket_location get_public_access_block get_bucket_policy_status get_bucket_policy get_bucket_encryption get_bucket_versioning get_bucket_acl get_bucket_ownership_controls get_bucket_logging get_bucket_lifecycle_configuration get_bucket_notification_configuration get_bucket_replication get_object_lock_configuration get_bucket_tagging",
    "s3control": "get_public_access_block",
    "organizations": "list_accounts list_policies_for_target describe_policy list_parents describe_organization describe_organizational_unit",
    "kms": "describe_key get_key_rotation_status get_key_policy list_aliases",
    "cloudtrail": "get_trail_status get_event_selectors get_insight_selectors lookup_events",
    "config": "describe_configuration_recorder_status",
    "dlm": "get_lifecycle_policy",
    "gameliftstreams": "list_stream_sessions",
    "guardduty": "get_detector",
    "eks": "describe_cluster",
    "lambda": "get_policy get_function_url_config",
    "ecr": "get_repository_policy get_lifecycle_policy",
    "secretsmanager": "describe_secret get_resource_policy",
    "sns": "get_topic_attributes",
    "sqs": "get_queue_attributes",
    "elbv2": "describe_load_balancer_attributes describe_listeners describe_target_health",
    "elb": "describe_load_balancer_attributes describe_load_balancer_policies",
    "rds": "describe_db_snapshot_attributes",
    "opensearch": "describe_domain",
    "dynamodb": "describe_table",
}
READ_ACTIONS = {(service, operation) for service, operations in _DETAIL_ACTIONS.items() for operation in operations.split()}
READ_ACTIONS.update((service, operation) for service, operation, expression in SPECS.values())

_NATIVE_IDS = {
    "vpc_account_inventory": "id",
    "ssm_managed_instance": "InstanceId", "autoscaling_group": "AutoScalingGroupARN", "config_delegated_administrator": "Id", "config_aggregator": "ConfigurationAggregatorArn", "config_account_aggregator_inventory": "ConfigurationAggregatorArn",
    "log_resource_policy": "policyName", "config_aggregate_authorization": "AggregationAuthorizationArn", "dlm_policy": "PolicyId",
    "gameliftstreams_stream_session": "Arn",
    "cloudtrail_account_inventory": "TrailARN", "config_account_region_coverage": "id",
    "macie2_account_classification_job_inventory": "id",
    "ec2_image": "ImageId", "ebs_snapshot": "SnapshotId",
    "flow_log": "FlowLogId",
    "access_analyzer": "arn",
    "aws_account": "Account", "iam_credential_report": "arn",
    "iam_access_key": "AccessKeyFingerprint", "iam_virtual_mfa_device": "SerialNumber", "iam_server_certificate": "Arn",
    "aws_cloudtrail_activity": "EventId",
    "aws_identity_center_user": "id", "aws_identity_center_permission_set": "id",
    "iam_user": "Arn", "iam_group": "Arn", "iam_role": "Arn", "iam_policy": "Arn", "iam_managed_policy": "Arn", "iam_customer_policy": "Arn",
    "bucket": "Name", "vpc": "VpcId", "subnet": "SubnetId", "route_table": "RouteTableId",
    "security_group": "GroupId", "network_acl": "NetworkAclId", "network_interface": "NetworkInterfaceId",
    "instance": "InstanceId", "ebs_volume": "VolumeId", "internet_gateway": "InternetGatewayId",
    "nat_gateway": "NatGatewayId", "vpc_endpoint": "VpcEndpointId", "vpc_peering": "VpcPeeringConnectionId",
    "transit_gateway": "TransitGatewayId", "transit_gateway_attachment": "TransitGatewayAttachmentId",
    "transit_gateway_vpc_attachment": "TransitGatewayAttachmentId",
    "transit_gateway_route_table": "TransitGatewayRouteTableId", "vpn_connection": "VpnConnectionId",
    "vpn_gateway": "VpnGatewayId", "load_balancer": "LoadBalancerArn", "classic_load_balancer": "LoadBalancerName",
    "target_group": "TargetGroupArn", "kms_key": "KeyArn", "cloudtrail": "TrailARN",
    "config_recorder": "name", "config_delivery_channel": "name", "guardduty_detector": "DetectorId",
    "synthetics_canary": "Name",
    "rds_instance": "DBInstanceArn", "rds_cluster": "DBClusterArn", "rds_snapshot": "DBSnapshotArn",
    "eks_cluster": "name", "lambda_function": "FunctionArn", "ecr_repository": "repositoryArn",
    "log_group": "logGroupName", "cloudwatch_alarm": "AlarmArn", "secret": "ARN",
    "sns_topic": "TopicArn", "sqs_queue": "QueueUrl", "rest_api": "id", "http_api": "ApiId",
    "opensearch_domain": "DomainName", "dynamodb_table": "TableName", "organization_account": "Id", "organization_parent": "ChildId", "scp_policy": "Id",
}


def _native_id(kind, item):
    value = item.get(_NATIVE_IDS.get(kind, "id"))
    if isinstance(value, str) and value:
        return value
    from peaso.snapshot import resource_id
    return resource_id("aws", kind, "", _safe(item))


def _policy(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            try:
                value = json.loads(unquote(value))
            except (ValueError, TypeError):
                return {"collection_status": "malformed", "error": {"code": "malformed_policy"}}
    return value


def _documented_omission(item, key, value, operation):
    """Project only a documented native API omission from a successful read."""
    if key not in item:
        item[key] = copy.deepcopy(value)
        item.setdefault("_coverage", {})[key] = {"status": "empty", "reason": "documented_optional_api_omission", "source_operation": operation}


def _enrich(requests, session, region, kind, items, *, account=None, partition=None):
    def detail(service, operation, **arguments):
        return requests.detail(session, service, region, operation, **arguments)

    def enrich_one(original):
        if isinstance(original, str):
            names = {"eks_cluster": "name", "guardduty_detector": "DetectorId", "sqs_queue": "QueueUrl", "dynamodb_table": "TableName"}
            item = {names.get(kind, _NATIVE_IDS.get(kind, "Name")): original}
        elif isinstance(original, dict):
            item = copy.deepcopy(original)
        else:
            raise ReadFailure("malformed", "malformed_resource")
        if kind == "instance":
            projected = detail("ec2", "describe_instance_attribute", InstanceId=item["InstanceId"], Attribute="userData")
            if projected.get("collection_status") == "collected" and isinstance(projected.get("UserDataIndicators"), dict):
                item["UserDataIndicators"] = {**projected["UserDataIndicators"], "collection_status": "collected"}
            else:
                item["UserDataIndicators"] = projected
            if projected.get("collection_status") == "collected" and isinstance(projected.get("UserDataSecretIndicators"), dict):
                item["UserDataSecretIndicators"] = projected["UserDataSecretIndicators"]
            else:
                item["UserDataSecretIndicators"] = {"collection_status": projected.get("collection_status", "not_collected")}
            protection = detail("ec2", "describe_instance_attribute", InstanceId=item["InstanceId"], Attribute="disableApiTermination")
            item.setdefault("Attributes", {})["DisableApiTermination"] = (
                protection["DisableApiTermination"]["Value"] if protection.get("collection_status") == "collected" else protection)
        elif kind == "log_resource_policy":
            if "policyDocument" in item:
                item["policyDocument"] = _policy(item["policyDocument"])
        elif kind == "dlm_policy":
            item["Details"] = detail("dlm", "get_lifecycle_policy", PolicyId=item["PolicyId"])
        elif kind == "ebs_snapshot":
            snapshot_id = item["SnapshotId"]
            attributes = detail("ec2", "describe_snapshot_attribute", SnapshotId=snapshot_id, Attribute="createVolumePermission")
            state = attributes.get("collection_status", "not_collected")
            if state == "collected" and attributes.get("SnapshotId") == snapshot_id:
                values = attributes.get("CreateVolumePermissions", [])
                if isinstance(values, list) and all(isinstance(value, dict) for value in values):
                    item["CreateVolumePermissions"] = values
                    item.setdefault("_coverage", {})["CreateVolumePermissions"] = {"status": "collected" if values else "empty", "source_operation": "ec2:DescribeSnapshotAttribute"}
                else:
                    item.setdefault("_coverage", {})["CreateVolumePermissions"] = {"status": "malformed", "reason": "malformed_snapshot_permissions"}
            else:
                item.setdefault("_coverage", {})["CreateVolumePermissions"] = {"status": "malformed" if state == "collected" else state, "source_operation": "ec2:DescribeSnapshotAttribute"}
        elif kind == "kms_key":
            key = item["KeyId"]
            item["Metadata"] = detail("kms", "describe_key", KeyId=key)
            metadata = item["Metadata"]
            if metadata.get("collection_status") == "collected":
                native = metadata.get("KeyMetadata")
                if (not isinstance(native, dict) or native.get("KeyId") != key or
                        (isinstance(item.get("KeyArn"), str) and native.get("Arn") != item["KeyArn"])):
                    item["Metadata"] = {"collection_status": "malformed",
                                        "error": {"code": "kms_key_identity_mismatch"}}
            item["Rotation"] = detail("kms", "get_key_rotation_status", KeyId=key)
            rotation = item["Rotation"]
            if (rotation.get("collection_status") == "collected" and "KeyId" in rotation
                    and rotation["KeyId"] not in {key, item.get("KeyArn")}):
                item["Rotation"] = {"collection_status": "malformed",
                                    "error": {"code": "kms_rotation_identity_mismatch"}}
            item["Policy"] = detail("kms", "get_key_policy", KeyId=key, PolicyName="default")
            if "Policy" in item["Policy"]:
                item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
            from .aws_kms_enclave_inventory import enrich_key_inventory
            enrich_key_inventory(requests, session, region, item)
        elif kind == "cloudtrail":
            _documented_omission(item, "KmsKeyId", "", "cloudtrail:DescribeTrails")
            arn = item.get("TrailARN") or item["Name"]
            home = item.get("HomeRegion", region)
            item["Status"] = requests.detail(session, "cloudtrail", home, "get_trail_status", Name=arn)
            item["EventSelectors"] = requests.detail(session, "cloudtrail", home, "get_event_selectors", TrailName=arn)
            selectors = item["EventSelectors"]
            if (selectors.get("collection_status") == "collected"
                    and selectors.get("TrailARN") != item.get("TrailARN")):
                item["EventSelectors"] = {"collection_status": "malformed",
                                          "error": {"code": "cloudtrail_selector_identity_mismatch"}}
            item["InsightSelectors"] = requests.detail(session, "cloudtrail", home, "get_insight_selectors", TrailName=arn, absent=("InsightNotEnabledException",))
        elif kind == "config_recorder":
            item["Status"] = detail("config", "describe_configuration_recorder_status", ConfigurationRecorderNames=[item["name"]])
        elif kind == "guardduty_detector":
            item["Configuration"] = detail("guardduty", "get_detector", DetectorId=item["DetectorId"])
        elif kind == "eks_cluster":
            item["Cluster"] = detail("eks", "describe_cluster", name=item["name"])
        elif kind == "lambda_function":
            name = item["FunctionName"]
            item["Policy"] = requests.detail(session, "lambda", region, "get_policy", FunctionName=name, absent=("ResourceNotFoundException",))
            item["FunctionUrl"] = requests.detail(session, "lambda", region, "get_function_url_config", FunctionName=name, absent=("ResourceNotFoundException",))
            if "Policy" in item["Policy"]:
                item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
        elif kind == "ecr_repository":
            name = item["repositoryName"]
            item["Policy"] = requests.detail(session, "ecr", region, "get_repository_policy", repositoryName=name, absent=("RepositoryPolicyNotFoundException",))
            item["LifecyclePolicy"] = requests.detail(session, "ecr", region, "get_lifecycle_policy", repositoryName=name, absent=("LifecyclePolicyNotFoundException",))
            if "policyText" in item["Policy"]:
                item["Policy"]["policyText"] = _policy(item["Policy"]["policyText"])
        elif kind == "secret":
            # ListSecrets can lag changes by five minutes. DescribeSecret gives
            # more recent per-secret metadata, though both reads are eventual.
            arn = item.get("ARN")
            for field in ("RotationEnabled", "RotationRules", "RotationLambdaARN", "OwningService", "RotationLambdaRequired", "KmsKeyId"):
                item.pop(field, None)
                item.setdefault("_coverage", {}).pop(field, None)
            valid_arn = (isinstance(account, str) and re.fullmatch(r"[0-9]{12}", account) is not None
                and partition in {"aws", "aws-us-gov", "aws-cn"} and isinstance(arn, str)
                and re.fullmatch(r"arn:" + re.escape(partition) + r":secretsmanager:" + re.escape(region)
                    + r":" + account + r":secret:[^:]+", arn) is not None)
            if not valid_arn:
                rotation = {"collection_status": "malformed", "error": {"code": "malformed_secret_arn"}}
            else:
                rotation = detail("secretsmanager", "describe_secret", SecretId=arn)
                if rotation.get("collection_status") == "collected" and (
                        rotation.get("ARN") != arn or
                        ("Name" in item and rotation.get("Name") != item["Name"])):
                    rotation = {"collection_status": "malformed", "error": {"code": "secret_identity_mismatch"}}
            state = rotation.get("collection_status", "malformed")
            if state == "collected":
                # DescribeSecret omits KmsKeyId for aws/secretsmanager. Preserve
                # the exact omission proof without inventing a key ID or ARN.
                if "KmsKeyId" not in rotation:
                    item["_coverage"]["KmsKeyId"] = {
                        "status": "empty", "source_operation": "secretsmanager:DescribeSecret",
                        "native_member_present": False, "documented_default": "aws/secretsmanager"}
                else:
                    key_id = rotation["KmsKeyId"]
                    if isinstance(key_id, str) and key_id:
                        item["KmsKeyId"] = key_id
                        item["_coverage"]["KmsKeyId"] = {
                            "status": "collected", "source_operation": "secretsmanager:DescribeSecret",
                            "native_member_present": True}
                    else:
                        item["_coverage"]["KmsKeyId"] = {
                            "status": "malformed", "source_operation": "secretsmanager:DescribeSecret",
                            "native_member_present": True}
                flag = rotation.get("RotationEnabled")
                if type(flag) is bool:
                    item["RotationEnabled"] = flag
                    item["_coverage"]["RotationEnabled"] = {"status": "collected", "source_operation": "secretsmanager:DescribeSecret"}
                elif flag is None and not any(rotation.get(field) for field in
                        ("RotationRules", "RotationLambdaARN", "NextRotationDate")):
                    # DescribeSecret documents null for never-configured
                    # rotation. This successful, identity-bound native read
                    # therefore proves automatic rotation is not enabled.
                    # Preserve whether AWS omitted the member or returned null;
                    # denied/partial/foreign reads never reach this branch.
                    item["RotationEnabled"] = False
                    item["_coverage"]["RotationEnabled"] = {
                        "status": "collected", "source_operation": "secretsmanager:DescribeSecret",
                        "native_member_present": "RotationEnabled" in rotation,
                        "native_value": None, "interpretation": "documented_never_configured_rotation",
                        "documentation": "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DescribeSecret.html#SecretsManager-DescribeSecret-response-RotationEnabled"}
                else:
                    item["_coverage"]["RotationEnabled"] = {"status": "malformed", "source_operation": "secretsmanager:DescribeSecret"}
                if "OwningService" in rotation:
                    owner = rotation["OwningService"]
                    if isinstance(owner, str) and owner:
                        item["OwningService"] = owner
                        item["_coverage"]["OwningService"] = {
                            "status": "collected", "source_operation": "secretsmanager:DescribeSecret"}
                    else:
                        item["_coverage"]["OwningService"] = {
                            "status": "malformed", "source_operation": "secretsmanager:DescribeSecret"}
                for field, typ in (("RotationRules", dict), ("RotationLambdaARN", str)):
                    if field in rotation:
                        if isinstance(rotation[field], typ):
                            item[field] = rotation[field]
                            item["_coverage"][field] = {"status": "collected", "source_operation": "secretsmanager:DescribeSecret"}
                        else:
                            item["_coverage"][field] = {"status": "malformed", "source_operation": "secretsmanager:DescribeSecret"}
                if "RotationRules" not in rotation:
                    item["_coverage"]["RotationRules"] = {
                        "status": "empty", "source_operation": "secretsmanager:DescribeSecret",
                        "native_member_present": False}
            else:
                status = state if state in {"denied", "timeout", "not_collected", "partial", "malformed", "unknown"} else "unknown"
                code = rotation.get("error", {}).get("code") if isinstance(rotation.get("error"), dict) else None
                code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", code) else "detail_unavailable"
                for field in ("RotationEnabled", "RotationRules", "RotationLambdaARN", "OwningService", "KmsKeyId"):
                    item["_coverage"][field] = {"status": status, "reason": code, "source_operation": "secretsmanager:DescribeSecret"}
            item["Policy"] = detail("secretsmanager", "get_resource_policy", SecretId=arn) if valid_arn else {"collection_status": "malformed"}
            policy = item["Policy"]
            if (policy.get("collection_status") == "collected" and "ResourcePolicy" in policy and
                    (policy.get("ARN") != arn or ("Name" in policy and policy["Name"] != item.get("Name")))):
                item["Policy"] = {"collection_status": "malformed", "error": {"code": "secret_policy_identity_mismatch"}}
            elif "ResourcePolicy" in policy:
                policy["ResourcePolicy"] = _policy(policy["ResourcePolicy"])
        elif kind == "sns_topic":
            item["Attributes"] = detail("sns", "get_topic_attributes", TopicArn=item["TopicArn"])
            attrs = item["Attributes"].get("Attributes", {})
            if item["Attributes"].get("collection_status") == "collected" and isinstance(item["Attributes"].get("Attributes"), dict):
                _documented_omission(attrs, "KmsMasterKeyId", "", "sns:GetTopicAttributes")
            if "Policy" in attrs:
                attrs["Policy"] = _policy(attrs["Policy"])
        elif kind == "sqs_queue":
            item["Attributes"] = detail("sqs", "get_queue_attributes", QueueUrl=item["QueueUrl"], AttributeNames=["All"])
            attrs = item["Attributes"].get("Attributes", {})
            if item["Attributes"].get("collection_status") == "collected" and isinstance(item["Attributes"].get("Attributes"), dict):
                _documented_omission(attrs, "KmsMasterKeyId", "", "sqs:GetQueueAttributes(All)")
            if "Policy" in attrs:
                attrs["Policy"] = _policy(attrs["Policy"])
        elif kind == "load_balancer":
            arn = item["LoadBalancerArn"]
            item["Attributes"] = detail("elbv2", "describe_load_balancer_attributes", LoadBalancerArn=arn)
            listeners = requests.pages(session, "elbv2", region, "describe_listeners", "Listeners", LoadBalancerArn=arn)
            if any(isinstance(listener, dict) and "LoadBalancerArn" in listener and listener["LoadBalancerArn"] != arn for listener in listeners.items):
                listeners = ReadResult([], "malformed", {"code": "listener_load_balancer_identity_mismatch"})
            item["Listeners"] = {"collection_status": listeners.status, "items": listeners.items}
            if listeners.error:
                item["Listeners"]["error"] = listeners.error
        elif kind == "classic_load_balancer":
            item["Attributes"] = detail("elb", "describe_load_balancer_attributes", LoadBalancerName=item["LoadBalancerName"])
            from .aws_classic_elb_policies_native import enrich as enrich_ssl_policies
            enrich_ssl_policies(requests, session, region, item, account)
        elif kind == "target_group":
            item["TargetHealth"] = detail("elbv2", "describe_target_health", TargetGroupArn=item["TargetGroupArn"])
        elif kind == "rds_snapshot":
            item["Attributes"] = detail("rds", "describe_db_snapshot_attributes", DBSnapshotIdentifier=item["DBSnapshotIdentifier"])
        elif kind == "opensearch_domain":
            item["Domain"] = detail("opensearch", "describe_domain", DomainName=item["DomainName"])
        elif kind == "dynamodb_table":
            item["Table"] = detail("dynamodb", "describe_table", TableName=item["TableName"])
        if isinstance(item.get("Policy"), str):
            item["Policy"] = _policy(item["Policy"])
        return item
    # Per-resource reads are independent: run them concurrently and keep the
    # input order (the first failing resource raises, as the serial loop did).
    from .aws_request_pool import ordered_map
    return ordered_map(requests, items, enrich_one)


def _access_keys(requests, session, region):
    """Read-only metadata, with no raw key identifier serialized in inventory."""
    users = requests.pages(session, "iam", region, "list_users", "Users")
    items, failure = [], None
    if users.status not in {"collected", "empty"}:
        return ReadResult([], users.status, users.error)
    for user in users.items:
        if not isinstance(user.get("UserName"), str) or not isinstance(user.get("Arn"), str):
            failure = ReadFailure("malformed", "malformed_access_key_user")
            continue
        keys = requests.pages(session, "iam", region, "list_access_keys", "AccessKeyMetadata", UserName=user["UserName"])
        for key in keys.items:
            if not isinstance(key.get("AccessKeyId"), str):
                failure = ReadFailure("malformed", "malformed_access_key_metadata")
                continue
            items.append(_safe({**key, "UserArn": user["Arn"]}))
        if keys.status not in {"collected", "empty"}:
            failure = ReadFailure((keys.error or {}).get("cause_status", keys.status), (keys.error or {}).get("code", "access_key_inventory_incomplete"))
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


def _iam_user_details(requests, session, region, item):
    """Per-user credential metadata reads; depend only on the user name."""
    fields = {}
    name = item["UserName"]
    access = requests.pages(session, "iam", region, "list_access_keys", "AccessKeyMetadata", UserName=name)
    for key_item in access.items:
        key_item["LastUsed"] = requests.detail(session, "iam", region, "get_access_key_last_used", AccessKeyId=key_item["AccessKeyId"])
    fields["AccessKeys"] = {"collection_status": access.status, "items": access.items}
    if access.error:
        fields["AccessKeys"]["error"] = access.error
    fields["LoginProfile"] = requests.detail(session, "iam", region, "get_login_profile", UserName=name, absent=("NoSuchEntity",))
    mfa = requests.pages(session, "iam", region, "list_mfa_devices", "MFADevices", UserName=name)
    fields["MFADevices"] = {"collection_status": mfa.status, "items": mfa.items}
    ssh = requests.pages(session, "iam", region, "list_ssh_public_keys", "SSHPublicKeys", UserName=name)
    fields["SSHPublicKeys"] = {"collection_status": ssh.status,
                               "items": [{key: value for key, value in row.items()
                                          if key in ("SSHPublicKeyId", "Status")}
                                         for row in ssh.items if isinstance(row, dict)]}
    if ssh.error:
        fields["SSHPublicKeys"]["error"] = ssh.error
    service_credentials = requests.pages(session, "iam", region,
        "list_service_specific_credentials", "ServiceSpecificCredentials", UserName=name)
    fields["ServiceSpecificCredentials"] = {
        "collection_status": service_credentials.status,
        "items": [{key: credential[key] for key in
                   ("ServiceName", "ServiceSpecificCredentialId", "Status") if key in credential}
                  for credential in service_credentials.items if isinstance(credential, dict)],
    }
    if service_credentials.error:
        fields["ServiceSpecificCredentials"]["error"] = service_credentials.error
    return fields


def _iam(requests, session, region, wanted):
    keys = {"iam_user": "UserDetailList", "iam_group": "GroupDetailList", "iam_role": "RoleDetailList", "iam_policy": "Policies"}
    result = {}
    for kind, key in keys.items():
        if kind not in wanted:
            continue
        read = requests.pages(session, "iam", region, "get_account_authorization_details", key)
        # Identical calls for four IAM projections are single-flight cached.
        if kind == "iam_user":
            # Users' reads are independent; fetch them concurrently and apply
            # them in list order, so every user row is built as before.
            from .aws_request_pool import ordered_map
            user_details = ordered_map(requests, read.items,
                                       lambda user: _iam_user_details(requests, session, region, user))
        for index, item in enumerate(read.items):
            item["_provenance"] = {"operation": "iam:GetAccountAuthorizationDetails", "native_response_complete": True}
            if kind in {"iam_user", "iam_group", "iam_role"}:
                _documented_omission(item, "AttachedManagedPolicies", [], "iam:GetAccountAuthorizationDetails")
            if kind == "iam_user":
                for field in ("UserPolicyList", "AttachedManagedPolicies"):
                    _documented_omission(item, field, [], "iam:GetAccountAuthorizationDetails")
            if "AssumeRolePolicyDocument" in item:
                item["AssumeRolePolicyDocument"] = _policy(item["AssumeRolePolicyDocument"])
            for field_name in ("UserPolicyList", "GroupPolicyList", "RolePolicyList"):
                for inline in item.get(field_name, []):
                    if "PolicyDocument" in inline:
                        inline["PolicyDocument"] = _policy(inline["PolicyDocument"])
            for version in item.get("PolicyVersionList", []):
                if "Document" in version:
                    version["Document"] = _policy(version["Document"])
            item["PolicySources"] = [
                {"source_type": "inline_policy", "attachment": kind.removeprefix("iam_"),
                 "attachment_name": item.get("UserName") or item.get("GroupName") or item.get("RoleName"),
                 "policy_name": policy.get("PolicyName"), "document": policy.get("PolicyDocument")}
                for policy in item.get({"iam_user": "UserPolicyList", "iam_group": "GroupPolicyList", "iam_role": "RolePolicyList"}.get(kind, "_none"), [])]
            item["PolicySources"].extend({"source_type": "managed_policy", "attachment": kind.removeprefix("iam_"),
                 "attachment_name": item.get("UserName") or item.get("GroupName") or item.get("RoleName"),
                 "policy_arn": p.get("PolicyArn"), "policy_name": p.get("PolicyName")}
                 for p in item.get("AttachedManagedPolicies", []))
            if kind == "iam_user":
                item.update(user_details[index])
        if kind == "iam_user":
            _services_last_accessed(requests, session, region, read.items)
        if kind == "iam_role":
            needed, excluded = _role_report_scope(requests, session, region, read.items)
            for role in excluded:
                role["ServicesLastAccessedStatus"] = {"collection_status": "not_collected", "reason": "identity_policies_cannot_allow_namespaces",
                    "namespaces": list(ROLE_REPORT_NAMESPACES), "source": "iam:GetAccountAuthorizationDetails"}
            _services_last_accessed(requests, session, region, needed)
        result[kind] = read
    return result


_LAST_ACCESSED_FIELDS = ("ServiceNamespace", "ServiceName", "LastAuthenticated", "LastAuthenticatedRegion", "TotalAuthenticatedEntities")


def _services_last_accessed(requests, session, region, principals):
    """Attach bounded SERVICE_LEVEL access reports to IAM users and roles.

    Each principal gets ServicesLastAccessed only from a COMPLETED, fully
    paginated job; any failure, FAILED job or deadline leaves that principal
    without the list (UNKNOWN downstream) and records why in
    ServicesLastAccessedStatus. Other principals are unaffected."""
    pending = {item["Arn"]: item for item in principals if isinstance(item.get("Arn"), str)}
    if not pending:
        return
    results = _sla_reports(requests, session, region, sorted(pending))
    for arn, item in pending.items():
        rows, state = results[arn]
        if rows is not None:
            item["ServicesLastAccessed"] = rows
        item["ServicesLastAccessedStatus"] = state


# Namespaces whose role-level access reports a check consumes. A role whose
# identity policies provably cannot allow any of them needs no report: AWS
# lists only services the principal's identity policies allow.
ROLE_REPORT_NAMESPACES = ("bedrock",)


def _may_allow_namespace(document, namespace):
    """Conservative: True unless every statement provably cannot allow `namespace`."""
    statements = document.get("Statement") if isinstance(document, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return True
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            return True
        if statement["Effect"] == "Deny":
            continue
        if "NotAction" in statement:
            return True
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        if not isinstance(actions, list):
            return True
        for action in actions:
            if not isinstance(action, str) or "[" in action:
                return True
            prefix = action.split(":", 1)[0].lower()
            pattern = "^" + re.escape(prefix).replace(r"\*", ".*").replace(r"\?", ".") + "$"
            if re.match(pattern, namespace):
                return True
    return False


def _role_report_scope(requests, session, region, roles):
    """Split roles into those needing an access report and those whose inline
    and attached managed policy documents cannot allow ROLE_REPORT_NAMESPACES."""
    policies = requests.pages(session, "iam", region, "get_account_authorization_details", "Policies")
    documents = {}
    if policies.status in {"collected", "empty"}:
        for policy in policies.items:
            versions = [v for v in policy.get("PolicyVersionList", []) if isinstance(v, dict) and v.get("IsDefaultVersion") is True]
            if isinstance(policy.get("Arn"), str) and len(versions) == 1:
                documents[policy["Arn"]] = _policy(versions[0].get("Document"))
    needed, excluded = [], []
    for role in roles:
        sources = [inline.get("PolicyDocument") for inline in role.get("RolePolicyList", []) if isinstance(inline, dict)]
        attached = role.get("AttachedManagedPolicies", [])
        known = isinstance(attached, list) and isinstance(role.get("RolePolicyList", []), list) and all(
            isinstance(p, dict) and p.get("PolicyArn") in documents for p in attached)
        if known:
            sources += [documents[p["PolicyArn"]] for p in attached]
        if not known or any(_may_allow_namespace(document, namespace) for document in sources for namespace in ROLE_REPORT_NAMESPACES):
            needed.append(role)
        else:
            excluded.append(role)
    return needed, excluded


def _sla_reports(requests, session, region, arns):
    from .aws_iam_report_native import service_reports
    return service_reports(requests, session, region, arns)


def _buckets(requests, session, region):
    result = requests.pages(session, "s3", region, "list_buckets", "Buckets")
    reads = [
        ("PublicAccessBlock", "get_public_access_block", ("NoSuchPublicAccessBlockConfiguration",)),
        ("PolicyStatus", "get_bucket_policy_status", ("NoSuchBucketPolicy",)),
        ("Policy", "get_bucket_policy", ("NoSuchBucketPolicy",)),
        ("Encryption", "get_bucket_encryption", ("ServerSideEncryptionConfigurationNotFoundError",)),
        ("Versioning", "get_bucket_versioning", ()),
        ("Acl", "get_bucket_acl", ()),
        ("OwnershipControls", "get_bucket_ownership_controls", ("OwnershipControlsNotFoundError",)),
        ("Logging", "get_bucket_logging", ()),
        ("Lifecycle", "get_bucket_lifecycle_configuration", ("NoSuchLifecycleConfiguration",)),
        ("Notifications", "get_bucket_notification_configuration", ()),
        ("Replication", "get_bucket_replication", ("ReplicationConfigurationNotFoundError",)),
        ("ObjectLock", "get_object_lock_configuration", ("ObjectLockConfigurationNotFoundError",)),
        ("Tags", "get_bucket_tagging", ("NoSuchTagSet",))]
    from .aws_request_pool import ordered_map
    items = list(result.items)
    # Independent per-bucket reads run concurrently; results are assigned in
    # the serial order, so every bucket row is built exactly as before.
    locations = ordered_map(requests, items, lambda item: requests.detail(
        session, "s3", region, "get_bucket_location", Bucket=item["Name"]))
    targets = []
    for location in locations:
        selected = location.get("LocationConstraint") or region
        if location.get("collection_status") in (None, "collected"):
            selected = "eu-west-1" if selected == "EU" else selected
            if location.get("LocationConstraint") is None:
                selected = "us-east-1"
        targets.append(selected)
    pairs = [(item["Name"], selected, read) for item, selected in zip(items, targets) for read in reads]
    values = iter(ordered_map(requests, pairs, lambda pair: requests.detail(
        session, "s3", pair[1], pair[2][1], Bucket=pair[0], absent=pair[2][2])))
    for item, location in zip(items, locations):
        item["Location"] = location
        for field_name, _operation, _absent in reads:
            item[field_name] = next(values)
        if "Policy" in item["Policy"]:
            item["Policy"]["Policy"] = _policy(item["Policy"]["Policy"])
    return result


def network_relationships(collections):
    """Evidence-backed adjacency only; no claim of end-to-end reachability."""
    relationships = []
    for collection in collections:
        if collection["type"] not in {"subnet", "route_table", "security_group", "network_interface", "instance", "load_balancer", "vpc_endpoint", "network_acl", "internet_gateway"}:
            continue
        for item in collection["items"]:
            source = next((item[k] for k in ("NetworkInterfaceId", "InstanceId", "RouteTableId", "SubnetId", "GroupId", "LoadBalancerArn", "VpcEndpointId", "NetworkAclId", "InternetGatewayId") if item.get(k)), None)
            if not source:
                continue
            links = [(k, item[k]) for k in ("VpcId", "SubnetId") if item.get(k)]
            links += [("security_group", group.get("GroupId")) for group in item.get("Groups", []) if isinstance(group, dict)]
            links += [("security_group", group) for group in item.get("SecurityGroups", []) if isinstance(group, str)]
            for association in item.get("Associations", []):
                if association.get("SubnetId"):
                    links.append(("association", association["SubnetId"]))
            for attachment in item.get("Attachments", []):
                if attachment.get("VpcId"):
                    links.append(("attachment", attachment["VpcId"]))
            for route in item.get("Routes", []):
                for key in ("GatewayId", "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId"):
                    if route.get(key):
                        links.append(("route_target", route[key]))
            for relation, target in links:
                if target and target != source:
                    relationships.append({"scope": collection["scope"], "source": source, "target": target,
                        "relation": relation, "evidence_type": collection["type"], "reachability": "unknown"})
    return sorted(relationships, key=lambda x: (x["scope"], x["source"], x["relation"], x["target"]))


_GAMELIFT_SHELL_STATES = ("ACTIVE", "CONNECTED", "PENDING_CLIENT_RECONNECTION", "RECONNECTING")


def _gameliftstreams_shell_sessions(requests, session, region, account, partition):
    """Read only role-bearing/live session metadata; retain incomplete group reads."""
    groups = requests.pages(session, "gameliftstreams", region, "list_stream_groups", "Items")
    if groups.status not in ("collected", "empty", "partial"):
        return groups
    items, errors, seen, conflicting = [], [], {}, set()
    complete = groups.status in ("collected", "empty")
    group_prefix = f"arn:{partition}:gameliftstreams:{region}:{account}:streamgroup/"
    session_prefix = f"arn:{partition}:gameliftstreams:{region}:{account}:streamsession/"
    if not complete:
        errors.append({"operation": "ListStreamGroups", "error": groups.error})
    for group in groups.items:
        arn = group.get("Arn") if isinstance(group, dict) else None
        if not isinstance(arn, str) or not arn.startswith(group_prefix) or not arn[len(group_prefix):]:
            complete = False
            errors.append({"operation": "ListStreamGroups", "code": "malformed_group_arn"})
            continue
        group_id = arn[len(group_prefix):]
        if "/" in group_id:
            complete = False
            errors.append({"operation": "ListStreamGroups", "code": "malformed_group_arn"})
            continue
        group_status = group.get("Status")
        if not isinstance(group_status, str) or not group_status:
            complete = False
            errors.append({"operation": "ListStreamGroups", "code": "missing_group_status"})
            group_status = ""
        for status in _GAMELIFT_SHELL_STATES:
            read = requests.pages(session, "gameliftstreams", region, "list_stream_sessions", "Items",
                                  Identifier=arn, Status=status)
            if read.status not in ("collected", "empty"):
                complete = False
                errors.append({"operation": "ListStreamSessions", "group": arn, "status": status,
                               "error": read.error})
            for raw in read.items:
                session_arn = raw.get("Arn") if isinstance(raw, dict) else None
                if (not isinstance(session_arn, str) or
                        not session_arn.startswith(session_prefix + group_id + "/") or
                        not session_arn[len(session_prefix + group_id + "/"):]):
                    complete = False
                    errors.append({"operation": "ListStreamSessions", "code": "malformed_session_arn"})
                    continue
                if raw.get("Status") != status:
                    complete = False
                    errors.append({"operation": "ListStreamSessions", "code": "mismatched_session_status"})
                    continue
                role = raw.get("RoleArn")
                if role is not None and (not isinstance(role, str) or
                                         not role.startswith(f"arn:{partition}:iam::{account}:role/")):
                    complete = False
                    errors.append({"operation": "ListStreamSessions", "code": "malformed_session_role"})
                    continue
                row = {"Arn": session_arn, "Status": status, "RoleArn": role or "",
                       "StreamGroupArn": arn, "StreamGroupStatus": group_status}
                if session_arn in seen and seen[session_arn] != row:
                    complete = False
                    conflicting.add(session_arn)
                    errors.append({"operation": "ListStreamSessions", "code": "conflicting_session_metadata"})
                else:
                    seen[session_arn] = row
    items = [row for arn, row in seen.items() if arn not in conflicting]
    return ReadResult(items, ("collected" if items else "empty") if complete else "partial",
                      {"code": "gameliftstreams_session_inventory_incomplete", "sources": errors} if errors else None)


def _single(requests, session, region, service, operation, *, absent=(), **arguments):
    try:
        return ReadResult([requests.call(session, service, region, operation, **arguments)])
    except Exception as exc:
        failure = _failure(exc)
        if failure.code in absent:
            return ReadResult([], "empty", {"code": failure.code})
        return ReadResult([], failure.status, {"code": failure.code})


def _credentials_report(requests, session, region):
    from .aws_iam_report_native import credential_report
    return credential_report(requests, session, region)


def _scp_policies(requests, session, region, account):
    policies, path, seen = {}, [{"Id": account, "Type": "ACCOUNT"}], {account}
    target = path[0]
    failure = None
    while True:
        attached = requests.pages(session, "organizations", region, "list_policies_for_target", "Policies",
            TargetId=target["Id"], Filter="SERVICE_CONTROL_POLICY")
        if attached.status not in {"collected", "empty"}:
            failure = ReadFailure((attached.error or {}).get("cause_status", attached.status), (attached.error or {}).get("code", "scp_attachment_collection_incomplete"))
        for original in attached.items:
            if not isinstance(original, dict) or not isinstance(original.get("Id"), str):
                failure = ReadFailure("malformed", "malformed_scp_policy")
                continue
            policy_id = original["Id"]
            item = policies.setdefault(policy_id, {**original, "TargetId": account, "Attachments": []})
            item["Attachments"].append({"TargetId": target["Id"], "TargetType": target["Type"],
                "Inherited": target["Type"] != "ACCOUNT", "ParentPath": copy.deepcopy(path), "collection_status": "collected"})
            if "Detail" not in item:
                response = requests.detail(session, "organizations", region, "describe_policy", PolicyId=policy_id)
                if response.get("collection_status") not in (None, "collected", "empty"):
                    failure = ReadFailure(response["collection_status"], response.get("error", {}).get("code", "scp_document_unavailable"))
                content = response.get("Policy", {}).get("Content")
                if content is not None:
                    response["Policy"]["Content"] = _policy(content)
                    document = response["Policy"]["Content"]
                    if not isinstance(document, dict) or not isinstance(document.get("Statement"), (list, dict)):
                        failure = ReadFailure("malformed", "malformed_scp_document")
                elif response.get("collection_status") is None:
                    failure = ReadFailure("malformed", "missing_scp_document")
                item["Detail"] = response
        if attached.status not in {"collected", "empty"} or target["Type"] == "ROOT":
            break
        parents = requests.pages(session, "organizations", region, "list_parents", "Parents", ChildId=target["Id"])
        if parents.status not in {"collected", "empty"}:
            failure = ReadFailure((parents.error or {}).get("cause_status", parents.status), (parents.error or {}).get("code", "organization_parent_visibility_incomplete"))
            break
        if len(parents.items) != 1 or not isinstance(parents.items[0], dict):
            failure = ReadFailure("malformed", "missing_or_ambiguous_organization_parent")
            break
        parent = parents.items[0]
        parent_id, parent_type = parent.get("Id"), parent.get("Type")
        valid = isinstance(parent_id, str) and parent_type in {"ORGANIZATIONAL_UNIT", "ROOT"}
        valid = valid and bool(re.fullmatch(r"r-[a-z0-9]+" if parent_type == "ROOT" else r"ou-[a-z0-9]+-[a-z0-9]+", parent_id))
        if not valid:
            failure = ReadFailure("malformed", "malformed_organization_parent")
            break
        if parent_id in seen:
            failure = ReadFailure("malformed", "organization_parent_cycle")
            break
        seen.add(parent_id)
        target = {"Id": parent_id, "Type": parent_type}
        path.append(target)
    complete = failure is None and target["Type"] == "ROOT"
    # Every OU/root (policy, target) attachment observed on the account's path,
    # so an SCP attached only above the account is evaluated at its own level.
    inherited_items = [{"TargetId": attachment["TargetId"], "TargetType": attachment["TargetType"], "Id": item.get("Id"),
        "Name": item.get("Name"), "Content": ((item.get("Detail") or {}).get("Policy") or {}).get("Content")}
        for item in policies.values() for attachment in item["Attachments"] if attachment["Inherited"]]
    for item in policies.values():
        direct = [a for a in item["Attachments"] if not a["Inherited"]]
        item["TargetId"] = account if direct else item["Attachments"][0]["TargetId"]
        item["TargetType"] = "ACCOUNT" if direct else item["Attachments"][0]["TargetType"]
        item["AttachedToAccount"] = bool(direct)
        item["InheritanceComplete"] = complete
        item["InheritedPolicies"] = {"collection_status": "collected" if complete else (failure.status if failure else "unknown"),
            "ParentPath": copy.deepcopy(path), "complete": complete, "items": copy.deepcopy(inherited_items)}
        if failure:
            item["InheritedPolicies"]["error"] = {"code": failure.code}
    items = list(policies.values())
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


def _organization_parents(requests, session, region, account):
    """Observed account/OU parent edges only, with explicit path completeness."""
    child, path, seen, items = account, [account], {account}, []
    failure = None
    while True:
        read = requests.pages(session, "organizations", region, "list_parents", "Parents", ChildId=child)
        if read.status not in {"collected", "empty"}:
            # The provider's typed not-in-use response is known absence, unlike
            # denied visibility. Never infer root from an arbitrary empty list.
            if not items and (read.error or {}).get("code") == "AWSOrganizationsNotInUseException":
                return ReadResult([], "empty", {"code": "AWSOrganizationsNotInUseException"})
            failure = ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "organization_parent_visibility_incomplete"))
            break
        if len(read.items) != 1 or not isinstance(read.items[0], dict):
            failure = ReadFailure("malformed", "missing_or_ambiguous_organization_parent")
            break
        parent = read.items[0]
        parent_id, parent_type = parent.get("Id"), parent.get("Type")
        valid = isinstance(parent_id, str) and parent_type in {"ROOT", "ORGANIZATIONAL_UNIT"}
        valid = valid and bool(re.fullmatch(r"r-[a-z0-9]+" if parent_type == "ROOT" else r"ou-[a-z0-9]+-[a-z0-9]+", parent_id))
        if not valid:
            failure = ReadFailure("malformed", "malformed_organization_parent")
            break
        if parent_id in seen:
            failure = ReadFailure("malformed", "organization_parent_cycle")
            break
        seen.add(parent_id)
        path.append(parent_id)
        items.append({**parent, "ChildId": child, "ParentId": parent_id,
            "ParentType": parent_type, "ParentPath": list(path)})
        if parent_type == "ROOT":
            break
        child = parent_id
    for item in items:
        item["InheritanceComplete"] = failure is None
        item["ParentCollection"] = {"collection_status": "collected" if failure is None else failure.status,
            "complete": failure is None}
        if failure:
            item["ParentCollection"]["error"] = {"code": failure.code}
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


def _identity_center(requests, session, region, kind):
    """Accessible regional instances and ordinary directory/permission metadata."""
    instances = requests.pages(session, "sso-admin", region, "list_instances", "Instances")
    if instances.status not in {"collected", "empty"}:
        return ReadResult([], instances.status, instances.error)
    items, failure = [], None
    for instance in instances.items:
        if not isinstance(instance, dict) or not isinstance(instance.get("InstanceArn"), str):
            failure = ReadFailure("malformed", "malformed_identity_center_instance")
            continue
        arn = instance["InstanceArn"]
        if kind == "aws_identity_center_user":
            store = instance.get("IdentityStoreId")
            if not isinstance(store, str) or not store:
                failure = ReadFailure("malformed", "missing_identity_store_id")
                continue
            read = requests.pages(session, "identitystore", region, "list_users", "Users", IdentityStoreId=store)
            for user in read.items:
                if not isinstance(user, dict) or not isinstance(user.get("UserId"), str):
                    failure = ReadFailure("malformed", "malformed_identity_center_user")
                    continue
                items.append({**user, "InstanceArn": arn, "InstanceOwnerAccountId": instance.get("OwnerAccountId"),
                    "IdentityStoreId": store, "id": f"{arn}/identitystore/{store}/user/{user['UserId']}"})
        else:
            read = requests.pages(session, "sso-admin", region, "list_permission_sets", "PermissionSets", InstanceArn=arn)
            for permission in read.items:
                if not isinstance(permission, str):
                    failure = ReadFailure("malformed", "malformed_permission_set_arn")
                    continue
                detail = requests.detail(session, "sso-admin", region, "describe_permission_set", InstanceArn=arn, PermissionSetArn=permission)
                inline = requests.detail(session, "sso-admin", region, "get_inline_policy_for_permission_set", InstanceArn=arn, PermissionSetArn=permission)
                if isinstance(inline.get("InlinePolicy"), str) and inline["InlinePolicy"]:
                    inline["InlinePolicy"] = _policy(inline["InlinePolicy"])
                managed = requests.pages(session, "sso-admin", region, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", InstanceArn=arn, PermissionSetArn=permission)
                boundary = requests.detail(session, "sso-admin", region, "get_permissions_boundary_for_permission_set", InstanceArn=arn, PermissionSetArn=permission)
                items.append({"id": f"{arn}/permission-set/{permission}", "InstanceArn": arn,
                    "InstanceOwnerAccountId": instance.get("OwnerAccountId"), "PermissionSetArn": permission,
                    "PermissionSet": detail, "InlinePolicy": inline,
                    "AttachedManagedPolicies": {"collection_status": managed.status, "items": managed.items,
                        **({"error": managed.error} if managed.error else {})}, "PermissionsBoundary": boundary})
        if read.status not in {"collected", "empty"}:
            failure = ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "identity_center_inventory_incomplete"))
    if failure:
        return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(items, "collected" if items else "empty")


# Event names defined only by the IAM API (checked against every botocore
# service model). IAM is a global service whose CloudTrail events are recorded
# only in us-east-1 for the aws partition:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events
IAM_ONLY_ACTIVITY_NAMES = frozenset({"AddRoleToInstanceProfile", "AddUserToGroup", "AttachGroupPolicy", "AttachRolePolicy",
    "AttachUserPolicy", "CreateAccessKey", "CreateLoginProfile", "CreateRole", "DeleteRolePermissionsBoundary", "DeleteRolePolicy",
    "DeleteUserPermissionsBoundary", "DeleteUserPolicy", "DetachRolePolicy", "DetachUserPolicy", "GetAccountAuthorizationDetails",
    "GetUserPolicy", "ListAccessKeys", "ListAttachedUserPolicies", "ListRoles", "PutGroupPolicy", "PutRolePermissionsBoundary",
    "PutRolePolicy", "PutUserPermissionsBoundary", "PutUserPolicy", "UpdateAccessKey", "UpdateAssumeRolePolicy", "UpdateLoginProfile"})
IAM_EVENT_REGION = "us-east-1"


def activity_event_names(region):
    names = sorted({name for values in ACTIVITY_ACTIONS.values() for name in values})
    # Only standard aws-partition commercial Regions skip IAM-only names;
    # every other partition and us-east-1 itself query the full list.
    if region != IAM_EVENT_REGION and re.fullmatch(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[0-9]", region) and not region.startswith("us-gov-"):
        names = [name for name in names if name not in IAM_ONLY_ACTIVITY_NAMES]
    return names


def _cloudtrail_activity(requests, session, region):
    end = requests.observed_at
    start = end - timedelta(minutes=requests.activity_minutes)
    names = activity_event_names(region)
    items, failures = {}, []
    from .aws_request_pool import ordered_reads
    # Event names are read concurrently under the same 2 TPS Region limiter;
    # results are merged in the original name order.
    reads = ordered_reads(requests, names, lambda name: requests.pages(session, "cloudtrail", region, "lookup_events", "Events",
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], StartTime=start, EndTime=end))
    for name, read in zip(names, reads):
        for event in read.items:
            if event.get("EventName") != name:
                failures.append(ReadFailure("malformed", "activity_query_name_mismatch"))
                continue
            items[event["EventId"]] = {**event, "WindowStart": start.isoformat(), "WindowEnd": end.isoformat(),
                "ObservationSource": "cloudtrail:LookupEvents", "Projection": "actor_arn_type_event_name_time_id_only"}
        if read.status not in {"collected", "empty"}:
            failures.append(ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "activity_window_incomplete")))
    if failures:
        failure = failures[0]
        return ReadResult(list(items.values()), "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
    return ReadResult(list(items.values()), "collected" if items else "empty")


def _ec2_regional_settings(requests, session, region):
    """Independent account/region settings, preserving field-level read status."""
    operations = [("get_ebs_encryption_by_default", "EbsEncryptionByDefault", "EbsEncryptionByDefault"),
        ("get_snapshot_block_public_access_state", "State", "SnapshotBlockPublicAccessState"),
        ("get_image_block_public_access_state", "ImageBlockPublicAccessState", "ImageBlockPublicAccessState"),
        ("get_instance_metadata_defaults", "AccountLevel", "InstanceMetadataDefaults")]
    item = {"id": "ec2-regional-settings", "_coverage": {}}
    for operation, native_field, field in operations:
        detail = requests.detail(session, "ec2", region, operation)
        state = detail.get("collection_status", "not_collected")
        if state == "collected" and native_field in detail:
            item[field] = detail[native_field]
            item["_coverage"][field] = {"status": "collected", "source_operation": operation, "source_member": native_field}
        else:
            item["_coverage"][field] = {"status": "malformed" if state == "collected" else state,
                "source_operation": operation, "reason": "setting_unavailable", **({"error": detail["error"]} if "error" in detail else {})}
    return ReadResult([item], "collected")


def _account_configuration(requests, session, region, identity):
    """Only presence metadata; contact names/email/phone are not serialized."""
    contact = requests.detail(session, "account", region, "get_alternate_contact", AlternateContactType="SECURITY", absent=("ResourceNotFoundException",))
    if contact.get("collection_status") == "collected":
        value = contact.get("AlternateContact")
        if isinstance(value, dict) and isinstance(value.get("Name"), str) and value["Name"] and value.get("AlternateContactType") == "SECURITY":
            contact = {"collection_status": "collected", "NamePresent": True, "AlternateContactType": "SECURITY"}
        else:
            contact = {"collection_status": "malformed", "error": {"code": "malformed_security_contact"}}
    organization = requests.detail(session, "organizations", region, "describe_organization", absent=("AWSOrganizationsNotInUseException",))
    if organization.get("collection_status") == "collected":
        value = organization.get("Organization")
        if (isinstance(value, dict) and isinstance(value.get("Id"), str) and value["Id"].startswith("o-")
                and isinstance(value.get("MasterAccountId"), str) and re.fullmatch(r"[0-9]{12}", value["MasterAccountId"])):
            organization = {"collection_status": "collected", "OrganizationId": value["Id"], "MasterAccountId": value["MasterAccountId"]}
        else:
            organization = {"collection_status": "malformed", "error": {"code": "malformed_organization_metadata"}}
    return ReadResult([{"id": "account-configuration", "Partition": identity["Arn"].split(":")[1],
        "SecurityContact": contact, "Organization": organization}], "collected")


def _identity(requests, session, region, expected=None):
    identity = requests.call(session, "sts", region, "get_caller_identity")
    account, arn = identity.get("Account"), identity.get("Arn")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account) or not isinstance(arn, str) or not arn.startswith("arn:"):
        raise ReadFailure("malformed", "malformed_caller_identity")
    if expected and expected != account:
        raise ReadFailure("denied", "account_identity_mismatch")
    return _safe(identity)


def _selection(connector):
    options, auth = connector.get("options", {}), connector.get("auth", {})
    scopes = connector.get("scopes") or []
    if not isinstance(scopes, list) or any(not isinstance(x, str) for x in scopes):
        raise ValueError("scopes must be a list of account IDs or account/region scopes")
    selected_regions = options.get("regions") or []
    if not isinstance(selected_regions, list):
        raise ValueError("regions must be a list")
    regions = list(selected_regions)
    accounts = []
    for scope in scopes:
        if re.fullmatch(r"[0-9]{12}", scope):
            accounts.append(scope)
        elif re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
            account, region = scope.split("/")
            accounts.append(account)
            regions.append(region)
        elif re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
            regions.append(scope)
        else:
            raise ValueError("AWS scope must be an account ID, account/region or AWS region")
    regions = list(dict.fromkeys(regions or [auth.get("region_name", "us-east-1")]))
    if any(not isinstance(r, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", r) for r in regions):
        raise ValueError("regions must contain AWS region names")
    return list(dict.fromkeys(accounts)), regions


def collect(connector, requirements=None):
    """Collect only requested facts, with explicit coverage for omitted types.

    Explicit account scopes are an allowlist. Cross-account reads require a
    configured assume_roles target or an organization_role_name opt-in; there
    is never an attempt to guess role names or to fall back after auth failure.
    """
    from peaso.snapshot import make_snapshot
    from peaso.progress import emit_progress
    from .aws_policy import backup_plan_policy, bind_backup_plan_policy
    from .aws_ssm_inventory_events_native import approved_readers

    options, auth = connector.get("options", {}), connector.get("auth", {})
    if not isinstance(options, dict) or not isinstance(auth, dict):
        raise ValueError("auth and options must be objects")
    from . import aws_image_vulnerability_runtime_20261021 as image_vulnerabilities
    image_vulnerabilities.selections(options, connector.get('scopes') or [])
    image_targets = (image_vulnerabilities.authorize_collector(options, connector.get('scopes') or [])
                     if image_vulnerabilities.GRANT in options else [])
    from . import aws_ecr_public_image_runtime_20261021 as ecr_public_image
    ecr_public_image.selected_targets(options, connector.get('scopes') or [])
    public_targets, public_secret, public_vuln = ecr_public_image.authorize_collector(options, connector.get('scopes') or [])
    if (requirements is not None and ecr_public_image.KIND in requirements
            and set(requirements) <= {ecr_public_image.KIND, 'aws_account'} and not public_targets):
        return ecr_public_image.disabled_snapshot(connector.get('scopes') or [])
    from . import aws_workload_image_secret_native_20261021 as workload_image_secrets
    secret_image_targets = workload_image_secrets.authorize_collector(options, connector.get('scopes') or [])
    if (requirements is not None and image_vulnerabilities.KIND in requirements
            and set(requirements) <= {image_vulnerabilities.KIND, 'aws_account'} and not image_targets):
        return image_vulnerabilities.disabled_snapshot(connector.get('scopes') or [])
    if (requirements is not None and workload_image_secrets.KIND in requirements
            and set(requirements) <= {workload_image_secrets.KIND, 'aws_account'} and not secret_image_targets):
        return workload_image_secrets.disabled_snapshot(connector.get('scopes') or [])
    from . import aws_codebuild_buildspec_runtime_20261020 as codebuild_inline
    from . import aws_workload_command_runtime_20261020 as workload_commands
    workload_command_plan = workload_commands.authorize_collector(options, connector.get('scopes') or [])
    if requirements is not None and workload_commands.KIND in requirements and set(requirements) <= {workload_commands.KIND, 'aws_account'} and workload_command_plan is None:
        return workload_commands.disabled_snapshot(connector.get('scopes') or [])
    codebuild_inline_permitted = codebuild_inline.authorize_collector(options, connector.get('scopes') or [])
    if requirements is not None and codebuild_inline.KIND in requirements and set(requirements) <= {codebuild_inline.KIND, 'aws_account'} and not codebuild_inline_permitted:
        return codebuild_inline.disabled_snapshot(connector.get('scopes') or [])
    from . import aws_lambda_environment_secret_indicators
    from . import aws_selected_configuration_secret_indicators
    # Named opt-in without a hand-picked target uses completed native inventory.
    # Keep the selected reader dormant until its exact targets are planned.
    granted_content = options.get('_content_secret_scan_kinds', [])
    auto_lambda_environment = (options.get('content_secret_scans') is True
        and aws_lambda_environment_secret_indicators.KIND in granted_content
        and aws_lambda_environment_secret_indicators.OPTION not in options)
    auto_ecs_environment = (options.get('content_secret_scans') is True
        and aws_selected_configuration_secret_indicators.KIND in granted_content
        and aws_selected_configuration_secret_indicators.OPTION not in options)
    initial_content_options = {**options, '_content_secret_scan_kinds': [kind for kind in granted_content
        if not (auto_lambda_environment and kind == aws_lambda_environment_secret_indicators.KIND)
        and not (auto_ecs_environment and kind == aws_selected_configuration_secret_indicators.KIND)]}
    aws_lambda_environment_secret_indicators.selected_targets(initial_content_options, connector.get('scopes') or [])
    aws_selected_configuration_secret_indicators.selected_targets(initial_content_options, connector.get('scopes') or [])
    from . import aws_s3_selected_source_secret_indicators
    aws_s3_selected_source_secret_indicators.selected_targets(options, connector.get('scopes') or [])
    from . import aws_ecs_environment_file_secret_indicators
    aws_ecs_environment_file_secret_indicators.selected_targets(options, connector.get('scopes') or [])
    from . import aws_workload_referenced_source_indicators
    aws_workload_referenced_source_indicators.selected_targets(options, connector.get('scopes') or [])
    from . import aws_build_deployment_referenced_source_indicators
    aws_build_deployment_referenced_source_indicators.selected_targets(options, connector.get('scopes') or [])
    from .aws_codecommit_review_native import review_policy
    review_policy(options, connector.get("scopes") or [])
    from .aws_controltower_native import normalize as normalize_controltower
    controltower_policy = normalize_controltower(options, connector.get('scopes') or [])
    from .aws_region_data_native import normalize as normalize_data_regions
    data_regions_policy = normalize_data_regions(options)
    inventory_readers = approved_readers(options)
    from peaso.aws_lightsail_owner_policy import normalize as normalize_lightsail, bind_scopes as bind_lightsail, owner_metadata as lightsail_metadata, merge_metadata as merge_lightsail
    lightsail_owner = normalize_lightsail(options)
    bind_lightsail(lightsail_owner, connector.get('scopes') or [])
    from .aws_environment_boundaries_native import normalize as normalize_environment_boundaries
    environment_boundaries_owner = normalize_environment_boundaries(options, connector.get('scopes') or [])
    from .aws_eks_admission_native import normalize as normalize_eks_admission
    eks_admission_owner = normalize_eks_admission(options, connector.get('scopes') or [])
    # Operator-declared thresholds are validated before any AWS request; none is ever defaulted.
    backup_policy = backup_plan_policy(options)
    from .aws_cost_policy import normalize as normalize_cost_policy
    cost_policy = normalize_cost_policy(options)
    from peaso.aws_budget_policy import normalize as normalize_budget_stop_policy
    normalize_budget_stop_policy(options)
    if "_ecr_latest_scan_requested" in options and type(options["_ecr_latest_scan_requested"]) is not bool:
        raise ValueError("internal ECR scan fact selection must be boolean")
    progress_callback = options.get("_progress_callback")
    collection_callback = options.get("_collection_callback")
    progress_total = None
    emit_progress(progress_callback, phase="discovering", provider="aws", scope="", completed=0, total=None, resources=0, dynamic_total=True)
    selected_accounts, regions = _selection(connector)
    explicit_regions = bool(options.get("regions") or auth.get("region_name")) or any(not re.fullmatch(r"[0-9]{12}", scope) for scope in connector.get("scopes") or [])
    discovered_regions = {}
    region_discovery_errors = {}
    # Preserve explicitly selected account/region pairs; account-only scopes
    # use options.regions. Avoid broadening pairs into a Cartesian product.
    plain_accounts = {s for s in (connector.get("scopes") or []) if re.fullmatch(r"[0-9]{12}", s)}
    paired_regions = {}
    for scope in connector.get("scopes") or []:
        if "/" in scope:
            account, region = scope.split("/")
            paired_regions.setdefault(account, []).append(region)

    def regions_for(account):
        if account in paired_regions and account not in plain_accounts:
            return list(dict.fromkeys(paired_regions[account]))
        return discovered_regions.get(account, regions)

    requests = Requests(options)
    requests.progress_callback = progress_callback
    aws_lambda_environment_secret_indicators.initialize(requests, initial_content_options, connector.get('scopes') or [])
    aws_selected_configuration_secret_indicators.initialize(requests, initial_content_options, connector.get('scopes') or [])
    aws_s3_selected_source_secret_indicators.initialize(requests, options, connector.get('scopes') or [])
    aws_ecs_environment_file_secret_indicators.initialize(requests, options, connector.get('scopes') or [])
    aws_workload_referenced_source_indicators.initialize(requests, options, connector.get('scopes') or [])
    aws_build_deployment_referenced_source_indicators.initialize(requests, options, connector.get('scopes') or [])
    codebuild_inline.initialize(requests, codebuild_inline_permitted)
    content_kinds = options.get('_content_secret_scan_kinds', [])
    if isinstance(content_kinds, list) and codebuild_inline_permitted:
        content_kinds = [kind for kind in content_kinds if kind != codebuild_inline.KIND]
    if not isinstance(content_kinds, list) or any(kind not in {
            'codecommit_repository', 'log_group', 'lambda_function', 'lambda_layer_version', 'ecr_repository', 'instance', 'lambda_selected_environment', 'configuration_selected_content', 's3_selected_source_content', 'ecs_selected_environment_file_content', 'workload_referenced_source_content', 'build_deployment_referenced_source_content'
    } for kind in content_kinds):
        raise ValueError('invalid internal content check selection')
    requests.content_secret_scan_kinds = frozenset(content_kinds)
    if codebuild_inline_permitted:
        requests.content_secret_scan_kinds |= {codebuild_inline.KIND}
    requests.ec2_clock_metric_requested = options.get('_ec2_clock_metric_requested', requirements is None)
    if type(requests.ec2_clock_metric_requested) is not bool:
        raise ValueError('invalid internal EC2 clock metric selection')
    for flag in ('ebs_optimization_facts_requested', 'sqs_dead_letter_sources_requested'):
        selected = options.get('_'+flag, requirements is None)
        if type(selected) is not bool:
            raise ValueError('invalid internal metadata fact selection')
        setattr(requests, flag, selected)
    requests.lightsail_iam_policy = lightsail_metadata(lightsail_owner, requests.observed_at)
    requests.environment_boundaries_policy = environment_boundaries_owner
    requests.eks_admission_policy = eks_admission_owner
    requests.controltower_policy = controltower_policy
    requests.data_regions_policy = data_regions_policy
    from .aws_ecr_artifacts_native import normalize as normalize_ecr_artifacts
    requests.ecr_artifacts_policy = normalize_ecr_artifacts(options)
    requests.backup_region_discovery = {}
    from .aws_operational_groups_native import normalize as normalize_operational_groups
    requests.operational_groups_policy = normalize_operational_groups(options)
    from .aws_resolver_firewall_native import normalize as normalize_resolver_firewall
    requests.resolver_firewall_policy = normalize_resolver_firewall(options)
    # Selection is derived by collect_snapshot, not supplied as a resource kind.
    requests.ecr_latest_scan_requested = (requirements is None or options.get("_ecr_latest_scan_requested") is True)
    scope_workers = _bound(options, "scope_concurrency", 2, maximum=8)
    region_workers = _bound(options, "region_concurrency", 2, maximum=8)
    inventories = options.get("inventories", [kind for kind in AWS_TYPES if kind not in (aws_lambda_environment_secret_indicators.KIND, aws_selected_configuration_secret_indicators.KIND, aws_s3_selected_source_secret_indicators.KIND, aws_ecs_environment_file_secret_indicators.KIND, aws_workload_referenced_source_indicators.KIND, aws_build_deployment_referenced_source_indicators.KIND, image_vulnerabilities.KIND, workload_image_secrets.KIND, ecr_public_image.KIND)] if requirements is None else AWS_TYPES)
    if not isinstance(inventories, list) or any(kind not in AWS_TYPES for kind in inventories):
        raise ValueError("inventories must be supported AWS resource types")
    if requirements is not None and (not isinstance(requirements, list) or any(not isinstance(x, str) for x in requirements)):
        raise ValueError("requirements must be a list of resource types")
    wanted = set(inventories) & (set(requirements) if requirements is not None else set(AWS_TYPES))
    if auto_lambda_environment and aws_lambda_environment_secret_indicators.KIND in wanted:
        wanted.remove(aws_lambda_environment_secret_indicators.KIND)
        wanted.add('lambda_function')
    else:
        auto_lambda_environment = False
    if auto_ecs_environment and aws_selected_configuration_secret_indicators.KIND in wanted:
        wanted.remove(aws_selected_configuration_secret_indicators.KIND)
        wanted.update({'ecs_task_definition', 'codebuild_project',
            'batch_job_definition', 'amplify_app', 'glue_job'})
    else:
        auto_ecs_environment = False
    if not image_targets:
        wanted.discard(image_vulnerabilities.KIND)
    if not public_targets:
        wanted.discard(ecr_public_image.KIND)
    if not secret_image_targets:
        wanted.discard(workload_image_secrets.KIND)
    if not codebuild_inline_permitted:
        wanted.discard(codebuild_inline.KIND)
    if workload_command_plan is None:
        wanted.discard(workload_commands.KIND)
    elif workload_commands.KIND not in wanted:
        workload_command_plan = None
    if 'lightsail_iam_policy_attachment' in wanted:
        wanted.add('lightsail_bucket')
    lightsail_iam_only = ('lightsail_iam_policy_attachment' in wanted
                         and wanted <= {'lightsail_bucket', 'lightsail_iam_policy_attachment'})
    requests.sagemaker_clarify_requested = "sagemaker_endpoint" in wanted
    derive_account_vpcs = "vpc_account_inventory" in wanted
    derive_config_account = "config_account_region_coverage" in wanted
    if derive_config_account:
        wanted.update(("config_recorder", "config_delivery_channel"))
    if derive_account_vpcs:
        wanted.add("vpc")
    # Caller identity is mandatory even when no resource inventories are chosen.
    wanted.add("aws_account")
    unsupported = set(requirements or []) - set(AWS_TYPES)
    collections, contexts, identities, auth_errors = [], [], [], []
    metadata = {"collection": "read-only", "selected_scopes": list(connector.get("scopes") or []),
        "regions": regions, "supported_inventories": AWS_TYPES,
        "omitted_inventories": sorted(set(AWS_TYPES) - wanted),
        "service_concurrency": requests.workers, "scope_concurrency": scope_workers,
        "region_concurrency": region_workers, "reachability": "unknown"}
    trusted = options.get("trusted_scope_ids", [])
    if not isinstance(trusted, list) or any(not isinstance(x, str) or not re.fullmatch(r"[0-9]{12}", x) for x in trusted):
        raise ValueError("trusted_scope_ids must be explicit AWS account IDs")
    metadata["trusted_scope_ids"] = list(dict.fromkeys(trusted))
    metadata["usage_evidence"] = {"credential_report": "existing_only",
        "access_keys": "AWS last observed use; missing last use is unknown",
        "roles": "AWS RoleLastUsed observation window; missing last use is unknown",
        "policy_usage": "not_collected", "effective_access": "unknown"}
    total_items = 0

    def append(kind, scope, service, read, account=None, region=None):
        nonlocal total_items
        # Deterministic emission order ensures deterministic resource-limit
        # selection despite concurrent API completion.
        unique = {}
        status, error = read.status, read.error
        for original in read.items:
            if not isinstance(original, dict):
                status, error = ("partial" if unique else "malformed"), {"code": "malformed_resource"}
                break
            if account and kind in {"iam_user", "iam_group", "iam_role", "iam_policy", "iam_credential_report", "access_analyzer"}:
                caller = next((value for value in identities if value.get("Account") == account), {})
                caller_arn = caller.get("Arn", "")
                expected_partition = caller_arn.split(":")[1] if isinstance(caller_arn, str) and caller_arn.startswith("arn:") else None
                field = "arn" if kind in {"iam_credential_report", "access_analyzer"} else "Arn"
                native_arn = original.get(field)
                parts = native_arn.split(":", 5) if isinstance(native_arn, str) else []
                valid = len(parts) == 6 and parts[0] == "arn" and parts[1] == expected_partition
                if kind == "access_analyzer":
                    valid = valid and parts[2] == "access-analyzer" and parts[3] == region and parts[4] == account and parts[5].startswith("analyzer/") and len(parts[5]) > len("analyzer/")
                else:
                    label = kind.removeprefix("iam_")
                    allowed_accounts = {account, "aws"} if kind == "iam_policy" else {account}
                    valid = valid and parts[2] == "iam" and parts[3] == "" and parts[4] in allowed_accounts
                    if kind == "iam_credential_report":
                        valid = valid and (parts[5] == "root" if original.get("user") == "<root_account>" else parts[5].startswith("user/"))
                    else:
                        valid = valid and parts[5].startswith(label + "/") and len(parts[5]) > len(label) + 1
                if not valid:
                    status, error = ("partial" if unique else "malformed"), {"code": "native_identity_scope_mismatch"}
                    break
            item = _safe(original)
            # This reviewed classification is an enum, not an environment
            # variable payload. Keep generic credential redaction unchanged.
            if (kind == 'environment_workload_resource'
                    and type(original.get('Environment')) is str
                    and original['Environment'] in {'production', 'development', 'test'}):
                item['Environment'] = original['Environment']
            if kind == 'organization_tag_policy' and isinstance(original.get('Ec2Tags'), dict):
                # Governance enums are not Lambda environment-variable values.
                # Restore only known environment labels after generic redaction;
                # any other omitted policy metadata makes the policy incomplete.
                environments = {'production', 'prod', 'development', 'dev', 'test', 'testing',
                                'stage', 'staging', 'qa', 'uat', 'sandbox', 'preprod',
                                'preproduction', 'nonprod', 'nonproduction', 'demo', 'shared', 'management'}
                tags = item.setdefault('Ec2Tags', {})
                for key, values in original['Ec2Tags'].items():
                    if key in tags and tags[key] == values:
                        continue
                    if (isinstance(key, str) and key.casefold() == 'environment'
                            and isinstance(values, list)
                            and all(isinstance(value, str) and value.casefold() in environments for value in values)):
                        tags[key] = copy.deepcopy(values)
                    else:
                        item['Complete'] = False
                        item.setdefault('_coverage', {})['Ec2Tags'] = {
                            'status': 'not_collected', 'reason': 'tag_policy_metadata_redacted'}
            singleton = kind in {"iam_account_summary", "iam_password_policy", "s3_account_public_access_block"}
            item.setdefault("id", account if singleton and account else _native_id(kind, item))
            if account:
                item["AccountId"] = account
            if region:
                item["Region"] = region
            rid = _native_id(kind, item)
            if rid in unique:
                continue
            if requests.max_items is not None and total_items >= requests.max_items:
                status, error = ("partial" if unique else "not_collected"), {"code": "resource_limit"}
                break
            unique[rid] = item
            total_items += 1
        envelope = {"type": kind, "scope": scope, "service": service, "status": status, "items": list(unique.values())}
        if account:
            envelope["account_id"] = account
            envelope["global"] = kind in GLOBAL_TYPES
        if kind == "aws_tagged_resource" and status in ("collected", "empty"):
            from .aws_priority_tags_native import SOURCE_KINDS
            envelope["covered_source_kinds"] = list(SOURCE_KINDS)
        if error:
            envelope["error"] = error
        collections.append(envelope)
        from peaso.collection_events import emit_collection
        if not ((auto_lambda_environment and kind == aws_lambda_environment_secret_indicators.KIND)
                or (auto_ecs_environment and kind == aws_selected_configuration_secret_indicators.KIND)):
            emit_collection(collection_callback, envelope)
        emit_progress(progress_callback, phase="collecting", provider="aws", scope=scope, completed=len(collections),
            total=progress_total, resources=total_items, dynamic_total=progress_total is None)

    def failed_scope(scope, failure):
        account = scope.split("/")[0]
        account_regions = regions_for(account)
        for region in [GLOBAL_SCOPE, *account_regions]:
            current_scope = f"{account}/{region}"
            kinds = sorted(GLOBAL_TYPES) if region == GLOBAL_SCOPE else sorted(set(SPECS) - GLOBAL_TYPES)
            for kind in kinds + ([] if region == GLOBAL_SCOPE else sorted(unsupported)):
                if any(c["scope"] == current_scope and c["type"] == kind for c in collections):
                    continue
                append(kind, current_scope, SPECS.get(kind, ("iam" if kind.startswith("iam_") else "aws",))[0],
                    ReadResult([], failure.status if kind in wanted or kind in unsupported else "not_collected",
                        {"code": failure.code if kind in wanted or kind in unsupported else "inventory_not_requested"}),
                    account if region == GLOBAL_SCOPE and re.fullmatch(r"[0-9]{12}", account) else None)

    try:
        session, credential_method = _session(auth, regions[0] if explicit_regions else None)
        if not explicit_regions:
            regions[:] = [session.region_name or "us-east-1"]
        metadata["credential_method"] = credential_method
        chain = auth.get("role_chain", [])
        if not isinstance(chain, list) or len(chain) > 10:
            raise ValueError("role_chain must contain at most 10 role targets")
        hosted = bool(options.get("hosted"))
        hosted_platform = bool(hosted and auth.get("external_id") and not auth.get("aws_access_key_id"))
        if hosted_platform:
            from peaso.server.validation import COLLECTOR_ROLE_ARN, PLATFORM_ACCOUNT_IDS
            # The ECS task identity retains only platform storage access. Customer
            # STS calls must originate from the separate, locally blind broker.
            session = _assume(requests, session, regions[0],
                {"role_arn": COLLECTOR_ROLE_ARN, "role_session_name": "peaso-customer-broker"}, {})
        if auth.get("role_arn") and not hosted_platform:
            chain = chain + [{"role_arn": auth["role_arn"]}]
        for target in chain:
            session = _assume(requests, session, regions[0], target, auth)
        identity = _identity(requests, session, regions[0])
        base_account = identity["Account"]
        if not hosted_platform and options.get("include_source_account", True) and (not selected_accounts or base_account in selected_accounts):
            contexts.append((session, identity))
            identities.append(identity)
        targets = auth.get("assume_roles", [])
        if not isinstance(targets, list):
            raise ValueError("assume_roles must be a list of role targets")
        targets = list(targets)
        if hosted_platform and auth.get("role_arn"):
            targets.append({"role_arn": auth["role_arn"]})
        organization_role = options.get("organization_role_name")
        org_inventory = None
        if organization_role:
            if not isinstance(organization_role, str) or not re.fullmatch(r"[\w+=,.@/-]{1,512}", organization_role):
                raise ValueError("invalid organization_role_name")
            # Hosted discovery is bounded independently of the role scan cap.
            # Local scans paginate fully unless the caller opts into max_pages.
            org_inventory = requests.pages(session, "organizations", regions[0], "list_accounts", "Accounts",
                _page_limit=10 if hosted else None)
            metadata["organization_discovery"] = {"status": org_inventory.status,
                "accounts_seen": len(org_inventory.items), "error": org_inventory.error}
            partition = identity["Arn"].split(":")[1]
            for member in org_inventory.items:
                account = member.get("Id")
                if member.get("State", member.get("Status")) != "ACTIVE" or not re.fullmatch(r"[0-9]{12}", str(account)):
                    continue
                if account != base_account and (not selected_accounts or account in selected_accounts):
                    targets.append({"role_arn": f"arn:{partition}:iam::{account}:role/{organization_role}"})
        seen_targets = set()
        selected_targets = []
        for target in targets:
            target_info = {"role_arn": target} if isinstance(target, str) else target
            if not isinstance(target_info, dict):
                raise ValueError("assume_roles entries must be role ARNs or objects")
            arn = target_info.get("role_arn", "")
            expected = arn.split(":")[4] if isinstance(arn, str) and len(arn.split(":")) > 4 else None
            if selected_accounts and expected not in selected_accounts:
                continue
            if arn in seen_targets:
                continue
            seen_targets.add(arn)
            selected_targets.append((target_info, expected))
        scheduled = selected_targets[:50] if hosted else selected_targets
        omitted = selected_targets[50:] if hosted else []
        metadata["role_target_selection"] = {"requested": len(selected_targets), "scheduled_limit": 50 if hosted else None,
            "scheduled": len(scheduled), "omitted": len(omitted),
            "omitted_role_arns": [target["role_arn"] for target, _ in omitted],
            "status": "partial" if omitted or (org_inventory and org_inventory.status not in {"collected", "empty"}) else "collected"}
        for target_info, expected in omitted:
            auth_errors.append({"account": expected or "unresolved", "role_arn": target_info["role_arn"],
                                "error": {"code": "role_target_limit"}, "status": "not_collected"})
        selected_context_accounts = {identity["Account"] for _, identity in contexts}
        duplicate_targets = []
        for target_info, expected in scheduled:
            if expected in selected_context_accounts:
                skipped = {"account": expected, "role_arn": target_info["role_arn"],
                    "status": "not_collected", "code": "duplicate_account_target"}
                duplicate_targets.append(skipped)
                continue
            try:
                if hosted_platform:
                    if expected in PLATFORM_ACCOUNT_IDS:
                        raise ReadFailure("denied", "platform_owned_account")
                    _reject_unprotected_hosted_role(requests, session, regions[0], target_info, auth)
                role_session = _assume(requests, session, regions[0], target_info, auth)
                role_identity = _identity(requests, role_session, regions[0], expected)
                if hosted_platform and role_identity["Account"] in PLATFORM_ACCOUNT_IDS:
                    raise ReadFailure("denied", "platform_owned_account")
                contexts.append((role_session, role_identity))
                identities.append(role_identity)
                selected_context_accounts.add(role_identity["Account"])
            except Exception as exc:
                failure = _failure(exc)
                auth_errors.append({"account": expected or "unresolved", "role_arn": target_info["role_arn"],
                                    "error": {"code": failure.code}, "status": failure.status})
        metadata["role_target_selection"]["duplicate_account_targets"] = duplicate_targets
        if duplicate_targets:
            metadata["role_target_selection"]["status"] = "partial"
            metadata["scan_coverage"] = [{"level": "credential_target", "scope": row["account"],
                "account": row["account"], "role_arn": row["role_arn"],
                "status": row["status"], "code": row["code"], "error_code": row["code"]} for row in duplicate_targets]
        resolved = {x[1]["Account"] for x in contexts}
        for account in selected_accounts:
            if account not in resolved:
                error = next((x for x in auth_errors if x["account"] == account), None)
                failed_scope(f"{account}/{regions[0]}", ReadFailure(error["status"] if error else "not_collected", error["error"]["code"] if error else "account_role_not_configured"))
        for error in auth_errors:
            if not selected_accounts and error["account"] not in resolved:
                failed_scope(f"{error['account']}/{regions[0]}", ReadFailure(error["status"], error["error"]["code"]))
    except Exception as exc:
        failure = _failure(exc)
        emit_progress(progress_callback, phase="error", provider="aws", scope="", completed=len(collections),
            total=None, resources=total_items, dynamic_total=True)
        contexts = []
        for account in selected_accounts or ["unresolved"]:
            failed_scope(f"{account}/{regions[0]}", failure)
        org_inventory = None

    if not explicit_regions:
        metadata["region_discovery"] = []
        for account_session, identity in contexts:
            account = identity["Account"]
            read = requests.pages(account_session, "ec2", regions[0], "describe_regions", "Regions", AllRegions=True)
            requests.backup_region_discovery[account] = copy.deepcopy(read)
            partition = account_session.get_partition_for_region(regions[0])
            caller_arn = identity.get("Arn", "")
            caller = re.fullmatch(r"arn:([^:]+):(iam|sts)::([0-9]{12}):.+", caller_arn) if isinstance(caller_arn, str) else None
            raw_regions = copy.deepcopy(read.items)
            seen_regions, enabled = set(), []
            valid = read.status == "collected" and isinstance(raw_regions, list) and bool(raw_regions)
            valid = valid and caller is not None and caller.group(1) == partition and caller.group(3) == account
            if valid:
                for row in raw_regions:
                    name = row.get("RegionName") if isinstance(row, dict) else None
                    state = row.get("OptInStatus") if isinstance(row, dict) else None
                    if (not isinstance(name, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", name)
                            or name in seen_regions or state not in {"opt-in-not-required", "opted-in", "not-opted-in"}
                            or account_session.get_partition_for_region(name) != partition):
                        valid = False
                        break
                    seen_regions.add(name)
                    if state != "not-opted-in":
                        enabled.append(name)
            enabled = sorted(enabled) if valid else []
            proof = {"account_id": account, "caller_account_id": account, "scope": account + "/global",
                "partition": partition, "source_operation": "ec2:DescribeRegions", "all_regions": True,
                "read_only": True, "observed_at": requests.observed_at.isoformat(), "raw_regions": raw_regions}
            if not valid or not enabled:
                failure = ReadFailure(read.status if read.status not in {"collected", "empty"} else "malformed", (read.error or {}).get("code", "enabled_region_discovery_unavailable"))
                region_discovery_errors[account] = failure
                metadata["region_discovery"].append({**proof, "status": failure.status, "error": {"code": failure.code}})
            else:
                discovered_regions[account] = enabled
                metadata["region_discovery"].append({**proof, "status": "collected", "regions": enabled})
        if discovered_regions:
            regions[:] = sorted({region for values in discovered_regions.values() for region in values})
        metadata["regions"] = list(regions)
    # Freeze exact account/region pairs only after target resolution and region
    # discovery have succeeded for the entire selection. An observed subset,
    # fallback region, truncated organization roster or failed role is not a
    # discovery-completion proof. This is a private in-process signal, never a
    # connector option, progress event or credential-bearing identity payload.
    target_roster_complete = org_inventory is None or (
        org_inventory.status in {'collected', 'empty'}
        and all(isinstance(row, dict) and re.fullmatch(r'[0-9]{12}', str(row.get('Id', '')))
                and row.get('State', row.get('Status')) in {
                    'ACTIVE', 'PENDING_ACTIVATION', 'SUSPENDED', 'PENDING_CLOSURE', 'CLOSED'}
                for row in org_inventory.items)
        and len({row['Id'] for row in org_inventory.items}) == len(org_inventory.items))
    identities_bound = all(re.fullmatch(
        rf"arn:[^:]+:(?:iam|sts)::{identity['Account']}:.+", identity.get('Arn', ''))
        for _, identity in contexts)
    if (contexts and target_roster_complete and identities_bound
            and not auth_errors and not region_discovery_errors
            and metadata.get('role_target_selection', {}).get('status') == 'collected'
            and set(selected_accounts) <= {identity['Account'] for _, identity in contexts}):
        from peaso.collection_events import emit_scope_plan
        emit_scope_plan(tuple(sorted({f"{identity['Account']}/{region}"
            for _, identity in contexts for region in regions_for(identity['Account'])})))
    workload_command_capture = workload_commands.collect_selected(workload_command_plan, contexts, requests)
    from peaso.ai.access import aws as capture_ai_access
    capture_ai_access(contexts)
    requests.audited_regions_by_account = {identity["Account"]: list(regions_for(identity["Account"])) for _, identity in contexts}
    progress_total = len(collections) + sum(len(GLOBAL_TYPES) + len(regions_for(identity["Account"])) * (len(set(SPECS) - GLOBAL_TYPES) + len(unsupported)) for context, identity in contexts)
    emit_progress(progress_callback, phase="collecting", provider="aws", scope="", completed=len(collections),
        total=progress_total, resources=total_items, dynamic_total=False)

    def global_job(session, identity, kind):
        from peaso.runtime_metrics import span as _runtime_span
        with _runtime_span("collection.job"):
            account = identity["Account"]
            region = regions_for(account)[0]
            if kind in FETCHERS:
                return regional_job(session, identity, region, kind)
            if kind == "aws_account":
                return ReadResult([identity])
            if kind == "aws_account_configuration":
                return _account_configuration(requests, session, region, identity)
            if kind == "config_delegated_administrator":
                read = requests.pages(session, "organizations", region, "list_delegated_administrators", "DelegatedAdministrators", ServicePrincipal="config.amazonaws.com")
                read.items = [{"Id": original["Id"]} for original in read.items]
                return read
            if kind == "config_account_aggregator_inventory":
                if account in region_discovery_errors:
                    failure = region_discovery_errors[account]
                    return ReadResult([], failure.status, {"code": failure.code, "reason": "full_account_region_discovery_incomplete"})
                if explicit_regions:
                    return ReadResult([], "not_collected", {"code": "full_account_region_coverage_not_proven"})
                items, failure = [], None
                for observed_region in regions_for(account):
                    read = regional_job(session, identity, observed_region, "config_aggregator")
                    items.extend({**original, "SourceRegion": observed_region} for original in read.items)
                    if read.status not in {"collected", "empty"}:
                        failure = ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "account_aggregator_inventory_incomplete"))
                if failure:
                    return ReadResult(items, "partial" if items else failure.status, {"code": failure.code, "cause_status": failure.status})
                return ReadResult(items, "collected" if items else "empty")
            if kind == "cloudtrail_account_inventory":
                if account in region_discovery_errors:
                    failure = region_discovery_errors[account]
                    return ReadResult([], failure.status, {"code": failure.code, "reason": "full_account_region_discovery_incomplete"})
                if explicit_regions:
                    return ReadResult([], "not_collected", {"code": "full_account_region_coverage_not_proven"})
                observations, malformed, failure = {}, [], None
                for observed_region in regions_for(account):
                    read = regional_job(session, identity, observed_region, "cloudtrail")
                    for original in read.items:
                        if not isinstance(original, dict) or not isinstance(original.get("TrailARN"), str) or not original["TrailARN"]:
                            failure = ReadFailure("malformed", "malformed_account_trail")
                            malformed.append({"SourceRegion": observed_region, "NativeObservation": original})
                            continue
                        item = {**original, "SourceRegion": observed_region}
                        observations.setdefault(item["TrailARN"], []).append(item)
                    if read.status not in {"collected", "empty"}:
                        failure = ReadFailure((read.error or {}).get("cause_status", read.status), (read.error or {}).get("code", "account_trail_inventory_incomplete"))
                trails = []
                for arn, copies in observations.items():
                    # Keep every native observation; a dict overwrite would erase a
                    # second home row before the signed uniqueness gate sees it.
                    homes = [row for row in copies if row.get("SourceRegion") == row.get("HomeRegion")]
                    selected = homes[0] if homes else copies[0]
                    identity_fields = ("TrailARN", "Name", "HomeRegion", "IsOrganizationTrail", "IsMultiRegionTrail")
                    consistent = all(all(row.get(field) == selected.get(field) for field in identity_fields) for row in copies)
                    arn_parts = re.fullmatch(r"arn:aws(?:-[a-z0-9-]+)?:cloudtrail:([a-z0-9-]+):([0-9]{12}):trail/[^/]+", arn)
                    home = selected.get("HomeRegion")
                    if (len(homes) != 1 or not consistent or arn_parts is None or
                            arn_parts.group(1) != home or not isinstance(selected.get("Name"), str) or not selected["Name"] or
                            (arn_parts.group(2) != account and selected.get("IsOrganizationTrail") is not True)):
                        failure = ReadFailure("malformed", "ambiguous_account_trail")
                    selected = {**selected, "_account_trail_observations": copies}
                    # identity comes only from this session's GetCallerIdentity;
                    # a declared AccountId on a trail is not an account binding.
                    selected["_account_trail_binding"] = {
                        "caller_account_id": account, "identity_operation": "sts:GetCallerIdentity",
                        "describe_operation": "cloudtrail:DescribeTrails", "include_shadow_trails": True,
                        "trail_arn": arn, "capture_observed_at": requests.observed_at.isoformat(),
                    }
                    trails.append(selected)
                # Reuse the strict native, read-only IAM simulation. Its rows are
                # bound to a single home-region trail, role, and log group; an
                # incomplete regional read never supplies permission evidence.
                permission_rows = {}
                for home_region in ({row.get("HomeRegion") for row in trails
                                    if row.get("SourceRegion") == row.get("HomeRegion") and
                                    row.get("Status", {}).get("IsLogging") is True and
                                    row.get("IsOrganizationTrail") is False and type(row.get("IsMultiRegionTrail")) is bool and
                                    row.get("CloudWatchLogsRoleArn") and row.get("CloudWatchLogsLogGroupArn")}
                                    if "cloudtrail_delivery_role_scope" in wanted else set()):
                    if not isinstance(home_region, str):
                        continue
                    read = regional_job(session, identity, home_region, "cloudtrail_delivery_role_scope")
                    permission_rows[home_region] = read
                for trail in trails:
                    read = permission_rows.get(trail.get("HomeRegion"))
                    if read is not None and read.status not in {"collected", "empty"}:
                        trail.setdefault("_coverage", {})["CloudWatchLogsRole"] = {
                            "status": read.status, "code": (read.error or {}).get("code", "delivery_role_scope_incomplete")}
                    rows = read.items if read is not None and read.status in {"collected", "empty"} else []
                    matches = [row for row in rows if row.get("_provenance", {}).get("trail_arn") == trail.get("TrailARN") and
                               row.get("role_arn") == trail.get("CloudWatchLogsRoleArn") and
                               row.get("log_group_arn") == trail.get("CloudWatchLogsLogGroupArn")]
                    if len(matches) == 1:
                        trail["CloudWatchLogsRole"] = matches[0]
                trails.extend(malformed)
                if failure:
                    return ReadResult(trails, "partial" if trails else failure.status, {"code": failure.code, "cause_status": failure.status})
                return ReadResult(trails, "collected" if trails else "empty")
            if kind == "macie2_account_classification_job_inventory":
                if account in region_discovery_errors:
                    failure = region_discovery_errors[account]
                    return ReadResult([], failure.status, {"code": failure.code, "reason": "full_account_region_discovery_incomplete"})
                if explicit_regions:
                    return ReadResult([], "not_collected", {"code": "full_account_region_coverage_not_proven"})
                # Every enabled Region gets a row carrying its own read status, so a
                # failed Region leaves only buckets homed there unknown.
                rows = []
                for observed_region in regions_for(account):
                    # Same single-flight cached reads as the regional inventory.
                    read = regional_job(session, identity, observed_region, "macie2_classification_job")
                    state = (read.error or {}).get("code") if read.status == "empty" else None
                    jobs = {"collection_status": read.status, "items": read.items}
                    if read.error:
                        jobs["error"] = {"code": (read.error or {}).get("code")}
                    rows.append({"id": f"macie-jobs/{account}/{observed_region}", "SourceRegion": observed_region,
                        "ServiceState": state if state in SERVICE_STATE_CODES else "available" if read.status in {"collected", "empty"} else "unavailable",
                        "Jobs": jobs})
                return ReadResult(rows, "collected" if rows else "empty")
            if kind == "metric_alarm_account_inventory":
                # Every enabled Region gets a row with its own metric filter, alarm and
                # subscription read status (aws_facts_gap.metric_alarm_rows).
                if account in region_discovery_errors:
                    failure = region_discovery_errors[account]
                    return ReadResult([], failure.status, {"code": failure.code, "reason": "full_account_region_discovery_incomplete"})
                if explicit_regions:
                    return ReadResult([], "not_collected", {"code": "full_account_region_coverage_not_proven"})
                from .aws_facts_gap import metric_alarm_rows
                return metric_alarm_rows(regional_job, session, identity, regions_for(account))
            if kind == "bucket":
                return _buckets(requests, session, region)
            if kind == "iam_customer_policy":
                from .aws_customer_policies import collect as collect_customer_policies
                return collect_customer_policies(requests, session, region, account)
            if kind == "iam_managed_policy":
                from .aws_all_policies import collect as collect_all_policies
                return collect_all_policies(requests, session, region, account)
            if kind in {"iam_user", "iam_group", "iam_role", "iam_policy"}:
                return _iam(requests, session, region, {kind})[kind]
            if kind == "iam_account_summary":
                return _single(requests, session, region, "iam", "get_account_summary")
            if kind == "iam_password_policy":
                return _single(requests, session, region, "iam", "get_account_password_policy", absent=("NoSuchEntity",))
            if kind == "iam_credential_report":
                return _credentials_report(requests, session, region)
            if kind == "iam_access_key":
                return _access_keys(requests, session, region)
            if kind == "s3_account_public_access_block":
                return _single(requests, session, region, "s3control", "get_public_access_block", AccountId=account, absent=("NoSuchPublicAccessBlockConfiguration",))
            if kind == "organization_account":
                if org_inventory is not None and account == base_account:
                    return org_inventory
                return requests.pages(session, "organizations", region, "list_accounts", "Accounts")
            if kind == "organization_parent":
                if "organization_account" in wanted:
                    from .aws_organization_ou_native import collect as collect_organization_ou
                    return collect_organization_ou(requests, session, region, account,
                        account_inventory=org_inventory if account == base_account else None)
                return _organization_parents(requests, session, region, account)
            if kind == "scp_policy":
                return _scp_policies(requests, session, region, account)
            if kind in SPECS:
                # Global extension specs share the exact same native read/enrich
                # dispatcher as regional specs, rather than falling through.
                return regional_job(session, identity, region, kind)
            return ReadResult([], "not_collected", {"code": "unsupported_inventory"})

    def regional_job(session, identity, region, kind):
        from peaso.runtime_metrics import span as _runtime_span
        with _runtime_span("collection.job"):
            if kind == ecr_public_image.KIND:
                return ecr_public_image.collect_scope(requests, session, identity, region, public_targets, secret=public_secret, vuln=public_vuln)
            if kind == image_vulnerabilities.KIND:
                return image_vulnerabilities.collect_scope(requests, session, identity, region, image_targets)
            if kind == workload_image_secrets.KIND:
                return workload_image_secrets.collect_collection(requests, session, identity, region, secret_image_targets)
            if kind == "access_analyzer":
                return analyzer_lifecycle.collect(session, identity, region, ENRICHERS[kind])
            if kind == 'lightsail_bucket' and lightsail_iam_only:
                from .aws_lightsail_iam_native import bucket_metadata
                return bucket_metadata(requests, session, region, identity['Account'])
            from peaso.aws_service_lifecycle import retired_collection_error
            retired = retired_collection_error(kind, requests.observed_at)
            if retired is not None:
                # A full-shutdown service has no current resource inventory. Keep
                # the exact kind and reason in the snapshot without calling its SDK.
                return ReadResult([], "empty", retired)
            if kind == "ec2_regional_settings":
                read = _ec2_regional_settings(requests, session, region)
            elif kind == "aws_cloudtrail_activity":
                read = _cloudtrail_activity(requests, session, region)
            elif kind in {"aws_identity_center_user", "aws_identity_center_permission_set"}:
                read = _identity_center(requests, session, region, kind)
            elif kind == "gameliftstreams_stream_session":
                read = _gameliftstreams_shell_sessions(
                    requests, session, region, identity["Account"], identity["Arn"].split(":")[1])
            elif kind == aws_lambda_environment_secret_indicators.KIND:
                read = aws_lambda_environment_secret_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == aws_selected_configuration_secret_indicators.KIND:
                read = aws_selected_configuration_secret_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == aws_s3_selected_source_secret_indicators.KIND:
                read = aws_s3_selected_source_secret_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == aws_ecs_environment_file_secret_indicators.KIND:
                read = aws_ecs_environment_file_secret_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == aws_workload_referenced_source_indicators.KIND:
                read = aws_workload_referenced_source_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == aws_build_deployment_referenced_source_indicators.KIND:
                read = aws_build_deployment_referenced_source_indicators.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind == codebuild_inline.KIND:
                read = codebuild_inline.collect_selected(requests, session, region, identity, options, connector.get('scopes') or [])
            elif kind in FETCHERS:
                read = FETCHERS[kind](requests, session, region, identity["Account"])
                if not isinstance(read, ReadResult):
                    return ReadResult([], "malformed", {"code": "malformed_extension_result"})
            else:
                service, operation, expression = SPECS[kind]
                args = {"Owners": ["self"], "IncludeDeprecated": True, "IncludeDisabled": True} if kind == "ec2_image" else {"OwnerIds": ["self"]} if kind == "ebs_snapshot" else {"includeShadowTrails": True} if kind == "cloudtrail" else {"MaxResults": 1000} if kind == "sqs_queue" else {}
                read = _single(requests, session, region, service, operation, **args) if expression is None else requests.pages(session, service, region, operation, expression, **args)
            try:
                if kind == "transit_gateway_route_table":
                    for item in read.items:
                        table_id = item.get("TransitGatewayRouteTableId")
                        if not isinstance(table_id, str) or not table_id:
                            continue
                        routes = [requests.pages(session, "ec2", region, "search_transit_gateway_routes", "Routes",
                            TransitGatewayRouteTableId=table_id,
                            Filters=[{"Name": "type", "Values": [route_type]}])
                            for route_type in ("static", "propagated")]
                        route_items = [route for result in routes for route in result.items]
                        complete = all(result.status in {"collected", "empty"} for result in routes)
                        item["RouteInventory"] = {"collection_status": ("collected" if route_items else "empty") if complete else "partial",
                            "items": route_items, "queries": ["type=static", "type=propagated"],
                            **({"error": {"code": "transit_gateway_routes_incomplete",
                                "sources": [result.error for result in routes if result.error]}} if not complete else {})}
                        associations = requests.pages(session, "ec2", region, "get_transit_gateway_route_table_associations",
                            "Associations", TransitGatewayRouteTableId=table_id)
                        item["AssociationInventory"] = {"collection_status": associations.status,
                            "items": associations.items,
                            **({"error": associations.error} if associations.error else {})}
                read.items = _enrich(requests, session, region, kind, read.items, account=identity["Account"], partition=identity["Arn"].split(":")[1])
                if kind == "cloudtrail":
                    for item in read.items:
                        item["_provenance"] = {"operation": "cloudtrail:DescribeTrails", "native_response_complete": True}
                        _documented_omission(item, "CloudWatchLogsLogGroupArn", "", "cloudtrail:DescribeTrails")
                        _documented_omission(item, "CloudWatchLogsRoleArn", "", "cloudtrail:DescribeTrails")
                        _documented_omission(item, "S3KeyPrefix", "", "cloudtrail:DescribeTrails")
                if kind == "instance":
                    for item in read.items:
                        item["_provenance"] = {"operation": "ec2:DescribeInstances", "native_response_complete": True}
                if kind == "config_aggregator":
                    for item in read.items:
                        item["_provenance"] = {"operation": "config:DescribeConfigurationAggregators", "native_response_complete": True}
                if kind == "log_group":
                    for item in read.items:
                        item["_provenance"] = {"operation": "logs:DescribeLogGroups", "native_response_complete": True}
                if kind == "elasticache_replication_group" and read.status == "collected" and not read.error:
                    # DescribeReplicationGroups returns an unprojected ReplicationGroups
                    # record. Its documented omitted SnapshotRetentionLimit default is
                    # meaningful only when every page was read successfully.
                    for item in read.items:
                        if not isinstance(item, dict) or item.get("collection_status") not in (None, "collected"):
                            continue
                        coverage = item.get("_coverage", {})
                        if not isinstance(coverage, dict) or any(not isinstance(value, dict) or value.get("status") not in ("collected", "empty") for value in coverage.values()):
                            continue
                        provenance = item.get("_provenance", {})
                        if not isinstance(provenance, dict) or provenance.get("operation") not in (None, "elasticache:DescribeReplicationGroups"):
                            continue
                        item["_provenance"] = {**provenance, "operation": "elasticache:DescribeReplicationGroups", "native_response_complete": True}
                if kind in ENRICHERS:
                    read.items = ENRICHERS[kind](requests, session, region, read.items)
                    if read.items and read.status not in {"collected", "partial"}:
                        # Independent setting reads can add rows to an unavailable
                        # parent inventory. They never prove parent completeness.
                        # Preserve the failure and per-row coverage as partial data;
                        # the strict snapshot invariant remains unchanged.
                        cause = read.status
                        read.status = "partial"
                        read.error = {**(read.error or {}),
                                      "code": (read.error or {}).get("code", "incomplete_parent_inventory"),
                                      "cause_status": cause}
                from .aws_workload_detail_identity import bind_workload_details
                read.items = bind_workload_details(kind, read.items, identity["Account"], region, identity["Arn"].split(":")[1])
                if kind == "cloudfront_distribution":
                    prefix = "arn:" + identity["Arn"].split(":")[1] + ":cloudfront::" + identity["Account"] + ":distribution/"
                    if any(not isinstance(item.get("Id"), str) or not item["Id"]
                            or item.get("ARN") != prefix + item["Id"] for item in read.items):
                        return ReadResult([], "malformed", {"code": "cloudfront_distribution_identity_mismatch"})
                if kind == "lambda_function":
                    for item in read.items:
                        configuration = item.get("Configuration", {})
                        if isinstance(configuration, dict) and configuration.get("collection_status") == "collected":
                            for field, empty_value in (("DeadLetterConfig", {}), ("VpcConfig", {"VpcId": ""})):
                                if field not in item:
                                    if field in configuration:
                                        item[field] = copy.deepcopy(configuration[field])
                                    else:
                                        _documented_omission(item, field, empty_value, "lambda:GetFunctionConfiguration")
                            vpc = item.get("VpcConfig")
                            if isinstance(vpc, dict) and "VpcId" not in vpc:
                                _documented_omission(vpc, "VpcId", "", "lambda:GetFunctionConfiguration")
                            from .aws_lambda_omission_native import normalize_documented_omissions
                            normalize_documented_omissions(item)
            except Exception as exc:
                failure = _failure(exc)
                # Retain original valid dictionary evidence, mark incomplete detail.
                read.items = [x for x in read.items if isinstance(x, dict)]
                read.status = "partial" if read.items else failure.status
                read.error = {"code": failure.code}
            return read

    iam_kinds = {"iam_user", "iam_group", "iam_role", "iam_policy"}
    # CloudTrail LookupEvents is rate limited per account and Region (2 TPS,
    # enforced in Requests.call), so each Region's activity read runs on its
    # own thread instead of occupying a shared service worker for minutes.
    activity_workers = _bound(options, "activity_concurrency", min(32, max(1, len(regions) * min(scope_workers, max(1, len(contexts))))), maximum=32)
    metadata["activity_concurrency"] = activity_workers
    content_kinds = ({ecr_public_image.KIND, image_vulnerabilities.KIND,
        workload_image_secrets.KIND, aws_lambda_environment_secret_indicators.KIND,
        aws_selected_configuration_secret_indicators.KIND,
        aws_s3_selected_source_secret_indicators.KIND,
        aws_ecs_environment_file_secret_indicators.KIND,
        aws_workload_referenced_source_indicators.KIND,
        aws_build_deployment_referenced_source_indicators.KIND, codebuild_inline.KIND}
        | (set(requests.content_secret_scan_kinds) if requests.content_secret_scans else set())) & wanted
    # Long selected-content reads can otherwise occupy every service worker
    # before ordinary inventory reaches the FIFO executor queue. Reserve a
    # bounded part of the same service budget for ordinary reads. A global
    # call cap retains the original single-queue admission order.
    content_workers = (min(4, max(1, requests.workers // 3))
        if content_kinds and requests.workers > 1 and requests.max_calls is None else 0)
    ordinary_workers = requests.workers - content_workers
    from .aws_access_analyzer_lifecycle import AnalyzerLifecycle
    from .aws_image_capture_20261022 import capture_scope
    from .aws_iam_usage_extension import register_context, start_account_usage, join_account_usage
    usage_overlap = "access_analyzer" in wanted and bool({"iam_user", "iam_role"} & wanted)
    if usage_overlap:
        # Set ACTION_LEVEL before IAM workers can issue their first report;
        # account contexts also authorize bounded early finalization jobs.
        for session, identity in contexts:
            if identity["Account"] not in region_discovery_errors:
                register_context(requests, session, identity, regions_for(identity["Account"]))
    metadata["access_analyzer_lifecycle"] = []
    if "access_analyzer" in wanted:
        metadata["collection"] = "read-only-with-temporary-access-analyzers"
    analyzer_lifecycle = AnalyzerLifecycle(requests, metadata["access_analyzer_lifecycle"], progress_callback)
    # A global call cap assigns budget by admission order. Keep the original
    # analyzer-first admission in that explicitly limited mode.
    defer_analyzer_preparation = requests.max_calls is None
    with capture_scope(requests), analyzer_lifecycle, ThreadPoolExecutor(max_workers=ordinary_workers, thread_name_prefix="aws-read") as pool, \
            ThreadPoolExecutor(max_workers=max(1, content_workers), thread_name_prefix="aws-content") as content_pool, \
            ThreadPoolExecutor(max_workers=activity_workers, thread_name_prefix="aws-activity") as activity_pool:
        for offset in range(0, len(contexts), scope_workers):
            scope_batch = contexts[offset:offset + scope_workers]
            jobs, activity_jobs = [], {}
            for session, identity in scope_batch:
                if not defer_analyzer_preparation and "access_analyzer" in wanted and identity["Account"] not in region_discovery_errors:
                    analyzer_lifecycle.prepare(session, identity, regions_for(identity["Account"]))
                # Activity reads start first: they are the longest rate-limited chains.
                if "aws_cloudtrail_activity" in wanted and identity["Account"] not in region_discovery_errors:
                    for region in regions_for(identity["Account"]):
                        activity_jobs[(id(identity), region)] = activity_pool.submit(regional_job, session, identity, region, "aws_cloudtrail_activity")
                # The four IAM projections share one GetAccountAuthorizationDetails
                # pagination; one job reads them instead of four blocked workers.
                selected_iam = sorted(iam_kinds & wanted)
                iam_future = pool.submit(_iam, requests, session, regions_for(identity["Account"])[0], set(selected_iam)) if selected_iam else None
                if iam_future is not None and usage_overlap:
                    def start_usage(done, session=session, identity=identity):
                        if done.cancelled():
                            return
                        try:
                            seed = done.result()
                        except Exception:
                            return  # Native IAM collection retains its own failure.
                        start_account_usage(requests, session, identity,
                            regions_for(identity["Account"])[0], seed)
                    usage_context = copy_context()
                    iam_future.add_done_callback(lambda done, callback=start_usage, context=usage_context:
                        context.run(callback, done))
                for kind in sorted(GLOBAL_TYPES - {"vpc_account_inventory", "config_account_region_coverage"}):
                    if kind in wanted:
                        if kind in iam_kinds:
                            future = Future()
                            def project(done, future=future, kind=kind):
                                try:
                                    future.set_result(done.result()[kind])
                                except Exception as exc:
                                    future.set_exception(exc)
                            iam_future.add_done_callback(project)
                        else:
                            lane = content_pool if content_workers and kind in content_kinds else pool
                            future = lane.submit(global_job, session, identity, kind)
                        jobs.append((kind, identity, regions_for(identity["Account"])[0], session, future))
            # Regional jobs are queued behind the global ones without a per-Region
            # barrier; emission below stays in the same deterministic order.
            regional_jobs, deferred_analyzers = [], []
            for session, identity in scope_batch:
                for region in regions:
                    if region not in regions_for(identity["Account"]):
                        continue
                    for kind in sorted(set(SPECS) - GLOBAL_TYPES - {"vpc_account_inventory"}):
                        if kind in wanted:
                            if identity["Account"] in region_discovery_errors:
                                failure = region_discovery_errors[identity["Account"]]
                                future = Future()
                                future.set_result(ReadResult([], failure.status, {"code": failure.code, "reason": "default_region_discovery_incomplete"}))
                            elif kind == "aws_cloudtrail_activity":
                                future = activity_jobs[(id(identity), region)]
                            elif kind == "access_analyzer" and defer_analyzer_preparation:
                                # Preparation can make slow SDK calls in every
                                # Region. Queue ordinary reads first so they
                                # progress while analyzers are prepared.
                                deferred_analyzers.append((len(regional_jobs), session, identity, region))
                                future = None
                            else:
                                lane = content_pool if content_workers and kind in content_kinds else pool
                                future = lane.submit(regional_job, session, identity, region, kind)
                            regional_jobs.append((kind, identity, region, session, future))
            if deferred_analyzers:
                for session, identity in scope_batch:
                    if identity["Account"] not in region_discovery_errors:
                        analyzer_lifecycle.prepare(session, identity, regions_for(identity["Account"]))
                        for index, job_session, job_identity, region in deferred_analyzers:
                            if job_identity is identity:
                                regional_jobs[index] = ("access_analyzer", identity, region, job_session,
                                    pool.submit(regional_job, job_session, identity, region, "access_analyzer"))
            from peaso.collection_events import completed_reads
            ordered_regional_jobs = [row for region_offset in range(0, len(regions), region_workers)
                for _, identity in scope_batch
                for region in regions[region_offset:region_offset + region_workers]
                for row in regional_jobs if row[1] is identity and row[2] == region]
            # A slow content read must not hide already completed IAM/network
            # evidence. Explicit cross-inventory caps retain deterministic order.
            for kind, identity, region, job_session, future in completed_reads(
                    jobs + ordered_regional_jobs, preserve_order=requests.max_items is not None):
                try:
                    read = future.result()
                    if not isinstance(read, ReadResult):
                        raise ReadFailure("malformed", "malformed_extension_result")
                    if kind in GLOBAL_TYPES and kind in ENRICHERS and kind not in SPECS and kind not in FETCHERS and read.items:
                        read.items = ENRICHERS[kind](requests, job_session, region, read.items)
                except Exception as exc:
                    failure = _failure(exc)
                    read = ReadResult([], failure.status, {"code": failure.code})
                if kind in GLOBAL_TYPES:
                    append(kind, f"{identity['Account']}/{GLOBAL_SCOPE}", SPECS[kind][0] if kind in SPECS else "sts" if kind == "aws_account" else "s3" if kind == "bucket" else "organizations" if kind in {"organization_account", "organization_parent", "scp_policy"} else "s3control" if kind == "s3_account_public_access_block" else "iam", read, identity["Account"])
                else:
                    append(kind, f"{identity['Account']}/{region}", SPECS[kind][0], read, identity["Account"], region)
            for session, identity in scope_batch:
                if derive_config_account:
                    from .aws_config_account_native import derive as derive_config_account_proof
                    rows, status, error = derive_config_account_proof(identity["Account"], identity,
                        metadata.get("region_discovery", []), collections, requests.observed_at.isoformat())
                    append("config_account_region_coverage", f"{identity['Account']}/{GLOBAL_SCOPE}", "config",
                        ReadResult(rows, status, error), identity["Account"])
                if derive_account_vpcs:
                    from .aws_inventory import vpc_account_inventory
                    items, status, error = vpc_account_inventory(collections, identity["Account"], regions_for(identity["Account"]),
                        full_region_coverage=not explicit_regions and identity["Account"] not in region_discovery_errors)
                    append("vpc_account_inventory", f"{identity['Account']}/{GLOBAL_SCOPE}", "ec2", ReadResult(items, status, error), identity["Account"])
                for kind in sorted(GLOBAL_TYPES - wanted):
                    append(kind, f"{identity['Account']}/{GLOBAL_SCOPE}", SPECS.get(kind, ("aws",))[0], ReadResult([], "not_collected", {"code": "inventory_not_requested"}), identity["Account"])
                for region in regions_for(identity["Account"]):
                    for kind in sorted((set(SPECS) - GLOBAL_TYPES - wanted - {"vpc_account_inventory"}) | unsupported):
                        append(kind, f"{identity['Account']}/{region}", SPECS.get(kind, ("aws",))[0], ReadResult([], "not_collected", {"code": "unsupported_inventory" if kind in unsupported else "inventory_not_requested"}))
        if auto_lambda_environment or auto_ecs_environment:
            from . import workload_environment_discovery as environment_discovery
            automatic = {}
            automatic_batches = {}
            automatic_configuration_redactions = {}
            automatic_configuration_overflow = False
            for active, producer, make_plan, option, kind, service in (
                (auto_lambda_environment, aws_lambda_environment_secret_indicators,
                 environment_discovery.aws_lambda, aws_lambda_environment_secret_indicators.OPTION,
                 aws_lambda_environment_secret_indicators.KIND, 'lambda'),
                (auto_ecs_environment, aws_selected_configuration_secret_indicators,
                 environment_discovery.aws_configuration, aws_selected_configuration_secret_indicators.OPTION,
                 aws_selected_configuration_secret_indicators.KIND, 'ecs')):
                if not active:
                    continue
                source_scopes = sorted({identity['Account'] + '/' + region
                    for _, identity in contexts for region in regions_for(identity['Account'])})
                plan = make_plan(collections, expected_scopes=source_scopes)
                automatic[kind] = {'discovered': plan.discovered, 'planned': len(plan.targets),
                                   'complete': plan.complete, 'reason': plan.reason}
                content_complete = True
                automatic_batches[kind] = []
                by_scope = {}
                for target in plan.targets:
                    scope = (producer.parse(target)[3] + '/' + producer.parse(target)[2]
                             if isinstance(target, str) else target['scope'])
                    by_scope.setdefault(scope, []).append(target)
                for session, identity in contexts:
                    account = identity.get('Account')
                    for region in regions_for(account):
                        scope = account + '/' + region
                        for batch in environment_discovery.batches(by_scope.get(scope, ()), producer.MAX_TARGETS):
                            planned_options = {**options, option: list(batch)}
                            producer.initialize(requests, planned_options, [scope])
                            requests.automatic_workload_environment_active = True
                            requests.automatic_workload_environment_issues = {}
                            try:
                                read = producer.collect_selected(requests, session, region, identity,
                                    planned_options, [scope])
                                batch_issues = dict(requests.automatic_workload_environment_issues)
                            finally:
                                requests.automatic_workload_environment_active = False
                                requests.automatic_workload_environment_issues = {}
                            batch_metadata = dict(getattr(requests,
                                'lambda_environment_metadata' if isinstance(batch[0], str)
                                else 'configuration_content_metadata'))
                            if not read.items or read.status not in ('collected', 'empty') or any(
                                    not row.get(producer.MARKER, {}).get('complete') for row in read.items):
                                content_complete = False
                            append(kind, scope, service, read, account, region)
                            collection = collections[-1]
                            batch_id = kind + ':' + str(len(automatic_batches[kind]) + 1)
                            collection['automatic_batch'] = batch_id
                            automatic_batches[kind].append({'id': batch_id, 'scope': scope,
                                'metadata': batch_metadata, 'issues': batch_issues})
                            if (collection['status'] not in ('collected', 'empty')
                                    or len(collection['items']) != len(read.items)):
                                content_complete = False
                            if not isinstance(batch[0], str):
                                for length, fingerprints in requests.configuration_content_redactions.items():
                                    automatic_configuration_redactions.setdefault(length, set()).update(fingerprints)
                                automatic_configuration_overflow |= requests.configuration_content_redaction_overflow
                if not plan.targets:
                    for scope in sorted({c['scope'] for c in collections if c['type'] in
                            ({'lambda_function'} if kind == aws_lambda_environment_secret_indicators.KIND
                             else {'ecs_task_definition'})}):
                        append(kind, scope, service, ReadResult([], 'empty' if plan.complete else 'unknown',
                            None if plan.complete else {'code': plan.reason}))
                environment_discovery.fold_collections(collections, kind, automatic_batches[kind])
                automatic[kind]['complete'] = plan.complete and content_complete
                automatic[kind]['inspected'] = sum(len(c['items']) for c in collections if c['type'] == kind)
                automatic[kind]['uninspected'] = max(0, plan.discovered - automatic[kind]['inspected'])
                issues = {ident: issue for record in automatic_batches[kind]
                    for ident, issue in record['issues'].items()}
                automatic[kind]['targets'] = environment_discovery.target_coverage(
                    plan.targets, producer.identity, collections, kind, producer.MARKER, issues)
                if not content_complete and plan.complete:
                    automatic[kind]['reason'] = 'automatic_content_incomplete'
            metadata['automatic_workload_environment_coverage'] = automatic
            metadata['automatic_workload_environment_batches'] = automatic_batches
            if automatic_configuration_redactions:
                requests.configuration_content_redactions = automatic_configuration_redactions
                if sum(len(values) for values in automatic_configuration_redactions.values()) > aws_selected_configuration_secret_indicators.MAX_REDACTION_DESCRIPTORS:
                    automatic_configuration_overflow = True
            requests.configuration_content_redaction_overflow |= automatic_configuration_overflow
    if usage_overlap:
        join_account_usage(collections)
    collections.sort(key=lambda c: (c["scope"], c["type"]))
    from peaso.collectors.aws_lambda_role_usage import summarize_lambda_role_usage
    metadata["lambda_execution_role_usage"] = summarize_lambda_role_usage(
        collections, identities, metadata.get("region_discovery"), explicit_regions=explicit_regions)
    metadata.update(requests.lambda_environment_metadata)
    metadata.update(requests.configuration_content_metadata)
    metadata.update(requests.ecs_envfile_metadata)
    metadata.update(requests.workload_source_metadata)
    metadata.update(requests.build_deployment_metadata)
    metadata.update({"calls": requests.calls, "cache_hits": requests.cache_hits,
        "max_calls": requests.max_calls, "max_pages": requests.max_pages,
        "max_resources": requests.max_items, "resource_count": total_items,
        "credential_resolution_calls": "sdk_managed_not_counted",
        "intentional_limits": {key: options[key] for key in ("max_calls", "max_pages", "max_resources", "deadline_seconds") if options.get(key) is not None},
        "authorized_evidence_generation": {"iam_credential_report": requests.iam_credential_report_generation_requested, "generation_requests": requests.evidence_generations,
            "iam_service_last_accessed_report": requests.iam_service_access_reports_requested, "service_last_accessed_generation_requests": requests.service_last_accessed_generations},
        "activity_collection": {"projection": "actor_arn_type_event_name_time_id_only", "minutes": requests.activity_minutes,
            "window_end": requests.observed_at.isoformat(), "declared_event_names": sorted({name for values in ACTIVITY_ACTIONS.values() for name in values}),
            "global_service_event_names": {"names": sorted(IAM_ONLY_ACTIVITY_NAMES), "queried_only_in": IAM_EVENT_REGION,
                "reason": "IAM-only API events are recorded by CloudTrail in us-east-1 for the aws partition"},
            "lookup_attempts": requests.activity_lookup_calls, "maximum_requests_per_second_per_region": 2,
            "limit": "CloudTrail LookupEvents management event history, no claim of data-event coverage"},
        "caller_identities": identities, "authentication_errors": auth_errors,
        "network_relationships": network_relationships(collections)})
    report_collected = any(c["type"] == "iam_credential_report" and c["status"] in {"collected", "partial"} for c in collections)
    metadata["usage_evidence"]["credential_report"] = ("authorized_generation_then_read" if report_collected else "authorized_generation_attempted_unavailable") if requests.evidence_generations else "existing_report_read" if report_collected else "report_unavailable_or_not_requested"
    # <account>/global holds account-wide envelopes; it is not a regional evaluation scope
    # (the engine joins it into every regional scope of the same account).
    scopes = sorted({c["scope"] for c in collections if not c["scope"].endswith("/" + GLOBAL_SCOPE)} or {c["scope"] for c in collections})
    emit_progress(progress_callback, phase="completed", provider="aws", scope="", completed=len(collections),
        total=len(collections), resources=total_items, dynamic_total=False)
    if backup_policy is not None:
        metadata["compliance_policy"] = {"aws_backup_plan": bind_backup_plan_policy(backup_policy, scopes)}
    if cost_policy is not None:
        metadata.setdefault('compliance_policy', {})['cost_anomaly_alerts'] = cost_policy
    if inventory_readers is not None:
        metadata["compliance_inputs"] = {"approved_inventory_reader_arns": inventory_readers}
    from .aws_ecr_artifacts_native import owner_metadata as ecr_owner_metadata
    metadata.update(ecr_owner_metadata(requests.ecr_artifacts_policy))
    from .aws_region_data_native import owner_metadata as data_region_owner_metadata
    region_metadata = data_region_owner_metadata(data_regions_policy, scopes)
    metadata.setdefault("parameters", {}).update(region_metadata.pop("parameters", {}))
    metadata.update(region_metadata)
    merge_lightsail(metadata, requests.lightsail_iam_policy)
    from .aws_environment_boundaries_native import owner_metadata as environment_boundaries_metadata
    metadata.setdefault('parameters', {}).update(environment_boundaries_metadata(environment_boundaries_owner, requests.observed_at))
    if eks_admission_owner is not None:
        metadata.setdefault('compliance_policy', {})['eks_image_integrity'] = eks_admission_owner
    codebuild_inline.retain_union(requests)
    collections, metadata = aws_selected_configuration_secret_indicators.finalize(requests, collections, metadata)
    collections, metadata = aws_s3_selected_source_secret_indicators.finalize(requests, collections, metadata)
    collections, metadata = codebuild_inline.finalize(requests, collections, metadata, options)
    collections, metadata = workload_commands.publish(workload_command_capture, workload_command_plan, collections, metadata, options)
    image_vulnerabilities.attach_metadata(metadata, collections, image_targets)
    workload_image_secrets.attach_metadata(metadata, secret_image_targets)
    ecr_public_image.attach_metadata(metadata, public_targets, public_secret, public_vuln)
    return make_snapshot("aws", scopes, collections, created_at=requests.observed_at.isoformat(), metadata=_safe(metadata))


# Trusted in-repository read-only extension modules, loaded in this order. Each
# may add new kinds (SPECS/FETCHERS/NATIVE_IDS/GLOBAL_TYPES), declare read-only
# detail operations (READ_ACTIONS) and add ENRICHERS. Enrichers for the same
# kind from several modules are chained (never replaced), so independent
# fact owners can extend one existing inventory.
EXTENSION_MODULES = ("peaso.collectors.aws_b_services", "peaso.collectors.aws_privesc_facts",
    "peaso.collectors.aws_facts_compute_edge", "peaso.collectors.aws_facts_data_identity", "peaso.collectors.aws_facts_cb_ca",
    "peaso.collectors.aws_facts_gap", "peaso.collectors.aws_facts_swc", "peaso.collectors.aws_facts_ext",
    "peaso.collectors.aws_facts_v4_holds", "peaso.collectors.aws_bulk_inventory", "peaso.collectors.aws_operational_groups_native", "peaso.collectors.aws_macie_coverage_native", "peaso.collectors.aws_budget_stop_native", "peaso.collectors.aws_ecr_artifacts_native", "peaso.collectors.aws_resolver_firewall_native", "peaso.collectors.aws_sagemaker_clarify_native", "peaso.collectors.aws_codecommit_review_native", "peaso.collectors.aws_cloudtrail_delivery_native", "peaso.collectors.aws_controltower_native", "peaso.collectors.aws_region_data_native", "peaso.collectors.aws_lightsail_iam_native", "peaso.collectors.aws_eks_admission_native", "peaso.collectors.aws_resource_tag_compliance_native", "peaso.collectors.aws_effective_tag_policy_native", "peaso.collectors.aws_bedrock_reasoning_native", "peaso.collectors.aws_fms_rule_metadata_native", "peaso.collectors.aws_wave_semantics_native")


def _chain(first, second):
    def enrich(requests, session, region, items):
        return second(requests, session, region, first(requests, session, region, items))
    return enrich


def _explicit_content_enricher(kind, function):
    def enrich(requests, session, region, items):
        selected = getattr(requests, 'content_secret_scan_kinds', None)
        if selected is not None and kind not in selected:
            return items
        return function(requests, session, region, items)
    return enrich


def _load_metadata_extension(name="peaso.collectors.aws_b_services"):
    """Trusted in-repository read-only specs, sharing the scan request context."""
    from importlib import import_module
    try:
        extension = import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        return
    specs = getattr(extension, "SPECS", {})
    for kind, spec in specs.items():
        if not isinstance(kind, str) or not isinstance(spec, tuple) or len(spec) != 3:
            raise ValueError("invalid AWS extension service specification")
        if kind in SPECS and SPECS[kind] != spec:
            raise ValueError("AWS extension cannot replace existing service specification: " + kind)
    actions = set(getattr(extension, "READ_ACTIONS", set()))
    for service, operation in actions | {(s, o) for s, o, expression in specs.values()}:
        content_log = name == 'peaso.collectors.aws_code_log_content_indicators' and (service, operation) == ('logs', 'filter_log_events')
        if (operation in _PROHIBITED_VALUE_OPERATIONS and not content_log) or (not operation.startswith(("get_", "list_", "describe_", "batch_get_", "batch_describe_")) and (service, operation) not in {("cloudtrail", "lookup_events"), ("iam", "simulate_principal_policy"), ("braket", "search_devices")} and not content_log):
            raise ValueError("AWS extension includes a prohibited operation")
    fetchers = getattr(extension, "FETCHERS", {})
    for kind in fetchers:
        if kind in FETCHERS and FETCHERS[kind] is not fetchers[kind]:
            raise ValueError("AWS extension cannot replace an existing fetcher: " + kind)
    SPECS.update(specs)
    READ_ACTIONS.update(actions)
    READ_ACTIONS.update((s, o) for s, o, expression in specs.values())
    _NATIVE_IDS.update(getattr(extension, "NATIVE_IDS", {}))
    GLOBAL_TYPES.update(getattr(extension, "GLOBAL_TYPES", set()))
    FETCHERS.update(fetchers)
    for kind, enricher in getattr(extension, "ENRICHERS", {}).items():
        if name in {'peaso.collectors.aws_code_log_content_indicators', 'peaso.collectors.aws_package_content_indicators'}:
            enricher = _explicit_content_enricher(kind, enricher)
        from .aws_request_pool import item_wise
        enricher = item_wise(name, enricher)
        ENRICHERS[kind] = _chain(ENRICHERS[kind], enricher) if kind in ENRICHERS else enricher
    AWS_TYPES[:] = sorted(set(SPECS) | GLOBAL_TYPES)


EXTENSION_MODULES += ("peaso.collectors.aws_bedrock_security_metadata",
                      "peaso.collectors.aws_s3_object_acl_review_20261019",
                      "peaso.collectors.aws_configuration_payload_secret_indicators",
                      "peaso.collectors.aws_code_log_content_indicators",
                      "peaso.collectors.aws_package_content_indicators",
                      "peaso.collectors.aws_lambda_environment_secret_indicators",
                      "peaso.collectors.aws_selected_configuration_secret_indicators",
                      "peaso.collectors.aws_launch_template_instance_metadata",
                      "peaso.collectors.aws_ec2_clock_metadata",
                      "peaso.collectors.aws_cloudtrail_s3_delivery_metadata",
                      "peaso.collectors.aws_alb_waf_association_metadata",
                      "peaso.collectors.aws_beanstalk_runtime_metadata",
                      "peaso.collectors.aws_network_service_metadata",
                      "peaso.collectors.aws_network_catalog")

EXTENSION_MODULES += ("peaso.collectors.aws_ai_recheck_facts_20261020",)

EXTENSION_MODULES += ("peaso.collectors.aws_network_inventory",)
for _extension in EXTENSION_MODULES:
    _load_metadata_extension(_extension)

_load_metadata_extension("peaso.collectors.unused_iam_aws_completion")

# Explicit selected S3 source profile; never a generic listing/read fallback.
SPECS['s3_selected_source_content'] = ('s3', 'head_object', None)
SPECS['ecs_selected_environment_file_content'] = ('ecs', 'describe_task_definition', None)
SPECS['workload_referenced_source_content'] = ('glue', 'get_job', None)
SPECS['build_deployment_referenced_source_content'] = ('codebuild', 'batch_get_projects', None)
_NATIVE_IDS['workload_referenced_source_content'] = 'id'
_NATIVE_IDS['build_deployment_referenced_source_content'] = 'id'
_NATIVE_IDS['ecs_selected_environment_file_content'] = 'id'
READ_ACTIONS.update({('s3', 'head_object'), ('s3', 'get_object')})
AWS_TYPES[:] = sorted(set(SPECS) | GLOBAL_TYPES)

# Default-off inline buildspec runtime; generic inventory dispatch is forbidden.
SPECS['codebuild_selected_inline_buildspec'] = ('codebuild', 'batch_get_projects', None)
_NATIVE_IDS['codebuild_selected_inline_buildspec'] = 'id'
AWS_TYPES[:] = sorted(set(SPECS) | GLOBAL_TYPES)
AWS_TYPES.append('aws_selected_workload_command_literals')

# Explicit immutable image CVE kind, excluded from default inventory reads.
SPECS['ecr_selected_image_vulnerabilities'] = ('ecr', 'batch_get_image', None)
_NATIVE_IDS['ecr_selected_image_vulnerabilities'] = 'id'
AWS_TYPES.append('ecr_selected_image_vulnerabilities')

# Named, selected workload image secret reads; no repository inventory or S3 grant.
SPECS['aws_selected_workload_image_secrets'] = ('ecr', 'batch_get_image', None)
_NATIVE_IDS['aws_selected_workload_image_secrets'] = 'id'
AWS_TYPES.append('aws_selected_workload_image_secrets')

SPECS['ecr_public_selected_image_content'] = ('ecr-public', 'describe_images', None)
_NATIVE_IDS['ecr_public_selected_image_content'] = 'id'
AWS_TYPES.append('ecr_public_selected_image_content')
READ_ACTIONS.update({('ecr-public','describe_registries'), ('ecr-public','describe_repositories'), ('ecr-public','describe_images')})

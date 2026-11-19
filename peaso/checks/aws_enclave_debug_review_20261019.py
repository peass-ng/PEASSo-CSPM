"""Observed debug-mode measurements, with no customer golden-image baseline."""
from datetime import datetime, timezone
import re

from .facts import Unavailable, get

CHECK_ID = "aws.review.kms.enclave_debug_measurements"
SOURCE = "https://github.com/prowler-cloud/prowler/blob/1783527c1147f584f30b60f2d7ccc8a53b4a63b7/prowler/providers/aws/services/kms/kms_key_enclave_debug_attestation_detected/kms_key_enclave_debug_attestation_detected.py"


def _time(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except (ValueError, AttributeError, TypeError):
        raise Unavailable("attestation event time is unavailable") from None


def evaluate(item, index):
    try:
        scope = get(index, "context.scope", str)
        if (get(index, "context.provider", str) != "aws" or
                scope != get(item, "AccountId", str) + "/" + get(item, "Region", str)):
            raise Unavailable("attestation event belongs to a different account or Region")
        if get(item, "EventSource", str) != "kms.amazonaws.com" or not get(item, "IsEnclaveAttestation", bool):
            raise Unavailable("event is not an observed KMS enclave attestation")
        event_id = get(item, "EventId", str)
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", event_id):
            raise Unavailable("attestation event identifier is malformed")
        proof = get(item, "_provenance", dict)
        if get(proof, "source_operation", str) != "cloudtrail:LookupEvents":
            raise Unavailable("attestation source is not bound to the native event lookup")
        when = _time(get(item, "EventTime", str))
        start, end = _time(get(proof, "window_start", str)), _time(get(proof, "window_end", str))
        if not start <= when <= end:
            raise Unavailable("attestation event lies outside its observed window")
        pcrs = get(item, "AttestationPcrs", dict)
        values = [get(pcrs, "PCR" + str(n), str) for n in range(3)]
        if any(not re.fullmatch(r"[0-9a-fA-F]{96}", value) for value in values):
            raise Unavailable("attestation image, kernel or application measurement is malformed")
        debug = all(value == "0" * 96 for value in values)
        return ("FAIL" if debug else "PASS"), {
            "observed": ("CloudTrail event " + event_id + " records " +
                         ("zeroed PCR0, PCR1 and PCR2, indicating enclave debug mode." if debug else
                          "enclave measurements that are not all zero.")),
            "event_id": event_id, "event_time": get(item, "EventTime", str),
            "window_start": get(proof, "window_start", str), "window_end": get(proof, "window_end", str),
            "debug_measurements": debug}
    except Unavailable as error:
        return "UNKNOWN", {"reason": str(error)}


def evaluate_empty_inventory(context, collection):
    proof = collection.get("error", {})
    if proof.get("code") != "no_current_enclave_enabled_instances":
        return None
    scope = context.get("scope")
    if (context.get("provider") != "aws" or not isinstance(scope, str)
            or not re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+", scope)
            or collection.get("scope") != scope
            or proof.get("scope") != scope or proof.get("complete") is not True
            or proof.get("source_operation") != "ec2:DescribeInstances"
            or proof.get("instance_ids") != [] or collection.get("status") != "empty"
            or collection.get("items") != [] or collection.get("type") != "cloudtrail_event"):
        return "UNKNOWN", {"reason":"Enclave applicability discovery is incomplete or unbound."}
    _time(proof.get("observed_at"))
    return "NOT_APPLICABLE", {
        "observed":"No current enclave-enabled EC2 instances were discovered in this account and Region; enclave history collection was skipped.",
        "source_operation":"ec2:DescribeInstances", "scope":scope,
        "history_collected":False,
        "boundary":"Current local EC2 configuration only; historical and cross-account enclave use is not excluded."}


evaluate.evaluate_empty_inventory = evaluate_empty_inventory


def fixture(debug):
    value = "0" * 96 if debug else "ab" * 48
    item = {"AccountId": "123456789012", "Region": "us-east-1", "EventSource": "kms.amazonaws.com",
            "EventId": "11111111-1111-1111-1111-111111111111", "EventTime": "2026-10-19T10:05:00Z",
            "IsEnclaveAttestation": True, "AttestationPcrs": {"PCR" + str(n): value for n in range(3)},
            "_provenance": {"source_operation": "cloudtrail:LookupEvents", "window_start": "2026-10-19T10:00:00Z",
                            "window_end": "2026-10-19T11:00:00Z"}}
    return item, {"context": {"provider": "aws", "scope": "123456789012/us-east-1"}}


_good, _good_index = fixture(False)
_bad, _bad_index = fixture(True)
RUNTIME_CASES = {CHECK_ID: {"pass": _good, "pass_index": _good_index, "fail": _bad,
                           "fail_index": _bad_index, "missing": {}, "malformed": None}}


def admission(source_sha256):
    description = ("Checks PCR0, PCR1 and PCR2 recorded in each KMS enclave CloudTrail event for zeroed debug-mode measurements. "
                   "It evaluates observed events only; it does not approve images or certify unobserved history.")
    spec = {"id": CHECK_ID, "provider": "aws", "resource_kind": "cloudtrail_event",
            "data_source": "cloudtrail:LookupEvents projected enclave AttestationPcrs and native account, Region, event and window provenance",
            "predicate": "FAIL when an observed bound event has all-zero PCR0/1/2; PASS when all three are valid and not all zero; UNKNOWN on missing or unbound evidence. No event means no resource verdict.",
            "severity": "high", "category": "hardening", "title": "Observed enclave attestations avoid debug-mode measurements",
            "description": description, "remediation_hint": "Run production enclaves without debug mode and restrict KMS policy attestation conditions."}
    return {"spec": spec, "description": {"description": description,
            "evaluated": ["AttestationPcrs.PCR0/PCR1/PCR2", "EventId", "AccountId", "Region", "_provenance.window_start/window_end"],
            "pass_when": "The observed event has three valid measurements that are not all zero.",
            "fail_when": "PCR0, PCR1 and PCR2 are all zero in the observed attestation.",
            "not_applicable_when": "No observed enclave event produces no resource finding."},
            "sources": [{"url": SOURCE, "sha256": source_sha256}], "requirements": [],
            "function": "peaso.checks.aws_enclave_debug_review_20261019:evaluate"}


ADMISSION_DATA = {"schema_version": 1, "checks": [admission("e802b7fbf8ec85404b951b5742766b7e446e26ec22aaa0b9243111defa73d471")]}

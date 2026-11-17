"""Separate analyzer inventory presence and active-state regional predicates.

Only customer analyzers count. A temporary ``peaso-scan-*`` analyzer that the
scan created (because none existed) never satisfies either predicate; its
presence proves the Region had no usable analyzer, so the Region fails.
"""
from . import register, result, unknown
from .facts import Unavailable, get
from .fixtures import CASES
from .aws_a_facts import scope_subject, scope_fixture
from .aws_access_analyzer_scope import inventory


def customer_analyzers(item, index):
    customer, temporary, complete = inventory(index, scope_subject(item))
    if not complete:
        raise Unavailable("incomplete inventory: access_analyzer")
    return customer, temporary

NATIVE_IDS = []
SUBJECT = {"scope": "123456789012/us-east-1"}


@register("aws.a.accessanalyzer.region_present", "aws", "hardening", "access_analyzer", "Enabled AWS region has a declared IAM Access Analyzer",
    "medium", "AC-6", "Review analyzer configuration and its separate active state.", target="scope", dependencies=["access_analyzer"],
    allow_incomplete_failure=True)
def presence(item, index):
    rows, temporary = customer_analyzers(item, index)
    for row in rows:
        get(row, "arn", str)
    return result(not bool(rows), analyzer_count=len(rows), scan_temporary_analyzers=len(temporary),
        semantics="Exact source declared-inventory presence of customer analyzers; a scan-created temporary analyzer never counts")
CASES["aws.a.accessanalyzer.region_present"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("access_analyzer", [{"arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/inert"}]), "fail_index": scope_fixture("access_analyzer", [])}
NATIVE_IDS.append("aws.a.accessanalyzer.region_present")


@register("aws.a.accessanalyzer.region_active", "aws", "hardening", "access_analyzer", "All declared regional Access Analyzers are active",
    "medium", "AC-6", "Review absent or inactive analyzers without creating a service or resource during collection.", target="scope", dependencies=["access_analyzer"],
    allow_incomplete_failure=True)
def active(item, index):
    rows, _ = customer_analyzers(item, index)
    statuses = [get(row, "status", str) for row in rows]
    if any(state not in {"ACTIVE", "CREATING", "DISABLED", "FAILED"} for state in statuses):
        return unknown("unrecognized Access Analyzer native status")
    return result(not statuses or any(state != "ACTIVE" for state in statuses), analyzer_statuses=statuses,
        semantics="Aggregate of source per-analyzer outcomes; complete empty region is source synthetic absence FAIL")
CASES["aws.a.accessanalyzer.region_active"] = {"pass": SUBJECT, "fail": SUBJECT, "missing": {}, "malformed": None,
    "index": scope_fixture("access_analyzer", [{"status": "ACTIVE"}]), "fail_index": scope_fixture("access_analyzer", [])}
NATIVE_IDS.append("aws.a.accessanalyzer.region_active")

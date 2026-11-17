"""Which ECS task-definition revisions configuration-hardening checks evaluate.

ListTaskDefinitions returns every ACTIVE revision, and long-lived families keep
thousands of them. Reporting a container setting once per historic revision is
noise: what runs is the revision a service or task references, and what will
run next is the family's latest revision. Configuration checks therefore judge
those revisions and mark other historic revisions NOT_APPLICABLE.

Secret/credential checks are deliberately excluded: a historic ACTIVE revision
still exposes its environment to ecs:DescribeTaskDefinition, so a secret there
remains a real finding.

The selection is applied only when the scope's task-definition, service and
task inventories are complete; otherwise every revision is evaluated as before.
"""
from __future__ import annotations

import re
from dataclasses import replace
from functools import wraps

from .facts import MemoIndex, memoized

CONFIGURATION_CHECKS = frozenset({
    "aws.b.ecs.no_privileged_containers", "aws.b.ecs.some_logging_configuration", "aws.b.ecs.no_host_pid",
    "aws.b.ecs.all_readonly_roots", "aws.b.ecs.declared_nonroot_users", "aws.b.ecs.host_network_nonprivileged",
    "aws.c2b.ecs.host_network_root_user", "aws.c2b.ecs.all_containers_logging", "aws.c2b.ecs.logging_non_blocking",
    "aws.htbp.ecs.no_sensitive_host_mounts", "aws_g6_ecs_all_containers_logging",
})
USAGE_KINDS = (("ecs_service", "taskDefinition", True), ("ecs_task", "taskDefinitionArn", True),
               ("ecs_task_set", "taskDefinition", False))
_ARN = re.compile(r"arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:task-definition/([A-Za-z0-9_-]+):([1-9][0-9]*)")
_COMPLETE = ("collected", "empty")


def _rows(index, kind):
    return [row.get("data", row) for row in index.get(kind, []) if isinstance(row, dict)]


def _complete(index, kind):
    envelopes = (index.get("collections") or {}).get(kind) or []
    return bool(envelopes) and all(isinstance(e, dict) and e.get("status") in _COMPLETE for e in envelopes)


def _selection(index):
    """Return (latest revision per family, referenced ARNs), or None when unprovable."""
    if not _complete(index, "ecs_task_definition") or not all(
            _complete(index, kind) for kind, _, required in USAGE_KINDS if required):
        return None
    latest = {}
    for row in _rows(index, "ecs_task_definition"):
        match = _ARN.fullmatch(str(row.get("taskDefinitionArn", "")))
        if match is None:
            return None
        family, revision = match.group(1), int(match.group(2))
        latest[family] = max(latest.get(family, 0), revision)
    referenced = set()
    for kind, field, _ in USAGE_KINDS:
        for row in _rows(index, kind):
            value = row.get(field)
            if isinstance(value, str) and value:
                referenced.add(value)
    return latest, frozenset(referenced)


def historic_revision(item, index):
    """Evidence when ``item`` is an unreferenced, superseded revision; else None."""
    match = _ARN.fullmatch(str(item.get("taskDefinitionArn", ""))) if isinstance(item, dict) else None
    if match is None or not isinstance(index, dict):
        return None
    selection = (memoized(index, ("aws_ecs_revision_selection",), lambda: _selection(index))
                 if type(index) is MemoIndex else _selection(index))
    if selection is None:
        return None
    latest, referenced = selection
    family, revision = match.group(1), int(match.group(2))
    if item["taskDefinitionArn"] in referenced or revision >= latest.get(family, revision):
        return None
    return {"reason": "Historic task-definition revision: no service or running task uses it and the family has a newer revision.",
            "task_definition_family": family, "revision": revision, "latest_revision": latest[family],
            "evaluated_revisions": "latest revision per family plus revisions referenced by services, task sets or running tasks"}


def install():
    from . import CHECKS
    for position, check in enumerate(CHECKS):
        if check.id not in CONFIGURATION_CHECKS or check.provider != "aws" or check.kind != "ecs_task_definition":
            continue
        original = check.evaluate

        def wrap(original):
            @wraps(original)
            def evaluate(item, index):
                historic = historic_revision(item, index)
                return ("NOT_APPLICABLE", historic) if historic else original(item, index)
            return evaluate
        dependencies = tuple(dict.fromkeys([*check.dependencies, *(kind for kind, _, _ in USAGE_KINDS)]))
        CHECKS[position] = replace(check, evaluate=wrap(original), declared_dependencies=dependencies)

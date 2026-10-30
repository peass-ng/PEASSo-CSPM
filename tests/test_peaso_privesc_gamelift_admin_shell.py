"""A live GameLift Streams session reaches only its recorded role and parent group."""

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import sys
import types

import pytest

from peaso.privesc import versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from scripts.peaso_deploy_customer_policy import build_policy, policy_size
from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, reached, real, role, role_arn, user,
)


TECHNIQUE = "aws-gameliftstreams-createstreamsessionadminshell"
PRECONDITION = "gameliftstreams_live_role_session_admin_shell"
GROUP = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:streamgroup/sg-123"
OTHER_GROUP = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:streamgroup/sg-other"
SESSION = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:streamsession/sg-123/ss-123"
TARGET = role_arn("GameLiftStreams-target")


@dataclass
class ReadResult:
    items: list
    status: str = "collected"
    error: dict | None = None


def collector_function():
    # The collector package installs unrelated signed check adapters at import.
    # Compile this exact source function so a focused test can exercise its reads.
    source = Path(__file__).resolve().parents[1] / "peaso/collectors/aws.py"
    tree = ast.parse(source.read_text())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name == "_gameliftstreams_shell_sessions"]
    assert len(nodes) == 1
    namespace = {"ReadResult": ReadResult,
                 "_GAMELIFT_SHELL_STATES": ("ACTIVE", "CONNECTED", "PENDING_CLIENT_RECONNECTION", "RECONNECTING")}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace[nodes[0].name]


def test_collector_keeps_exact_live_session_without_user_data():
    calls = []

    class Requests:
        def pages(self, _session, service, region, operation, key, **kwargs):
            calls.append((service, region, operation, key, kwargs))
            if operation == "list_stream_groups":
                return ReadResult([{"Arn": GROUP, "Status": "ACTIVE"}])
            if kwargs["Status"] == "ACTIVE":
                return ReadResult([{"Arn": SESSION, "Status": "ACTIVE", "RoleArn": TARGET,
                                    "UserId": "private-user"}])
            return ReadResult([], "empty")

    read = collector_function()(Requests(), object(), REGION, ACCOUNT, "aws")
    assert read.status == "collected"
    assert read.items == [{"Arn": SESSION, "Status": "ACTIVE", "RoleArn": TARGET,
                           "StreamGroupArn": GROUP, "StreamGroupStatus": "ACTIVE"}]
    assert len(calls) == 5


def test_collector_rejects_conflicting_session_metadata_and_marks_partial():
    class Requests:
        def pages(self, _session, _service, _region, operation, _key, **kwargs):
            if operation == "list_stream_groups":
                return ReadResult([{"Arn": GROUP, "Status": "ACTIVE"}])
            if kwargs["Status"] in ("ACTIVE", "CONNECTED"):
                return ReadResult([{"Arn": SESSION, "Status": kwargs["Status"], "RoleArn": TARGET}])
            return ReadResult([], "empty")

    read = collector_function()(Requests(), object(), REGION, ACCOUNT, "aws")
    assert read.status == "partial" and read.items == []


def test_collector_keeps_denied_session_list_unknown():
    class Requests:
        def pages(self, _session, _service, _region, operation, _key, **kwargs):
            if operation == "list_stream_groups":
                return ReadResult([{"Arn": GROUP, "Status": "ACTIVE"}])
            if kwargs["Status"] == "ACTIVE":
                return ReadResult([], "access_denied", {"code": "AccessDeniedException"})
            return ReadResult([], "empty")

    read = collector_function()(Requests(), object(), REGION, ACCOUNT, "aws")
    assert read.status == "partial" and read.items == []


def test_collector_marks_missing_group_status_partial():
    class Requests:
        def pages(self, _session, _service, _region, operation, _key, **kwargs):
            if operation == "list_stream_groups":
                return ReadResult([{"Arn": GROUP}])
            if kwargs["Status"] == "ACTIVE":
                return ReadResult([{"Arn": SESSION, "Status": "ACTIVE", "RoleArn": TARGET}])
            return ReadResult([], "empty")

    read = collector_function()(Requests(), object(), REGION, ACCOUNT, "aws")
    assert read.status == "partial"
    assert read.items[0]["StreamGroupStatus"] == ""


def route(*, grant=GROUP, status="ACTIVE", group=GROUP, session=SESSION, role_name="GameLiftStreams-target",
          group_status="ACTIVE", inventory_status="collected"):
    row = {"Arn": session, "Status": status, "RoleArn": role_arn(role_name),
           "StreamGroupArn": group, "StreamGroupStatus": group_status}
    snap = aws_snap([user("alice", allow("gameliftstreams:CreateStreamSessionAdminShell", resource=grant))],
                    [role("GameLiftStreams-target", "gameliftstreams.amazonaws.com")],
                    [col("gameliftstreams_stream_session", [row] if inventory_status == "collected" else [],
                         inventory_status)])
    model = AwsModel(snap)
    return model.precondition(PRECONDITION, {TARGET: model.principals[TARGET]}, model.principals[ALICE])


def test_catalog_route_accepts_a_grant_scoped_to_the_exact_stream_group(monkeypatch):
    # Principal-exposure annotations are outside this route's permission proof.
    exposure = types.ModuleType("peaso.principal_exposure")
    exposure.annotate_privesc = lambda snapshot, graph, findings, model, inventory=None: None
    monkeypatch.setitem(sys.modules, exposure.__name__, exposure)
    row = {"Arn": SESSION, "Status": "ACTIVE", "RoleArn": TARGET,
           "StreamGroupArn": GROUP, "StreamGroupStatus": "ACTIVE"}
    for grant, expected in ((GROUP, {TARGET: "conditional"}), (OTHER_GROUP, {})):
        snap = aws_snap([user("alice", allow("gameliftstreams:CreateStreamSessionAdminShell", resource=grant))],
                        [role("GameLiftStreams-target", "gameliftstreams.amazonaws.com")],
                        [col("gameliftstreams_stream_session", [row])])
        assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE) == expected


def test_exact_live_session_and_scoped_grant_reach_its_recorded_role():
    assert route() == {TARGET: ("conditional", "gameliftstreams_live_role_session_shell")}


@pytest.mark.parametrize("change", (
    {"grant": OTHER_GROUP}, {"status": "TERMINATED"}, {"group": OTHER_GROUP},
    {"group_status": "ERROR"}, {"group_status": "ACTIVE_WITH_ERRORS"}, {"group_status": None},
    {"session": SESSION.replace("sg-123", "sg-other")}, {"role_name": "GameLiftStreams-other"},
))
def test_wrong_group_session_state_or_role_cannot_reach_target(change):
    assert TARGET not in {target for target, verdict in route(**change).items()
                          if verdict[0] == "conditional"}


def test_missing_session_inventory_is_not_a_confirmed_route():
    assert route(inventory_status="access_denied")[TARGET][0] == "unknown"


def test_passrole_without_controlled_application_is_unresolved(monkeypatch):
    exposure = types.ModuleType("peaso.principal_exposure")
    exposure.annotate_privesc = lambda snapshot, graph, findings, model, inventory=None: None
    monkeypatch.setitem(sys.modules, exposure.__name__, exposure)
    technique = "aws-gameliftstreams-passrole-startstreamsession"
    snap = aws_snap([user("alice", allow("gameliftstreams:StartStreamSession"),
                          allow("iam:PassRole", resource=TARGET))],
                    [role("GameLiftStreams-target", "gameliftstreams.amazonaws.com")])
    result = real(snap, technique, include_unknown=True)
    assert reached(result, ALICE, technique) == {}
    assert_unresolved(result, ALICE, technique)


def test_current_and_previous_catalog_bindings_keep_their_exact_meanings():
    current, status = versioned_catalog.lookup_entries([TECHNIQUE], versioned_catalog.current_binding())
    assert status == "exact_strict_privesc" and set(current) == {TECHNIQUE}
    assert "ACTIVE" in current[TECHNIQUE]["conditions"][0]["description"]
    group_previous = {"schema": versioned_catalog.BINDING_SCHEMA,
                      "manifest_sha256": versioned_catalog.GAMELIFT_GROUP_682_PREVIOUS_MANIFEST,
                      "effective_tree_sha256": versioned_catalog.GAMELIFT_GROUP_682_PREVIOUS_TREE,
                      "source_revision": versioned_catalog.V4_REVISION}
    earlier, status = versioned_catalog.lookup_entries([TECHNIQUE], group_previous)
    assert status == "exact_previous_current" and set(earlier) == {TECHNIQUE}
    assert "ACTIVE" not in earlier[TECHNIQUE]["conditions"][0]["description"]
    previous = {"schema": versioned_catalog.BINDING_SCHEMA,
                "manifest_sha256": versioned_catalog.GAMELIFT_CURRENT_MANIFEST,
                "effective_tree_sha256": versioned_catalog.GAMELIFT_CURRENT_TREE,
                "source_revision": versioned_catalog.V4_REVISION}
    old, status = versioned_catalog.lookup_entries([TECHNIQUE], previous)
    assert status == "exact_previous_current" and old == {}


def test_customer_role_grants_both_metadata_reads():
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "infra/aws/customer-role.json").read_text())
    documents = [row["Properties"]["PolicyDocument"] for name, row in template["Resources"].items()
                 if name.startswith("CspmConfigurationReadOnly")]
    actions = {action for doc in documents for statement in doc["Statement"]
               for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                              else statement["Action"])}
    assert {"gameliftstreams:ListStreamGroups", "gameliftstreams:ListStreamSessions"} <= actions
    assert all(policy_size(doc) <= 6144 for doc in documents)
    for operation, action in (("list_stream_groups", "gameliftstreams:ListStreamGroups"),
                              ("list_stream_sessions", "gameliftstreams:ListStreamSessions")):
        generated = build_policy({("gameliftstreams", operation)}, include_credential_report_generation=False)
        assert generated["Statement"][0]["Action"] == [action]

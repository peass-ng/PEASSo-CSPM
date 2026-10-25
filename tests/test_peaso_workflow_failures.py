"""Run compiled hosted failure states against Moto; no cloud or large allocation."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from peaso.storage.cost import runtime_estimate, worker_resources

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("workflow_validator", ROOT / "scripts/peaso_deploy_validate_workflow.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


@pytest.fixture(scope="module")
def terraform():
    binary = os.getenv("PEASO_TERRAFORM") or "/tmp/peaso-terraform-1.14.3/terraform"
    if not Path(binary).is_file():
        binary = shutil.which("terraform")
    if not binary:
        pytest.skip("Terraform required to compile the actual workflow")
    return binary


@pytest.fixture(scope="module")
def workflow(terraform):
    definition, bounds = validator.compile_definition(ROOT, terraform)
    assert bounds == {"workflow_seconds": 7200, "stage_seconds": 7200, "lease_seconds": 7500}
    compiled = json.loads(definition)
    parallel = compiled["States"]["ScanStages"]
    assert parallel["Type"] == "Parallel" and compiled["StartAt"] == "ScanStages"
    assert [branch["StartAt"] for branch in parallel["Branches"]] == ["Collect", "Analyze"]
    assert parallel["Branches"][0]["States"]["Collect"]["TimeoutSeconds"] == bounds["stage_seconds"]
    assert parallel["Branches"][1]["States"]["Analyze"]["TimeoutSeconds"] == bounds["workflow_seconds"]
    assert "'--progressive'" in parallel["Branches"][1]["States"]["Analyze"]["Parameters"]["Overrides"]["ContainerOverrides"][0]["Command.$"]
    return compiled


def test_actual_terraform_sizing_defaults_and_validation(terraform, tmp_path, monkeypatch):
    text = (ROOT / "infra/aws/variables.tf").read_text()
    match = re.search(r'variable\s+"worker_resources"', text)
    _, stop = validator.balanced(text[match.end():], "{", "}")
    (tmp_path / "main.tf").write_text(text[match.start():match.end() + stop])

    def evaluate(override=None):
        command = [terraform, f"-chdir={tmp_path}", "console", "-no-color"]
        if override is not None:
            command.append("-var=worker_resources=" + json.dumps(override))
        return subprocess.run(command, input="jsonencode(var.worker_resources)\n", capture_output=True, text=True)

    result = evaluate()
    assert result.returncode == 0, result.stderr
    defaults = json.loads(json.loads(result.stdout))
    assert defaults == {"collector": {"cpu": 4096, "memory": 16384}, "analyzer": {"cpu": 1024, "memory": 8192}}
    for key in list(os.environ):
        if key.startswith("PEASO_"):
            monkeypatch.delenv(key)
    assert worker_resources() == {stage: {"vcpu": size["cpu"] / 1024, "memory_gib": size["memory"] / 1024} for stage, size in defaults.items()}
    larger = {"collector": {"cpu": 1024, "memory": 8192}, "analyzer": {"cpu": 1024, "memory": 8192}}
    assert evaluate(larger).returncode == 0
    assert evaluate({"collector": {"cpu": 4096, "memory": 30720}, "analyzer": {"cpu": 4096, "memory": 8192}}).returncode == 0
    for invalid in [dict(larger, analyzer={"cpu": 512, "memory": 2048}),
                    dict(larger, collector={"cpu": 512, "memory": 6144}),
                    dict(larger, collector={"cpu": 1024, "memory": 4096}),
                    dict(larger, collector={"cpu": 4096, "memory": 31744}),
                    dict(larger, extra={"cpu": 512, "memory": 4096})]:
        result = evaluate(invalid)
        # Terraform console can print the value even when reporting a failed
        # variable validation, so assert its diagnostic as well as status.
        assert "Invalid value for variable" in result.stderr



def test_actual_runtime_limit_defaults_and_upper_bounds(terraform, tmp_path):
    text = (ROOT / "infra/aws/variables.tf").read_text()
    match = re.search(r'variable\s+"scan_runtime_limits"', text)
    _, stop = validator.balanced(text[match.end():], "{", "}")
    (tmp_path / "main.tf").write_text(text[match.start():match.end() + stop])
    def evaluate(value=None):
        command = [terraform, f"-chdir={tmp_path}", "console", "-no-color"]
        if value is not None:
            command.append("-var=scan_runtime_limits=" + json.dumps(value))
        return subprocess.run(command, input="jsonencode(var.scan_runtime_limits)\n", capture_output=True, text=True)
    result = evaluate()
    assert result.returncode == 0, result.stderr
    defaults = json.loads(json.loads(result.stdout))
    assert defaults == {"workflow_seconds": 7200, "stage_seconds": 7200, "lease_seconds": 7500}
    for change in ({"workflow_seconds": 7201}, {"stage_seconds": 7201}, {"lease_seconds": 7501},
                   {"lease_seconds": 7499}, {"workflow_seconds": 899}, {"stage_seconds": 299},
                   {"stage_seconds": 7200.5}):
        assert "Invalid value for variable" in evaluate(dict(defaults, **change)).stderr

def test_cost_uses_both_stage_sizes_and_60_second_minimum(monkeypatch):
    for key in list(os.environ):
        if key.startswith("PEASO_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("PEASO_STORAGE", "dynamodb")
    monkeypatch.setenv("PEASO_ANALYZER_MEMORY_GIB", "8")
    events = [{"status": status, "at": at} for status, at in [
        ("collecting", "2026-10-11T00:00:00+00:00"),
        ("collected", "2026-10-11T00:00:01+00:00"),
        ("analyzing", "2026-10-11T00:00:02+00:00"),
        ("completed", "2026-10-11T00:00:03+00:00"),
    ]]
    estimate = runtime_estimate(events)["compute_cost_estimate"]
    assert estimate["stage_sizes"] == {"collector": {"vcpu": 4, "memory_gib": 16}, "analyzer": {"vcpu": 1, "memory_gib": 8}}
    assert estimate["amount_usd"] == round(60 * (5 * 0.000011244 + 24 * 0.000001235), 8)


def lookup(value, path):
    for part in path.split("."):
        value = value[part]
    return value


def resolve(value, data, execution):
    """Small strict stand-in for dynamic ASL inputs, not a JSONata validator."""
    if isinstance(value, dict):
        return {key.removesuffix(".$"): resolve(item, data, execution) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve(item, data, execution) for item in value]
    if not isinstance(value, str):
        return value
    if value == "$$.Execution.Id":
        return execution
    if value.startswith("States.Format("):
        match = re.fullmatch(r"States.Format\('([^']+)', \$\.([a-z_]+)\)", value)
        assert match, value
        return match[1].format(data[match[2]])
    if not value.startswith("{% "):
        return value
    expression = value[3:-3].strip()
    if expression == "$now()":
        return "2026-10-11T00:00:00+00:00"
    match = re.fullmatch(r"'([^']*)' & \$states.input.([a-z_]+)", expression)
    if match:
        return match[1] + data[match[2]]
    match = re.fullmatch(r"\$exists\(\$states.input.([a-z_.]+)\) \? \$states.input.\1 : '([^']+)'", expression)
    if match:
        try:
            return lookup(data, match[1])
        except KeyError:
            return match[2]
    raise AssertionError("Unsupported fixture expression: " + expression)


@pytest.mark.parametrize("stage", ["collector", "analyzer"])
@pytest.mark.parametrize("failure", ["ecs_oom", "ecs_sigkill", "stopped_without_result"])
def test_compiled_task_death_fails_scan_and_reconciles_status(workflow, stage, failure):
    run_failure(workflow, stage, failure)


@pytest.mark.parametrize("terminal", ["cancelled", "completed", "timed_out", "failed"])
def test_workflow_failure_does_not_overwrite_terminal_scan(workflow, terminal):
    run_failure(workflow, "analyzer", "ecs_sigkill", terminal)


@pytest.mark.parametrize("stage", ["collector", "analyzer"])
@pytest.mark.parametrize("terminal", ["cancelled", "completed", "timed_out", "failed"])
def test_terminal_race_before_failure_write_reconciles_workflow(workflow, stage, terminal):
    run_failure(workflow, stage, "ecs_sigkill", terminal, terminal_race=True)


def run_failure(workflow, stage, failure, terminal=None, *, terminal_race=False):
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ClientError
    from peaso.storage.dynamodb import attrs, row
    private = "fixture-private-provider-cause"
    data = {"tenant_id": "alice", "scan_id": "fixture"}
    execution = "arn:aws:states:us-east-1:111122223333:execution:hacktricks-cspm:fixture"
    outer = workflow["States"]
    parallel = outer["ScanStages"]
    branch = parallel["Branches"][0 if stage == "collector" else 1]
    states = {**outer, **branch["States"]}
    state_name = "Collect" if stage == "collector" else "Analyze"
    visited = []
    with moto.mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(TableName="hacktricks-cspm", BillingMode="PAY_PER_REQUEST",
                            KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
                            AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"} for key in ["PK", "SK"]])
        key = attrs({"PK": "tenant/alice", "SK": "job/fixture"})
        initial_status = ("collecting" if stage == "collector" else "analyzing") if terminal_race else terminal or ("collecting" if stage == "collector" else "analyzing")
        client.put_item(TableName="hacktricks-cspm", Item=attrs({"PK": "tenant/alice", "SK": "job/fixture", "status": initial_status, "owner": "worker-owner", "lease": 100, "rev": 0,
                                                               "partial_report": "tenant/alice/partial-report", "checkpoint_sequence": 2}))
        raced = False
        for _ in range(15):
            state = states[state_name]
            visited.append(state_name)
            if state["Type"] == "Fail" and state_name in {"CollectorBranchFailed", "AnalyzerBranchFailed"}:
                error = state["Error"]
                handler = next(item for item in parallel["Catch"] if error in item["ErrorEquals"])
                data["failure"] = {"Error": error, "Cause": state["Cause"]}
                state_name = handler["Next"]
                continue
            if state["Type"] in {"Fail", "Succeed"}:
                break
            try:
                if state["Type"] == "Pass":
                    if "ResultPath" in state:
                        data[state["ResultPath"][2:]] = copy.deepcopy(state["Result"])
                elif state["Type"] == "Choice":
                    def matches(choice):
                        try:
                            value = lookup(data, choice["Variable"][2:])
                        except KeyError:
                            return choice.get("IsPresent") is False
                        return choice.get("IsPresent") is True if "IsPresent" in choice else value == choice["StringEquals"]
                    state_name = next((choice["Next"] for choice in state["Choices"] if matches(choice)), state["Default"])
                    continue
                elif state["Resource"] == "arn:aws:states:::ecs:runTask.sync":
                    if failure != "stopped_without_result":
                        reason = "OutOfMemoryError: Container killed due to memory usage" if failure == "ecs_oom" else "Essential container exited with exit code 137"
                        data["failure"] = {"Error": "States.TaskFailed", "Cause": reason + private}
                        raise ClientError({"Error": {"Code": "TaskFailed"}}, "RunTask")
                else:
                    operation = state["Resource"].rsplit(":", 1)[1]
                    if state_name == "MarkFailed" and terminal_race and not raced:
                        client.update_item(TableName="hacktricks-cspm", Key=key,
                                           UpdateExpression="SET #s=:s", ExpressionAttributeNames={"#s": "status"},
                                           ExpressionAttributeValues=attrs({":s": terminal}))
                        raced = True
                    arguments = resolve(state.get("Arguments", state.get("Parameters")), data, execution)
                    result = getattr(client, {"getItem": "get_item", "deleteItem": "delete_item", "updateItem": "update_item"}[operation])(**arguments)
                    if state.get("ResultPath"):
                        data[state["ResultPath"][2:]] = result
                state_name = state["Next"]
            except ClientError as error:
                code = "DynamoDB." + error.response["Error"]["Code"]
                handler = next((catch for catch in state.get("Catch", []) if "States.ALL" in catch["ErrorEquals"] or code in catch["ErrorEquals"]), None)
                assert handler, (state_name, code)
                state_name = handler["Next"]
        else:
            pytest.fail("Compiled failure path did not terminate")
        persisted = row(client.get_item(TableName="hacktricks-cspm", Key=key)["Item"])
        assert persisted["status"] == (terminal or "failed")
        assert persisted["partial_report"] == "tenant/alice/partial-report"
        assert persisted["checkpoint_sequence"] == 2
        if not terminal:
            assert persisted["error_code"] == "worker_task_failed" and persisted["error_stage"] == stage
            assert persisted["owner"] is None and persisted["lease"] is None
            assert persisted["history"][-1]["status"] == "failed"
        assert private not in json.dumps(persisted)
        assert states["Collect" if stage == "collector" else "Analyze"]["Type"] == "Task"
        assert workflow["StartAt"] == "ScanStages"
        expected_end = {"cancelled": "Cancelled", "completed": "Succeeded"}.get(terminal, "Failed")
        assert visited[-1] == expected_end
        assert ("MarkFailed" in visited) == (not terminal or terminal_race)
        if terminal_race:
            assert visited.count("ReadFailureStatus") == 2
        if stage == "collector":
            assert "Analyze" not in visited

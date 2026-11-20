"""Compile the actual workflow expression with stand-in IDs, then ask AWS to validate ASL."""
import json
from pathlib import Path
import re
import subprocess
import tempfile


def balanced(text, opening, close):
    start = text.index(opening)
    depth = 0
    quoted = escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == opening:
            depth += 1
        elif char == close:
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise ValueError("Unbalanced workflow HCL")


def compile_definition(root: Path, terraform: str):
    text = (root / "infra/aws/workflow.tf").read_text()
    definitions, removals = [], []
    for match in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', text):
        start, stop = balanced(text[match.end():], "{", "}")
        begin, end = match.end() + start, match.end() + stop
        block = text[begin:end]
        if match.group(1) == "aws_sfn_state_machine":
            assignment = re.search(r"definition\s*=\s*jsonencode", block)
            if not assignment:
                raise ValueError("Workflow definition expression missing")
            left, right = balanced(block[assignment.end():], "(", ")")
            definitions.append("jsonencode" + block[assignment.end() + left:assignment.end() + right])
        removals.append((match.start(), end))
    if len(definitions) != 1:
        raise ValueError("Expected one actual state-machine definition")
    for begin, end in reversed(removals):
        text = text[:begin] + text[end:]
    text += "\nlocals { validation_definition = " + definitions[0] + " }\n"
    prefix = "arn:aws:ecs:us-east-1:111122223333:"
    values = {
        "aws_ecs_task_definition.tasks[stage].arn": '"' + prefix + 'task-definition/hacktricks-cspm-${stage}:1"',
        "aws_ecs_cluster.cspm.arn": json.dumps(prefix + "cluster/hacktricks-cspm"),
        "aws_subnet.tasks.id": '"subnet-0123456789abcdef0"',
        "aws_security_group.tasks.id": '"sg-0123456789abcdef0"',
        "aws_s3_bucket.artifacts.id": '"hacktricks-cspm-artifacts-111122223333"',
        "aws_dynamodb_table.metadata.name": '"hacktricks-cspm"',
        "aws_cloudwatch_log_group.tasks.name": '"/ecs/hacktricks-cspm"',
        "aws_secretsmanager_secret.credentials.arn": '"arn:aws:secretsmanager:us-east-1:111122223333:secret:hacktricks-cspm-validation-abcdef"',
        "var.region": '"us-east-1"', "var.source_version": '"validation"',
        "local.issuer": '"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example"',
        "local.client_id": '"example-client"',
        "aws_secretsmanager_secret.ai.arn": '"arn:aws:secretsmanager:us-east-1:111122223333:secret:example-ai-abcdef"',
        "aws_iam_role.customer_trust.arn": '"arn:aws:iam::111122223333:role/ExampleCollector"',
        "var.codex_token_secret_arn": '""',
        "var.account_id": '"111122223333"',
        "var.platform_account_ids": '[]',
        "var.gcp_platform_project": '"example-project"',
        "var.gcp_platform_email": '"auditor@example-project.iam.gserviceaccount.com"',
        "var.gcp_platform_sa_secret_arn": '""',
    }
    # Resolve sizing/time limits from the actual dedicated configuration, rather
    # than validating a second, stale hard-coded workflow definition.
    variables_text = (root / "infra/aws/variables.tf").read_text()
    variable_file = root / "infra/aws/deployment.auto.tfvars.json"
    overrides = json.loads(variable_file.read_text()) if variable_file.is_file() else {}
    for name in ["worker_resources", "scan_runtime_limits"]:
        if name in overrides:
            expression = json.dumps(overrides[name])
        else:
            match = re.search(r'variable\s+"' + name + r'"', variables_text)
            if not match:
                raise ValueError("Workflow sizing/time input missing")
            start, stop = balanced(variables_text[match.end():], "{", "}")
            block = variables_text[match.end() + start:match.end() + stop]
            default = re.search(r"default\s*=", block)
            if not default:
                raise ValueError("Workflow sizing/time default missing")
            left, right = balanced(block[default.end():], "{", "}")
            expression = block[default.end() + left:default.end() + right]
        values["var." + name] = "(" + expression + ")"
    for role in ["collector", "analyzer"]:
        values[f"aws_iam_role.{role}.arn"] = json.dumps(f"arn:aws:iam::111122223333:role/hacktricks-cspm-{role}")
    for reference, value in values.items():
        text = text.replace(reference, value)
    if re.search(r"\b(?:aws_[a-z_]+\.[a-z_]+|var\.|data\.)", text):
        raise ValueError("Unresolved workflow reference; update stand-in ID mapping")
    with tempfile.TemporaryDirectory(prefix="peaso-asl-") as folder:
        Path(folder, "main.tf").write_text(text)
        result = subprocess.run([terraform, f"-chdir={folder}", "console", "-no-color"],
                                input="local.validation_definition\n", capture_output=True, text=True, check=True)
        definition = json.loads(result.stdout.strip())
    compiled = json.loads(definition)
    workflow_seconds = compiled["TimeoutSeconds"]
    stages = compiled["States"]
    parallel = stages.get("ScanStages", {})
    branches = parallel.get("Branches", [])
    if compiled.get("StartAt") != "AssessmentMode" or stages.get("AssessmentMode") != {"Type": "Choice", "Choices": [{"Variable": "$.combined_report_id", "IsPresent": True, "Next": "CombineReports"}, {"Variable": "$.report_generation", "IsPresent": True, "Next": "GenerateReport"}], "Default": "ScanStages"} or parallel.get("Type") != "Parallel" or len(branches) != 2:
        raise ValueError("Collector and progressive analyzer must start in one Parallel state")
    collector, analyzer = (branch["States"] for branch in branches)
    stage_seconds = collector["Collect"]["TimeoutSeconds"]
    lease_match = re.search(r'["\s]*lease_seconds["\s]*[:=]\s*([0-9]+)', values["var.scan_runtime_limits"])
    if not lease_match or not 0 < stage_seconds <= workflow_seconds < int(lease_match[1]):
        raise ValueError("Workflow stage/deadline/admission invariant violated")
    if analyzer["Analyze"]["TimeoutSeconds"] != workflow_seconds:
        raise ValueError("Analyzer must fit the workflow deadline while collection retains its stage limit")
    if "AcquireSlot" in stages or "SCAN_LOCK" in json.dumps(compiled):
        raise ValueError("Only durable pre-workflow admission may reserve scan capacity")
    validate_failure_paths(compiled)
    return definition, {"workflow_seconds": workflow_seconds, "stage_seconds": stage_seconds,
                        "lease_seconds": int(lease_match[1])}


def validate_failure_paths(definition):
    """Check the compiled deployed path, including uncatchable worker death."""
    states = definition["States"]
    parallel = states["ScanStages"]
    if parallel.get("ResultPath", "missing") is not None or parallel.get("Next") != "ReleaseSucceeded":
        raise ValueError("Parallel workers must both settle before success")
    analyzer = parallel['Branches'][1]['States']['Analyze']
    report = states.get('GenerateReport', {})
    expected_parameters = __import__('copy').deepcopy(analyzer['Parameters'])
    expected_parameters['Overrides'] = {'ContainerOverrides': [{'Name': 'analyzer',
        'Command.$': "States.Array('analyzer', '--findings-report-generation', $.report_generation, '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"}]}
    if (report.get('Resource') != analyzer['Resource'] or report.get('Parameters') != expected_parameters
            or report.get('TimeoutSeconds') != analyzer['TimeoutSeconds']
            or report.get('Catch') != [{'ErrorEquals': ['States.ALL'], 'ResultPath': '$.failure', 'Next': 'ReportFailed'}]
            or report.get('Next') != 'ReportSucceeded' or states.get('ReportSucceeded') != {'Type': 'Succeed'}):
        raise ValueError('Report generation must run only the bound analyzer without collection or runtime overrides')
    combined = states.get('CombineReports', {})
    expected_parameters['Overrides'] = {'ContainerOverrides': [{'Name': 'analyzer',
        'Command.$': "States.Array('analyzer', '--combined-report-id', $.combined_report_id, '--tenant-id', $.tenant_id)"}]}
    if (combined.get('Resource') != analyzer['Resource'] or combined.get('Parameters') != expected_parameters
            or combined.get('TimeoutSeconds') != analyzer['TimeoutSeconds']
            or combined.get('Catch') != report.get('Catch') or combined.get('Next') != 'ReportSucceeded'):
        raise ValueError('Combined reports must run only the bound isolated analyzer workflow')
    expected_catches = [
        {"ErrorEquals": ["CollectorBranchFailed"], "ResultPath": "$.failure", "Next": "CollectorTaskFailed"},
        {"ErrorEquals": ["AnalyzerBranchFailed"], "ResultPath": "$.failure", "Next": "AnalyzerTaskFailed"},
        {"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": "ParallelTaskFailed"},
    ]
    if parallel.get("Catch") != expected_catches:
        raise ValueError("Parallel branch failure must cancel its sibling and reconcile the job")
    for branch, stage, task, failed, status, good in [
        (parallel["Branches"][0], "collector", "Collect", "CollectorBranchFailed", "CollectedStatus", "CollectorSucceeded"),
        (parallel["Branches"][1], "analyzer", "Analyze", "AnalyzerBranchFailed", "CompletedStatus", "AnalyzerSucceeded"),
    ]:
        branch_states = branch["States"]
        if branch.get("StartAt") != task or branch_states[task]["Resource"] != "arn:aws:states:::ecs:runTask.sync":
            raise ValueError("Worker failure detection requires ECS synchronous tasks")
        command = branch_states[task]["Parameters"]["Overrides"]["ContainerOverrides"][0]["Command.$"]
        expected_command = "States.Array('" + stage + "', " + ("'--progressive', " if stage == "analyzer" else "") + "'--once', '--tenant-id', $.tenant_id, '--scan-id', $.scan_id)"
        if command != expected_command:
            raise ValueError("Worker command must bind exact scan and progressive analyzer mode")
        catch = branch_states[task].get("Catch", [])
        if not any(item["ErrorEquals"] == ["States.ALL"] and item["Next"] == failed for item in catch):
            raise ValueError("ECS worker failures must enter the persisted failure path")
        if branch_states[status]["Default"] != failed:
            raise ValueError("Stopped tasks without a completed job must fail the scan")
        read = branch_states["ReadCollectedStatus" if stage == "collector" else "ReadCompletedStatus"]
        if (read.get("Parameters", {}).get("ConsistentRead") is not True or
                read.get("Catch") != [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.failure", "Next": failed}]):
            raise ValueError("Each branch must read authoritative status before reporting success")
        if branch_states[failed] != {"Type": "Fail", "Error": failed, "Cause": "Collector task did not complete" if stage == "collector" else "Analyzer task did not complete"}:
            raise ValueError("Branch failure must stop the sibling worker")
        if branch_states[good] != {"Type": "Succeed"}:
            raise ValueError("Branch success must be explicit")
        if states["CollectorTaskFailed" if stage == "collector" else "AnalyzerTaskFailed"].get("Result") != {"code": "worker_task_failed", "stage": stage}:
            raise ValueError("Task failures require a safe code and persisted failure path")
    collector_choices = parallel["Branches"][0]["States"]["CollectedStatus"].get("Choices")
    if collector_choices != [{"Variable": "$.job_status.Item.status.S", "StringEquals": value, "Next": "CollectorSucceeded"}
                             for value in ("collected", "analyzing", "completed")]:
        raise ValueError("Collector status read must tolerate analyzer claim racing the read")
    if parallel["Branches"][1]["States"]["CompletedStatus"].get("Choices") != [
            {"Variable": "$.job_status.Item.status.S", "StringEquals": "completed", "Next": "AnalyzerSucceeded"}]:
        raise ValueError("Progressive analyzer exit must verify final completion")
    for failure in ("CollectorTaskFailed", "AnalyzerTaskFailed", "ParallelTaskFailed"):
        if states[failure].get("Next") != "ReleaseFailed":
            raise ValueError("Workflow branch failure must reconcile persisted status")
    release = states["ReleaseFailed"]
    if release != {"Type": "Pass", "Next": "ReadFailureStatus"} or states["ReleaseSucceeded"] != {"Type": "Pass", "Next": "Succeeded"}:
        raise ValueError("Workflow must rely on fenced worker release and scheduler reconciliation")
    read = states["ReadFailureStatus"]
    if (read["Resource"] != "arn:aws:states:::dynamodb:getItem" or
            read["Parameters"].get("ConsistentRead") is not True or read["Next"] != "FailureStatus"):
        raise ValueError("Failure reconciliation must read the authoritative terminal status")
    choices = states["FailureStatus"]
    expected = [{"Variable": "$.job_status.Item.status.S", "IsPresent": False, "Next": "Failed"}]
    expected += [{"Variable": "$.job_status.Item.status.S", "StringEquals": status, "Next": target}
                 for status, target in [("cancelled", "Cancelled"), ("completed", "Succeeded"),
                                        ("failed", "Failed"), ("timed_out", "Failed"),
                                        ("queue_exhausted", "Failed"), ("credentials_expired", "Failed")]]
    if choices.get("Choices") != expected or choices.get("Default") != "MarkFailed" or states["Cancelled"] != {"Type": "Succeed"}:
        raise ValueError("Failure reconciliation must distinguish cancellation from failed scans")
    catch = states["MarkFailed"].get("Catch", [])
    if catch != [{"ErrorEquals": ["DynamoDB.ConditionalCheckFailedException"],
                  "Output": "{% $states.input %}", "Next": "ReadFailureStatus"}]:
        raise ValueError("A terminal-state race must preserve inputs and re-read the job")
    mark = states["MarkFailed"]["Arguments"]
    if mark.get("ConditionExpression") != "attribute_exists(PK) AND #status IN (:queued,:collecting,:collected,:analyzing)":
        raise ValueError("Workflow failure must preserve terminal scan states")
    for assignment in ["#owner=:null", "lease=:null", "error_code=:code", "error_stage=:stage"]:
        if assignment not in mark["UpdateExpression"]:
            raise ValueError("Workflow failure must clear job ownership and persist diagnostics")


def validate(root: Path, terraform: str, session):
    definition, bounds = compile_definition(root, terraform)
    result = session.client("stepfunctions").validate_state_machine_definition(
        definition=definition, type="STANDARD", severity="WARNING", maxResults=100)
    report = {"result": result["result"], "diagnostics": result.get("diagnostics", []),
              "truncated": result.get("truncated", False), "stand_in_resource_ids": True,
              "bounds": bounds, "admission": "durable_before_workflow"}
    output = root / "infra/aws/build/workflow-validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if report["result"] != "OK":
        raise RuntimeError("AWS rejected the actual workflow expression")
    return report

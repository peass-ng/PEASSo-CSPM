"""Static contract for hosted own-service calls (no boto3, Moto, or AWS calls).

The small typed receiver map resolves the actual AST call graph, not an IAM action
allowlist. Lambda scheduling runs with the API role; ECS --once skips scheduling.
HCL extraction intentionally fails on unsupported statement values/conditions.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
TABLE = "aws_dynamodb_table.metadata.arn"
OBJECTS = "${aws_s3_bucket.artifacts.arn}/*"
BUCKET = "aws_s3_bucket.artifacts.arn"
CREDENTIALS = "aws_secretsmanager_secret.credentials.arn"
KEY = "aws_kms_key.connectors.arn"
AI_KEY = "aws_kms_key.ai.arn"
AI_SECRET = "aws_secretsmanager_secret.ai.arn"
MODULES = (
    "peaso/storage/dynamodb.py", "peaso/storage/artifacts.py",
    "peaso/storage/runtime.py", "peaso/storage/reports.py", "peaso/worker.py",
    "peaso/server/app.py", "peaso/server/scheduler_handler.py",
    "peaso/auth/secrets.py", "peaso/auth/identity.py", "peaso/auth/billing.py",
)
# Types of dependency-injected receivers, validated by source wiring below.
RECEIVERS = {
    "store": "DynamoStore", "self.store": "DynamoStore", "worker.store": "DynamoStore",
    "artifacts": "S3Artifacts", "self.artifacts": "S3Artifacts",
    "cipher": "CredentialCipher", "self.cipher": "CredentialCipher",
    "authenticator": "Authenticator", "self.authenticator": "Authenticator",
    "dispatcher": "WorkflowDispatcher", "worker": "Worker",
    "self.entitlements": "StripeEntitlements",
}
TRANSACTION_ACTIONS = {
    "ConditionCheck": "ConditionCheckItem", "Put": "PutItem",
    "Update": "UpdateItem", "Delete": "DeleteItem", "Get": "GetItem",
}


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + "." + node.attr
    return ""


def operation(name):
    # SDK spelling differs from IAM for batch operations and S3 HEAD.
    return {"batch_get_item": "BatchGetItem", "batch_write_item": "BatchWriteItem",
            "head_object": "GetObject", "delete_objects": "DeleteObject"}.get(name, "".join(part.title() for part in name.split("_")))


@dataclass(frozen=True)
class Requirement:
    role: str
    action: str
    resource: str
    trace: tuple[str, ...]


class Graph:
    def __init__(self, overrides=None):
        self.sources = {path: (overrides or {}).get(path, (ROOT / path).read_text()) for path in MODULES}
        self.functions = {}
        self.locations = {}
        for path, source in self.sources.items():
            for node in ast.parse(source).body:
                if isinstance(node, ast.ClassDef):
                    for method in node.body:
                        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self.functions[node.name + "." + method.name] = method
                            self.locations[node.name + "." + method.name] = path
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = "scheduler_handler" if path.endswith("scheduler_handler.py") and node.name == "handler" else node.name
                    self.functions[name] = node
                    self.locations[name] = path

    def nodes(self, function, worker_role, targeted=False):
        """Prune only proven role predicates; retain errors/deadlines/optional inputs."""
        def truth(node):
            if targeted and function == "DynamoStore.claim":
                if dotted(node) == "ident":
                    return True
                if (isinstance(node, ast.Compare) and dotted(node.left) == "ident"
                        and len(node.ops) == 1 and isinstance(node.ops[0], ast.IsNot)
                        and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)
                        and node.comparators[0].value is None):
                    return True
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
                if dotted(node.left) in {"role", "self.role"} and isinstance(node.comparators[0], ast.Constant):
                    right = node.comparators[0].value
                    if isinstance(node.ops[0], ast.Eq):
                        return worker_role == right
                    if isinstance(node.ops[0], ast.NotEq):
                        return worker_role != right
            return None

        def walk(node):
            yield node
            if isinstance(node, (ast.If, ast.IfExp)):
                known = truth(node.test)
                if known is not None:
                    branch = node.body if known else node.orelse
                    for child in branch if isinstance(branch, list) else [branch]:
                        yield from walk(child)
                    return
            for child in ast.iter_child_nodes(node):
                yield from walk(child)

        return list(walk(self.functions[function]))

    def transaction_items(self, function, nodes):
        """Follow TransactItems variables, append calls and typed extra arguments."""
        def bindings(items):
            assignments = {}
            for node in items:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments.setdefault(target.id, []).append(node.value)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "append":
                    assignments.setdefault(dotted(node.func.value), []).extend(node.args)
            return assignments

        def expression(node, assignments, seen=frozenset()):
            if isinstance(node, ast.Call) and dotted(node.func) == 'dict':
                assert not node.args and all(kw.arg is not None for kw in node.keywords)
                return ast.Dict(keys=[ast.Constant(value=kw.arg) for kw in node.keywords],
                                values=[kw.value for kw in node.keywords])
            if isinstance(node, ast.Name) and node.id in assignments:
                assert node.id not in seen and len(assignments[node.id]) == 1
                return expression(assignments[node.id][0], assignments, seen | {node.id})
            if isinstance(node, ast.Call) and dotted(node.func).startswith('self.'):
                callee = function.split('.')[0] + '.' + node.func.attr
                assert callee in self.functions and callee not in seen
                returns = [n.value for n in ast.walk(self.functions[callee]) if isinstance(n, ast.Return)]
                assert len(returns) == 1, f'Unresolved transaction helper {callee}'
                return expression(returns[0], bindings(self.nodes(callee, None)), seen | {callee})
            if isinstance(node, ast.Subscript):
                value = expression(node.value, assignments, seen)
                assert isinstance(value, ast.Dict) and isinstance(node.slice, ast.Constant)
                matches = [v for k, v in zip(value.keys, value.values)
                           if isinstance(k, ast.Constant) and k.value == node.slice.value]
                assert len(matches) == 1
                return expression(matches[0], assignments, seen)
            return node

        def resolve(node, assignments, seen=frozenset()):
            if isinstance(node, ast.Name):
                if node.id in seen:
                    return
                if node.id == "extra":
                    # enqueue's optional transaction comes from actual self.enqueue callers.
                    for caller_name, caller in self.functions.items():
                        for call in ast.walk(caller):
                            if isinstance(call, ast.Call) and dotted(call.func) == "self.enqueue":
                                parameter = [arg.arg for arg in self.functions["DynamoStore.enqueue"].args.args if arg.arg != "self"].index("extra")
                                extra = call.args[parameter:parameter + 1] + [kw.value for kw in call.keywords if kw.arg == "extra"]
                                for value in extra:
                                    yield from resolve(value, bindings(self.nodes(caller_name, None)), seen | {node.id})
                    return
                parameters = [arg.arg for arg in self.functions[function].args.args if arg.arg != 'self']
                parameter_marker = function + ':' + node.id
                if node.id in parameters and parameter_marker not in seen:
                    position = parameters.index(node.id)
                    found = False
                    for caller_name, caller in self.functions.items():
                        if caller_name.split('.')[0] != function.split('.')[0]:
                            continue
                        for call in ast.walk(caller):
                            if isinstance(call, ast.Call) and dotted(call.func) == 'self.' + function.split('.')[1]:
                                actual = call.args[position:position + 1] + [kw.value for kw in call.keywords if kw.arg == node.id]
                                caller_bindings = bindings(self.nodes(caller_name, None))
                                for value in actual:
                                    found = True
                                    values = caller_bindings.get(value.id, []) if isinstance(value, ast.Name) else [value]
                                    assert values, f'Unresolved caller transaction argument {caller_name}'
                                    for actual_value in values:
                                        yield from resolve(actual_value, caller_bindings, seen | {parameter_marker})
                    assert found, f'Unresolved transaction argument {function}.{node.id}'
                    if node.id not in assignments:
                        return
                assert node.id in assignments, f"Unresolved transaction variable {node.id}"
                for value in assignments[node.id]:
                    yield from resolve(value, assignments, seen | {node.id})
            elif isinstance(node, ast.Dict):
                assert node.keys and all(isinstance(key, ast.Constant) and key.value in TRANSACTION_ACTIONS for key in node.keys), f"Unknown transaction item in {function}"
                for key, value in zip(node.keys, node.values):
                    value = expression(value, assignments)
                    assert isinstance(value, ast.Dict), f'Unresolved transaction body in {function}: {ast.dump(value)}'
                    yield key.value, value, key.lineno
            elif isinstance(node, (ast.List, ast.Tuple)):
                for value in node.elts:
                    yield from resolve(value, assignments, seen)
            elif isinstance(node, ast.Call):
                value = expression(node, assignments)
                assert value is not node, f'Unresolved transaction call in {function}'
                yield from resolve(value, assignments, seen)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                yield from resolve(node.left, assignments, seen)
                yield from resolve(node.right, assignments, seen)
            else:
                raise AssertionError(f"Unresolved transaction value in {function}: {ast.dump(node)}")

        for call in nodes:
            if isinstance(call, ast.Call) and dotted(call.func) in {"self.client.transact_write_items", "self.client.transact_get_items"}:
                items = next(kw.value for kw in call.keywords if kw.arg == "TransactItems")
                yield from resolve(items, bindings(nodes))

    def requirements(self, role, roots, worker_role=None):
        requirements, visited = set(), set()

        def visit(name, trace):
            if name in visited:
                return
            assert name in self.functions, f"Unknown typed call target {name}"
            visited.add(name)
            path = self.locations[name]
            nodes = self.nodes(name, worker_role, targeted=role in {"collector", "analyzer"})
            step = f"{path}:{self.functions[name].lineno} {name}"
            trace = trace + (step,)

            def require(action, resource, line):
                requirements.add(Requirement(role, action, resource, trace + (f"{path}:{line} {action}",)))

            for node in nodes:
                if not isinstance(node, ast.Call):
                    continue
                target = dotted(node.func)
                receiver, _, method = target.rpartition(".")
                if name.startswith("DynamoStore.") and receiver == "self.client":
                    # Every own-table SDK call must carry the wired metadata TableName.
                    table = next((kw.value for kw in node.keywords if kw.arg == "TableName"), None)
                    if method == "batch_get_item":
                        # Batch reads name the table as the only RequestItems key.
                        request = next(kw.value for kw in node.keywords if kw.arg == "RequestItems")
                        assert isinstance(request, ast.Dict) and [dotted(key) for key in request.keys] == ["self.table"], f"Wrong RequestItems table at {path}:{node.lineno}"
                    elif table is None and any(kw.arg is None for kw in node.keywords):
                        assert any((isinstance(value, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "TableName" and dotted(v) == "self.table" for k, v in zip(value.keys, value.values)))
                                   or (isinstance(value, ast.Call) and dotted(value.func) == "dict" and any(kw.arg == "TableName" and dotted(kw.value) == "self.table" for kw in value.keywords))
                                   for value in nodes), f"Unresolved TableName at {path}:{node.lineno}"
                    elif method not in {"transact_write_items", "transact_get_items"}:
                        assert dotted(table) == "self.table", f"Wrong TableName at {path}:{node.lineno}"
                    require("dynamodb:" + operation(method), TABLE, node.lineno)
                elif name.startswith("S3Artifacts.") and receiver == "self.client":
                    if method == "generate_presigned_url":
                        assert isinstance(node.args[0], ast.Constant)
                        method = node.args[0].value
                    elif method == "get_paginator":
                        assert len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
                        assert node.args[0].value == "list_objects_v2"
                        assert any(
                            isinstance(call, ast.Call) and dotted(call.func) == "paginator.paginate"
                            and dotted(next((kw.value for kw in call.keywords if kw.arg == "Bucket"), None)) == "self.bucket"
                            and dotted(next((kw.value for kw in call.keywords if kw.arg == "Prefix"), None)) == "target"
                            for call in nodes
                        )
                        require("s3:ListBucket", BUCKET, node.lineno)
                        continue
                    else:
                        bucket = next(kw.value for kw in node.keywords if kw.arg == "Bucket")
                        assert dotted(bucket) == "self.bucket"
                    require("s3:" + operation(method), OBJECTS, node.lineno)
                elif name == "CredentialCipher.__init__" and method == "get_secret_value":
                    assert isinstance(node.func.value, ast.Call) and node.func.value.args[0].value == "secretsmanager"
                    assert any(isinstance(value, ast.Constant) and value.value == "PEASO_CREDENTIAL_SECRET_ARN" for value in nodes)
                    require("secretsmanager:GetSecretValue", CREDENTIALS, node.lineno)
                    # Secrets Manager decrypts its explicitly configured customer KMS key.
                    require("kms:Decrypt", KEY, node.lineno)
                elif name == "StripeEntitlements._key" and receiver == "self.secrets_client":
                    require("secretsmanager:" + operation(method), "local.stripe_arn", node.lineno)
                elif name.startswith("WorkflowDispatcher.") and receiver == "self.client":
                    assert method == "start_execution"
                    require("states:" + operation(method), "local.workflow_arn", node.lineno)
                else:
                    callee = None
                    if receiver == "self" and "." in name:
                        candidate = name.split(".")[0] + "." + method
                        if candidate in self.functions:
                            callee = candidate
                    elif receiver in RECEIVERS:
                        candidate = RECEIVERS[receiver] + "." + method
                        # public_job/public_schedule are pure inherited serialization.
                        if candidate in self.functions:
                            callee = candidate
                        elif RECEIVERS[receiver] in {"DynamoStore", "S3Artifacts"}:
                            assert method in {"public_job", "public_schedule", "connect"}, f"Unresolved storage method {target}"
                    elif receiver == "WorkflowDispatcher()":
                        callee = "WorkflowDispatcher." + method
                    elif isinstance(node.func, ast.Name):
                        if target in self.functions:
                            callee = target
                        elif target + ".__init__" in self.functions:
                            callee = target + ".__init__"
                    # Calls such as WorkflowDispatcher().dispatch have a Call receiver.
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call) and dotted(node.func.value.func) == "WorkflowDispatcher":
                        callee = "WorkflowDispatcher." + method
                    if callee:
                        visit(callee, trace)
                    # _process is a multiprocessing target, not a direct call expression.
                    for kw in node.keywords:
                        if kw.arg == "target" and dotted(kw.value) == "_process":
                            visit("_process", trace)
            for kind, item, line in self.transaction_items(name, nodes):
                assert isinstance(item, (ast.Dict, ast.Name)), f"Unsupported {kind} transaction item"
                if isinstance(item, ast.Dict):
                    assert any(isinstance(k, ast.Constant) and k.value == "TableName" and dotted(v) == "self.table" for k, v in zip(item.keys, item.values))
                require("dynamodb:" + TRANSACTION_ACTIONS[kind], TABLE, line)

        for root in roots:
            visit(root, ())
        return requirements


# Tokenize quoted strings atomically, including Terraform interpolations/braces.
TOKEN = re.compile(r'\s+|\#[^\n]*|//[^\n]*|"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z_0-9.:-]*|[{}\[\](),=?]|\S')


def tokens(text):
    return [m.group() for m in TOKEN.finditer(text) if not m.group().isspace() and not m.group().startswith(("#", "//"))]


def balanced(stream, start):
    opening = stream[start]
    closing = {"{": "}", "[": "]", "(": ")"}[opening]
    depth = 0
    for end in range(start, len(stream)):
        if stream[end] == opening:
            depth += 1
        elif stream[end] == closing:
            depth -= 1
            if depth == 0:
                return stream[start + 1:end], end + 1
    raise AssertionError("Unbalanced HCL")


def resource_blocks(text, kind):
    stream, result = tokens(text), {}
    for pos in range(len(stream) - 3):
        if stream[pos:pos + 2] == ["resource", '"' + kind + '"']:
            assert stream[pos + 3] == "{"
            body, _ = balanced(stream, pos + 3)
            result[stream[pos + 2].strip('"')] = body
    return result


def field(stream, name):
    depth = 0
    for pos, value in enumerate(stream):
        if depth == 0 and value == name and stream[pos + 1] == "=":
            return pos + 2
        if value in {"{", "[", "("}:
            depth += 1
        elif value in {"}", "]", ")"}:
            depth -= 1
    raise AssertionError(f"Missing HCL field {name}")


def values(stream, name):
    pos = field(stream, name)
    if stream[pos] == 'compact':
        assert stream[pos + 1:pos + 3] == ['(', '[']
        content, _ = balanced(stream, pos + 2)
        assert all(value not in {'{', '[', ']', '}'} for value in content)
        return tuple(value.strip('"') for value in content if value != ',')
    if stream[pos] == "[":
        content, _ = balanced(stream, pos)
        if content == tokens('for task in aws_ecs_task_definition.tasks : task.arn'):
            assert name == 'Resource'
            return tuple('aws_ecs_task_definition.tasks["' + role + '"].arn' for role in ('collector', 'analyzer'))
        if content and content[0] == 'for':
            # Conservatively broaden an unresolved Deny, never an Allow. The
            # platform-account role comprehension cannot prove an exact grant.
            assert name == 'Resource' and values(stream, 'Effect') == ('Deny',)
            return ('*',)
        assert all(value not in {"{", "[", "]", "}"} for value in content)
        return tuple(value.strip('"') for value in content if value != ",")
    return (stream[pos].strip('"'),)


@dataclass(frozen=True)
class Statement:
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    conditional: bool = False
    not_actions: bool = False
    artifact_prefix: bool = False
    not_resources: bool = False


def alternative_values(stream, positive, negative):
    """IAM permits exactly one of each positive/complement field pair."""
    present = []
    for name in (positive, negative):
        try:
            field(stream, name)
        except AssertionError:
            continue
        present.append(name)
    assert len(present) == 1, f"Expected exactly one of {positive}/{negative}"
    return values(stream, present[0]), present[0] == negative


def policies(text):
    result = {}
    for name, body in resource_blocks(text, "aws_iam_role_policy").items():
        role = values(body, "role")[0]
        assert role.startswith("aws_iam_role.") and role.endswith(".id")
        role = role.split(".")[1]
        statements = []
        # Statement objects have an Effect at their top level, nested conditions do not.
        for pos, token in enumerate(body):
            if token != "{":
                continue
            obj, _ = balanced(body, pos)
            try:
                effect = values(obj, "Effect")[0]
            except AssertionError:
                continue
            try:
                field(obj, "Condition")
                conditional = True
            except AssertionError:
                conditional = False
            assert values(obj, "Effect") in {("Allow",), ("Deny",)}, f"Unsupported IAM Effect {effect}"
            actions, not_actions = alternative_values(obj, "Action", "NotAction")
            resources, not_resources = alternative_values(obj, "Resource", "NotResource")
            artifact_prefix = any(obj[i:i + 3] == ['"s3:prefix"', "=", '"artifacts/*"'] for i in range(len(obj) - 2))
            statements.append(Statement(effect, actions, resources, conditional, not_actions, artifact_prefix, not_resources))
        assert statements, f"No IAM statements parsed for {name}"
        result.setdefault(role, []).extend(statements)
    return result


def grants(statements, action, resource):
    def matches(statement):
        # Exact symbolic resource on allow; broad/inexact grants cannot satisfy the contract.
        if statement.effect == "Allow":
            # A complement allow does not prove the required exact resource grant.
            resources = not statement.not_resources and resource in statement.resources
        else:
            resources = any(fnmatchcase(resource, value) for value in statement.resources)
            if statement.not_resources:
                resources = not resources
        action_matches = any(fnmatchcase(action.lower(), value.lower()) for value in statement.actions)
        return resources and (not action_matches if statement.not_actions else action_matches)
    # This contract has no condition context; any matching deny fails closed.
    def valid_condition(statement):
        return not statement.conditional or (
            action == "s3:ListBucket" and resource == BUCKET and statement.artifact_prefix
        )
    return any(s.effect == "Allow" and valid_condition(s) and matches(s) for s in statements) and not any(s.effect == "Deny" and matches(s) for s in statements)


def missing(requirements, text):
    statements = policies(text)
    return sorted((r for r in requirements if not grants(statements.get(r.role, []), r.action, r.resource)), key=lambda r: (r.role, r.action, r.trace))


def assert_contract(requirements, text):
    gaps = missing(requirements, text)
    assert not gaps, "\n".join(f"{r.role} lacks {r.action} on {r.resource}: " + " -> ".join(r.trace) for r in gaps)


@pytest.fixture(scope="module")
def graph():
    return Graph()


@pytest.fixture(scope="module")
def iam():
    return (ROOT / "infra/aws/iam.tf").read_text()


@pytest.fixture(scope="module")
def requirements(graph):
    return {
        "api": graph.requirements("api", ["create_app", "scheduler_handler"], "collector"),
        "collector": graph.requirements("collector", ["Worker.__init__", "Worker.run_once"], "collector"),
        "analyzer": graph.requirements("analyzer", ["Worker.__init__", "Worker.run_once"], "analyzer"),
    }




def test_api_scheduler_actual_calls_have_exact_resource_grants(requirements, iam):
    assert_contract(requirements["api"], iam)


@pytest.mark.parametrize("role", ["collector", "analyzer"])
def test_worker_actual_calls_have_exact_resource_grants(role, requirements, iam):
    assert_contract(requirements[role], iam)


def workflow_requirements(text):
    stream = tokens(text)
    for pos in range(len(stream) - 2):
        if stream[pos:pos + 2] == ["Resource", "="] and stream[pos + 2].startswith('"arn:aws:states:::dynamodb:'):
            action = stream[pos + 2].strip('"').rsplit(":", 1)[1]
            # Integration TableName is checked in its containing task, including Arguments.
            start = next(i for i in range(pos, -1, -1) if stream[i] == "{")
            obj, _ = balanced(stream, start)
            assert any(obj[i:i + 3] == ["TableName", "=", "aws_dynamodb_table.metadata.name"] for i in range(len(obj) - 2))
            yield Requirement("workflow", "dynamodb:" + action[0].upper() + action[1:], TABLE, (f"infra/aws/workflow.tf integration {action}",))


def test_workflow_only_its_actual_dynamodb_integrations_have_grants(iam):
    required = set(workflow_requirements((ROOT / "infra/aws/workflow.tf").read_text()))
    assert {r.action for r in required} == {"dynamodb:GetItem", "dynamodb:UpdateItem"}
    assert_contract(required, iam)


def test_roles_do_not_inherit_every_store_method(requirements):
    api = {r.action for r in requirements["api"]}
    assert {"dynamodb:ConditionCheckItem", "dynamodb:TransactWriteItems", "dynamodb:DeleteItem", "dynamodb:DescribeTable", "states:StartExecution"} <= api
    for role in ("collector", "analyzer"):
        actions = {r.action for r in requirements[role]}
        assert {"dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:TransactWriteItems", "s3:PutObject"} <= actions
        assert "dynamodb:Scan" not in actions
        assert not actions & {"dynamodb:ConditionCheckItem", "dynamodb:DescribeTable", "states:StartExecution"}
        assert not any("schedule_tick" in step or "delete_connector" in step for r in requirements[role] for step in r.trace)
    assert "s3:GetObject" in {r.action for r in requirements["analyzer"]}
    assert not any(r.action.startswith(("secretsmanager:", "kms:")) for r in requirements["analyzer"])


def test_analyzer_explicit_deny_beats_future_shared_allow(iam):
    statements = policies(iam)["analyzer"]
    for action, resource in (("secretsmanager:GetSecretValue", CREDENTIALS), ("kms:Decrypt", KEY), ("sts:AssumeRole", "customer-role")):
        assert not grants(statements + [Statement("Allow", (action,), (resource,))], action, resource)
    for action, resource in (("secretsmanager:GetSecretValue", AI_SECRET), ("kms:Decrypt", AI_KEY)):
        assert grants(statements, action, resource)


def assert_analyzer_kms_isolation(text):
    body = resource_blocks(text, "aws_iam_role_policy")["analyzer"]
    decrypt = []
    for pos, token in enumerate(body):
        if token != "{":
            continue
        obj, _ = balanced(body, pos)
        try:
            actions = values(obj, "Action")
        except AssertionError:
            continue
        if "kms:Decrypt" in actions:
            decrypt.append(obj)
    assert len(decrypt) == 3
    allows = [obj for obj in decrypt if values(obj, "Effect") == ("Allow",)]
    denies = [obj for obj in decrypt if values(obj, "Effect") == ("Deny",)]
    assert len(allows) == 2 and len(denies) == 1
    assert values(allows[0], "Action") == ("kms:Decrypt",)
    assert {alternative_values(obj, "Resource", "NotResource") for obj in allows} == {
        ((AI_KEY,), False), (('var.codex_token_kms_key_arn',), False)}
    assert all('Condition' not in obj for obj in allows)
    obj = denies[0]
    assert values(obj, "Action") == ("kms:Decrypt",)
    assert alternative_values(obj, "Resource", "NotResource") == ((AI_KEY, "var.codex_token_kms_key_arn"), True)
    condition, _ = balanced(obj, field(obj, "Condition"))
    assert condition == tokens('{ StringNotEquals = { "kms:ViaService" = "dynamodb.${var.region}.amazonaws.com" } }')[1:-1]
    statements = policies(text)["analyzer"]
    assert any(s.effect == "Deny" and not s.conditional and not s.not_actions and not s.not_resources
               and s.actions == ("sts:AssumeRole",) and s.resources == ("*",) for s in statements)
    assert any(s.effect == "Deny" and not s.conditional and not s.not_actions and s.not_resources
               and s.actions == ("secretsmanager:GetSecretValue",) and s.resources == (AI_SECRET, "var.codex_token_secret_arn") for s in statements)
    assert grants(statements, "secretsmanager:GetSecretValue", AI_SECRET)


def test_analyzer_decrypt_exception_is_only_regional_dynamodb(iam):
    assert_analyzer_kms_isolation(iam)


@pytest.mark.parametrize("before,after", [
    ("StringNotEquals", "StringEquals"),
    ('"kms:ViaService"', '"aws:RequestedRegion"'),
    ("dynamodb.${var.region}.amazonaws.com", "s3.${var.region}.amazonaws.com"),
    ("dynamodb.${var.region}.amazonaws.com", "dynamodb.*.amazonaws.com"),
    ('Effect    = "Deny", Action = ["kms:Decrypt"]', 'Effect    = "Allow", Action = ["kms:Decrypt"]'),
])
def test_analyzer_decrypt_exception_mutations_fail_closed(iam, before, after):
    changed = iam.replace(before, after)
    assert changed != iam
    with pytest.raises(AssertionError):
        assert_analyzer_kms_isolation(changed)


@pytest.mark.parametrize("before,after", [
    ("NotResource = compact([" + AI_KEY, "Resource = compact([" + AI_KEY),
    ("NotResource = compact([" + AI_KEY, "NotResource = compact([" + KEY),
    ("NotResource = compact([" + AI_SECRET, "Resource = compact([" + AI_SECRET),
    ("NotResource = compact([" + AI_SECRET, "NotResource = compact([" + CREDENTIALS),
    ('Effect = "Allow", Action = ["kms:Decrypt"], Resource = ' + AI_KEY,
     'Effect = "Deny", Action = ["kms:Decrypt"], Resource = ' + AI_KEY),
    ('Effect = "Allow", Action = ["kms:Decrypt"], Resource = ' + AI_KEY,
     'Effect = "Allow", Action = ["kms:Decrypt"], Resource = "*"'),
])
def test_analyzer_ai_exceptions_reject_resource_and_effect_mutations(iam, before, after):
    changed = iam.replace(before, after)
    assert changed != iam
    with pytest.raises(AssertionError):
        assert_analyzer_kms_isolation(changed)


def fixture_policy(statement):
    return 'resource "aws_iam_role_policy" "fixture" { role = aws_iam_role.fixture.id policy = jsonencode({ Statement = [' + statement + '] }) }'


@pytest.mark.parametrize("selector", ['Resource = "allowed"', 'Resource = ["allowed"]',
                                     'NotResource = "excluded"', 'NotResource = ["excluded"]'])
def test_resource_complements_and_deny_precedence(selector):
    text = fixture_policy('{ Effect = "Deny", Action = ["s3:Get*"], ' + selector + ' }')
    deny = policies(text)["fixture"]
    assert len(deny) == 1 and deny[0].effect == "Deny"
    for resource, denied in (("allowed", True), ("excluded", False), ("other", selector.startswith("NotResource"))):
        statements = deny + [Statement("Allow", ("s3:GetObject",), (resource,))]
        assert grants(statements, "s3:GetObject", resource) is not denied
        assert grants(deny + [Statement("Allow", ("s3:PutObject",), (resource,))], "s3:PutObject", resource)


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_not_action_and_not_resource_are_independent_complements(effect):
    statements = policies(fixture_policy('{ Effect = "' + effect + '", NotAction = "s3:Get*", NotResource = "excluded*" }'))["fixture"]
    assert statements[0].not_actions and statements[0].not_resources
    for action in ("s3:GetObject", "s3:PutObject"):
        for resource in ("excluded-one", "other"):
            if effect == "Deny":
                allowed = grants(statements + [Statement("Allow", (action,), (resource,))], action, resource)
                assert allowed == (action == "s3:GetObject" or resource == "excluded-one")
            else:
                # Complement allows never substitute for an exact source-bound grant.
                assert not grants(statements, action, resource)


@pytest.mark.parametrize("fields", [
    'Action = "s3:GetObject"',
    'Action = "s3:GetObject", Resource = "*", NotResource = "excluded"',
    'Action = "s3:GetObject", NotAction = "s3:PutObject", Resource = "*"',
    'Resource = "*"',
])
def test_missing_or_conflicting_iam_selectors_fail_closed(fields):
    with pytest.raises(AssertionError, match="Expected exactly one"):
        policies(fixture_policy('{ Effect = "Deny", ' + fields + ' }'))


def test_unknown_iam_effect_fails_closed():
    with pytest.raises(AssertionError, match="Unsupported IAM Effect"):
        policies(fixture_policy('{ Effect = "Audit", Action = "s3:GetObject", Resource = "*" }'))


@pytest.mark.parametrize("kind,action", list(TRANSACTION_ACTIONS.items())[:4])
def test_transaction_item_types_are_derived_from_source_not_a_policy_list(kind, action, graph):
    path = "peaso/storage/dynamodb.py"
    # Change only in-memory AST input; no source/runtime file is modified.
    source = graph.sources[path]
    marker = 'transactions = [\n'
    assert marker in source
    mutation = source.replace(marker, marker + f'                {{"{kind}": {{"TableName": self.table}}}},\n', 1)
    calls = Graph({path: mutation}).requirements("api", ["create_app"], "collector")
    assert any(r.action == "dynamodb:" + action and any("DynamoStore.enqueue" in step for step in r.trace) for r in calls)


@pytest.mark.parametrize("mutation", ["missing-grant", "wrong-resource", "wrong-role", "explicit-deny"])
def test_needed_transaction_permission_negative_fixtures_fail(mutation, requirements, iam):
    # Mutate only the API policy, retaining the other roles' real statements.
    anchor = 'resource "aws_iam_role_policy" "api" {'
    start = iam.index(anchor)
    end = iam.index('resource "aws_iam_role" "execution"', start)
    original = iam[start:end]
    if mutation == "missing-grant":
        changed = original.replace('"dynamodb:ConditionCheckItem", ', "")
    elif mutation == "wrong-resource":
        changed = original.replace(TABLE, "aws_dynamodb_table.other.arn")
    elif mutation == "wrong-role":
        changed = original.replace("role = aws_iam_role.api.id", "role = aws_iam_role.collector.id")
    else:
        changed = original.replace('Statement = concat([', 'Statement = concat([{ Effect = "Deny", Action = ["dynamodb:ConditionCheckItem"], Resource = "*" },', 1)
    assert changed != original
    broken = iam[:start] + changed + iam[end:]
    with pytest.raises(AssertionError, match="api lacks dynamodb:ConditionCheckItem"):
        assert_contract(requirements["api"], broken)


def test_new_worker_call_changes_only_that_roles_contract(graph):
    path = "peaso/worker.py"
    source = graph.sources[path].replace('if self.role == "collector":\n                encrypted', 'if self.role == "collector":\n                self.store.delete_connector(job["tenant"], job["connector_id"])\n                encrypted', 1)
    assert source != graph.sources[path]
    mutant = Graph({path: source})
    collector = mutant.requirements("collector", ["Worker.run_once"], "collector")
    analyzer = mutant.requirements("analyzer", ["Worker.run_once"], "analyzer")
    assert any(r.action == "dynamodb:DeleteItem" and any("delete_connector" in step for step in r.trace) for r in collector)
    assert not any(any("delete_connector" in step for step in r.trace) for r in analyzer)


def test_legacy_api_dynamodb_statement_reproduces_conditioncheck_gap(requirements, iam):
    # Reproduce the legacy DynamoDB action gap, without claiming the entire
    # current IAM template equals the historical frozen46 archive member.
    frozen = iam.replace('"dynamodb:ConditionCheckItem", ', "")
    assert frozen != iam
    gaps = missing(requirements["api"], frozen)
    assert gaps and {r.action for r in gaps} == {"dynamodb:ConditionCheckItem"}
    assert all(r.resource == TABLE and any("DynamoStore." in step for step in r.trace) for r in gaps)
    with pytest.raises(AssertionError, match="ConditionCheckItem"):
        assert_contract(requirements["api"], frozen)
    assert_contract(requirements["api"], iam)


@pytest.mark.parametrize("role", ["collector", "analyzer"])
@pytest.mark.parametrize("action", ["dynamodb:GetItem", "dynamodb:UpdateItem"])
@pytest.mark.parametrize("mutation", ["missing-grant", "wrong-resource", "wrong-role", "explicit-deny"])
def test_worker_scoped_expiry_negative_fixtures_fail(role, action, mutation, graph, iam):
    anchor = f'resource "aws_iam_role_policy" "{role}" {{'
    start = iam.index(anchor)
    end = iam.index('resource "aws_iam_role"', start + len(anchor))
    original = iam[start:end]
    if mutation == "missing-grant":
        changed = original.replace(f'"{action}", ', "")
    elif mutation == "wrong-resource":
        changed = original.replace(TABLE, "aws_dynamodb_table.other.arn")
    elif mutation == "wrong-role":
        changed = original.replace(f"role = aws_iam_role.{role}.id", "role = aws_iam_role.execution.id")
    else:
        marker = 'Statement = concat(['
        changed = original.replace(marker, marker + f'{{ Effect = "Deny", Action = ["{action}"], Resource = "*" }},', 1)
    assert changed != original
    expiry = {r for r in graph.requirements(role, ["DynamoStore.expire_job"], role) if r.action == action}
    assert expiry, f"No actual scoped expiry {action} call found"
    with pytest.raises(AssertionError, match=f"{role} lacks {action}"):
        assert_contract(expiry, iam[:start] + changed + iam[end:])


def test_targeted_worker_paths_do_not_scan_but_api_scheduler_still_does(requirements, iam):
    for role in ("collector", "analyzer"):
        assert not any(r.action == "dynamodb:Scan" for r in requirements[role])
        assert all("dynamodb:Scan" not in statement.actions for statement in policies(iam)[role])
    assert any(r.action == "dynamodb:Scan" and any("DynamoStore.expire" in step for step in r.trace) for r in requirements["api"])
    assert grants(policies(iam)["api"], "dynamodb:Scan", TABLE)


@pytest.mark.parametrize("path,marker,replacement", [
    ("peaso/worker.py", 'self.store.expire_job(job["tenant"], job["id"], now)', 'self.store.expire(now)'),
    ("peaso/storage/dynamodb.py", '                self._expire_job(job, now)\n                continue', '                self.expire(now)\n                continue'),
])
def test_reintroducing_global_expiry_in_targeted_paths_fails_contract(graph, iam, path, marker, replacement):
    source = graph.sources[path]
    assert marker in source
    mutant = Graph({path: source.replace(marker, replacement, 1)})
    for role in ("collector", "analyzer"):
        calls = mutant.requirements(role, ["Worker.run_once"], role)
        assert any(r.action == "dynamodb:Scan" for r in calls)
        with pytest.raises(AssertionError, match=f"{role} lacks dynamodb:Scan"):
            assert_contract(calls, iam)


def test_legacy_dynamodb_actions_reproduce_three_gaps_and_only_api_gap_now(requirements, iam, graph):
    frozen = iam.replace('"dynamodb:ConditionCheckItem", ', "").replace(
        '"dynamodb:PutItem", "dynamodb:Query", "dynamodb:Scan"',
        '"dynamodb:PutItem", "dynamodb:Query"',
    )
    path = "peaso/worker.py"
    marker = 'self.store.expire_job(job["tenant"], job["id"], now)'
    assert marker in graph.sources[path]
    legacy = Graph({path: graph.sources[path].replace(marker, 'self.store.expire(now)', 1)})
    legacy_required = set(requirements["api"])
    for role in ("collector", "analyzer"):
        legacy_required.update(legacy.requirements(role, ["Worker.__init__", "Worker.run_once"], role))
    assert {(r.role, r.action, r.resource) for r in missing(legacy_required, frozen)} == {
        ("api", "dynamodb:ConditionCheckItem", TABLE),
        ("collector", "dynamodb:Scan", TABLE),
        ("analyzer", "dynamodb:Scan", TABLE),
    }
    required = set().union(*requirements.values())
    assert {(r.role, r.action, r.resource) for r in missing(required, frozen)} == {("api", "dynamodb:ConditionCheckItem", TABLE)}
    with pytest.raises(AssertionError):
        assert_contract(legacy_required, frozen)
    assert_contract(required, iam)


def test_transaction_arguments_and_worker_call_resource_changes_are_rejected(graph):
    path = "peaso/storage/dynamodb.py"
    source = graph.sources[path].replace('{"ConditionCheck": {"TableName": self.table', '{"ConditionCheck": {"TableName": "wrong-table"', 1)
    assert source != graph.sources[path]
    with pytest.raises(AssertionError):
        Graph({path: source}).requirements("api", ["create_app"], "collector")
    source = graph.sources[path].replace('{"Update": update}', '{"Delete": update}', 1)
    assert source != graph.sources[path]
    calls = Graph({path: source}).requirements("api", ["scheduler_handler"], "collector")
    assert any(r.action == "dynamodb:DeleteItem" and any("DynamoStore.enqueue" in step for step in r.trace) for r in calls)


def test_progressive_stage_transactions_have_job_condition_permissions(graph, iam):
    required = graph.requirements("analyzer", ["DynamoStore.claim_stage", "DynamoStore.heartbeat_stage", "DynamoStore.finish_stage", "DynamoStore.stage_results"], "analyzer")
    assert {"dynamodb:ConditionCheckItem", "dynamodb:UpdateItem", "dynamodb:Query"} <= {row.action for row in required}
    assert_contract(required, iam)

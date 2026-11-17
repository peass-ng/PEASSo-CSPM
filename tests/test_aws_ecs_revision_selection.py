"""ECS configuration checks judge revisions that run or will run, not every historic one."""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

A = "123456789012"
SCOPE = A + "/us-east-1"
BASE = f"arn:aws:ecs:us-east-1:{A}:task-definition/"
CLUSTER = f"arn:aws:ecs:us-east-1:{A}:cluster/main"


def definition(family, revision, readonly=False, secret=False):
    container = {"name": "app", "readonlyRootFilesystem": readonly}
    if secret:
        container["environment"] = [{"name": "DB_PASSWORD"}]
    return {"taskDefinitionArn": f"{BASE}{family}:{revision}",
            "Definition": {"taskDefinition": {"family": family, "revision": revision, "status": "ACTIVE",
                                              "taskDefinitionArn": f"{BASE}{family}:{revision}",
                                              "containerDefinitions": [container]}}}


def envelope(kind, items, status=None):
    return {"type": kind, "scope": SCOPE, "service": "ecs", "status": status or ("collected" if items else "empty"), "items": items}


def run(definitions, services=(), tasks=(), service_status=None):
    collections = [envelope("ecs_task_definition", list(definitions)),
                   envelope("ecs_service", [{"serviceArn": f"arn:aws:ecs:us-east-1:{A}:service/main/{i}", "clusterArn": CLUSTER,
                                             "taskDefinition": arn} for i, arn in enumerate(services)], service_status),
                   envelope("ecs_task", [{"taskArn": f"arn:aws:ecs:us-east-1:{A}:task/main/{i}", "clusterArn": CLUSTER,
                                          "taskDefinitionArn": arn} for i, arn in enumerate(tasks)])]
    report = evaluate_snapshot(make_snapshot("aws", [SCOPE], collections),
                               checks=["aws.b.ecs.all_readonly_roots", "aws.c2b.ecs.no_credential_named_env_vars"])
    return {(f["check_id"], f["native_resource_id"].rsplit("/", 1)[1]): f["status"] for f in report["findings"]}


def test_only_latest_and_referenced_revisions_are_judged():
    revisions = [definition("api", n) for n in range(1, 6)] + [definition("worker", 1), definition("worker", 2, readonly=True)]
    found = run(revisions, services=[BASE + "api:3"], tasks=[BASE + "worker:1"])
    readonly = {name: status for (check, name), status in found.items() if check == "aws.b.ecs.all_readonly_roots"}
    assert readonly == {"api:1": "NOT_APPLICABLE", "api:2": "NOT_APPLICABLE", "api:3": "FAIL", "api:4": "NOT_APPLICABLE",
                        "api:5": "FAIL", "worker:1": "FAIL", "worker:2": "PASS"}


def test_secret_checks_still_cover_every_active_revision():
    found = run([definition("api", 1, secret=True), definition("api", 2)], services=[BASE + "api:2"])
    assert found[("aws.b.ecs.all_readonly_roots", "api:1")] == "NOT_APPLICABLE"
    assert found[("aws.c2b.ecs.no_credential_named_env_vars", "api:1")] in {"PASS", "FAIL"}


def test_without_complete_usage_inventory_every_revision_is_judged():
    found = run([definition("api", 1), definition("api", 2)], service_status="denied")
    assert {s for (c, _), s in found.items() if c == "aws.b.ecs.all_readonly_roots"} == {"FAIL"}

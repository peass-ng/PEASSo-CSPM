"""Offline artifact update route tests using exact private QA inputs."""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent if HERE.name == "tests" else HERE.parents[3]
sys.path.insert(0, str(ROOT))
if HERE.name == "tests":
    from scripts import peaso_deploy_artifact_update as artifact
    from scripts import peaso_deploy as deploy
else:
    sys.path.insert(0, str(HERE))
    import peaso_deploy_artifact_update as artifact
    deploy_spec = importlib.util.spec_from_file_location("proposed_peaso_deploy", HERE / "peaso_deploy.py")
    deploy = importlib.util.module_from_spec(deploy_spec)
    deploy_spec.loader.exec_module(deploy)
guard = artifact
fixture = SimpleNamespace(guard=artifact)
QA_ENV = "PEASO_ARTIFACT_UPDATE_QA_DIR"
QA_INPUTS = {
    "state.json": artifact.BASELINE_RAW_SHA,
    "old-plan.json": "a7d9ed2cd0cd8bc5fafdb986fe21dbbd169566aed7d01d94ade068b1aa5afdc0",
    "source.zip": artifact.SOURCE_ZIP_SHA,
    "api.zip": artifact.SOURCE_API_SHA,
    "frontend-build.json": artifact.SOURCE_FRONTEND_SHA,
    "release.json": artifact.SOURCE_RELEASE_SHA,
}

def candidate_frontend_files():
    """Retain every pinned asset name, with deterministic offline fixture bytes."""
    names = json.loads(OLD_FRONT.read_bytes())["files"]
    assert len(names) == 14 and "index.html" in names
    assert all(name and not Path(name).is_absolute() and ".." not in Path(name).parts for name in names)
    return {name: b"Offline artifact update fixture: " + name.encode() + b"\n"
            for name in sorted(names)}


def stage_candidate_frontend(destination: Path):
    """Materialize the candidate's own immutable build, independent of shared build output."""
    for name, body in candidate_frontend_files().items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

def private_inputs():
    value = os.environ.get(QA_ENV)
    if not value:
        raise unittest.SkipTest(f"{QA_ENV} exact private QA directory was not supplied")
    folder = Path(value)
    if not folder.is_absolute() or not folder.is_dir() or folder.is_symlink() or folder.stat().st_mode & 0o777 != 0o700:
        raise AssertionError("Artifact update QA input directory must be absolute, real, mode 0700")
    result = {}
    for name, expected in QA_INPUTS.items():
        path = folder / name
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("Artifact update QA input must be a real mode-0600 file: " + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise AssertionError("Artifact update QA input differs from pinned SHA256: " + name)
        result[name] = path
    return result

def synthetic_candidate_release(extra_files=None, api_extra=(), api_drop=(), drop_files=()):
    """One harmless README byte change, while retaining all 1,299 real members."""
    with zipfile.ZipFile(OLD_ZIP) as old:
        files = {name: old.read(name) for name in old.namelist() if name != "release.json"}
    assert len(files) == 1299 and "README.md" in files
    files["README.md"] += b"\nOffline artifact-update fixture only.\n"
    files.update(extra_files or {})
    for name in drop_files:
        del files[name]
    api_added = {name: files[name] for name in api_extra}
    manifest = {name: guard.sha(value) for name, value in files.items()}
    version = guard.sha(guard.canonical(manifest))
    release = {"source_version": version,
               "source_url": f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip",
               "license": "AGPL-3.0", "files": manifest}
    release_raw = (json.dumps(release, indent=2) + "\n").encode()
    source_output = io.BytesIO()
    with zipfile.ZipFile(source_output, "w", compression=zipfile.ZIP_DEFLATED) as out:
        for name, value in sorted(files.items()):
            out.writestr(name, value)
        out.writestr("release.json", release_raw)
    source_zip = source_output.getvalue()
    del files
    api_output = io.BytesIO()
    with zipfile.ZipFile(OLD_API) as old, zipfile.ZipFile(api_output, "w") as out:
        for member in old.infolist():
            if member.filename in api_drop:
                continue
            body = release_raw if member.filename == "peaso_release.json" else old.read(member)
            out.writestr(member, body)
        for name, body in sorted(api_added.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, body)
    api_zip = api_output.getvalue()
    frontend = {"source_version": version,
                "files": {name: guard.sha(body) for name, body in candidate_frontend_files().items()}}
    frontend_raw = (json.dumps(frontend, indent=2) + "\n").encode()
    image = ("111122223333.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker"
             "@sha256:" + "1" * 64)
    candidate = {"source_version": version, "release_json_sha256": guard.sha(release_raw),
                 "source_zip_sha256": guard.sha(source_zip), "api_zip_sha256": guard.sha(api_zip),
                 "frontend_manifest_sha256": guard.sha(frontend_raw), "worker_image": image}
    return candidate, release_raw, source_zip, api_zip, frontend_raw


def complete_positive_fixture(state, release=None):
    """Build a complete offline plan from actual 75 state rows and seven data inputs."""
    candidate, release_raw, source_zip, api_zip, frontend_raw = release or synthetic_candidate_release()
    old = json.loads(OLD_PLAN.read_bytes())
    raw_resources = guard.managed(state)
    state_data = {}
    for block in state["resources"]:
        if block.get("mode") == "data":
            state_data[f'data.{block["type"]}.{block["name"]}'] = block["instances"][0]["attributes"]
    assert len(state_data) == 7
    drift = []
    resources = deepcopy(raw_resources)
    for address in ('aws_ecs_task_definition.tasks["collector"]',
                    'aws_ecs_task_definition.tasks["analyzer"]'):
        before = raw_resources[address]
        assert before.get("tags") is None
        after = deepcopy(before)
        after["tags"] = {}
        drift.append({"address": address, "mode": "managed", "change": {
            "actions": ["update"], "before": before, "after": after, "after_unknown": {}}})
        resources[address] = after
    prior = deepcopy(old["prior_state"]["values"]["root_module"]["resources"])
    assert len(prior) == 82
    for row in prior:
        address = row["address"]
        row["values"] = deepcopy(resources[address] if row["mode"] == "managed" else state_data[address])
    prior_map = {row["address"]: row for row in prior}
    old_changes = {row["address"]: row for row in old["resource_changes"]}
    assert len(old_changes) == 75
    rows = []
    for address, before in resources.items():
        old_row = old_changes[address]
        row = {key: deepcopy(old_row[key]) for key in ("address", "mode", "type", "name", "provider_name")}
        if "index" in old_row:
            row["index"] = deepcopy(old_row["index"])
        row["change"] = {"actions": ["no-op"], "before": deepcopy(before),
                         "after": deepcopy(before), "after_unknown": {}}
        rows.append(row)
    changes = {row["address"]: row["change"] for row in rows}
    version = candidate["source_version"]
    source_url = f"https://cspm.hacktricks.wiki/source/peaso-source-{version}.zip"
    api_hash = base64.b64encode(bytes.fromhex(candidate["api_zip_sha256"])).decode()
    for address in ("aws_lambda_function.api", "aws_lambda_function.scheduler"):
        before = changes[address]["before"]
        after = deepcopy(before)
        after["source_code_hash"] = api_hash
        after["environment"][0]["variables"]["PEASO_SOURCE_VERSION"] = version
        after["environment"][0]["variables"]["PEASO_SOURCE_URL"] = source_url
        changes[address].update({"actions": ["update"], "after": after})
    for address in ('aws_ecs_task_definition.tasks["collector"]',
                    'aws_ecs_task_definition.tasks["analyzer"]'):
        before = changes[address]["before"]
        after = deepcopy(before)
        container = json.loads(after["container_definitions"])
        container[0]["image"] = candidate["worker_image"]
        for item in container[0]["environment"]:
            if item["name"] == "PEASO_SOURCE_VERSION":
                item["value"] = version
        after["container_definitions"] = json.dumps(container, separators=(",", ":"))
        for key in ("arn", "arn_without_revision", "id", "revision", "enable_fault_injection", "ipc_mode", "pid_mode", "tags"):
            after[key] = None
        after["volume"] = [dict(after["volume"][0])]
        after["volume"][0].pop("configure_at_launch")
        markers = {key: True for key in ("arn", "arn_without_revision", "id", "revision", "enable_fault_injection")}
        markers["volume"] = [{"configure_at_launch": True, "docker_volume_configuration": [],
                              "efs_volume_configuration": [], "fsx_windows_file_server_volume_configuration": [],
                              "s3files_volume_configuration": []}]
        changes[address].update({"actions": ["delete", "create"], "after": after,
                                 "after_unknown": markers})
    for address, field in (("aws_sfn_state_machine.scan", "definition"),
                           ("aws_iam_role_policy.workflow", "policy")):
        before = changes[address]["before"]
        after = deepcopy(before)
        after[field] = re.sub(r'(task-definition/hacktricks-cspm-(?:collector|analyzer)):7', r'\1:8', before[field])
        assert after[field] != before[field]
        changes[address].update({"actions": ["update"], "after": after})
    data = {"errored": False, "applyable": True, "complete": True,
            "terraform_version": "1.14.3", "resource_drift": drift,
            "prior_state": {"values": {"root_module": {"resources": prior}}},
            "resource_changes": rows}
    refresh = {"errored": False, "terraform_version": "1.14.3", "resource_drift": deepcopy(drift)}
    refresh_raw = guard.canonical(refresh)
    plan_raw = guard.canonical(data)
    plan_binary = b"offline synthetic Terraform plan; never apply\n"
    approved_drift = {row["address"]: {
        "before_sha256": guard.sha(guard.canonical(row["change"]["before"])),
        "after_sha256": guard.sha(guard.canonical(row["change"]["after"])),
        "change_sha256": guard.sha(guard.canonical(row["change"]))} for row in drift}
    approved_changes = {address: {"actions": changes[address]["actions"],
                                  "changed_fields": guard.current.changed_fields(changes[address]),
                                  "change_sha256": guard.sha(guard.canonical(changes[address]))}
                        for address in guard.SIX_ACTIONS}
    baseline_release = {"source_version": guard.SOURCE_VERSION,
                        "release_json_sha256": guard.SOURCE_RELEASE_SHA,
                        "source_zip_sha256": guard.SOURCE_ZIP_SHA,
                        "api_zip_sha256": guard.SOURCE_API_SHA,
                        "frontend_manifest_sha256": guard.SOURCE_FRONTEND_SHA,
                        "worker_image": guard.SOURCE_IMAGE}
    contract = {"schema": "peaso-artifact-update-epoch29-v1", "account": guard.ACCOUNT,
                "backend": guard.BACKEND,
                "state": {"sha256": guard.BASELINE_RAW_SHA,
                          "canonical_sha256": guard.BASELINE_CANONICAL_SHA,
                          "lineage": guard.LINEAGE, "serial": guard.SERIAL,
                          "managed_address_sha256": guard.ADDRESS_SHA, "managed_count": guard.COUNT},
                "baseline_release": baseline_release, "candidate_release": candidate,
                "plan": {"sha256": guard.sha(plan_binary), "json_sha256": guard.sha(plan_raw)},
                "refresh": {"json_sha256": guard.sha(refresh_raw)},
                "approved_drift": approved_drift, "approved_changes": approved_changes}
    blobs = {"contract_raw": guard.canonical(contract), "state_raw": BASELINE.read_bytes(),
             "baseline_release_raw": OLD_RELEASE.read_bytes(),
             "refresh_raw": refresh_raw, "plan_raw": plan_raw, "plan_binary": plan_binary,
             "candidate_release_raw": release_raw, "candidate_source_zip": source_zip,
             "candidate_api_zip": api_zip, "candidate_frontend_manifest": frontend_raw}
    return contract, data, refresh, blobs


def private_file(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    return path


class Client:
    def __init__(self, kind, *, active=False, account=artifact.ACCOUNT):
        self.kind, self.active, self.account = kind, active, account

    def get_caller_identity(self):
        return {"Account": self.account}

    def list_executions(self, **kwargs):
        return {"executions": [{"executionArn": "active"}] if self.active else []}

    def list_tasks(self, **kwargs):
        return {"taskArns": ["active"] if self.active else []}

    def get_item(self, **kwargs):
        return {}

    def scan(self, **kwargs):
        return {"Count": 0}

    def create_invalidation(self, **kwargs):
        return {"Invalidation": {"Id": "offline-only"}}


class Session:
    def __init__(self, *, active=False, account=artifact.ACCOUNT):
        self.active, self.account = active, account

    def client(self, kind):
        return Client(kind, active=self.active, account=self.account)


class ResolvedSession(Session):
    def __init__(self, resources, plan_rows, *, corrupt_object=False):
        super().__init__()
        self.resources, self.plan_rows = resources, plan_rows
        self.corrupt_object = corrupt_object

    def client(self, kind):
        if kind == "iam":
            return self
        if kind == "s3":
            return self
        return super().client(kind)

    def get_role_policy(self, **kwargs):
        workflow = self.resources["aws_iam_role_policy.workflow"]
        api = self.resources["aws_iam_role_policy.api"]
        if kwargs["RoleName"] == workflow["role"] and kwargs["PolicyName"] == workflow["name"]:
            text = self.plan_rows["aws_iam_role_policy.workflow"]["change"]["after"]["policy"]
        elif kwargs["RoleName"] == api["role"] and kwargs["PolicyName"] == api["name"]:
            text = api["policy"]
        else:
            raise AssertionError(kwargs)
        return {"PolicyDocument": json.loads(text)}

    def get_bucket_policy(self, **kwargs):
        assert kwargs["Bucket"] == self.resources["aws_s3_bucket.templates[0]"]["id"]
        return {"Policy": self.resources["aws_s3_bucket_policy.templates[0]"]["policy"]}

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        digest = key.rsplit("customer-role-", 1)[-1].removesuffix(".json") if "customer-role-" in key else fixture.guard.current.TEMPLATE_HASHES[-1]
        path = ROOT / "infra/aws" / f"customer-role-{digest}.json"
        body = path.read_bytes()
        if self.corrupt_object:
            body += b"changed"
        template = key.startswith("customer-role-")
        result = {"ContentLength": len(body), "Body": io.BytesIO(body),
                  "ContentType": "application/json",
                  "ContentDisposition": 'attachment; filename="customer-role.json"'}
        if template:
            result.update({"Metadata": {"sha256": digest},
                           "CacheControl": "public,max-age=31536000,immutable"})
        if kwargs.get("ChecksumMode") == "ENABLED":
            result.update({"ServerSideEncryption": "AES256", "ChecksumType": "FULL_OBJECT",
                           "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode()})
        return result

    def get_object_acl(self, **kwargs):
        return {"Owner": {"ID": "owner"}, "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"}]}


class ArtifactOuterRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inputs = private_inputs()
        global BASELINE, OLD_PLAN, OLD_ZIP, OLD_API, OLD_FRONT, OLD_RELEASE
        BASELINE = inputs["state.json"]
        OLD_PLAN = inputs["old-plan.json"]
        OLD_ZIP = inputs["source.zip"]
        OLD_API = inputs["api.zip"]
        OLD_FRONT = inputs["frontend-build.json"]
        OLD_RELEASE = inputs["release.json"]
        fixture.BASELINE = BASELINE
        fixture.complete_positive_fixture = complete_positive_fixture
        cls.temporary = tempfile.TemporaryDirectory(prefix="epoch29-private-route-")
        cls.root = Path(cls.temporary.name)
        cls.infra = cls.root / "infra/aws"
        cls.build = cls.infra / "build"
        cls.build.mkdir(parents=True)
        state = json.loads(fixture.BASELINE.read_bytes())
        cls.review, cls.plan_data, cls.refresh, cls.blobs = fixture.complete_positive_fixture(state)
        # A real refresh-only JSON includes the same complete prior inventory.
        cls.refresh["prior_state"] = {"values": {"root_module": {
            "resources": deepcopy(cls.plan_data["prior_state"]["values"]["root_module"]["resources"])}}}
        cls.blobs["refresh_raw"] = artifact.canonical(cls.refresh)
        cls.review["refresh"]["json_sha256"] = artifact.sha(cls.blobs["refresh_raw"])
        with zipfile.ZipFile(io.BytesIO(cls.blobs["candidate_source_zip"])) as archive:
            for name in archive.namelist():
                body = archive.read(name)
                if name == "release.json":
                    path = cls.build / "source-snapshot/release.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
                    continue
                for base in (cls.root, cls.build / "source-snapshot"):
                    path = base / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(body)
        target_dist = cls.build / "source-snapshot/frontend/dist"
        stage_candidate_frontend(target_dist)
        cls.release = json.loads(cls.blobs["candidate_release_raw"])
        (cls.build / "release.json").write_bytes(cls.blobs["candidate_release_raw"])
        (cls.build / f'peaso-source-{cls.release["source_version"]}.zip').write_bytes(cls.blobs["candidate_source_zip"])
        (cls.build / "api.zip").write_bytes(cls.blobs["candidate_api_zip"])
        (cls.build / "frontend-build.json").write_bytes(cls.blobs["candidate_frontend_manifest"])
        (cls.infra / "deployment.auto.tfvars.json").write_text(json.dumps({
            "source_version": cls.release["source_version"],
            "worker_image": cls.review["candidate_release"]["worker_image"],
            "api_zip": str((cls.build / "api.zip").resolve())}))
        backend = cls.infra / ".terraform/terraform.tfstate"
        backend.parent.mkdir(parents=True)
        backend.write_text(json.dumps({"backend": {"type": "s3", "config": artifact.BACKEND}}))
        cls.plan = private_file(cls.root / "saved-plan.tfplan", cls.blobs["plan_binary"])
        paths = {"state_path": private_file(cls.root / "state.private.json", cls.blobs["state_raw"]),
                 "refresh_path": private_file(cls.root / "refresh.private.json", cls.blobs["refresh_raw"]),
                 "plan_json_path": private_file(cls.root / "plan.private.json", cls.blobs["plan_raw"]),
                 "baseline_release_path": private_file(cls.root / "baseline-release.private.json",
                                                       cls.blobs["baseline_release_raw"])}
        outer = {"schema": "peaso-artifact-update-evidence-v1", "review": cls.review,
                 "evidence": {key: str(value.resolve()) for key, value in paths.items()}}
        cls.contract_raw = artifact.canonical(outer)
        cls.contract = private_file(cls.root / "contract.private.json", cls.contract_raw)
        cls.contract_sha = artifact.sha(cls.contract_raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def real_context(self):
        return artifact.load_context(self.plan, self.blobs["plan_raw"], self.plan_data,
                                     self.contract, self.contract_sha, self.infra, self.build)

    def test_real_private_loader_reviews_complete_fixture_and_frozen_root(self):
        result = self.real_context()
        self.assertEqual(len(result["resources"]), 75)
        self.assertEqual(len(result["approved_changes"]), 6)
        self.assertEqual(result["release"]["source_version"], self.release["source_version"])


    def test_original_preapply_accepts_real_outer_envelope_and_rejects_changed_live_facts(self):
        state_text = [self.blobs["state_raw"].decode()]
        refresh_text = [self.blobs["refresh_raw"].decode()]
        def terraform_stub(*args, capture=False):
            if args[:2] == ("show", "-json") and Path(args[2]) == self.plan:
                return SimpleNamespace(stdout=self.blobs["plan_raw"].decode())
            if args[:2] == ("state", "pull"):
                return SimpleNamespace(stdout=state_text[0])
            if args[:2] == ("plan", "-refresh-only"):
                return SimpleNamespace(stdout="")
            if args[:2] == ("show", "-json"):
                return SimpleNamespace(stdout=refresh_text[0])
            raise AssertionError(args)
        with patch.object(deploy, "INFRA", self.infra), patch.object(deploy, "BUILD", self.build), \
             patch.object(deploy, "terraform", side_effect=terraform_stub):
            self.assertIsNone(deploy.verify_current_update_live(
                self.plan, self.contract, self.contract_sha, Session(), artifact=True))
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(active=True), artifact=True)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(account="000000000000"), artifact=True)
            altered_state = json.loads(state_text[0])
            altered_state["serial"] = 30
            state_text[0] = json.dumps(altered_state)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(), artifact=True)
            state_text[0] = self.blobs["state_raw"].decode()
            altered_refresh = deepcopy(self.refresh)
            altered_refresh["resource_drift"] = []
            refresh_text[0] = json.dumps(altered_refresh)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_live(self.plan, self.contract, self.contract_sha,
                                                  Session(), artifact=True)


    def test_original_resolved_route_uses_real_loader_and_complete_object_readback(self):
        context = self.real_context()
        rows = {row["address"]: row for row in self.plan_data["resource_changes"]}
        revisions = {stage: f"arn:aws:ecs:us-east-1:{artifact.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:8"
                     for stage in ("collector", "analyzer")}
        definition = json.loads(rows["aws_sfn_state_machine.scan"]["change"]["after"]["definition"])
        def show(*args, capture=False):
            self.assertEqual(args[:2], ("show", "-json"))
            return SimpleNamespace(stdout=self.blobs["plan_raw"].decode())
        with patch.object(deploy, "INFRA", self.infra), patch.object(deploy, "BUILD", self.build), \
             patch.object(deploy, "terraform", side_effect=show):
            deploy.verify_current_update_resolved(ResolvedSession(context["resources"], rows),
                                                  self.plan, self.contract, self.contract_sha,
                                                  definition, revisions, artifact=True)
            with self.assertRaises(RuntimeError):
                deploy.verify_current_update_resolved(
                    ResolvedSession(context["resources"], rows, corrupt_object=True),
                    self.plan, self.contract, self.contract_sha, definition, revisions, artifact=True)

    def test_resolved_reference_and_publication_target_binding(self):
        context = self.real_context()
        resources = context["resources"]
        rows = {row["address"]: row for row in self.plan_data["resource_changes"]}
        revisions = {stage: f"arn:aws:ecs:us-east-1:{artifact.ACCOUNT}:task-definition/hacktricks-cspm-{stage}:8"
                     for stage in ("collector", "analyzer")}
        workflow = json.loads(rows["aws_sfn_state_machine.scan"]["change"]["after"]["definition"])
        workflow_policy = json.loads(rows["aws_iam_role_policy.workflow"]["change"]["after"]["policy"])
        api_policy = json.loads(resources["aws_iam_role_policy.api"]["policy"])
        template_policy = json.loads(resources["aws_s3_bucket_policy.templates[0]"]["policy"])
        artifact.check_resolved_documents(resources, rows, workflow, workflow_policy,
                                          api_policy, template_policy, revisions)
        artifact.check_publish_target({"frontend_bucket": {"value": "hacktricks-cspm-frontend-111122223333"},
                                       "cloudfront_distribution_id": {"value": "E24KDR2EDPKSBS"}})
        with self.assertRaises(RuntimeError):
            artifact.check_publish_target({"frontend_bucket": {"value": "wiki-tools"},
                                           "cloudfront_distribution_id": {"value": "E24KDR2EDPKSBS"}})

    def test_candidate_frontend_survives_an_unrelated_later_build(self):
        manifest = json.loads(self.blobs["candidate_frontend_manifest"])
        self.assertEqual(len(manifest["files"]), 14)
        target = self.build / "source-snapshot/frontend/dist"
        actual = {str(path.relative_to(target)): artifact.sha(path.read_bytes())
                  for path in target.rglob("*") if path.is_file()}
        self.assertEqual(actual, manifest["files"])
        with tempfile.TemporaryDirectory(prefix="foreign-build-") as temporary:
            foreign = Path(temporary) / "frontend/dist"
            foreign.mkdir(parents=True)
            (foreign / "index.html").write_bytes(b"A different release was built later.\n")
            independent = Path(temporary) / "candidate/dist"
            stage_candidate_frontend(independent)
            staged = {str(path.relative_to(independent)): artifact.sha(path.read_bytes())
                      for path in independent.rglob("*") if path.is_file()}
            self.assertEqual(staged, manifest["files"])
            self.assertNotEqual(artifact.sha((foreign / "index.html").read_bytes()),
                                manifest["files"]["index.html"])




class ArtifactSourceInventoryBounds(unittest.TestCase):
    """Public reproduction inputs grow the source ZIP; bounds and runtime set stay exact."""
    CONFIG = "peaso/checks/aws_config_recording.py"
    UNEXPECTED = "peaso/checks/zz_offline_runtime_fixture.py"
    LEDGER = "docs/compliance-ledgers/offline-fixture.json"

    @classmethod
    def setUpClass(cls):
        inputs = private_inputs()
        global BASELINE, OLD_PLAN, OLD_ZIP, OLD_API, OLD_FRONT, OLD_RELEASE
        BASELINE, OLD_PLAN, OLD_ZIP = inputs["state.json"], inputs["old-plan.json"], inputs["source.zip"]
        OLD_API, OLD_FRONT, OLD_RELEASE = inputs["api.zip"], inputs["frontend-build.json"], inputs["release.json"]
        cls.state = json.loads(BASELINE.read_bytes())
        cls.config = (ROOT / cls.CONFIG).read_bytes()
        assert guard.sha(cls.config) == guard.APPROVED_RUNTIME_ADDITIONS[cls.CONFIG]
        cls.extra = {cls.CONFIG: cls.config, cls.LEDGER: b'{"offline": true}\n'}
        cls.blobs = cls.fixture(extra_files=cls.extra, api_extra=(cls.CONFIG,))

    @classmethod
    def fixture(cls, **release):
        return complete_positive_fixture(cls.state, synthetic_candidate_release(**release))[3]


    def test_legacy_baseline_runtime_set_is_reviewed(self):
        blobs = self.fixture(extra_files={self.LEDGER: self.extra[self.LEDGER]})
        self.assertEqual(len(guard.review_bytes(**blobs)["approved_changes"]), 6)

    def test_approved_config_runtime_and_ledger_members_are_reviewed(self):
        result = guard.review_bytes(**self.blobs)
        self.assertEqual(len(result["approved_changes"]), 6)
        release = json.loads(self.blobs["candidate_release_raw"])
        self.assertEqual(len(release["files"]), 1301)
        self.assertEqual(release["files"][self.CONFIG], guard.APPROVED_RUNTIME_ADDITIONS[self.CONFIG])






    def test_unexpected_runtime_member_rejected(self):
        for extra in ({self.UNEXPECTED: b"VALUE = 1\n"},
                      {self.CONFIG: self.config, self.UNEXPECTED: b"VALUE = 1\n"},
                      {"risk_rules/zz_offline.yaml": b"rules: []\n"}):
            with self.subTest(sorted(extra)):
                blobs = self.fixture(extra_files=extra, api_extra=tuple(extra))
                with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
                    guard.review_bytes(**blobs)

    def test_approved_runtime_member_wrong_bytes_rejected(self):
        blobs = self.fixture(extra_files={self.CONFIG: self.config + b"\n"}, api_extra=(self.CONFIG,))
        with self.assertRaisesRegex(RuntimeError, "required runtime inventory differs"):
            guard.review_bytes(**blobs)

    def test_source_archive_budget_rejects_one_byte_over(self):
        size = len(self.blobs["candidate_source_zip"])
        with patch.object(guard, "MAX_SOURCE_ARCHIVE_BYTES", size - 1):
            with self.assertRaisesRegex(RuntimeError, "source ZIP exceeds measured archive budget"):
                guard.review_bytes(**self.blobs)
        with patch.object(guard, "MAX_SOURCE_ARCHIVE_BYTES", size):
            guard.review_bytes(**self.blobs)

    def test_source_expanded_and_member_budgets_reject_one_over(self):
        with zipfile.ZipFile(io.BytesIO(self.blobs["candidate_source_zip"])) as archive:
            members = archive.infolist()
        expanded = sum(member.file_size for member in members)
        largest = max(member.file_size for member in members)
        for name, value in (("MAX_SOURCE_UNCOMPRESSED_BYTES", expanded - 1),
                            ("MAX_SOURCE_MEMBERS", len(members) - 2),
                            ("MAX_SOURCE_MEMBER_BYTES", largest - 1)):
            with self.subTest(name), patch.object(guard, name, value):
                with self.assertRaisesRegex(RuntimeError, "source ZIP inventory differs"):
                    guard.review_bytes(**self.blobs)

    def test_api_must_carry_approved_runtime_member(self):
        blobs = self.fixture(extra_files=self.extra)
        with self.assertRaisesRegex(RuntimeError, "API ZIP inventory or metadata differs"):
            guard.review_bytes(**blobs)

    def test_api_must_keep_every_baseline_runtime_member(self):
        blobs = self.fixture(extra_files=self.extra, api_extra=(self.CONFIG,), api_drop=("peaso/engine.py",))
        with self.assertRaisesRegex(RuntimeError, "API ZIP inventory or metadata differs"):
            guard.review_bytes(**blobs)

    def test_candidate_cannot_drop_baseline_runtime_member(self):
        # The ledger keeps the candidate at 1,299 members so the drop itself is judged.
        blobs = self.fixture(extra_files={self.LEDGER: self.extra[self.LEDGER]},
                             drop_files=("peaso/engine.py",), api_drop=("peaso/engine.py",))
        with self.assertRaisesRegex(RuntimeError, "omitted a baseline source member"):
            guard.review_bytes(**blobs)


if __name__ == "__main__":
    unittest.main()

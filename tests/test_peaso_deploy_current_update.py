"""Offline source-bound decisions for one reviewed hosted update plan."""
from __future__ import annotations

import contextlib
import base64
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
import zlib
from unittest.mock import patch

from scripts import peaso_deploy as deploy
from scripts import peaso_deploy_current_update as update


POOL = f"arn:aws:cognito-idp:us-east-1:{update.ACCOUNT}:userpool/us-east-1_example"
CALLER_ROLE = f"arn:aws:sts::{update.ACCOUNT}:assumed-role/LabManagementOutOfScope/"


def prior_data_fixture(state):
    """Terraform prior_state shape: seven data rows alongside managed rows."""
    values = {
        "data.aws_acm_certificate.wiki": {"id": "owned-certificate", "domain": "cspm.hacktricks.wiki"},
        "data.aws_availability_zones.available": {"id": "us-east-1", "names": ["us-east-1a"]},
        "data.aws_caller_identity.current": {
            "account_id": update.ACCOUNT, "id": update.ACCOUNT,
            "arn": CALLER_ROLE + "gntd-StateFixture", "user_id": "AROAOWNED:gntd-StateFixture"},
        "data.aws_cloudfront_cache_policy.api": {"id": "owned-api-cache"},
        "data.aws_cloudfront_cache_policy.frontend": {"id": "owned-frontend-cache"},
        "data.aws_cloudfront_origin_request_policy.api": {"id": "owned-api-origin"},
        "data.aws_route53_zone.wiki": {"id": "owned-wiki-zone", "name": "hacktricks.wiki."},
    }
    rows = []
    for address, (kind, name) in update.PRIOR_DATA_SOURCES.items():
        attributes = values[address]
        state["resources"].append({"mode": "data", "type": kind, "name": name,
                                   "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                                   "instances": [{"schema_version": 0, "attributes": attributes,
                                                  "sensitive_attributes": []}]})
        current = dict(attributes)
        if kind == "aws_caller_identity":
            current["arn"] = CALLER_ROLE + "gntd-PlanFixture"
            current["user_id"] = "AROAOWNED:gntd-PlanFixture"
        rows.append({"mode": "data", "type": kind, "name": name, "address": address,
                     "provider_name": "registry.terraform.io/hashicorp/aws",
                     "schema_version": 0, "sensitive_values": {}, "values": current})
    return rows


def policy(actions):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": actions, "Resource": POOL}]}, sort_keys=True)


def fixture():
    api_before = {"id": "hacktricks-cspm-api:cognito", "name": "hacktricks-cspm-api-cognito",
                  "role": "hacktricks-cspm-api",
                  "policy": policy(["cognito-idp:AdminGetUser", "cognito-idp:DescribeUserPoolClient"])}
    api_after = dict(api_before, policy=policy([
        "cognito-idp:AdminGetUser", "cognito-idp:ListUserPoolClients", "cognito-idp:DescribeUserPoolClient"]))
    bucket = {"id": "hacktricks-cspm-templates-111122223333",
              "arn": "arn:aws:s3:::hacktricks-cspm-templates-111122223333"}
    state = {"lineage": "07a58930-bf9f-7350-17e9-5e4d275a308a", "serial": 23, "resources": [
        {"mode": "managed", "type": "aws_iam_role_policy", "name": "api",
         "instances": [{"attributes": api_before}]},
        {"mode": "managed", "type": "aws_s3_bucket", "name": "templates",
         "instances": [{"index_key": 0, "attributes": bucket}]},
    ]}
    resources = {"aws_iam_role_policy.api": api_before, "aws_s3_bucket.templates[0]": bucket}
    change = {"actions": ["update"], "before": api_before, "after": api_after, "after_unknown": {}}
    rows = [{"mode": "managed", "type": "aws_iam_role_policy", "name": "api",
             "address": "aws_iam_role_policy.api", "change": change},
            {"mode": "managed", "type": "aws_s3_bucket", "name": "templates", "index": 0,
             "address": "aws_s3_bucket.templates[0]", "change": {
                 "actions": ["no-op"], "before": bucket, "after": bucket, "after_unknown": {}}}]
    prior_managed = [{"mode": "managed", "address": key, "values": value}
                     for key, value in resources.items()]
    prior_data = prior_data_fixture(state)
    data = {"resource_drift": [], "prior_state": {"values": {"root_module": {"resources":
            prior_managed + prior_data}}},
            "resource_changes": rows}
    contract = {"schema": "peaso-current-update-v1", "account": update.ACCOUNT,
                "backend": update.BACKEND,
                "state": {"path": "/private/fixture/state.json", "sha256": "0" * 64,
                          "lineage": state["lineage"], "serial": state["serial"],
                          "managed_address_sha256": update.digest(("\n".join(sorted(resources)) + "\n").encode())},
                "plan": {"sha256": "1" * 64, "json_sha256": "2" * 64,
                         "json_path": "/private/fixture/plan.json"},
                "release": {"source_version": "3" * 64, "release_json_sha256": "4" * 64,
                            "source_zip_sha256": "5" * 64, "api_zip_sha256": "6" * 64,
                            "frontend_manifest_sha256": "7" * 64, "worker_image": "fixture"},
                "approved_drift": {},
                "approved_changes": {"aws_iam_role_policy.api": {
                    "actions": ["update"], "changed_fields": ["policy"],
                    "change_sha256": update.digest(update.canonical(change))}}}
    return data, contract, state


class CurrentUpdateReview(unittest.TestCase):
    def setUp(self):
        self.data, self.contract, self.state = fixture()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.infra = Path(self.temp.name)
        addresses = "aws_iam_role_policy.api\naws_s3_bucket.templates[0]\n"
        self.patches = [
            patch.object(update, "BASELINE_COUNT", 2),
            patch.object(update, "BASELINE_ADDRESSES_SHA256", update.digest(addresses.encode())),
            patch.object(update, "TEMPLATE_ADDRESSES", {}),
            patch.object(update, "RUNTIME_REQUIRED", set()),
            patch.object(update, "REVIEWED_DRIFT", {}),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def review(self):
        return update.review(self.data, self.contract, self.state, self.infra)

    def test_exact_owned_iam_read_addition_and_untouched_resource(self):
        result = self.review()
        self.assertEqual(list(result["approved_changes"]), ["aws_iam_role_policy.api"])
        self.assertEqual(result["serial"], 23)

    def test_extra_iam_action_is_rejected_even_when_contract_hash_is_updated(self):
        row = self.data["resource_changes"][0]["change"]
        document = json.loads(row["after"]["policy"])
        document["Statement"][0]["Action"].append("cognito-idp:AdminUpdateUserAttributes")
        row["after"]["policy"] = json.dumps(document)
        self.contract["approved_changes"]["aws_iam_role_policy.api"]["change_sha256"] = update.digest(update.canonical(row))
        with self.assertRaisesRegex(RuntimeError, "beyond the one read action"):
            self.review()

    def test_unknown_iam_policy_and_foreign_address_are_rejected(self):
        row = self.data["resource_changes"][0]["change"]
        row["after_unknown"] = {"policy": True}
        self.contract["approved_changes"]["aws_iam_role_policy.api"]["change_sha256"] = update.digest(update.canonical(row))
        with self.assertRaisesRegex(RuntimeError, "defers a security"):
            self.review()
        row["after_unknown"] = {}
        self.data["resource_changes"].append({"mode": "managed", "address": "aws_s3_bucket.wiki",
                                               "type": "aws_s3_bucket", "name": "wiki", "change": {
                                                   "actions": ["create"], "before": None, "after": {"bucket": "wiki"}}})
        with self.assertRaisesRegex(RuntimeError, "exact CSPM address inventory"):
            self.review()

    def test_prior_identity_and_signed_change_hash_are_bound(self):
        self.data["prior_state"]["values"]["root_module"]["resources"][0]["values"] = {"id": "other"}
        with self.assertRaisesRegex(RuntimeError, "prior values differ"):
            self.review()
        self.data, self.contract, self.state = fixture()
        self.contract["approved_changes"]["aws_iam_role_policy.api"]["changed_fields"] = []
        with self.assertRaisesRegex(RuntimeError, "reviewed action/fields/values"):
            self.review()


    def test_prior_data_sources_are_exact_and_caller_session_may_rotate(self):
        self.assertEqual(len(self.data["prior_state"]["values"]["root_module"]["resources"]), 9)
        self.review()
        data_rows = self.data["prior_state"]["values"]["root_module"]["resources"]
        caller = next(row for row in data_rows if row["address"] == "data.aws_caller_identity.current")
        caller["values"]["user_id"] = "AROAOWNED:gntd-WrongSession"
        with self.assertRaisesRegex(RuntimeError, "caller role or session"):
            self.review()

    def test_altered_eighth_or_foreign_prior_data_source_is_rejected(self):
        data_rows = self.data["prior_state"]["values"]["root_module"]["resources"]
        acm = next(row for row in data_rows if row["address"] == "data.aws_acm_certificate.wiki")
        acm["values"]["domain"] = "unreviewed.example"
        with self.assertRaisesRegex(RuntimeError, "values differ from state"):
            self.review()
        acm["values"]["domain"] = "cspm.hacktricks.wiki"
        extra = dict(acm, address="data.aws_s3_bucket.wiki", type="aws_s3_bucket", name="wiki")
        data_rows.append(extra)
        with self.assertRaisesRegex(RuntimeError, "prior inventory"):
            self.review()
        data_rows.pop()
        acm["address"] = "data.aws_acm_certificate.foreign"
        with self.assertRaisesRegex(RuntimeError, "data-source identity"):
            self.review()


class CurrentUpdateFieldPolicies(unittest.TestCase):
    def test_worker_image_and_source_only_preserve_readonly_security(self):
        old = {"name": "collector", "readonlyRootFilesystem": True, "user": "10001:10001",
               "image": "old@sha256:" + "0" * 64,
               "environment": [{"name": "PEASO_SOURCE_VERSION", "value": "old"},
                               {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"}]}
        new = dict(old, image="new@sha256:" + "1" * 64,
                   environment=[{"name": "PEASO_SOURCE_VERSION", "value": "new"},
                                {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"}])
        update.check_task({"container_definitions": json.dumps([old])},
                          {"container_definitions": json.dumps([new])})
        new["readonlyRootFilesystem"] = False
        with self.assertRaisesRegex(RuntimeError, "security or configuration"):
            update.check_task({"container_definitions": json.dumps([old])},
                              {"container_definitions": json.dumps([new])})

    def test_lambda_source_fields_do_not_open_other_environment_values(self):
        old = {"environment": [{"variables": {"PEASO_SOURCE_VERSION": "old", "PEASO_STORAGE": "dynamodb"}}]}
        new = {"environment": [{"variables": {"PEASO_SOURCE_VERSION": "new", "PEASO_STORAGE": "dynamodb"}}]}
        update.check_lambda(old, new)
        new["environment"][0]["variables"]["PEASO_STORAGE"] = "sqlite"
        with self.assertRaisesRegex(RuntimeError, "unrelated values"):
            update.check_lambda(old, new)

    def test_template_policy_adds_only_three_signed_object_arns(self):
        bucket_arn = "arn:aws:s3:::hacktricks-cspm-templates-111122223333"
        old_arns = [bucket_arn + "/customer-role-old-a.json", bucket_arn + "/customer-role-old-b.json"]
        statements = [{"Sid": "PublicReadOnlyCustomerRoleTemplate", "Effect": "Allow",
                       "Principal": "*", "Action": "s3:GetObject", "Resource": old_arns},
                      {"Sid": "RequireTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                       "Resource": [bucket_arn, bucket_arn + "/*"],
                       "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
        old = {"policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}
        extra = [bucket_arn + "/customer-role-" + item + ".json" for item in update.TEMPLATE_HASHES]
        new_doc = json.loads(old["policy"])
        new_doc["Statement"][0]["Resource"] += extra
        new = {"policy": json.dumps(new_doc)}
        update.check_template_policy(old, new, {"aws_s3_bucket.templates[0]": {"arn": bucket_arn}})
        new_doc["Statement"][1]["Effect"] = "Allow"
        with self.assertRaisesRegex(RuntimeError, "unrelated permissions"):
            update.check_template_policy(old, {"policy": json.dumps(new_doc)},
                                         {"aws_s3_bucket.templates[0]": {"arn": bucket_arn}})


    def test_combined_resolved_workflow_iam_and_template_documents(self):
        prefix = f"arn:aws:ecs:us-east-1:{update.ACCOUNT}:task-definition/hacktricks-cspm-"
        old = {stage: prefix + stage + ":5" for stage in ("collector", "analyzer")}
        new = {stage: prefix + stage + ":6" for stage in ("collector", "analyzer")}
        def workflow(arns):
            return {"StartAt": "Collect", "States": {
                "Collect": {"Parameters": {"TaskDefinition": arns["collector"]}, "Next": "Analyze"},
                "Analyze": {"Parameters": {"TaskDefinition": arns["analyzer"]}, "End": True}}}
        def workflow_iam(arns):
            return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ecs:RunTask",
                    "Resource": [arns["collector"], arns["analyzer"]]}]}
        bucket = "arn:aws:s3:::hacktricks-cspm-templates-111122223333"
        old_objects = [bucket + "/customer-role-old-a.json", bucket + "/customer-role-old-b.json"]
        new_objects = old_objects + [bucket + "/customer-role-" + item + ".json" for item in update.TEMPLATE_HASHES]
        template = lambda objects: {"Version": "2012-10-17", "Statement": [
            {"Sid": "PublicReadOnlyCustomerRoleTemplate", "Effect": "Allow", "Principal": "*",
             "Action": "s3:GetObject", "Resource": objects},
            {"Sid": "RequireTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
             "Resource": [bucket, bucket + "/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        api_old = policy(["cognito-idp:AdminGetUser", "cognito-idp:DescribeUserPoolClient"])
        api_new = policy(["cognito-idp:AdminGetUser", "cognito-idp:ListUserPoolClients",
                          "cognito-idp:DescribeUserPoolClient"])
        resources = {"aws_sfn_state_machine.scan": {"definition": json.dumps(workflow(old))},
                     "aws_iam_role_policy.workflow": {"policy": json.dumps(workflow_iam(old))},
                     "aws_iam_role_policy.api": {"policy": api_old},
                     "aws_s3_bucket_policy.templates[0]": {"policy": json.dumps(template(old_objects))},
                     "aws_s3_bucket.templates[0]": {"arn": bucket}}
        planned = {"aws_iam_role_policy.api": {"change": {"after": {"policy": api_new}}},
                   "aws_s3_bucket_policy.templates[0]": {"change": {"after": {
                       "policy": json.dumps(template(new_objects))}}}}
        current = {"workflow": workflow(new), "workflow_policy": workflow_iam(new),
                   "api_policy": json.loads(api_new), "template_policy": template(new_objects)}
        def verify():
            update.check_resolved_documents(resources, planned, current["workflow"],
                                            current["workflow_policy"], current["api_policy"],
                                            current["template_policy"], new)
        verify()
        planned["aws_s3_bucket_policy.templates[0]"]["change"] = {
            "after": {"policy": None}, "after_unknown": {"policy": True}}
        verify()
        current["template_policy"] = template(new_objects[:-1])
        with self.assertRaisesRegex(RuntimeError, "lacks exact new resources"):
            verify()
        current["template_policy"] = template(new_objects)
        current["workflow"]["States"]["Analyze"]["End"] = False
        with self.assertRaisesRegex(RuntimeError, "beyond task revisions"):
            verify()
        current["workflow"] = workflow(new)
        current["workflow_policy"]["Statement"][0]["Action"] = "ecs:*"
        with self.assertRaisesRegex(RuntimeError, "beyond task revisions"):
            verify()
        current["workflow_policy"] = workflow_iam(new)
        current["api_policy"]["Statement"][0]["Action"].append("cognito-idp:AdminUpdateUserAttributes")
        with self.assertRaisesRegex(RuntimeError, "beyond the one read action"):
            verify()
        current["api_policy"] = json.loads(api_new)
        current["template_policy"]["Statement"][0]["Principal"] = {"AWS": "*"}
        with self.assertRaisesRegex(RuntimeError, "public read statement differs"):
            verify()
        current["template_policy"] = template(new_objects)
        current["workflow"]["States"]["Analyze"]["Parameters"]["TaskDefinition"] = prefix + "analyzer:7"
        with self.assertRaisesRegex(RuntimeError, "another task revision"):
            verify()

    def test_private_approval_file_requires_mode_and_exact_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "contract.json"
            path.write_bytes(b"{}")
            path.chmod(0o600)
            self.assertEqual(update.private_artifact(path.resolve(), hashlib.sha256(b"{}").hexdigest()), b"{}")
            with self.assertRaisesRegex(RuntimeError, "digest changed"):
                update.private_artifact(path.resolve(), "0" * 64)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "mode-0600"):
                update.private_artifact(path.resolve(), hashlib.sha256(b"{}").hexdigest())

    def test_contract_binds_saved_plan_and_all_local_release_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            infra, build = root / "infra", root / "build"
            infra.mkdir(); build.mkdir()
            version = "a" * 64
            image = (f"{update.ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/"
                     "hacktricks-cspm-worker@sha256:" + "b" * 64)
            release = build / "release.json"
            release.write_text(json.dumps({"source_version": version}))
            artifacts = {"source_zip_sha256": build / f"peaso-source-{version}.zip",
                         "api_zip_sha256": build / "api.zip",
                         "frontend_manifest_sha256": build / "frontend-build.json"}
            for path in artifacts.values():
                path.write_bytes(b"reviewed artifact")
            (infra / "deployment.auto.tfvars.json").write_text(json.dumps({
                "worker_image": image, "api_zip": str(artifacts["api_zip_sha256"])}))
            plan = root / "current.tfplan"
            plan.write_bytes(b"saved binary")
            raw = b'{"resource_changes":[]}'
            saved_json = root / "saved-plan.private.json"
            saved_json.write_bytes(raw)
            saved_json.chmod(0o600)
            state = root / "state.private.json"
            state.write_bytes(b"{}")
            state.chmod(0o600)
            contract = root / "contract.private.json"
            release_meta = {"source_version": version,
                            "release_json_sha256": update.digest(release.read_bytes()),
                            "worker_image": image,
                            **{key: update.digest(path.read_bytes()) for key, path in artifacts.items()}}
            value = {"plan": {"sha256": update.digest(plan.read_bytes()),
                              "json_sha256": update.digest(raw), "json_path": str(saved_json)},
                     "state": {"path": str(state), "sha256": update.digest(state.read_bytes())},
                     "release": release_meta}
            contract.write_text(json.dumps(value))
            contract.chmod(0o600)
            approved = update.digest(contract.read_bytes())
            with (patch.object(update, "review", return_value={"lineage": "approved", "serial": 23,
                                                                "approved_changes": {}}),
                  patch.object(update, "check_source_pins")):
                result = update.load_context(plan, raw, {}, contract, approved, infra, build)
                self.assertEqual(result["release"]["source_version"], version)
                artifacts["api_zip_sha256"].write_bytes(b"changed")
                with self.assertRaisesRegex(RuntimeError, "api_zip_sha256 differs"):
                    update.load_context(plan, raw, {}, contract, approved, infra, build)
                artifacts["api_zip_sha256"].write_bytes(b"reviewed artifact")
                saved_json.write_bytes(b"tampered")
                with self.assertRaisesRegex(RuntimeError, "digest changed"):
                    update.load_context(plan, raw, {}, contract, approved, infra, build)


class CurrentUpdateExactDrift(unittest.TestCase):
    def fixture(self):
        addresses = list(update.REVIEWED_DRIFT)
        raw = {address: {"id": address, "tags": None} for address in addresses}
        child_policy = {"Version": "2012-10-17", "Statement": [{"Action": "ecs:RunTask",
                         "Resource": "owned-task-revision-5"}]}
        role = "aws_iam_role.workflow"
        bucket = "aws_s3_bucket.templates[0]"
        raw["aws_iam_role_policy.workflow"] = {"name": "terraform-owned", "policy": json.dumps(child_policy)}
        raw["aws_s3_bucket_policy.templates[0]"] = {"policy": json.dumps({"Version": "2012-10-17",
                                                      "Statement": [{"Sid": "PublicReadOnlyCustomerRoleTemplate",
                                                                     "Resource": ["old-a", "old-b"]}]})}
        raw[role] = {"id": "owned-role", "inline_policy": [{"name": "terraform-owned",
                     "policy": json.dumps({"Version": "2012-10-17", "Statement": []})}]}
        raw[bucket] = {"id": "owned-bucket", "policy": json.dumps({"Version": "2012-10-17", "Statement": []})}
        rows = []
        for address in addresses:
            before = raw[address]
            after = json.loads(json.dumps(before))
            if address == role:
                after["inline_policy"][0]["policy"] = json.dumps(child_policy)
            elif address == bucket:
                after["policy"] = raw["aws_s3_bucket_policy.templates[0]"]["policy"]
            else:
                after["tags"] = {}
            rows.append({"mode": "managed", "address": address,
                         "change": {"actions": ["update"], "before": before, "after": after,
                                    "after_unknown": {}}})
        reviewed = {r["address"]: (
            update.digest(update.canonical(r["change"]["before"])),
            update.digest(update.canonical(r["change"]["after"])),
            update.digest(update.canonical(r["change"]))) for r in rows}
        approved = {address: dict(zip(("before_sha256", "after_sha256", "change_sha256"), hashes))
                    for address, hashes in reviewed.items()}
        return raw, rows, reviewed, approved

    def test_exact_five_read_enrichments_preserve_owned_child_policies(self):
        raw, rows, reviewed, approved = self.fixture()
        with patch.object(update, "REVIEWED_DRIFT", reviewed):
            normalized, actual = update.reviewed_drift(rows, raw, approved)
            self.assertEqual(actual, rows)
            self.assertEqual(normalized[rows[0]["address"]], rows[0]["change"]["after"])
            self.assertEqual(raw[rows[0]["address"]]["tags"], None)
            rows.append({"mode": "managed", "address": "aws_s3_bucket.wiki"})
            with self.assertRaisesRegex(RuntimeError, "exact reviewed rows"):
                update.reviewed_drift(rows, raw, approved)

    def test_changed_contract_hash_or_child_policy_rejected(self):
        raw, rows, reviewed, approved = self.fixture()
        with patch.object(update, "REVIEWED_DRIFT", reviewed):
            approved[rows[0]["address"]]["after_sha256"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "reviewed hashes"):
                update.reviewed_drift(rows, raw, approved)
            approved[rows[0]["address"]]["after_sha256"] = reviewed[rows[0]["address"]][1]
            raw["aws_iam_role_policy.workflow"]["policy"] = json.dumps({"Statement": [{"Action": "ecs:*"}]})
            with self.assertRaisesRegex(RuntimeError, "owned child policy"):
                update.reviewed_drift(rows, raw, approved)


class CurrentUpdateDefaultsAndPins(unittest.TestCase):
    def test_immutable_object_accepts_verified_sdk_crc32_and_s3_crc64_metadata(self):
        content = b'{"reviewed":"customer-role"}\n'
        signed = hashlib.sha256(content).hexdigest()
        response = {"ServerSideEncryption": "AES256", "ChecksumType": "FULL_OBJECT",
                    "ChecksumCRC32": base64.b64encode(zlib.crc32(content).to_bytes(4, "big")).decode()}
        update.check_reviewed_object_checksum(response, content, signed)
        crc64 = dict(response, ChecksumCRC64NVME=base64.b64encode(b"12345678").decode())
        del crc64["ChecksumCRC32"]
        update.check_reviewed_object_checksum(crc64, content, signed)
        with self.assertRaisesRegex(RuntimeError, "signed source"):
            update.check_reviewed_object_checksum(response, content + b"corrupted", signed)

    def test_immutable_object_rejects_malformed_or_mismatched_checksum_and_security(self):
        content = b'{"reviewed":"customer-role"}\n'
        signed = hashlib.sha256(content).hexdigest()
        response = {"ServerSideEncryption": "AES256", "ChecksumType": "FULL_OBJECT",
                    "ChecksumCRC32": base64.b64encode(zlib.crc32(content).to_bytes(4, "big")).decode()}
        for changed, message in (
            ({"ChecksumCRC32": "not base64!"}, "malformed"),
            ({"ChecksumCRC32": base64.b64encode(b"\x00" * 4).decode()}, "differs from bytes"),
            ({"ChecksumCRC32": ""}, "algorithm differs"),
            ({"ChecksumCRC32C": "AAAAAA=="}, "algorithm differs"),
            ({"SSEKMSKeyId": "unreviewed-key"}, "encryption or storage differs"),
            ({"StorageClass": "GLACIER"}, "encryption or storage differs"),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(RuntimeError, message):
                update.check_reviewed_object_checksum(dict(response, **changed), content, signed)
        malformed_crc64 = dict(response, ChecksumCRC64NVME=base64.b64encode(b"short").decode())
        del malformed_crc64["ChecksumCRC32"]
        with self.assertRaisesRegex(RuntimeError, "CRC64 checksum is malformed"):
            update.check_reviewed_object_checksum(malformed_crc64, content, signed)

    def test_active_job_scope_counts_collected_before_analyzer_resume(self):
        query = update.active_owned_jobs_query("hacktricks-cspm", 123)
        self.assertEqual(query["TableName"], "hacktricks-cspm")
        self.assertEqual(query["Select"], "COUNT")
        self.assertTrue(query["ConsistentRead"])
        self.assertIn(":collected", query["FilterExpression"])
        self.assertEqual(query["ExpressionAttributeValues"][":collected"], {"S": "collected"})
        self.assertEqual(query["ExpressionAttributeValues"][":now"], {"N": "123"})
        with self.assertRaisesRegex(RuntimeError, "scope"):
            update.active_owned_jobs_query("wiki-tools", 123)

    def test_ecs_defaults_allow_only_observed_computed_false_and_empty_shapes(self):
        volume = [{"name": "scratch", "configure_at_launch": False, "host_path": "",
                   "docker_volume_configuration": [], "efs_volume_configuration": [],
                   "fsx_windows_file_server_volume_configuration": [], "s3files_volume_configuration": []}]
        before = {"enable_fault_injection": False, "ipc_mode": "", "pid_mode": "", "tags": {},
                  "tags_all": {"Application": "hacktricks-cspm", "ManagedBy": "Terraform"},
                  "volume": volume}
        after = dict(before, enable_fault_injection=None, ipc_mode=None, pid_mode=None, tags=None,
                     volume=[{k: v for k, v in volume[0].items() if k != "configure_at_launch"}])
        markers = {"enable_fault_injection": True, "volume": [{"configure_at_launch": True,
                   "docker_volume_configuration": [], "efs_volume_configuration": [],
                   "fsx_windows_file_server_volume_configuration": [], "s3files_volume_configuration": []}]}
        update.check_ecs_defaults(before, after, markers)
        for change, expected in (({"enable_fault_injection": True}, "default-false"),
                                 ({"ipc_mode": "host"}, "default-false"),
                                 ({"tags": {"Unreviewed": "yes"}}, "default-false"),
                                 ({"volume": [{"name": "scratch", "host_path": "/host"}]}, "default-false")):
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, expected):
                update.check_ecs_defaults(before, dict(after, **change), markers)
        with self.assertRaisesRegex(RuntimeError, "default-false"):
            update.check_ecs_defaults(before, after, dict(markers, enable_fault_injection=False))



class DeploymentModeIntegration(unittest.TestCase):
    def test_current_api_generated_policy_name_binds_owned_role_and_id(self):
        name = "terraform-98a7819c04b3df5d7e74a23aa2"
        before = {"name": name, "role": "hacktricks-cspm-api",
                  "id": "hacktricks-cspm-api:" + name}
        deploy.check_current_api_policy_identity(before, dict(before))
        for field, changed in (("name", "terraform-foreign"),
                               ("role", "wiki-tools-api"),
                               ("id", "hacktricks-cspm-api:other")):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "name/role/id binding"):
                deploy.check_current_api_policy_identity(before, dict(before, **{field: changed}))
        with self.assertRaisesRegex(RuntimeError, "name/role/id binding"):
            deploy.check_current_api_policy_identity(dict(before, id="foreign"), dict(before))

    def test_saved_json_is_byte_exact_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "one.unreviewed.json"
            raw = b'{  "resource_changes": [] }\n'
            deploy.private_bytes_once(path, raw)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                deploy.private_bytes_once(path, b"replaced")
            self.assertEqual(path.read_bytes(), raw)

    def test_saved_update_requires_opt_in_and_binds_generated_workflow_policy_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            plan = Path(folder) / "review.tfplan"
            plan.write_bytes(b"one saved plan")
            role = "hacktricks-cspm-workflow"
            name = "provider-generated-workflow-policy"
            before = {"id": role + ":" + name, "name": name, "role": role,
                      "policy": '{"Statement":[],"Version":"2012-10-17"}'}
            after = dict(before, policy='{"Statement":[{"Resource":"owned-task-reference"}],"Version":"2012-10-17"}')
            row = {"mode": "managed", "type": "aws_iam_role_policy", "name": "workflow",
                   "address": "aws_iam_role_policy.workflow",
                   "change": {"actions": ["update"], "before": before, "after": after}}
            data = {"resource_changes": [row]}
            context = {"contract_path": "/private/review.json", "contract_sha256": "a" * 64,
                       "state_sha256": "b" * 64, "lineage": "reviewed", "serial": 23,
                       "approved_changes": {row["address"]: {}},
                       "release": {"source_version": "c" * 64}}
            def review(*, approved):
                with (patch.object(deploy, "terraform", return_value=SimpleNamespace(stdout=json.dumps(data))),
                      patch.object(deploy.current_update, "load_context", return_value=context),
                      contextlib.redirect_stdout(io.StringIO())):
                    return deploy.plan_summary(plan, current_update_contract=Path("/private/review.json"),
                                               current_update_sha256="a" * 64) if approved else deploy.plan_summary(plan)
            with self.assertRaisesRegex(RuntimeError, "Non-additive plan refused"):
                review(approved=False)
            self.assertEqual(review(approved=True), hashlib.sha256(plan.read_bytes()).hexdigest())
            after["role"] = "wiki-workflow"
            with self.assertRaisesRegex(RuntimeError, "binding differs"):
                review(approved=True)


if __name__ == "__main__":
    unittest.main()

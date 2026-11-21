"""Delete only ledger-owned temporary tenant rows/objects; retain all infrastructure.

Run inside the authorized wiki session, after fixture jobs are terminal.
Reads are constrained to exact fresh test subjects, never a table/bucket scan.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

import boto3

from peaso import deployment
from peaso.storage.sqlite import TERMINAL

ACCOUNT = deployment.value("account_id")
TABLE = "hacktricks-cspm"
BUCKET = (("hacktricks-cspm-artifacts-DEPLOYMENT_ACCOUNT_ID").replace("DEPLOYMENT_ACCOUNT_ID", deployment.value("account_id")))
OWNED_SCAN_ROW = re.compile(r"(?:scan_checkpoint|scan_stage)/([a-f0-9]{32})/[^/]+\Z")


def validate_record(record, tenant, known_jobs):
    key = record["SK"]["S"]
    owned_scan_row = OWNED_SCAN_ROW.fullmatch(key)
    if (record["PK"]["S"] != "tenant/" + tenant or
            ("tenant" in record and record["tenant"].get("S") != tenant)):
        raise RuntimeError("Row subject mismatch")
    if owned_scan_row:
        if owned_scan_row[1] not in known_jobs:
            raise RuntimeError("Unledgered test scan checkpoint or stage")
    elif key.startswith("job/"):
        if record.get("status", {}).get("S") not in TERMINAL:
            raise RuntimeError("Fixture job still active; cancel before cleanup")
        ident = key.removeprefix("job/")
        if ident not in known_jobs or not re.fullmatch(r"[a-f0-9]{32}", ident):
            raise RuntimeError("Unledgered test job")
    elif key != "ai/configuration_error" and not key.startswith(("connector/", "idem/", "quota/", "schedule/", "entitlement/")):
        raise RuntimeError("Unexpected tenant row kind")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    root = Path(args.directory).resolve()
    ledger = root / "hosted-data-ledger.json"
    if not ledger.exists():
        print("No hosted data was created")
        return
    data = json.loads(ledger.read_text())
    users = json.loads((root / "cognito-ledger.json").read_text())
    owned = {r["sub"] for r in users["resources"] if r["account"] == ACCOUNT and r.get("sub") and r["name"].startswith("peaso-test-") and r["pool_id"] == deployment.value("cognito_pool_id")}
    if data["task_id"] != "task_02a312b5ac1f" or not {r["tenant"] for r in data["resources"]}.issubset(owned):
        raise RuntimeError("Tenant data is outside exact fixture user ledger")
    sts = boto3.client("sts", region_name="us-east-1")
    ddb = boto3.client("dynamodb", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    def identity():
        actual = sts.get_caller_identity()
        if actual["Account"] != ACCOUNT:
            raise RuntimeError("Wiki identity mismatch")
    def save():
        ledger.write_text(json.dumps(data, indent=2) + "\n")
        os.chmod(ledger, 0o600)
    def rows(tenant):
        output, start = [], None
        while True:
            args = {"TableName": TABLE, "KeyConditionExpression": "PK=:pk", "ExpressionAttributeValues": {":pk": {"S": "tenant/" + tenant}},
                    "ConsistentRead": True, "ProjectionExpression": "PK,SK,#status,#tenant", "ExpressionAttributeNames": {"#status": "status", "#tenant": "tenant"}}
            if start:
                args["ExclusiveStartKey"] = start
            response = ddb.query(**args)
            output.extend(response["Items"])
            start = response.get("LastEvaluatedKey")
            if not start:
                return output
    def objects(prefix):
        output, token = [], None
        while True:
            args = {"Bucket": BUCKET, "Prefix": prefix, "ExpectedBucketOwner": ACCOUNT}
            if token:
                args["ContinuationToken"] = token
            response = s3.list_objects_v2(**args)
            output.extend(item["Key"] for item in response.get("Contents", []))
            token = response.get("NextContinuationToken")
            if not token:
                return output
    identity()
    table_arn = ddb.describe_table(TableName=TABLE)["Table"]["TableArn"]
    if table_arn != "arn:aws:dynamodb:us-east-1:" + ACCOUNT + ":table/" + TABLE:
        raise RuntimeError("Permanent store identity mismatch")
    for row in data["resources"]:
        if row.get("verification") == "rows_and_objects_not_found":
            continue
        if row["account"] != ACCOUNT or row["dynamodb_table"] != TABLE or row["artifact_bucket"] != BUCKET:
            raise RuntimeError("Store metadata differs from owned ledger")
        tenant = row["tenant"]
        records = rows(tenant)
        known_jobs = {entry["id"] for entry in row["api_objects"] if entry["kind"] == "scans" and entry.get("id")}
        if any(not re.fullmatch(r"[a-f0-9]{32}", ident) for ident in known_jobs):
            raise RuntimeError("Invalid job ID in fixture ledger")
        for record in records:
            validate_record(record, tenant, known_jobs)
        row["dynamodb_keys"] = [{"PK": item["PK"]["S"], "SK": item["SK"]["S"]} for item in records]
        row["s3_keys"] = []
        for job in sorted(known_jobs):
            prefix = "artifacts/" + hashlib.sha256(tenant.encode()).hexdigest() + "/" + job + "/"
            for key in objects(prefix):
                if not key.startswith(prefix):
                    raise RuntimeError("Object is outside owned exact job prefix")
                row["s3_keys"].append(key)
        save()  # Ledger every exact row/object key before ANY deletion.
        for key in row["s3_keys"]:
            identity()
            s3.delete_object(Bucket=BUCKET, Key=key, ExpectedBucketOwner=ACCOUNT)
            try:
                s3.head_object(Bucket=BUCKET, Key=key, ExpectedBucketOwner=ACCOUNT)
            except s3.exceptions.ClientError as exc:
                if str(exc.response["Error"]["Code"]) not in {"404", "NoSuchKey", "NotFound"}:
                    raise
            else:
                raise RuntimeError("Fixture S3 object still exists")
        for key in row["dynamodb_keys"]:
            identity()
            ddb.delete_item(TableName=TABLE, Key={"PK": {"S": key["PK"]}, "SK": {"S": key["SK"]}},
                            ConditionExpression="PK=:pk AND SK=:sk", ExpressionAttributeValues={":pk": {"S": key["PK"]}, ":sk": {"S": key["SK"]}})
        if rows(tenant) or any(objects("artifacts/" + hashlib.sha256(tenant.encode()).hexdigest() + "/" + job + "/") for job in known_jobs):
            raise RuntimeError("Owned tenant rows/objects remain")
        row.update(creation_status="deleted", verification="rows_and_objects_not_found", verified_at=datetime.now(timezone.utc).isoformat())
        save()
    print("Owned temporary tenant rows and exact artifact keys removed; infrastructure retained")


if __name__ == "__main__":
    main()

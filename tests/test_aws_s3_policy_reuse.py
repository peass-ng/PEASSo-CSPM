"""Cross-region S3 policy reads share one account-bound request."""
import json

from peaso.collectors import aws, aws_resource_policy_families


def test_bucket_policy_reuses_native_read_in_home_region():
    account = "123456789012"
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]})

    class Session:
        def get_partition_for_region(self, region):
            return "aws"

    class Requests:
        workers = 1

        def __init__(self):
            self.calls = []
            self.cache = {}

        def pages(self, session, service, region, operation, path, **arguments):
            assert (service, operation) == ("s3", "list_buckets")
            return aws.ReadResult([{"Name": "owned-bucket"}])

        def detail(self, session, service, region, operation, *, absent=(), **arguments):
            key = (service, region, operation, tuple(sorted(arguments.items())))
            if key not in self.cache:
                self.calls.append(key)
                if operation == "get_bucket_location":
                    response = {"LocationConstraint": "eu-west-1", "collection_status": "collected"}
                elif operation == "get_bucket_policy":
                    response = {"Policy": policy, "collection_status": "collected"}
                else:
                    response = {"collection_status": "collected"}
                self.cache[key] = response
            return dict(self.cache[key])

    requests, session = Requests(), Session()
    native = aws._buckets(requests, session, "us-east-1", account)
    recipe = next(row for row in aws_resource_policy_families.RECIPES if row.id == "s3-buckets")
    public = aws_resource_policy_families.collect(requests, session, "us-east-1", account, [recipe])

    assert native.status == public.status == "collected"
    assert len(native.items) == len(public.items) == 1
    assert [call for call in requests.calls if call[2] == "get_bucket_policy"] == [
        ("s3", "eu-west-1", "get_bucket_policy", (("Bucket", "owned-bucket"), ("ExpectedBucketOwner", account)))]

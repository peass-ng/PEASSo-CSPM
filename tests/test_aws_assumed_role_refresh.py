"""An assumed-role scan session renews itself instead of expiring mid-scan."""
from datetime import datetime, timedelta, timezone

import boto3
from botocore.stub import Stubber

from peaso.collectors import aws

ROLE = "arn:aws:iam::111122223333:role/ScannerFixture"


def _credentials(key, expires_in):
    return {"Credentials": {"AccessKeyId": key, "SecretAccessKey": "secret-" + key, "SessionToken": "token-" + key,
                            "Expiration": datetime.now(timezone.utc) + expires_in}}


def test_assumed_role_session_reassumes_the_same_role_before_expiry(monkeypatch):
    source = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    sts = source.client("sts", region_name="us-east-1")
    expected = {"RoleArn": ROLE, "RoleSessionName": "peaso-read-only", "ExternalId": "fixture-external"}
    with Stubber(sts) as stub:
        # The first session is about to expire; the renewal is a new exchange.
        stub.add_response("assume_role", _credentials("ASIAFIRSTFIXTURE0001", timedelta(minutes=2)), expected)
        stub.add_response("assume_role", _credentials("ASIASECONDFIXTURE002", timedelta(hours=1)), expected)
        monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: sts)
        requests = aws.Requests({"retry_attempts": 1})
        session = aws._assume(requests, source, "us-east-1", {"role_arn": ROLE, "external_id": "fixture-external"}, {})
        frozen = session.get_credentials().get_frozen_credentials()
        stub.assert_no_pending_responses()
    assert frozen.access_key == "ASIASECONDFIXTURE002"
    assert frozen.token == "token-ASIASECONDFIXTURE002"


def test_assumed_role_session_keeps_valid_credentials_without_new_exchange(monkeypatch):
    source = boto3.Session(aws_access_key_id="inert", aws_secret_access_key="inert", region_name="us-east-1")
    sts = source.client("sts", region_name="us-east-1")
    with Stubber(sts) as stub:
        stub.add_response("assume_role", _credentials("ASIAFIRSTFIXTURE0001", timedelta(hours=1)))
        monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: sts)
        requests = aws.Requests({"retry_attempts": 1})
        session = aws._assume(requests, source, "us-east-1", ROLE, {})
        assert session.get_credentials().get_frozen_credentials().access_key == "ASIAFIRSTFIXTURE0001"
        stub.assert_no_pending_responses()

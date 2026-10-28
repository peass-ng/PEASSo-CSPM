"""Scheduler recipient projection keeps the reviewed API read count and privacy boundary."""

from peaso.collectors.aws import ReadResult
from peaso.collectors import aws_ai_recheck_facts_20261020 as reviewed
from peaso.collectors import aws_scheduler_recipient_projection as successor


class _Requests:
    def __init__(self):
        self.calls = []

    def pages(self, session, service, region, operation, key):
        self.calls.append((service, operation))
        return ReadResult([{"Name": "one", "GroupName": "default"}], "collected", None)

    def detail(self, session, service, region, operation, **identity):
        self.calls.append((service, operation))
        return {"Arn": "arn:aws:scheduler:us-east-1:123456789012:schedule/default/one",
                "Name": "one", "GroupName": "default", "State": "ENABLED",
                "Target": {"Arn": "arn:aws:scheduler:::aws-sdk:sns:publish",
                           "RoleArn": "arn:aws:iam::123456789012:role/scheduler",
                           "Input": '{"TopicArn":"arn:aws:sns:us-east-1:999999999999:topic","Message":"private"}'}}


def test_scheduler_successor_reuses_exact_list_and_detail_reads():
    before, after = _Requests(), _Requests()
    baseline = reviewed.schedules(before, None, "us-east-1", "123456789012")
    candidate = successor.schedules(after, None, "us-east-1", "123456789012")
    assert before.calls == after.calls == [("scheduler", "list_schedules"),
                                           ("scheduler", "get_schedule")]
    assert candidate.status == baseline.status
    assert candidate.items[0]["Target"]["InputRecipient"] == {
        "collection_status": "collected", "Arn": "arn:aws:sns:us-east-1:999999999999:topic"}
    assert "private" not in repr(candidate.items)
    assert "Input" not in candidate.items[0]["Target"]

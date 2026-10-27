"""Related cloud snapshots, kept only as far as the privesc join reads them.

A K8s analyzer joins up to RELATED_MAX_SNAPSHOTS cloud snapshots of its scan
group. Only the privesc models read them, and they never name a few collection
kinds that make up most of a large cloud snapshot (CloudTrail activity,
CloudWatch metrics, usage and assessment evidence).
tests/test_related_snapshot_view.py proves that no privesc source or catalog
names a kind listed here. related_view validates the full document against its
snapshot_id and then drops those kinds, so each document is released as soon as
its view exists. A K8s related snapshot is kept whole: the AWS EKS join scans
every K8s collection for cluster provenance.
"""
from .snapshot import validate

UNREAD_KINDS = {
    "aws": frozenset({"aws_cloudtrail_activity", "cloudwatch_metric", "ec2_instance_type", "access_analyzer"}),
    "gcp": frozenset({"iam_usage_activity", "cloud_asset"}),
    "azure": frozenset({"azure_unused_iam_evidence", "service_tag", "iam_usage_activity", "activity_log",
                        "assessment_metadata", "security_assessment"}),
}


class RelatedSnapshot(dict):
    """A validated related snapshot without the kinds no privesc join reads."""
    __slots__ = ()


def related_view(snapshot):
    """Validated related snapshot with UNREAD_KINDS removed; a view is returned unchanged."""
    if type(snapshot) is RelatedSnapshot:
        return snapshot
    value = validate(snapshot, read_only=True)
    unread = UNREAD_KINDS.get(value["provider"])
    if unread:
        value["collections"] = [c for c in value["collections"] if c["type"] not in unread]
    return RelatedSnapshot(value)

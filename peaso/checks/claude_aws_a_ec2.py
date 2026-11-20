"""claude_aws_a EC2 compute: EBS volumes/snapshots, AMIs, instances, launch templates,
ENIs, Elastic IPs, Client VPN, transit gateways, spot fleets and Nitro Enclave hosts."""
from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from . import register, result
from .facts import Unavailable, get, list_of_objects, optional
from .claude_aws_a_common import (install, absent_or, items, account, region, clock, parse_time, tags,
    prowler_sg_open, is_cidr_public, security_groups, subnet_by_id, subnet_public_prowler,
    idx, C, P, R, ACCOUNT, REGION)

EC2_API = "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/"
DROP = object()


def w(base, **changes):
    """Copy ``base`` and apply ``a__b=value`` nested changes (``DROP`` removes)."""
    out = copy.deepcopy(base)
    for key, value in changes.items():
        parts = key.split("__")
        node = out
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        if value is DROP:
            node.pop(parts[-1], None)
        else:
            node[parts[-1]] = copy.deepcopy(value)
    return out


def partition(index):
    try:
        reg = region(index)
    except Unavailable:
        # Account-global inventories (S3 buckets, IAM) are evaluated in the
        # <account>/global scope: use the account configuration's partition.
        context = index.get("context", {}) if isinstance(index, dict) else {}
        scope = context.get("scope") if isinstance(context, dict) else None
        if not isinstance(scope, str) or not re.fullmatch(r"[0-9]{12}/global", scope):
            raise
        # The collector always records native STS caller identities, including
        # focused scans that do not request account contact/organization facts.
        # Use only identities bound to this exact account; never guess a
        # partition from another account or from the string "global".
        identities = context.get("metadata", {}).get("caller_identities", []) if isinstance(context.get("metadata"), dict) else []
        observed = set()
        for identity in identities if isinstance(identities, list) else []:
            if not isinstance(identity, dict) or identity.get("Account") != scope.split("/", 1)[0]:
                continue
            arn = identity.get("Arn")
            match = re.fullmatch(r"arn:(aws|aws-cn|aws-us-gov):(?:iam|sts)::([0-9]{12}):.+", arn) if isinstance(arn, str) else None
            if not match or match[2] != identity["Account"]:
                raise Unavailable("caller partition identity mismatch")
            observed.add(match[1])
        if len(observed) > 1:
            raise Unavailable("conflicting caller partitions for account")
        if observed:
            return observed.pop()
        values = {c.get("Partition") for c in items(index, "aws_account_configuration")}
        if len(values) != 1 or not values <= {"aws", "aws-cn", "aws-us-gov"}:
            raise Unavailable("account partition unavailable")
        return values.pop()
    return "aws-cn" if reg.startswith("cn-") else "aws-us-gov" if reg.startswith("us-gov-") else "aws"


def ec2_arn(index, kind, ident):
    return "arn:%s:ec2:%s:%s:%s/%s" % (partition(index), region(index), account(index), kind, ident)


def midnight_cutoff(item, index, days):
    """Steampipe ``current_date - interval 'N days'`` on the captured snapshot clock (UTC)."""
    now = clock(item, index).astimezone(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc) - timedelta(days=days)


# =========================================================================== EBS volumes
VOL = {"VolumeId": "vol-1", "State": "in-use", "Encrypted": True,
       "Attachments": [{"InstanceId": "i-1", "State": "attached", "DeleteOnTermination": True}], "Tags": []}


def volume_state(item):
    state = get(item, "State", str)
    if state not in ("creating", "available", "in-use", "deleting", "deleted", "error"):
        raise Unavailable("unrecognized EBS volume state")
    return state


@install("aws.claude_a.ebs.attached_volume_encrypted", "ebs_volume", "Attached EBS volume is encrypted",
    VOL, w(VOL, Encrypted=False), rows=[C + "ebs_attached_volume_encryption_enabled", C + "foundational_security_ec2_3"],
    severity="medium", remediation="Encrypt the volume: snapshot it, copy the snapshot with encryption enabled, create an encrypted volume and swap it in; enable EBS encryption by default.",
    docs=[EC2_API + "API_Volume.html"], category="hardening", control="SC-28", extra={"na": w(VOL, State="available")})
def ebs_attached_encrypted(item, index):
    if volume_state(item) != "in-use":
        return "NOT_APPLICABLE", {"state": item["State"]}
    value = get(item, "Encrypted", bool)
    return result(not value, encrypted=value)


@install("aws.claude_a.ebs.attached_delete_on_termination", "ebs_volume", "Attached EBS volume is deleted on instance termination",
    VOL, w(VOL, Attachments=[{"InstanceId": "i-1", "DeleteOnTermination": False}]),
    rows=[C + "ebs_attached_volume_delete_on_termination_enabled"], severity="low",
    remediation="Set DeleteOnTermination=true on the instance block-device mapping (ModifyInstanceAttribute) for volumes that hold no data that must outlive the instance.",
    docs=[EC2_API + "API_VolumeAttachment.html"], extra={"na": w(VOL, State="available")})
def ebs_attached_dot(item, index):
    if volume_state(item) != "in-use":
        return "NOT_APPLICABLE", {"state": item["State"]}
    attachments = list_of_objects(get(item, "Attachments", list))
    flags = [get(a, "DeleteOnTermination", bool) for a in attachments]
    return result(not flags or not all(flags), delete_on_termination=flags)


@install("aws.claude_a.ebs.volume_in_use", "ebs_volume", "EBS volume is attached (in use)",
    VOL, w(VOL, State="available", Attachments=[]), rows=[C + "ebs_volume_unused"], severity="low",
    remediation="Snapshot (if needed) and delete unattached EBS volumes to reduce data exposure and cost.",
    docs=[EC2_API + "API_Volume.html"])
def ebs_in_use(item, index):
    state = volume_state(item)
    return result(state != "in-use", state=state)


def _snapshot_volume_ids(index):
    return {s.get("VolumeId") for s in items(index, "ebs_snapshot")}


SNAP = {"SnapshotId": "snap-1", "VolumeId": "vol-1", "Encrypted": True, "State": "completed", "CreateVolumePermissions": []}


@install("aws.claude_a.ebs.volume_has_snapshot", "ebs_volume", "EBS volume has at least one snapshot",
    VOL, w(VOL, VolumeId="vol-2"), index=idx(ebs_snapshot=[SNAP]),
    rows=[C + "ebs_volume_snapshot_exists", P + "ec2_ebs_volume_snapshots_exists"], severity="medium",
    remediation="Snapshot the volume regularly (for example with AWS Backup or Data Lifecycle Manager).",
    docs=[EC2_API + "API_DescribeSnapshots.html"], dependencies=["ebs_volume", "ebs_snapshot"],
    note="Both sources join self-owned snapshots by VolumeId; requires the complete ebs_snapshot inventory.")
def ebs_has_snapshot(item, index):
    vid = get(item, "VolumeId", str)
    return result(not (found := vid in _snapshot_volume_ids(index)), volume_id=vid, snapshot_found=found)


PROTECTED = [{"ResourceArn": "arn:aws:ec2:us-east-1:%s:volume/vol-1" % ACCOUNT, "ResourceType": "EBS"},
             {"ResourceArn": "arn:aws:ec2:us-east-1:%s:instance/i-1" % ACCOUNT, "ResourceType": "EC2"}]


def _protected(index, rtype, arn):
    for row in items(index, "backup_protected_resource"):
        if get(row, "ResourceArn", str) == arn and get(row, "ResourceType", str) == rtype:
            return True
    return False


@install("aws.claude_a.ebs.volume_protected_by_backup", "ebs_volume", "EBS volume is an AWS Backup protected resource",
    VOL, w(VOL, VolumeId="vol-2"), index=idx(backup_protected_resource=PROTECTED),
    rows=[C + "ebs_volume_protected_by_backup_plan"], severity="medium",
    remediation="Assign the volume to an AWS Backup plan (resource assignment by ARN or tag) and confirm a recovery point exists.",
    docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListProtectedResources.html"],
    dependencies=["ebs_volume", "backup_protected_resource"])
def ebs_protected(item, index):
    arn = ec2_arn(index, "volume", get(item, "VolumeId", str))
    return result(not (found := _protected(index, "EBS", arn)), volume_arn=arn, protected_resource=found)


SELECTION = {"BackupPlanId": "plan-1", "SelectionName": "s", "Resources": ["arn:aws:ec2:us-east-1:%s:volume/vol-1" % ACCOUNT], "ListOfTags": []}


@install("aws.claude_a.ebs.volume_in_backup_selection", "ebs_volume", "EBS volume is selected by an AWS Backup plan (ARN or tag key)",
    VOL, w(VOL, VolumeId="vol-2"), index=idx(backup_selection=[SELECTION]),
    rows=[C + "ebs_volume_in_backup_plan"], severity="medium",
    remediation="Add the volume to an AWS Backup plan resource assignment by ARN or by tag.",
    docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupSelection.html"],
    dependencies=["ebs_volume", "backup_selection"],
    extra={"pass_by_tag": (w(VOL, VolumeId="vol-9", Tags=[{"Key": "backup", "Value": "yes"}]),
                           idx(backup_selection=[w(SELECTION, Resources=[], ListOfTags=[{"ConditionType": "STRINGEQUALS", "ConditionKey": "backup", "ConditionValue": "yes"}])]))},
    note="Steampipe matches the exact volume ARN in Resources or any ListOfTags ConditionKey equal to one of the volume's tag keys (values ignored).")
def ebs_in_selection(item, index):
    arn = ec2_arn(index, "volume", get(item, "VolumeId", str))
    keys = set(tags(item))
    for selection in items(index, "backup_selection"):
        resources = optional(selection, "Resources", [], list)
        if arn in resources:
            return result(False, volume_arn=arn, matched="arn")
        for cond in list_of_objects(optional(selection, "ListOfTags", [], list)):
            if cond.get("ConditionKey") in keys:
                return result(False, volume_arn=arn, matched="tag", key=cond["ConditionKey"])
    return result(True, volume_arn=arn)


@install("aws.claude_a.ebs.volume_in_backup_plan_resources", "ebs_volume", "EBS volume ARN (or a wildcard) is in an AWS Backup selection",
    VOL, w(VOL, VolumeId="vol-2"), index=idx(backup_selection=[SELECTION]),
    rows=[P + "ec2_ebs_volume_protected_by_backup_plan"], severity="medium",
    remediation="Add the volume to an AWS Backup plan resource assignment.",
    docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupSelection.html"],
    dependencies=["ebs_volume", "backup_selection"],
    note="Prowler collects every backup selection's Resources and passes on the exact ARN, arn:<partition>:ec2:*:*:volume/* or *.")
def ebs_in_plan_resources(item, index):
    arn = ec2_arn(index, "volume", get(item, "VolumeId", str))
    wildcard = "arn:%s:ec2:*:*:volume/*" % partition(index)
    resources = set()
    for selection in items(index, "backup_selection"):
        resources.update(optional(selection, "Resources", [], list))
    return result(not (found := {arn, wildcard, "*"} & resources), volume_arn=arn, backup_selection_match=bool(found))


# =========================================================================== EBS snapshots
@install("aws.claude_a.ebs.snapshot_encrypted", "ebs_snapshot", "EBS snapshot is encrypted",
    SNAP, w(SNAP, Encrypted=False), rows=[C + "ebs_snapshot_encryption_enabled", P + "ec2_ebs_snapshots_encrypted"],
    severity="medium", control="SC-28", remediation="Copy the snapshot with encryption enabled (CopySnapshot --encrypted) and delete the unencrypted copy.",
    docs=[EC2_API + "API_Snapshot.html"])
def snapshot_encrypted(item, index):
    value = get(item, "Encrypted", bool)
    return result(not value, encrypted=value)


@install("aws.claude_a.ebs.snapshot_not_public", "ebs_snapshot", "EBS snapshot is not publicly restorable",
    SNAP, w(SNAP, CreateVolumePermissions=[{"Group": "all"}]),
    rows=[C + "ebs_snapshot_not_publicly_restorable", C + "foundational_security_ec2_1", R + "ebs_snapshot_not_publicly_accessible", P + "ec2_ebs_public_snapshot"],
    severity="critical", category="exposure", control="AC-3",
    remediation="Remove the 'all' group from the snapshot createVolumePermission (ModifySnapshotAttribute) and enable EBS snapshot block public access.",
    docs=[EC2_API + "API_DescribeSnapshotAttribute.html", EC2_API + "API_CreateVolumePermission.html"])
def snapshot_public(item, index):
    perms = list_of_objects(get(item, "CreateVolumePermissions", list))
    public = any(p.get("Group") == "all" and p.get("UserId") is None for p in perms)
    return result(public, public=public)


# =========================================================================== regional EC2 settings
SETTINGS = {"EbsEncryptionByDefault": True, "SnapshotBlockPublicAccessState": "block-all-sharing",
            "ImageBlockPublicAccessState": "block-new-sharing", "InstanceMetadataDefaults": {"HttpTokens": "required"}}


@install("aws.claude_a.ec2.ebs_encryption_by_default", "ec2_regional_settings", "EBS encryption by default is enabled in the region",
    SETTINGS, w(SETTINGS, EbsEncryptionByDefault=False),
    rows=[C + "ebs_encryption_by_default_enabled", C + "ec2_ebs_default_encryption_enabled", C + "foundational_security_ec2_7"],
    severity="medium", control="SC-28", remediation="Enable EBS encryption by default in every region (EnableEbsEncryptionByDefault).",
    docs=[EC2_API + "API_GetEbsEncryptionByDefault.html"])
def ebs_default_encryption(item, index):
    value = get(item, "EbsEncryptionByDefault", bool)
    return result(not value, ebs_encryption_by_default=value)


@install("aws.claude_a.ec2.ebs_encryption_by_default_with_volumes", "ec2_regional_settings", "EBS encryption by default is enabled in a region that has volumes",
    SETTINGS, w(SETTINGS, EbsEncryptionByDefault=False), index=idx(ebs_volume=[VOL]),
    rows=[P + "ec2_ebs_default_encryption"], severity="high", control="SC-28",
    remediation="Enable EBS encryption by default (EnableEbsEncryptionByDefault) in regions that host volumes.",
    docs=[EC2_API + "API_GetEbsEncryptionByDefault.html"], dependencies=["ec2_regional_settings", "ebs_volume"],
    extra={"na": (SETTINGS, idx(ebs_volume=[]))}, note="Prowler reports only regions with at least one EBS volume.")
def ebs_default_encryption_used(item, index):
    value = get(item, "EbsEncryptionByDefault", bool)
    if not items(index, "ebs_volume"):
        return "NOT_APPLICABLE", {"reason": "no EBS volumes in region"}
    return result(not value, ebs_encryption_by_default=value)


def snapshot_sharing_state(item):
    state = get(item, "SnapshotBlockPublicAccessState", str)
    if state not in ("block-all-sharing", "block-new-sharing", "unblocked"):
        raise Unavailable("unrecognized snapshot block public access state")
    return state


@register("aws.ec2.prevent_public_snapshot_sharing", "aws", "hardening", "ec2_regional_settings",
    "The region blocks new public EBS snapshot sharing", "info", "AC-3",
    "Enable EBS snapshot Block Public Access in block-all-sharing mode to prevent accidental public sharing when snapshots are created.")
def prevent_public_snapshot_sharing(item, _index):
    """The account safeguard applies even before the first snapshot exists."""
    state = snapshot_sharing_state(item)
    return result(state == "unblocked", state=state)


@install("aws.claude_a.ec2.snapshot_block_public_access", "ec2_regional_settings", "EBS snapshot block public access blocks all sharing",
    SETTINGS, w(SETTINGS, SnapshotBlockPublicAccessState="block-new-sharing"), index=idx(ebs_snapshot=[SNAP]),
    rows=[P + "ec2_ebs_snapshot_account_block_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Enable EBS snapshot block public access in block-all-sharing mode (EnableSnapshotBlockPublicAccess).",
    docs=[EC2_API + "API_GetSnapshotBlockPublicAccessState.html"], dependencies=["ec2_regional_settings", "ebs_snapshot"],
    extra={"na": (SETTINGS, idx(ebs_snapshot=[]))}, note="Prowler reports only regions with snapshots; block-new-sharing is a FAIL.")
def snapshot_bpa(item, index):
    state = snapshot_sharing_state(item)
    if not items(index, "ebs_snapshot"):
        return "NOT_APPLICABLE", {"reason": "no EBS snapshots in region"}
    return result(state != "block-all-sharing", state=state)


@install("aws.claude_a.ec2.ami_block_public_access", "ec2_regional_settings", "AMI block public access is enabled",
    SETTINGS, w(SETTINGS, ImageBlockPublicAccessState="unblocked"), rows=[P + "ec2_ami_account_block_public_access"],
    severity="medium", category="exposure", control="AC-3",
    remediation="Enable block public access for AMIs (EnableImageBlockPublicAccess --image-block-public-access-state block-new-sharing).",
    docs=[EC2_API + "API_GetImageBlockPublicAccessState.html"])
def ami_bpa(item, index):
    state = get(item, "ImageBlockPublicAccessState", str)
    if state not in ("block-new-sharing", "unblocked"):
        raise Unavailable("unrecognized image block public access state")
    return result(state != "block-new-sharing", state=state)


INST = {"InstanceId": "i-1", "ImageId": "ami-1", "State": {"Name": "running"}, "Monitoring": {"State": "enabled"},
        "EbsOptimized": True, "VpcId": "vpc-1", "SubnetId": "subnet-1", "VirtualizationType": "hvm",
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}], "LaunchTime": "2025-12-01T00:00:00+00:00",
        "MetadataOptions": {"State": "applied", "HttpTokens": "required", "HttpEndpoint": "enabled"},
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1", "DeleteOnTermination": True}}],
        "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}], "StateTransitionReason": "",
        "IamInstanceProfile": {"Arn": "arn:aws:iam::%s:instance-profile/app" % ACCOUNT, "Id": "AIPAEXAMPLE"},
        "EnclaveOptions": {"Enabled": False}, "Tags": []}


@install("aws.claude_a.ec2.account_imdsv2_default", "ec2_regional_settings", "Account IMDS defaults require IMDSv2 in a region with instances",
    SETTINGS, w(SETTINGS, InstanceMetadataDefaults={"HttpTokens": "optional"}), index=idx(instance=[INST]),
    rows=[P + "ec2_instance_account_imdsv2_enabled"], severity="high",
    remediation="Set account-level instance metadata defaults to HttpTokens=required (ModifyInstanceMetadataDefaults).",
    docs=[EC2_API + "API_GetInstanceMetadataDefaults.html"], dependencies=["ec2_regional_settings", "instance"],
    extra={"na": (SETTINGS, idx(instance=[]))},
    note="GetInstanceMetadataDefaults omits HttpTokens when no default is set (no preference): that is a FAIL, as in Prowler.")
def account_imdsv2(item, index):
    defaults = get(item, "InstanceMetadataDefaults", dict)
    tokens = optional(defaults, "HttpTokens", None, str)
    if not items(index, "instance"):
        return "NOT_APPLICABLE", {"reason": "no instances in region"}
    return result(tokens != "required", http_tokens=tokens)


# =========================================================================== AMIs
AMI = {"ImageId": "ami-1", "Public": False, "CreationDate": "2025-12-15T00:00:00.000Z",
       "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": True, "SnapshotId": "snap-1"}}]}


@install("aws.claude_a.ec2.ami_not_public", "ec2_image", "Account-owned AMI is not public",
    AMI, w(AMI, Public=True),
    rows=[C + "ec2_ami_restrict_public_access", R + "ec2_instance_ami_prohibit_public_access", P + "ec2_ami_public"],
    severity="critical", category="exposure", control="AC-3",
    remediation="Make the AMI private (ModifyImageAttribute remove group all) and enable AMI block public access.",
    docs=[EC2_API + "API_Image.html"], note="ec2_image is DescribeImages Owners=[self]; every source evaluates self-owned images only.")
def ami_public(item, index):
    value = get(item, "Public", bool)
    return result(value, public=value)


@install("aws.claude_a.ec2.ami_ebs_encrypted", "ec2_image", "AMI block device mappings are all encrypted EBS",
    AMI, w(AMI, BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": False}}]),
    rows=[C + "ec2_ami_ebs_encryption_enabled"], severity="medium", control="SC-28",
    remediation="Re-create the AMI from encrypted snapshots (CopyImage --encrypted).",
    docs=[EC2_API + "API_BlockDeviceMapping.html"], extra={"na": w(AMI, BlockDeviceMappings=[])},
    note="Steampipe cross-joins mappings (no mappings: no row) and coalesces a missing Ebs.Encrypted to false.")
def ami_encrypted(item, index):
    mappings = list_of_objects(get(item, "BlockDeviceMappings", list))
    if not mappings:
        return "NOT_APPLICABLE", {"reason": "AMI has no block device mappings"}
    flags = [isinstance(m.get("Ebs"), dict) and m["Ebs"].get("Encrypted") is True for m in mappings]
    return result(not all(flags), encrypted=flags)


@install("aws.claude_a.ec2.ami_not_older_than_90_days", "ec2_image", "Account-owned AMI is not older than 90 days",
    AMI, w(AMI, CreationDate="2025-01-01T00:00:00.000Z"), index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[C + "ec2_ami_not_older_than_90_days"], severity="low",
    remediation="Rebuild AMIs regularly with current patches and deregister stale images.", docs=[EC2_API + "API_Image.html"])
def ami_age(item, index):
    created = parse_time(get(item, "CreationDate", str))
    cutoff = midnight_cutoff(item, index, 90)
    return result(created < cutoff, creation_date=item["CreationDate"])


# =========================================================================== Client VPN / TGW / spot fleet
CVPN = {"ClientVpnEndpointId": "cvpn-endpoint-1", "ConnectionLogOptions": {"Enabled": True, "CloudwatchLogGroup": "vpn"}}


@install("aws.claude_a.ec2.client_vpn_connection_logging", "ec2_client_vpn_endpoint", "Client VPN endpoint has client connection logging enabled",
    CVPN, w(CVPN, ConnectionLogOptions={"Enabled": False}),
    rows=[C + "ec2_client_vpn_endpoint_client_connection_logging_enabled", C + "foundational_security_ec2_51", P + "ec2_client_vpn_endpoint_connection_logging_enabled"],
    severity="low", control="AU-12", remediation="Enable connection logging to a CloudWatch Logs group on the Client VPN endpoint (ModifyClientVpnEndpoint).",
    docs=[EC2_API + "API_ConnectionLogResponseOptions.html"])
def client_vpn_logging(item, index):
    value = get(item, "ConnectionLogOptions.Enabled", bool)
    return result(not value, connection_logging=value)


TGW = {"TransitGatewayId": "tgw-1", "Options": {"AutoAcceptSharedAttachments": "disable"}}


@install("aws.claude_a.ec2.tgw_no_auto_accept_shared_attachments", "transit_gateway", "Transit gateway does not auto-accept shared attachments",
    TGW, w(TGW, Options={"AutoAcceptSharedAttachments": "enable"}),
    rows=[C + "ec2_transit_gateway_auto_cross_account_attachment_disabled", C + "foundational_security_ec2_23", P + "ec2_transitgateway_auto_accept_vpc_attachments"],
    severity="high", category="network", control="SC-7",
    remediation="Disable AutoAcceptSharedAttachments on the transit gateway (ModifyTransitGateway) so cross-account attachments require approval.",
    docs=[EC2_API + "API_TransitGatewayOptions.html"])
def tgw_auto_accept(item, index):
    value = get(item, "Options.AutoAcceptSharedAttachments", str)
    if value not in ("enable", "disable"):
        raise Unavailable("unrecognized AutoAcceptSharedAttachments")
    return result(value == "enable", auto_accept_shared_attachments=value)


SPOT = {"SpotFleetRequestId": "sfr-1", "SpotFleetRequestConfig": {"LaunchSpecifications": [
    {"BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": True}}]}]}}


@install("aws.claude_a.ec2.spot_fleet_ebs_encrypted", "ec2_spot_fleet_request", "Spot fleet launch specifications encrypt EBS volumes",
    SPOT, w(SPOT, SpotFleetRequestConfig={"LaunchSpecifications": [{"BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8}}]}]}),
    rows=[C + "ec2_spot_fleet_request_with_launch_parameter_ebs_encryption_enabled", C + "foundational_security_ec2_173"],
    severity="medium", control="SC-28", remediation="Set Encrypted=true on every EBS block device mapping of the spot fleet launch specifications.",
    docs=[EC2_API + "API_SpotFleetLaunchSpecification.html"], extra={"na": {"SpotFleetRequestId": "sfr-1", "SpotFleetRequestConfig": {}}},
    note="Spot fleets driven by launch templates have no LaunchSpecifications (skip). Instance-store mappings without Ebs are not EBS volumes and are not flagged.")
def spot_fleet_encrypted(item, index):
    config = get(item, "SpotFleetRequestConfig", dict)
    specs = optional(config, "LaunchSpecifications", None, list)
    if specs is None:
        return "NOT_APPLICABLE", {"reason": "spot fleet uses launch templates"}
    bad = []
    for spec in list_of_objects(specs):
        for bdm in list_of_objects(optional(spec, "BlockDeviceMappings", [], list)):
            ebs = bdm.get("Ebs")
            if isinstance(ebs, dict) and ebs.get("Encrypted") is not True:
                bad.append(bdm.get("DeviceName"))
    return result(bool(bad), unencrypted_devices=bad)


# =========================================================================== instances
STATES = ("pending", "running", "shutting-down", "terminated", "stopping", "stopped")


def state(item):
    value = get(item, "State.Name", str)
    if value not in STATES:
        raise Unavailable("unrecognized instance state")
    return value


def _na(value):
    return "NOT_APPLICABLE", {"state": value}


def _not_terminated(item):
    value = state(item)
    return None if value != "terminated" else _na(value)


@install("aws.claude_a.ec2.instance_detailed_monitoring", "instance", "EC2 instance has detailed monitoring enabled",
    INST, w(INST, Monitoring={"State": "disabled"}),
    rows=[C + "ec2_instance_detailed_monitoring_enabled", P + "ec2_instance_detailed_monitoring_enabled"], severity="low", control="SI-4",
    remediation="Enable detailed (1-minute) CloudWatch monitoring on the instance (MonitorInstances).", docs=[EC2_API + "API_Monitoring.html"])
def inst_monitoring(item, index):
    value = get(item, "Monitoring.State", str)
    return result(value != "enabled", monitoring_state=value)


@install("aws.claude_a.ec2.instance_ebs_optimized", "instance", "EC2 instance is EBS-optimized",
    INST, w(INST, EbsOptimized=False), rows=[C + "ec2_instance_ebs_optimized"], severity="low",
    remediation="Enable EBS optimization on the instance (stop it and ModifyInstanceAttribute --ebs-optimized) or use a type that is EBS-optimized by default.",
    docs=[EC2_API + "API_Instance.html"])
def inst_ebs_optimized(item, index):
    value = get(item, "EbsOptimized", bool)
    return result(not value, ebs_optimized=value)


def _profile(item):
    return absent_or(item, "InstanceId", "IamInstanceProfile", None, dict)


def _validated_profile(item):
    profile = _profile(item)
    if profile is not None:
        # A retained empty/malformed attachment object cannot establish a
        # profile. Native DescribeInstances attachments carry both identifiers.
        if not get(profile, "Arn", str) or not get(profile, "Id", str):
            raise Unavailable("instance profile identifiers unavailable")
    return profile


@install("aws.claude_a.ec2.instance_profile_attached", "instance", "EC2 instance has an IAM instance profile",
    INST, w(INST, IamInstanceProfile=DROP),
    rows=[C + "ec2_instance_iam_profile_attached", C + "ec2_instance_using_iam_instance_role"], severity="medium", category="least_privilege", control="AC-6",
    remediation="Attach an IAM instance profile with a least-privilege role instead of storing credentials on the instance.",
    docs=[EC2_API + "API_IamInstanceProfile.html"], note="IamInstanceProfile carries both Id and Arn; the two compliance queries differ only in which column they null-test.")
def inst_profile(item, index):
    profile = _validated_profile(item)
    return result(profile is None, instance_profile=(profile or {}).get("Arn"))


@install("aws.claude_a.ec2.instance_profile_attached_not_terminated", "instance", "Non-terminated EC2 instance has an IAM instance profile",
    INST, w(INST, IamInstanceProfile=DROP), rows=[P + "ec2_instance_profile_attached"], severity="medium", category="least_privilege", control="AC-6",
    remediation="Attach an IAM instance profile with a least-privilege role.", docs=[EC2_API + "API_IamInstanceProfile.html"],
    extra={"na": w(INST, State={"Name": "terminated"})})
def inst_profile_live(item, index):
    na = _not_terminated(item)
    if na:
        return na
    profile = _validated_profile(item)
    return result(profile is None, instance_profile=(profile or {}).get("Arn"))


@install("aws.claude_a.ec2.instance_in_vpc", "instance", "EC2 instance runs in a VPC",
    INST, w(INST, VpcId=DROP), rows=[C + "ec2_instance_in_vpc", R + "ec2_instance_in_vpc"], severity="medium", category="network", control="SC-7",
    remediation="Migrate EC2-Classic instances into a VPC.", docs=[EC2_API + "API_Instance.html"])
def inst_in_vpc(item, index):
    vpc = absent_or(item, "InstanceId", "VpcId", None, str)
    return result(vpc is None, vpc_id=vpc)


def _public_ip(item):
    return absent_or(item, "InstanceId", "PublicIpAddress", None, str)


@install("aws.claude_a.ec2.instance_no_public_ip", "instance", "EC2 instance has no public IPv4 address",
    INST, w(INST, PublicIpAddress="203.0.113.10"),
    rows=[C + "ec2_instance_not_publicly_accessible", C + "foundational_security_ec2_9", R + "ec2_instance_not_publicly_accessible"],
    severity="high", category="exposure", control="SC-7",
    remediation="Launch instances without public IPs (disable auto-assign, remove EIPs) and front them with load balancers, NAT or SSM.",
    docs=[EC2_API + "API_Instance.html"])
def inst_public(item, index):
    ip = _public_ip(item)
    return result(ip is not None, public_ip=ip)


@install("aws.claude_a.ec2.instance_no_public_ip_not_terminated", "instance", "Non-terminated EC2 instance has no public IPv4 address",
    INST, w(INST, PublicIpAddress="203.0.113.10"), rows=[P + "ec2_instance_public_ip"], severity="medium", category="exposure", control="SC-7",
    remediation="Remove public IPs from instances that do not need to be internet-facing.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": w(INST, State={"Name": "terminated"})})
def inst_public_live(item, index):
    na = _not_terminated(item)
    if na:
        return na
    ip = _public_ip(item)
    return result(ip is not None, public_ip=ip)


@install("aws.claude_a.ec2.public_instance_has_profile", "instance", "Public EC2 instance uses an IAM instance profile",
    w(INST, PublicIpAddress="203.0.113.10"), w(INST, PublicIpAddress="203.0.113.10", IamInstanceProfile=DROP),
    rows=[C + "ec2_instance_publicly_accessible_iam_profile_attached"], severity="medium", category="least_privilege", control="AC-6",
    remediation="Attach an IAM instance profile to internet-facing instances instead of static credentials.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": INST}, note="Only instances with a public IPv4 address are evaluated.")
def inst_public_profile(item, index):
    ip = _public_ip(item)
    if ip is None:
        return "NOT_APPLICABLE", {"reason": "instance has no public IPv4"}
    return result(_validated_profile(item) is None, public_ip=ip)


@install("aws.claude_a.ec2.internet_facing_without_profile", "instance", "Internet-facing EC2 instance has no IAM instance profile",
    INST, w(INST, PublicIpAddress="203.0.113.10"), rows=[P + "ec2_instance_internet_facing_with_instance_profile"],
    severity="high", category="exposure", control="AC-6",
    remediation="Remove public addressing from instances with instance profiles, or move them behind a load balancer.",
    docs=[EC2_API + "API_Instance.html"], extra={"na": w(INST, State={"Name": "terminated"})})
def inst_internet_profile(item, index):
    na = _not_terminated(item)
    if na:
        return na
    ip, profile = _public_ip(item), _profile(item)
    return result(ip is not None and profile is not None, public_ip=ip, instance_profile=(profile or {}).get("Arn"))


@install("aws.claude_a.ec2.running_instance_no_key_pair", "instance", "Running EC2 instance was launched without an EC2 key pair",
    INST, w(INST, KeyName="ops"), rows=[C + "ec2_instance_no_amazon_key_pair"], severity="medium", category="least_privilege", control="IA-2",
    remediation="Use SSM Session Manager or EC2 Instance Connect instead of long-lived EC2 key pairs.",
    docs=[EC2_API + "API_Instance.html"], extra={"na": w(INST, State={"Name": "stopped"})})
def inst_key_pair(item, index):
    value = state(item)
    if value != "running":
        return _na(value)
    key = absent_or(item, "InstanceId", "KeyName", None, str)
    return result(key is not None, key_name=key)


@install("aws.claude_a.ec2.instance_imdsv2_applied", "instance", "EC2 instance requires IMDSv2 and the metadata options are applied",
    INST, w(INST, MetadataOptions={"State": "applied", "HttpTokens": "optional", "HttpEndpoint": "enabled"}),
    rows=[C + "ec2_instance_uses_imdsv2", C + "foundational_security_ec2_8"], severity="high", control="AC-3",
    remediation="Set HttpTokens=required on the instance metadata options (ModifyInstanceMetadataOptions).",
    docs=[EC2_API + "API_InstanceMetadataOptionsResponse.html"])
def inst_imdsv2_applied(item, index):
    tokens = get(item, "MetadataOptions.HttpTokens", str)
    applied = get(item, "MetadataOptions.State", str)
    return result(not (tokens == "required" and applied == "applied"), http_tokens=tokens, state=applied)


@install("aws.claude_a.ec2.instance_imdsv2_or_disabled", "instance", "Non-terminated EC2 instance requires IMDSv2 or disables IMDS",
    INST, w(INST, MetadataOptions={"State": "applied", "HttpTokens": "optional", "HttpEndpoint": "enabled"}),
    rows=[P + "ec2_instance_imdsv2_enabled"], severity="high", control="AC-3",
    remediation="Require IMDSv2 tokens or disable the instance metadata endpoint.", docs=[EC2_API + "API_InstanceMetadataOptionsResponse.html"],
    extra={"na": w(INST, State={"Name": "terminated"})})
def inst_imdsv2_prowler(item, index):
    na = _not_terminated(item)
    if na:
        return na
    endpoint = get(item, "MetadataOptions.HttpEndpoint", str)
    tokens = get(item, "MetadataOptions.HttpTokens", str)
    passed = (endpoint == "enabled" and tokens == "required") or endpoint == "disabled"
    return result(not passed, http_endpoint=endpoint, http_tokens=tokens)


@install("aws.claude_a.ec2.instance_protected_by_backup", "instance", "EC2 instance is an AWS Backup protected resource",
    INST, w(INST, InstanceId="i-2"), index=idx(backup_protected_resource=PROTECTED),
    rows=[C + "ec2_instance_protected_by_backup_plan"], severity="medium",
    remediation="Assign the instance to an AWS Backup plan and confirm recovery points exist.",
    docs=["https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListProtectedResources.html"],
    dependencies=["instance", "backup_protected_resource"])
def inst_backup(item, index):
    arn = ec2_arn(index, "instance", get(item, "InstanceId", str))
    return result(not (found := _protected(index, "EC2", arn)), instance_arn=arn, protected_resource=found)


@install("aws.claude_a.ec2.instance_no_launch_wizard_sg", "instance", "EC2 instance does not use a launch-wizard security group",
    INST, w(INST, SecurityGroups=[{"GroupId": "sg-2", "GroupName": "launch-wizard-1"}]),
    rows=[C + "ec2_instance_no_launch_wizard_security_group"], severity="medium", category="network", control="SC-7",
    remediation="Replace launch-wizard security groups with purpose-built, least-privilege security groups.",
    docs=[EC2_API + "API_GroupIdentifier.html"])
def inst_launch_wizard(item, index):
    names = [get(g, "GroupName", str) for g in list_of_objects(get(item, "SecurityGroups", list))]
    bad = [n for n in names if n.startswith("launch-wizard")]
    return result(bool(bad), groups=bad)


def _paravirtual(item):
    value = get(item, "VirtualizationType", str)
    if value not in ("hvm", "paravirtual"):
        raise Unavailable("unrecognized virtualization type")
    return value


@install("aws.claude_a.ec2.instance_not_paravirtual", "instance", "EC2 instance does not use paravirtual virtualization",
    INST, w(INST, VirtualizationType="paravirtual"),
    rows=[C + "ec2_instance_virtualization_type_no_paravirtual", C + "foundational_security_ec2_24"], severity="medium",
    remediation="Migrate the workload to an HVM AMI and current-generation instance type.", docs=[EC2_API + "API_Instance.html"])
def inst_paravirtual(item, index):
    value = _paravirtual(item)
    return result(value == "paravirtual", virtualization_type=value)


@install("aws.claude_a.ec2.instance_not_paravirtual_not_terminated", "instance", "Non-terminated EC2 instance does not use paravirtual virtualization",
    INST, w(INST, VirtualizationType="paravirtual"), rows=[P + "ec2_instance_paravirtual_type"], severity="medium",
    remediation="Migrate the workload to an HVM AMI.", docs=[EC2_API + "API_Instance.html"], extra={"na": w(INST, State={"Name": "terminated"})})
def inst_paravirtual_live(item, index):
    na = _not_terminated(item)
    if na:
        return na
    value = _paravirtual(item)
    return result(value == "paravirtual", virtualization_type=value)


@install("aws.claude_a.ec2.instance_termination_protection", "instance", "EC2 instance has termination protection enabled",
    w(INST, Attributes={"DisableApiTermination": True}), w(INST, Attributes={"DisableApiTermination": False}),
    rows=[C + "ec2_instance_termination_protection_enabled"], severity="low",
    remediation="Enable termination protection (ModifyInstanceAttribute --disable-api-termination) on instances that must not be deleted accidentally.",
    docs=[EC2_API + "API_DescribeInstanceAttribute.html"], note="Requires DescribeInstanceAttribute(disableApiTermination), collected as Attributes.DisableApiTermination.")
def inst_termination(item, index):
    value = get(item, "Attributes.DisableApiTermination", bool)
    return result(not value, disable_api_termination=value)


@install("aws.claude_a.ec2.instance_not_older_than_180_days", "instance", "EC2 instance was launched within the last 180 days",
    INST, w(INST, LaunchTime="2025-01-01T00:00:00+00:00"), index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[C + "ec2_instance_not_older_than_180_days"], severity="low",
    remediation="Rebuild long-lived instances from current, patched images.", docs=[EC2_API + "API_Instance.html"])
def inst_age_compliance(item, index):
    launched = parse_time(get(item, "LaunchTime"))
    return result(launched < midnight_cutoff(item, index, 180), launch_time=str(item["LaunchTime"]))


@install("aws.claude_a.ec2.running_instance_age_180_days", "instance", "Running EC2 instance is not older than 180 days",
    INST, w(INST, LaunchTime="2025-01-01T00:00:00+00:00"), index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[P + "ec2_instance_older_than_specific_days"], severity="medium",
    remediation="Rebuild long-running instances from current, patched images.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": w(INST, State={"Name": "stopped"})}, note="Prowler default max_ec2_instance_age_in_days=180, whole days since launch > 180; non-running instances pass in Prowler and are not applicable here.")
def inst_age_prowler(item, index):
    value = state(item)
    launched = parse_time(get(item, "LaunchTime"))
    if value != "running":
        return _na(value)
    days = (clock(item, index) - launched).days
    return result(days > 180, days_since_launch=days)


_TRANSITION = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")


def transition_time(item):
    reason = get(item, "StateTransitionReason", str)
    match = _TRANSITION.search(reason)
    if not match:
        raise Unavailable("stop time not derivable from StateTransitionReason")
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


STOPPED = w(INST, State={"Name": "stopped"}, StateTransitionReason="User initiated (2025-12-30 10:00:00 GMT)")
OLD_STOP = w(INST, State={"Name": "stopped"}, StateTransitionReason="User initiated (2025-06-01 10:00:00 GMT)")


def _stopped_compliance(days):
    def evaluate(item, index):
        value = state(item)
        if value not in ("stopped", "stopping"):
            return _na(value)
        stamp = transition_time(item)
        return result(stamp <= midnight_cutoff(item, index, days), stopped_since=stamp.isoformat())
    return evaluate


install("aws.claude_a.ec2.stopped_instance_30_days", "instance", "Stopped EC2 instance has not been stopped for 30 days or more",
    STOPPED, OLD_STOP, index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[C + "ec2_stopped_instance_30_days", C + "foundational_security_ec2_4"], severity="low",
    remediation="Terminate or restart instances that have been stopped for 30 days or more.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": INST})(_stopped_compliance(30))
install("aws.claude_a.ec2.stopped_instance_90_days", "instance", "Stopped EC2 instance has not been stopped for 90 days or more",
    STOPPED, OLD_STOP, index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[C + "ec2_stopped_instance_90_days"], severity="low",
    remediation="Terminate or restart instances that have been stopped for 90 days or more.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": INST})(_stopped_compliance(90))


@install("aws.claude_a.ec2.stopped_instance_more_than_30_days", "instance", "Stopped EC2 instance has not been stopped for more than 30 days",
    STOPPED, OLD_STOP, index={"context": {"created_at": "2026-01-01T00:00:00+00:00"}},
    rows=[P + "ec2_instance_stopped_older_than_specific_days"], severity="low",
    remediation="Terminate or restart instances stopped for more than 30 days.", docs=[EC2_API + "API_Instance.html"],
    extra={"na": INST}, note="Prowler default max_ec2_instance_stopped_days=30, state 'stopped' only, whole days > 30; an unparsable stop time is UNKNOWN here.")
def stopped_prowler(item, index):
    value = state(item)
    if value != "stopped":
        return _na(value)
    days = (clock(item, index) - transition_time(item)).days
    return result(days > 30, days_stopped=days)


@install("aws.claude_a.ec2.instance_ebs_delete_on_termination", "instance", "EC2 instance EBS mappings delete on termination",
    INST, w(INST, BlockDeviceMappings=[{"DeviceName": "/dev/xvdb", "Ebs": {"VolumeId": "vol-2", "DeleteOnTermination": False}}]),
    rows=[C + "ec2_instance_attached_ebs_volume_delete_on_termination_enabled"], severity="low",
    remediation="Set DeleteOnTermination=true on instance EBS mappings that should not outlive the instance.",
    docs=[EC2_API + "API_EbsInstanceBlockDevice.html"])
def inst_dot(item, index):
    bad = []
    for mapping in list_of_objects(get(item, "BlockDeviceMappings", list)):
        ebs = optional(mapping, "Ebs", None, dict)
        if ebs is not None and get(ebs, "DeleteOnTermination", bool) is False:
            bad.append(mapping.get("DeviceName"))
    return result(bool(bad), devices=bad)


@install("aws.claude_a.ec2.instance_single_eni", "instance", "EC2 instance has exactly one network interface",
    INST, w(INST, NetworkInterfaces=[{"NetworkInterfaceId": "eni-1"}, {"NetworkInterfaceId": "eni-2"}]),
    rows=[C + "ec2_instance_not_use_multiple_enis", C + "foundational_security_ec2_17"], severity="low", category="network", control="SC-7",
    remediation="Detach secondary ENIs unless the instance is an approved multi-homed appliance.", docs=[EC2_API + "API_InstanceNetworkInterface.html"])
def inst_enis(item, index):
    count = len(list_of_objects(get(item, "NetworkInterfaces", list)))
    return result(count != 1, eni_count=count)


ENI = {"NetworkInterfaceId": "eni-1", "InterfaceType": "interface", "Status": "in-use", "SourceDestCheck": True,
       "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": [{"GroupId": "sg-1", "GroupName": "web"}],
       "Attachment": {"InstanceId": "i-1", "InstanceOwnerId": ACCOUNT, "Status": "attached"}, "Ipv6Addresses": [], "PrivateIpAddresses": []}


@install("aws.claude_a.ec2.instance_single_attachable_eni", "instance", "EC2 instance has at most one efa/interface/trunk ENI",
    INST, w(INST, NetworkInterfaces=[{"NetworkInterfaceId": "eni-1"}, {"NetworkInterfaceId": "eni-2"}]),
    index=idx(network_interface=[ENI, w(ENI, NetworkInterfaceId="eni-2")]),
    rows=[P + "ec2_instance_uses_single_eni"], severity="low", category="network", control="SC-7",
    remediation="Detach secondary ENIs unless multi-homing is required.", docs=[EC2_API + "API_NetworkInterface.html"],
    dependencies=["instance", "network_interface"], note="Prowler counts attached ENIs whose InterfaceType is efa, interface or trunk; an ENI missing from the inventory is UNKNOWN here.")
def inst_enis_prowler(item, index):
    ids = [get(n, "NetworkInterfaceId", str) for n in list_of_objects(get(item, "NetworkInterfaces", list))]
    if not ids:
        return result(False, eni_count=0)
    enis = {e.get("NetworkInterfaceId"): e for e in items(index, "network_interface")}
    if any(i not in enis for i in ids):
        raise Unavailable("instance ENI not in network_interface inventory")
    counted = [i for i in ids if get(enis[i], "InterfaceType", str) in ("efa", "interface", "trunk")]
    return result(len(counted) > 1, counted=counted)


SSM = {"InstanceId": "i-1", "PingStatus": "Online"}


@install("aws.claude_a.ec2.instance_ssm_managed", "instance", "EC2 instance is managed by Systems Manager",
    INST, w(INST, InstanceId="i-2"), index=idx(ssm_managed_instance=[SSM]),
    rows=[C + "ec2_instance_ssm_managed", C + "foundational_security_ssm_1"], severity="medium", control="CM-8",
    remediation="Install and register the SSM Agent with an instance profile that allows Systems Manager (AmazonSSMManagedInstanceCore).",
    docs=["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html"],
    dependencies=["instance", "ssm_managed_instance"], extra={"na": w(INST, State={"Name": "stopped"})},
    note="Stopped instances are 'info' upstream (not applicable).")
def inst_ssm(item, index):
    value = state(item)
    if value == "stopped":
        return _na(value)
    iid = get(item, "InstanceId", str)
    managed = any(m.get("InstanceId") == iid for m in items(index, "ssm_managed_instance"))
    return result(not managed, instance_id=iid, ssm_managed=managed)


@install("aws.claude_a.ec2.active_instance_ssm_managed", "instance", "Running EC2 instance is managed by Systems Manager",
    INST, w(INST, InstanceId="i-2"), index=idx(ssm_managed_instance=[SSM]),
    rows=[P + "ec2_instance_managed_by_ssm"], severity="medium", control="CM-8",
    remediation="Install and register the SSM Agent with an instance profile that allows Systems Manager.",
    docs=["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html"],
    dependencies=["instance", "ssm_managed_instance"], extra={"na": w(INST, State={"Name": "pending"})},
    note="Prowler passes pending, terminated and stopped instances without evaluation; they are not applicable here.")
def inst_ssm_prowler(item, index):
    value = state(item)
    if value in ("pending", "terminated", "stopped"):
        return _na(value)
    iid = get(item, "InstanceId", str)
    managed = any(m.get("InstanceId") == iid for m in items(index, "ssm_managed_instance"))
    return result(not managed, instance_id=iid, ssm_managed=managed)


IMG_USED = {"ImageId": "ami-1", "ImageOwnerAlias": "amazon", "DeprecationTime": "2027-01-01T00:00:00.000Z"}


@install("aws.claude_a.ec2.instance_ami_not_deprecated", "instance", "EC2 instance does not run a deprecated Amazon-owned AMI",
    INST, w(INST, ImageId="ami-2"),
    index=idx(ec2_instance_image=[IMG_USED, w(IMG_USED, ImageId="ami-2", DeprecationTime="2025-01-01T00:00:00.000Z")]),
    rows=[P + "ec2_instance_with_outdated_ami"], severity="medium", control="SI-2",
    remediation="Rebuild the instance from a current, supported Amazon AMI.", docs=[EC2_API + "API_Image.html"],
    dependencies=["instance", "ec2_instance_image"], extra={"na": w(INST, ImageId="ami-3")},
    note="ec2_instance_image is DescribeImages(ImageIds=<instance AMIs>, IncludeDeprecated=true). Only Amazon-owned AMIs are evaluated; AMIs not returned are not applicable.")
def inst_outdated_ami(item, index):
    image_id = get(item, "ImageId", str)
    images = [i for i in items(index, "ec2_instance_image") if i.get("ImageId") == image_id]
    if len(images) > 1:
        raise Unavailable("ambiguous image join")
    if not images or images[0].get("ImageOwnerAlias") != "amazon":
        return "NOT_APPLICABLE", {"reason": "AMI not Amazon-owned or not visible", "image_id": image_id}
    deprecation = absent_or(images[0], "ImageId", "DeprecationTime", None, str)
    if deprecation is None:
        return result(False, image_id=image_id)
    return result(parse_time(deprecation) < clock(item, index), image_id=image_id, deprecation_time=deprecation)


# --------------------------------------------------------------------------- Nitro Enclave parents
ENCLAVE = w(INST, EnclaveOptions={"Enabled": True})


def enclave_flag(item):
    return get(item, "EnclaveOptions.Enabled", bool)


def enclave_parent(item):
    return enclave_flag(item) and state(item) not in ("pending", "shutting-down", "terminated")


def _not_parent():
    return "NOT_APPLICABLE", {"reason": "not an active Nitro Enclave parent"}


@install("aws.claude_a.ec2.enclave_host_imdsv2", "instance", "Nitro Enclave parent declares HttpTokens required",
    ENCLAVE, w(ENCLAVE, MetadataOptions={"State": "applied", "HttpTokens": "optional", "HttpEndpoint": "enabled"}),
    rows=[P + "ec2_confidential_workload_host_imdsv2_not_enforced"], severity="high", control="AC-3",
    remediation="Require IMDSv2 (HttpTokens=required) on enclave parent instances.", docs=["https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"],
    extra={"na": INST})
def enclave_imds(item, index):
    if not enclave_parent(item):
        return _not_parent()
    tokens = get(item, "MetadataOptions.HttpTokens", str)
    return result(tokens != "required", http_tokens=tokens)


@install("aws.claude_a.ec2.enclave_host_running", "instance", "Nitro Enclave-enabled instance is not stopped or terminated",
    ENCLAVE, w(ENCLAVE, State={"Name": "stopped"}), rows=[P + "ec2_confidential_workload_host_not_running"], severity="medium",
    remediation="Restart or decommission stopped enclave hosts and remove their attestation bindings.",
    docs=["https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"], extra={"na": INST})
def enclave_running(item, index):
    if not enclave_flag(item):
        return _not_parent()
    value = state(item)
    return result(value in ("stopped", "shutting-down", "terminated"), state=value)


@install("aws.claude_a.ec2.enclave_host_not_public", "instance", "Nitro Enclave parent instance is not internet-reachable",
    ENCLAVE, w(ENCLAVE, PublicIpAddress="203.0.113.10"),
    index=idx(network_interface=[ENI], subnet=[{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
              route_table=[{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]}]),
    rows=[P + "ec2_confidential_workload_host_public_ip"], severity="medium", category="exposure", control="SC-7",
    remediation="Place enclave parents in private subnets without public IPv4/IPv6 addressing.",
    docs=["https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"],
    dependencies=["instance", "network_interface", "subnet", "route_table"], extra={"na": INST},
    note="FAIL on public IPv4, a global IPv6 on an attached ENI, or an IGW default route (IPv4 or IPv6) in the subnet route table; unresolved ENIs/subnets are UNKNOWN (Prowler MANUAL).")
def enclave_public(item, index):
    if not enclave_parent(item):
        return _not_parent()
    reasons = []
    if _public_ip(item) is not None:
        reasons.append("public_ipv4")
    enis = {e.get("NetworkInterfaceId"): e for e in items(index, "network_interface")}
    for ref in list_of_objects(get(item, "NetworkInterfaces", list)):
        eni = enis.get(get(ref, "NetworkInterfaceId", str))
        if eni is None:
            raise Unavailable("enclave host ENI not in inventory")
        for addr in list_of_objects(optional(eni, "Ipv6Addresses", [], list)):
            if ip_address(get(addr, "Ipv6Address", str)).is_global:
                reasons.append("global_ipv6")
    subnet_id = absent_or(item, "InstanceId", "SubnetId", None, str)
    if subnet_id:
        v4, v6 = subnet_public_prowler(index, subnet_by_id(index, subnet_id))
        if v4:
            reasons.append("igw_ipv4_default_route")
        if v6:
            reasons.append("igw_ipv6_default_route")
    return result(bool(reasons), reasons=reasons)


def _world_range(rule, protocols):
    from .claude_aws_a_common import _sg_protocol, _sg_bounds, _rule_ranges
    from ipaddress import ip_network
    v4, v6 = _rule_ranges(rule)
    for version, ranges in ((4, v4), (6, v6)):
        for cidr in ranges:
            try:
                if ip_network(cidr).version != version:
                    raise ValueError("address family mismatch")
            except ValueError as exc:
                raise Unavailable("malformed enclave security-group CIDR") from exc
    if not any(is_cidr_public(c) for c in v4 + v6):
        return None
    proto = _sg_protocol(get(rule, "IpProtocol", str))
    bounds = _sg_bounds(rule, proto)
    if proto == "-1":
        return "all"
    if proto not in {_sg_protocol(value) for value in protocols}:
        return None
    low, high = bounds
    if low == 0 and high == 65535:
        return "all"
    return (low, high)


def _instance_sgs(item, index):
    ids = [get(g, "GroupId", str) for g in list_of_objects(get(item, "SecurityGroups", list))]
    return security_groups(index, ids)


SG = {"GroupId": "sg-1", "GroupName": "web", "VpcId": "vpc-1",
      "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
      "IpPermissionsEgress": []}
SG_OPEN = w(SG, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}])


@install("aws.claude_a.ec2.enclave_host_ingress_allowlist", "instance", "Nitro Enclave parent allows world ingress only on ports 22, 80 and 443",
    ENCLAVE, w(ENCLAVE, SecurityGroups=[{"GroupId": "sg-2", "GroupName": "open"}]),
    index=idx(security_group=[SG, w(SG_OPEN, GroupId="sg-2")]),
    rows=[P + "ec2_confidential_workload_host_unrestricted_ingress"], severity="high", category="network", control="SC-7",
    remediation="Restrict enclave parent security groups to required ports from known sources.",
    docs=["https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"],
    dependencies=["instance", "security_group"], extra={"na": INST},
    note="Prowler default enclave_sg_allow_ports=[22,80,443]; world = any globally routable CIDR; TCP and UDP.")
def enclave_ingress(item, index):
    if not enclave_parent(item):
        return _not_parent()
    exposed = set()
    for sg in _instance_sgs(item, index):
        for rule in list_of_objects(get(sg, "IpPermissions", list)):
            span = _world_range(rule, ("tcp", "udp"))
            if span == "all":
                exposed.add("all")
            elif span:
                extra_ports = set(range(span[0], span[1] + 1)) - {22, 80, 443}
                if extra_ports:
                    exposed.add("%d-%d" % span)
    return result(bool(exposed), exposed=sorted(exposed))


_VSOCK = {5000, 9000, *range(8000, 8091)}


@install("aws.claude_a.ec2.enclave_host_vsock_ports_closed", "instance", "Nitro Enclave parent does not expose vsock-proxy ports to the world",
    ENCLAVE, w(ENCLAVE, SecurityGroups=[{"GroupId": "sg-2", "GroupName": "open"}]),
    index=idx(security_group=[SG, w(SG, GroupId="sg-2", IpPermissions=[{"IpProtocol": "tcp", "FromPort": 8000, "ToPort": 8000, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}])]),
    rows=[P + "ec2_confidential_workload_host_vsock_proxy_exposed"], severity="medium", category="network", control="SC-7",
    remediation="Do not expose vsock-proxy listener ports (5000, 8000-8090, 9000) to the internet.",
    docs=["https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"],
    dependencies=["instance", "security_group"], extra={"na": INST})
def enclave_vsock(item, index):
    if not enclave_parent(item):
        return _not_parent()
    exposed = set()
    for sg in _instance_sgs(item, index):
        for rule in list_of_objects(get(sg, "IpPermissions", list)):
            span = _world_range(rule, ("tcp",))
            if span == "all":
                exposed |= _VSOCK
            elif span:
                exposed |= _VSOCK & set(range(span[0], span[1] + 1))
    return result(bool(exposed), ports=sorted(exposed))


# --------------------------------------------------------------------------- instance port exposure
INSTANCE_PORTS = {
    "cassandra": [7000, 7001, 7199, 9042, 9160], "cifs": [139, 445], "elasticsearch_kibana": [9200, 9300, 5601],
    "ftp": [20, 21], "kafka": [9092], "kerberos": [88, 464, 749, 750], "ldap": [389, 636], "memcached": [11211],
    "mongodb": [27017, 27018], "mysql": [3306], "oracle": [1521, 2483, 2484], "postgresql": [5432], "rdp": [3389],
    "redis": [6379], "sqlserver": [1433, 1434], "ssh": [22], "telnet": [23],
}


def _instance_port_check(ports):
    def evaluate(item, index):
        get(item, "InstanceId", str)
        for sg in _instance_sgs(item, index):
            for rule in list_of_objects(get(sg, "IpPermissions", list)):
                if prowler_sg_open(rule, "tcp", ports, any_address=True):
                    return result(True, security_group=sg.get("GroupId"), ports=ports)
        return result(False, ports=ports, checked_ports_world_ingress=False)
    return evaluate


for _name, _ports in INSTANCE_PORTS.items():
    _sg = w(SG, GroupId="sg-9", IpPermissions=[{"IpProtocol": "tcp", "FromPort": _ports[0], "ToPort": _ports[0], "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}])
    install("aws.claude_a.ec2.instance_port_%s_not_internet_exposed" % _name, "instance",
        "EC2 instance security groups do not expose %s (%s) to 0.0.0.0/0 or ::/0" % (_name, ", ".join(map(str, _ports))),
        INST, w(INST, SecurityGroups=[{"GroupId": "sg-9", "GroupName": "db"}]), index=idx(security_group=[SG, _sg]),
        rows=[P + "ec2_instance_port_%s_exposed_to_internet" % _name], severity="critical", category="exposure", control="SC-7",
        remediation="Remove 0.0.0.0/0 and ::/0 ingress for TCP %s from the instance security groups; use private access paths." % ", ".join(map(str, _ports)),
        docs=[EC2_API + "API_IpPermission.html"], dependencies=["instance", "security_group"],
        note="Prowler check_security_group(tcp, ports, any_address=True) over the instance's security groups; Prowler's severity downgrade for private subnets is reported as a FAIL here.")(_instance_port_check(_ports))


# =========================================================================== launch templates
LT_DATA = {"MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
           "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": True}}],
           "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": False}]}
LT = {"LaunchTemplateId": "lt-1", "LaunchTemplateName": "app", "DefaultVersionNumber": 1,
      "Versions": [{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": LT_DATA}]}


def _versions(item):
    versions = list_of_objects(get(item, "Versions", list))
    if not versions:
        raise Unavailable("launch template versions not collected")
    return versions


def _default_data(item):
    rows = [v for v in _versions(item) if get(v, "DefaultVersion", bool)]
    if len(rows) != 1:
        raise Unavailable("default launch template version unresolved")
    return get(rows[0], "LaunchTemplateData", dict)


@install("aws.claude_a.ec2.launch_template_default_imdsv2", "ec2_launch_template", "Launch template default version requires IMDSv2",
    LT, w(LT, Versions=[{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": {"MetadataOptions": {"HttpTokens": "optional"}}}]),
    rows=[C + "ec2_launch_template_default_version_uses_imdsv2", C + "foundational_security_ec2_170"], severity="medium", control="AC-3",
    remediation="Create a launch template version with MetadataOptions.HttpTokens=required and make it the default.",
    docs=[EC2_API + "API_LaunchTemplateInstanceMetadataOptions.html"])
def lt_default_imds(item, index):
    data = _default_data(item)
    tokens = optional(data, "MetadataOptions", {}, dict).get("HttpTokens")
    return result(tokens != "required", http_tokens=tokens)


@install("aws.claude_a.ec2.launch_template_default_ebs_encrypted", "ec2_launch_template", "Launch template default version encrypts EBS volumes",
    LT, w(LT, Versions=[{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": {"BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 8}}]}}]),
    rows=[C + "ec2_launch_template_ebs_volume_encrypted", C + "foundational_security_ec2_181"], severity="medium", control="SC-28",
    remediation="Set Encrypted=true on every EBS block device mapping of the default launch template version.",
    docs=[EC2_API + "API_LaunchTemplateEbsBlockDevice.html"],
    extra={"na": w(LT, Versions=[{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": {}}])})
def lt_default_ebs(item, index):
    data = _default_data(item)
    mappings = optional(data, "BlockDeviceMappings", None)
    if not isinstance(mappings, list):
        return "NOT_APPLICABLE", {"reason": "default version has no block device mappings"}
    bad = [m.get("DeviceName") for m in list_of_objects(mappings) if isinstance(m.get("Ebs"), dict) and m["Ebs"].get("Encrypted") is not True]
    return result(bool(bad), unencrypted_devices=bad)


@install("aws.claude_a.ec2.launch_template_any_version_imdsv2", "ec2_launch_template", "Every launch template version requires IMDSv2 or disables IMDS",
    LT, w(LT, Versions=[{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": {"MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "optional"}}}]),
    rows=[P + "ec2_launch_template_imdsv2_required"], severity="high", control="AC-3",
    remediation="Review every launch template version that callers may select; set HttpTokens=required with HttpEndpoint=enabled, or explicitly disable the metadata endpoint, and update dependent launch settings after owner review.",
    docs=[EC2_API + "API_LaunchTemplateInstanceMetadataOptions.html"],
    note="All-version declaration check: explicit enabled/optional fails; every version must explicitly require tokens or disable the endpoint. Omitted metadata options inherit other settings and remain UNKNOWN; the separate default-version check is unchanged.")
def lt_versions_imds(item, index):
    versions = _versions(item)
    seen = set()
    unsafe = []
    uncertain = []
    required = disabled = 0
    for version in versions:
        try:
            number = get(version, "VersionNumber", int)
            if number < 1 or number in seen:
                raise Unavailable("launch template version identity malformed or duplicated")
            seen.add(number)
            data = get(version, "LaunchTemplateData", dict)
            meta = get(data, "MetadataOptions", dict)
        except Unavailable:
            uncertain.append(version.get("VersionNumber"))
            continue
        endpoint = meta.get("HttpEndpoint")
        tokens = meta.get("HttpTokens")
        if endpoint == "disabled":
            disabled += 1
        elif endpoint == "enabled" and tokens == "required":
            required += 1
        elif endpoint == "enabled" and tokens == "optional":
            unsafe.append(number)
        else:
            uncertain.append(number)
    if unsafe:
        return result(True, unsafe_versions=unsafe, uncertain_versions=uncertain)
    if uncertain:
        return "UNKNOWN", {"reason": "launch template metadata options unavailable or unrecognized", "uncertain_versions": uncertain}
    return result(False, imdsv2_required_versions=required, endpoint_disabled_versions=disabled)


@install("aws.claude_a.ec2.launch_template_no_public_ip", "ec2_launch_template", "Launch template versions do not assign public IPs",
    LT, w(LT, Versions=[{"VersionNumber": 1, "DefaultVersion": True, "LaunchTemplateData": {"NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}]}}]),
    rows=[P + "ec2_launch_template_no_public_ip"], severity="high", category="exposure", control="SC-7",
    remediation="Remove AssociatePublicIpAddress=true from launch template network interfaces.",
    docs=[EC2_API + "API_LaunchTemplateInstanceNetworkInterfaceSpecification.html"],
    note="Network interfaces referenced by NetworkInterfaceId need their own public-IP lookup (Prowler); such references are UNKNOWN here.")
def lt_public_ip(item, index):
    for version in _versions(item):
        data = get(version, "LaunchTemplateData", dict)
        for nic in list_of_objects(optional(data, "NetworkInterfaces", [], list)):
            if nic.get("AssociatePublicIpAddress") is True:
                return result(True, version=version.get("VersionNumber"))
            if nic.get("NetworkInterfaceId"):
                raise Unavailable("launch template references an existing ENI; its public addressing is not joined")
    return result(False, public_ip_assignment_found=False)


LT_INST = w(INST, Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-1"}],
            LaunchTemplateData={"NetworkInterfaces": [{"AssociatePublicIpAddress": False}],
                "InstanceId": INST["InstanceId"], "collection_status": "collected", "NetworkInterfacesComplete": True,
                "_provenance": {"profile": "aws-launch-template-instance-network-metadata-v1",
                    "source_operation": "ec2:GetLaunchTemplateData", "region": REGION, "read_only": True}})


@install("aws.claude_a.ec2.launch_template_instances_no_public_ip", "ec2_launch_template", "Instances launched from the launch template do not associate public IPs",
    LT, w(LT, LaunchTemplateId="lt-2"),
    index=idx(instance=[LT_INST, w(LT_INST, InstanceId="i-2", Tags=[{"Key": "aws:ec2launchtemplate:id", "Value": "lt-2"}],
                                   LaunchTemplateData__InstanceId="i-2",
                                   LaunchTemplateData__NetworkInterfaces=[{"AssociatePublicIpAddress": True}])]),
    rows=[C + "ec2_launch_template_not_publicly_accessible", C + "foundational_security_ec2_25"], severity="high", category="exposure", control="SC-7",
    remediation="Launch instances from templates whose network interfaces do not set AssociatePublicIpAddress.",
    docs=[EC2_API + "API_GetLaunchTemplateData.html"], dependencies=["ec2_launch_template", "instance"],
    extra={"na": w(LT, LaunchTemplateId="lt-9")},
    note="Steampipe joins instances by tag aws:ec2launchtemplate:id and reads each instance's GetLaunchTemplateData NetworkInterfaces; templates with no tagged instance are skipped.")
def lt_instances_public(item, index):
    lt_id = get(item, "LaunchTemplateId", str)
    tagged = [i for i in items(index, "instance") if tags(i).get("aws:ec2launchtemplate:id") == lt_id]
    if not tagged:
        return "NOT_APPLICABLE", {"reason": "no instance launched from this template"}
    incomplete = False
    for inst in tagged:
        try:
            data = get(inst, "LaunchTemplateData", dict)
            proof = get(data, "_provenance", dict)
            if (get(data, "collection_status", str) != "collected"
                    or get(data, "InstanceId", str) != get(inst, "InstanceId", str)
                    or get(proof, "profile", str) != "aws-launch-template-instance-network-metadata-v1"
                    or get(proof, "source_operation", str) != "ec2:GetLaunchTemplateData"
                    or get(proof, "region", str) != region(index) or get(proof, "read_only", bool) is not True):
                raise Unavailable("instance launch template data source binding unavailable")
            nics = list_of_objects(get(data, "NetworkInterfaces", list))
            flags = []
            for nic in nics:
                try:
                    flags.append(get(nic, "AssociatePublicIpAddress", bool))
                except Unavailable:
                    incomplete = True
            if any(flags):
                return result(True, instance=inst.get("InstanceId"))
            if get(data, "NetworkInterfacesComplete", bool) is not True:
                incomplete = True
        except Unavailable:
            incomplete = True
    if incomplete:
        raise Unavailable("instance launch template network metadata incomplete")
    return result(False, instances=len(tagged))


# =========================================================================== ENIs and Elastic IPs
_SDC_TYPES = ("aws_codestar_connections_managed", "branch", "efa", "interface", "lambda", "quicksight")


@install("aws.claude_a.ec2.eni_source_dest_check", "network_interface", "Network interface has source/destination check enabled",
    ENI, w(ENI, SourceDestCheck=False),
    rows=[C + "ec2_network_inteface_source_destination_check_enabled", C + "foundational_security_ec2_180"], severity="medium", category="network", control="SC-7",
    remediation="Enable SourceDestCheck on the ENI unless it belongs to an approved NAT/routing appliance.",
    docs=[EC2_API + "API_NetworkInterface.html"], extra={"na": w(ENI, InterfaceType="nat_gateway")})
def eni_sdc(item, index):
    kind = get(item, "InterfaceType", str)
    if kind not in _SDC_TYPES:
        return "NOT_APPLICABLE", {"interface_type": kind}
    value = get(item, "SourceDestCheck", bool)
    return result(not value, source_dest_check=value)


@install("aws.claude_a.ec2.eni_no_public_ip", "network_interface", "Network interface has no public IPv4 association",
    ENI, w(ENI, Association={"PublicIp": "203.0.113.5"}), rows=[R + "ec2_network_interface_not_publicly_accessible"],
    severity="high", category="exposure", control="SC-7", remediation="Remove public IP / Elastic IP associations from interfaces that need not be internet-facing.",
    docs=[EC2_API + "API_NetworkInterfaceAssociation.html"])
def eni_public(item, index):
    ip = absent_or(item, "NetworkInterfaceId", "Association.PublicIp", None, str)
    return result(ip is not None, public_ip=ip)


@install("aws.claude_a.ec2.eni_in_use", "network_interface", "Network interface is attached",
    ENI, w(ENI, Status="available", Attachment=DROP), rows=[C + "ec2_network_interface_unused"], severity="low",
    remediation="Delete unattached ENIs that are no longer needed.", docs=[EC2_API + "API_NetworkInterface.html"])
def eni_unused(item, index):
    status = get(item, "Status", str)
    if status not in ("available", "associated", "attaching", "in-use", "detaching"):
        raise Unavailable("unrecognized network interface status")
    attached = absent_or(item, "NetworkInterfaceId", "Attachment.InstanceId", None, str)
    return result(status == "available" and attached is None, status=status, attached_instance=attached)


EIP = {"AllocationId": "eipalloc-1", "PublicIp": "203.0.113.7", "AssociationId": "eipassoc-1", "Domain": "vpc"}


@install("aws.claude_a.ec2.eip_associated", "ec2_eip", "Elastic IP address is associated",
    EIP, w(EIP, AssociationId=DROP), rows=[C + "vpc_eip_associated", P + "ec2_elastic_ip_unassigned"], severity="low",
    remediation="Associate or release unused Elastic IP addresses.", docs=[EC2_API + "API_Address.html"],
    note="Every DescribeAddresses entry carries PublicIp, so Prowler's public-IP guard and the Steampipe association test coincide.")
def eip_associated(item, index):
    get(item, "PublicIp", str)
    assoc = absent_or(item, "PublicIp", "AssociationId", None, str)
    return result(assoc is None, association_id=assoc)

"""End-to-end evaluate benchmarks on synthetic AWS snapshots (no real account data).

The "10x" profile matches the audited 10x scale (~5.8k resources, ~3.1k principals, mixed policies,
privesc-relevant grants, VPC/subnet/ENI/instance hierarchy). Each run is a fresh subprocess; on Linux
VmHWM measures that process's peak without an inherited pre-exec ru_maxrss floor. Budgets were set from post-optimisation measurements
(see BUDGETS) with headroom for loaded CI hosts; CPU time is asserted because wall time is noisy.

    pytest tests/test_peaso_perf_benchmark.py                  # 1x profile only
    PEASO_BENCH=1 pytest tests/test_peaso_perf_benchmark.py    # also the 10x profile
"""
import json
import os
import resource
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "111111111111"
REGION_SCOPE = f"{ACCOUNT}/us-east-1"
GLOBAL_SCOPE = f"{ACCOUNT}/global"
PROFILES = {
    # vpcs, subnets, security groups, instances (each with an ENI), principals, groups
    "1x": (4, 40, 40, 120, 310, 12),
    "10x": (20, 200, 200, 1200, 3100, 60),
}
# Budgets: cpu_sec and wall_sec for evaluate_snapshot, maxrss_mb for the whole process (including the
# snapshot and the serialised report), report_mb for the JSON report. Post-optimisation measurements
# (Apple Silicon, Python 3.13, host load average ~40): 1x cpu 0.6 s, wall 1.1 s, 118 MB, 4.5 MB report;
# 10x cpu 8.8-43 s, wall 11-217 s, 288-507 MB, 37.6 MB report (privesc evaluation dominates 10x CPU).
# Budgets leave ~2-4x headroom for slower or loaded CI hosts.
# The October 2026 catalog has 1,556 controls and emits 20,681 findings here.
# Fresh-process measurements: Linux/3.12 3.93 CPU s, 313 MB; macOS/3.13
# 2.57 CPU s, 340 MB. Rebaseline the small profile for that catalog growth;
# keep the 10x limits and per-finding/report bounds unchanged.
# The combined native registry now loads at startup: main (48b70bc2) peaks at
# 528 MB and Linux CI at 514 MB, so the 1x process budget is 600 MB.
BUDGETS = {
    "1x": {"cpu_sec": 6, "wall_sec": 60, "maxrss_mb": 600},
    "10x": {"cpu_sec": 90, "wall_sec": 600, "maxrss_mb": 1000},
}
# Report size is budgeted on principle instead of as a fixed constant. The old fixed 12 MB came from a
# 4.5 MB report produced by a much smaller check registry, and every newly registered check legitimately
# adds rows (one per resource of its type), one check_frameworks / check_meta entry and coverage rows.
#  - finding_bytes: the average compact finding row (report["findings"] JSON bytes / rows). Per-check fields
#    (title, remediation, service, category, severity, framework labels) live once per check in
#    check_meta / check_frameworks, so a row is its id, resource, status and evidence. A regression that
#    re-inlines per-check data or bloats evidence breaks this regardless of how many checks exist
#    (measured ~480 B on the realistic 1x fixture).
#  - report_kb_per_check: the absolute ceiling for the whole compact report, scaled by the number of
#    registered AWS checks (report_mb <= registered_checks * KB / 1000). At a fixed fixture the report grows
#    linearly with the registry, so registering checks raises the ceiling and nothing else does. Measured
#    ~11.2 KB/check on 1x (1152 checks, 12.9 MB; ~25% headroom). The opt-in 10x fixture has 10x the
#    resources per check type, so its rate is the 1x rate scaled by 10 (not separately re-measured).
# Native source admissions are a one-off process startup cost. Keep their
# own bound visible instead of charging them to each snapshot evaluation.
# The combined native registry includes source admission at process startup.
# Reviewed Linux 3.12 cold startup reached 35.48 CPU s; keep a finite 45 s
# startup bound while preserving separate evaluation, wall-time and RSS limits.
NATIVE_CATALOG_BUDGETS = {"native_catalog_cpu_sec": 45, "native_catalog_wall_sec": 60}
FINDING_BYTES = 600
REPORT_KB_PER_CHECK = {"1x": 14, "10x": 140}


def _linux_peak_rss_mb(status_text):
    for line in status_text.splitlines():
        if line.startswith("VmHWM:"):
            parts = line.split()
            if len(parts) == 3 and parts[0] == "VmHWM:" and parts[2] == "kB":
                return int(parts[1]) / 1024
    raise ValueError("Linux /proc/self/status has no valid VmHWM")


def _process_peak_rss_mb():
    if sys.platform.startswith("linux"):
        # Linux getrusage preserves ru_maxrss across execve. Under xdist this
        # can report the much larger pytest worker's former address space.
        return _linux_peak_rss_mb(Path("/proc/self/status").read_text())
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1 << 20) if sys.platform == "darwin" else peak / 1024


def synthetic_snapshot(vpcs, subnets, groups_count, instances, principals, iam_groups):
    # Item shapes follow what peaso.collectors.aws emits for a live account (describe_* / IAM
    # authorization details plus the per-user access key, login profile and MFA reads), so checks see
    # the facts a real scan has. Account-global rows carry the collector's explicit
    # AccountId binding. Users include mock completed usage reports; roles whose
    # exact identity policies cannot allow Bedrock carry the native skip proof.
    # Reports unavailable in this fixture and unread instance attributes stay
    # absent, so missing evidence still produces UNKNOWN.
    def ts(i):
        return f"2026-{1 + i % 9:02d}-{1 + i % 27:02d}T{i % 24:02d}:00:00+00:00"

    def rule(protocol, port, cidr):
        return {"IpProtocol": protocol, **({"FromPort": port, "ToPort": port} if protocol != "-1" else {}),
                "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]}
    service_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    vpc_items = [{"VpcId": f"vpc-{i:05d}", "CidrBlock": f"10.{i % 250}.0.0/16", "OwnerId": ACCOUNT, "State": "available", "IsDefault": i == 0,
                  "InstanceTenancy": "default", "DhcpOptionsId": "dopt-00001",
                  "CidrBlockAssociationSet": [{"AssociationId": f"vpc-cidr-assoc-{i:05d}", "CidrBlock": f"10.{i % 250}.0.0/16", "CidrBlockState": {"State": "associated"}}],
                  "BlockPublicAccessStates": {"InternetGatewayBlockMode": "off"}} for i in range(vpcs)]
    subnet_items = [{"SubnetId": f"subnet-{i:05d}", "VpcId": f"vpc-{i % vpcs:05d}", "CidrBlock": f"10.{(i % vpcs) % 250}.{i // vpcs % 250}.0/24",
                     "MapPublicIpOnLaunch": i % 2 == 0, "State": "available", "AvailabilityZone": f"us-east-1{'abc'[i % 3]}", "AvailableIpAddressCount": 250 - i % 50,
                     "DefaultForAz": False, "AssignIpv6AddressOnCreation": False, "Ipv6CidrBlockAssociationSet": [], "Ipv6Native": False,
                     "EnableDns64": False, "MapCustomerOwnedIpOnLaunch": False, "OwnerId": ACCOUNT,
                     "SubnetArn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-{i:05d}",
                     "BlockPublicAccessStates": {"InternetGatewayBlockMode": "off"}} for i in range(subnets)]
    sg_items = [{"GroupId": f"sg-{i:05d}", "GroupName": f"sg{i}", "VpcId": f"vpc-{i % vpcs:05d}", "Description": f"sg{i} rules", "OwnerId": ACCOUNT,
                 "SecurityGroupArn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-{i:05d}",
                 "IpPermissions": [rule("tcp", 22, "0.0.0.0/0" if i % 5 == 0 else "10.0.0.0/8"), rule("tcp", 443, "10.0.0.0/8")],
                 "IpPermissionsEgress": [rule("-1", None, "0.0.0.0/0")]} for i in range(groups_count)]

    def eni(i, attached=True):
        value = {"NetworkInterfaceId": f"eni-{i:05d}", "SubnetId": f"subnet-{i % subnets:05d}", "VpcId": f"vpc-{(i % subnets) % vpcs:05d}",
                 "Groups": [{"GroupId": f"sg-{i % groups_count:05d}", "GroupName": f"sg{i % groups_count}"}], "Description": "", "InterfaceType": "interface",
                 "Status": "in-use", "OwnerId": ACCOUNT, "MacAddress": f"0e:00:00:00:{i // 256 % 256:02x}:{i % 256:02x}", "SourceDestCheck": True,
                 "PrivateIpAddress": f"10.0.{i // 250}.{i % 250}", "PrivateDnsName": f"ip-10-0-{i // 250}-{i % 250}.ec2.internal",
                 "PrivateIpAddresses": [{"Primary": True, "PrivateIpAddress": f"10.0.{i // 250}.{i % 250}"}], "Ipv6Addresses": []}
        if attached:
            value["Attachment"] = {"AttachmentId": f"eni-attach-{i:05d}", "DeleteOnTermination": True, "DeviceIndex": 0, "Status": "attached", "AttachTime": ts(i)}
        if i % 3 == 0:
            value["Association"] = {"PublicIp": f"3.3.{i // 250}.{i % 250}", "IpOwnerId": "amazon"}
        return value
    eni_items = [dict(eni(i), AvailabilityZone=f"us-east-1{'abc'[i % 3]}", RequesterManaged=False, TagSet=[]) for i in range(instances)]
    instance_items = [{"InstanceId": f"i-{i:05d}", "SubnetId": f"subnet-{i % subnets:05d}", "VpcId": f"vpc-{(i % subnets) % vpcs:05d}",
                       "SecurityGroups": [{"GroupId": f"sg-{i % groups_count:05d}", "GroupName": f"sg{i % groups_count}"}], "NetworkInterfaces": [eni(i)],
                       "State": {"Name": "running"}, "InstanceType": ("t3.micro", "m5.large", "c6g.xlarge")[i % 3], "ImageId": f"ami-{i % 7:05d}",
                       "LaunchTime": ts(i), "VirtualizationType": "hvm", "Architecture": "arm64" if i % 3 == 2 else "x86_64", "Hypervisor": "xen",
                       "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda", "EbsOptimized": i % 2 == 0, "EnaSupport": True,
                       "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": f"vol-{i:05d}", "Status": "attached", "DeleteOnTermination": True, "AttachTime": ts(i)}}],
                       "Monitoring": {"State": "enabled" if i % 5 == 0 else "disabled"}, "EnclaveOptions": {"Enabled": False}, "HibernationOptions": {"Configured": False},
                       "MetadataOptions": {"State": "applied", "HttpTokens": "required" if i % 4 else "optional", "HttpPutResponseHopLimit": 2 if i % 4 else 1,
                                           "HttpEndpoint": "enabled", "HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "disabled"},
                       "Placement": {"AvailabilityZone": f"us-east-1{'abc'[i % 3]}", "Tenancy": "default", "GroupName": ""},
                       "PrivateIpAddress": f"10.0.{i // 250}.{i % 250}", "PlatformDetails": "Linux/UNIX", "SourceDestCheck": True,
                       "MaintenanceOptions": {"AutoRecovery": "default"}, "CpuOptions": {"CoreCount": 1, "ThreadsPerCore": 2},
                       **({"IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/r{i}", "Id": f"AIPA{i:010d}"}} if i % 2 else {}),
                       "Tags": [{"Key": "Name", "Value": f"app-{i}"}]} for i in range(instances)]
    roles_count = principals // 2
    paths = ("/", "/app/", "/ops/", "/data/")

    def role_actions(i):
        actions = ["s3:GetObject", "ec2:Describe*"]
        if i % 50 == 0:
            actions += ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
        if i % 97 == 0:
            actions += ["iam:CreatePolicyVersion", "iam:AttachRolePolicy"]
        return actions

    roles = []
    for i in range(roles_count):
        role = {"RoleName": f"r{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:role{paths[i % 4]}r{i}", "Path": paths[i % 4], "RoleId": f"AROA{i:010d}",
                "CreateDate": ts(i), "MaxSessionDuration": 3600, "Tags": [],
                "InstanceProfileList": ([{"InstanceProfileName": f"r{i}",
                                         "Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/r{i}",
                                         "InstanceProfileId": f"AIPA{i:010d}"}] if i % 2 and i < instances else []),
                "RoleLastUsed": {"LastUsedDate": ts(i + 3), "Region": "us-east-1"} if i % 3 else {},
                "AssumeRolePolicyDocument": service_trust if i % 7 == 0 else trust,
                "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": role_actions(i), "Resource": "*"}]}}],
                "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyName": "AdministratorAccess"}] if i % 211 == 0 else []}
        roles.append(role)
        if role['AttachedManagedPolicies']:
            role['ServicesLastAccessedStatus'] = {'collection_status': 'not_collected', 'reason': 'synthetic_report_unavailable'}
        else:
            role['ServicesLastAccessedStatus'] = {'collection_status': 'not_collected',
                'reason': 'identity_policies_cannot_allow_namespaces', 'namespaces': ['bedrock'],
                'source': 'iam:GetAccountAuthorizationDetails'}
    users = []
    for i in range(principals - roles_count):
        statements = [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{ACCOUNT}:role{paths[(i % max(1, roles_count)) % 4]}r{i % max(1, roles_count)}"}]
        if i % 60 == 0:
            statements.append({"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"})
        keys = [{"UserName": f"u{i}", "AccessKeyFingerprint": f"fp{i:08d}{k}", "Status": "Active" if k == 0 else "Inactive", "CreateDate": ts(i + k),
                 "LastUsed": {"collection_status": "collected", "UserName": f"u{i}",
                              "AccessKeyLastUsed": {"LastUsedDate": ts(i + 5), "Region": "us-east-1", "ServiceName": "s3"} if i % 4 else {"Region": "N/A", "ServiceName": "N/A"}}}
                for k in range(i % 3)]
        console = i % 2 == 0
        users.append({"UserName": f"u{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:user{paths[i % 4]}u{i}", "Path": paths[i % 4], "UserId": f"AIDA{i:010d}",
                      "CreateDate": ts(i), "Tags": [],
                      "AccessKeys": {"collection_status": "collected" if keys else "empty", "items": keys},
                      "LoginProfile": {"collection_status": "collected", "LoginProfile": {"UserName": f"u{i}", "CreateDate": ts(i), "PasswordResetRequired": False}}
                      if console else {"collection_status": "empty"},
                      "MFADevices": {"collection_status": "collected" if console and i % 4 == 0 else "empty",
                                     "items": [{"UserName": f"u{i}", "SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/u{i}", "EnableDate": ts(i)}] if console and i % 4 == 0 else []},
                      "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}],
                      "AttachedManagedPolicies": [], "GroupList": [f"g{i % iam_groups}"] if i % 3 == 0 else []})
    group_items = [{"GroupName": f"g{i}", "Arn": f"arn:aws:iam::{ACCOUNT}:group/g{i}", "Path": "/", "GroupId": f"AGPA{i:010d}", "CreateDate": ts(i),
                    "GroupPolicyList": [{"PolicyName": "gp", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Action": ["iam:PassRole", "glue:CreateDevEndpoint"] if i % 10 == 0 else ["cloudwatch:Get*"], "Resource": "*"}]}}],
                    "AttachedManagedPolicies": []} for i in range(iam_groups)]
    group_by_name = {group['GroupName']: group for group in group_items}
    for i, user in enumerate(users):
        policies = list(user['UserPolicyList'])
        for group in user['GroupList']:
            policies.extend(group_by_name[group]['GroupPolicyList'])
        namespaces = set()
        for policy in policies:
            for statement in policy['PolicyDocument']['Statement']:
                actions = statement['Action']
                actions = [actions] if isinstance(actions, str) else actions
                namespaces.update(action.split(':', 1)[0] for action in actions)
        user['ServicesLastAccessed'] = [{'ServiceNamespace': namespace, 'LastAuthenticated': ts(i + 5),
                                       'LastAuthenticatedRegion': 'us-east-1'} for namespace in sorted(namespaces)]
        user['ServicesLastAccessedStatus'] = {'collection_status': 'collected'}

    def col(kind, scope, items, **extra):
        if extra.get('global'):
            for item in items:
                item['AccountId'] = ACCOUNT
        return {"type": kind, "scope": scope, "service": kind.split("_")[0], "status": "collected" if items else "empty", "items": items, **extra}

    glob = {"global": True, "account_id": ACCOUNT}
    collections = [col("vpc", REGION_SCOPE, vpc_items), col("subnet", REGION_SCOPE, subnet_items), col("security_group", REGION_SCOPE, sg_items),
                   col("network_interface", REGION_SCOPE, eni_items), col("instance", REGION_SCOPE, instance_items),
                   col("iam_role", GLOBAL_SCOPE, roles, **glob), col("iam_user", GLOBAL_SCOPE, users, **glob),
                   col("iam_group", GLOBAL_SCOPE, group_items, **glob), col("iam_policy", GLOBAL_SCOPE, [], **glob),
                   # A complete empty read is a valid synthetic collector result: the
                   # 120 running instances have no actionable CloudWatch alarms.
                   col("cloudwatch_alarm", REGION_SCOPE, [])]
    return {"schema_version": "1.0", "provider": "aws", "scopes": [REGION_SCOPE, GLOBAL_SCOPE],
            "created_at": "2026-10-10T00:00:00+00:00", "collections": collections, "metadata": {}}


def measure(profile):
    import time
    sys.path.insert(0, str(ROOT))
    from peaso import privesc
    from peaso.engine import evaluate_snapshot
    snapshot = synthetic_snapshot(*PROFILES[profile])
    privesc.catalog()  # catalog load is a one-off process cost, not evaluation
    assert "peaso.checks" not in sys.modules, "Benchmark must measure a cold native catalog"
    startup_wall, startup_cpu = time.perf_counter(), time.process_time()
    from peaso import checks as native_checks
    assert native_checks.CHECKS
    native_catalog_wall = time.perf_counter() - startup_wall
    native_catalog_cpu = time.process_time() - startup_cpu
    started, before = time.perf_counter(), resource.getrusage(resource.RUSAGE_SELF)
    report = evaluate_snapshot(snapshot)
    wall, after = time.perf_counter() - started, resource.getrusage(resource.RUSAGE_SELF)
    # Count the exact default-JSON bytes without holding a second full report
    # string beside the report while measuring process peak RSS.
    report_bytes = sum(map(len, json.JSONEncoder().iterencode(report)))
    peak_mb = _process_peak_rss_mb()
    from peaso.checks import CHECKS
    registered = sum(1 for check in CHECKS if check.provider == "aws")
    return {"native_catalog_cpu_sec": round(native_catalog_cpu, 2),
            "native_catalog_wall_sec": round(native_catalog_wall, 2),
            "profile": profile, "resources": report["stats"]["resource_count"], "findings": report["stats"]["finding_count"],
            "wall_sec": round(wall, 2), "cpu_sec": round(after.ru_utime - before.ru_utime + after.ru_stime - before.ru_stime, 2),
            "maxrss_mb": round(peak_mb),
            "report_mb": round(report_bytes / 1e6, 1), "snapshot_mb": round(len(json.dumps(snapshot)) / 1e6, 1),
            "finding_bytes": round(len(json.dumps(report["findings"])) / max(1, len(report["findings"]))),
            "registered_checks": registered, "unknown_findings": sum(f["status"] == "UNKNOWN" for f in report["findings"]),
            "schema_version": report["schema_version"]}


def run(profile):
    out = subprocess.run([sys.executable, __file__, profile], cwd=ROOT, capture_output=True, text=True, timeout=1800)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def check(result):
    budget = dict(BUDGETS[result["profile"]], **NATIVE_CATALOG_BUDGETS, finding_bytes=FINDING_BYTES,
                  report_mb=round(result["registered_checks"] * REPORT_KB_PER_CHECK[result["profile"]] / 1000, 1))
    print(json.dumps({"measured": result, "budget": budget}))
    assert result["schema_version"] == "1.1"
    for key, limit in budget.items():
        assert result[key] <= limit, f"{result['profile']} {key} {result[key]} exceeds budget {limit}: {result}"


def test_benchmark_1x_synthetic_evaluate():
    result = run("1x")
    assert result["resources"] >= 600
    # The broad synthetic fixture still decides at least four fifths of
    # findings; newly admitted checks may need facts this fixture omits.
    assert result["unknown_findings"] < 0.2 * result["findings"], result
    check(result)


def test_linux_peak_rss_uses_current_process_vm_high_water_mark():
    assert _linux_peak_rss_mb("VmRSS:\t2048 kB\nVmHWM:\t307200 kB\n") == 300


@pytest.mark.skipif(not os.environ.get("PEASO_BENCH"), reason="set PEASO_BENCH=1 to run the 10x synthetic benchmark")
def test_benchmark_10x_synthetic_evaluate():
    result = run("10x")
    assert result["resources"] >= 5800
    check(result)


if __name__ == "__main__":
    print(json.dumps(measure(sys.argv[1])))

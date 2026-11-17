"""claude2_aws_b devtools group: CodeBuild, CodeDeploy, CodePipeline, CodeCommit, CodeArtifact, CloudFormation, EventBridge and ECR.

Every predicate is a pure function over collected snapshot facts. Missing, denied or
malformed facts are UNKNOWN; non-applicable resources are NOT_APPLICABLE. Facts that the
collector does not read yet are listed in COLLECTOR_FACTS (read-only APIs only); until they
are collected the affected predicates have no items (or return UNKNOWN), never FAIL.
"""
from __future__ import annotations

import math
import re
from . import unknown
from .facts import Unavailable, get, list_of_objects, complete_items, optional
from .claude2_aws_b_common import (P, C, X, ABSENT, result, install, detail, detail_list, absent_or, clock, parse_time, account, policy_document,
    is_policy_public, turbot_public_statements, scope_of, inventory, indexes, CONTEXT, SCOPE)

ANCHOR = {"scope": SCOPE}
CTX = {"context": dict(CONTEXT)}

D_CB_PROJECT = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Project.html"
D_CB_SOURCE = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html"
D_CB_LOGS = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_S3LogsConfig.html"
D_CB_BUILD = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Build.html"
D_CB_LISTB = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListBuildsForProject.html"
D_CB_ENV = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_EnvironmentVariable.html"
D_CB_CRED = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_SourceCredentialsInfo.html"
D_CB_WEBHOOK = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_WebhookFilter.html"
D_CB_REPORT = "https://docs.aws.amazon.com/codebuild/latest/APIReference/API_S3ReportExportConfig.html"
D_SH_CB = "https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html"
D_CFN = "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Stack.html"
D_CFN_DRIFT = "https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackDriftInformation.html"
D_CDK = "https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-env.html"
D_CD = "https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_DeploymentGroupInfo.html"
D_CD_CFG = "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html"
D_ECR_POLICY = "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetRepositoryPolicy.html"
D_ECR_SCAN = "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetRegistryScanningConfiguration.html"
D_ECR_IMAGES = "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageDetail.html"
D_ECR_FINDINGS = "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DescribeImageScanFindings.html"
D_EB_BUS = "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_EventBus.html"
D_EB_ENDPOINT = "https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_Endpoint.html"
D_SCHEMA = "https://docs.aws.amazon.com/eventbridge/latest/schema-reference/v1-registries-name-registryname-policy.html"
D_CA_DOMAIN = "https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetDomainPermissionsPolicy.html"
D_CA_REPO = "https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetRepositoryPermissionsPolicy.html"
D_CA_PKG = "https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_PackageSummary.html"
D_CA_ORIGIN = "https://docs.aws.amazon.com/codeartifact/latest/ug/package-origin-controls.html"

# Facts the predicates below need but the collector does not read yet (read-only APIs only).
COLLECTOR_FACTS = [
    {"kind": "codebuild_project (Builds child list)", "api": "codebuild:ListBuildsForProject(projectName, sortOrder=DESCENDING) + codebuild:BatchGetBuilds(ids)",
     "fields": "Builds = {collection_status, items:[{id, buildStatus, startTime, endTime}]} in ListBuildsForProject order", "checks": ["aws.c2b.codebuild.invoked_last_90_days", "aws.c2b.codebuild.built_within_90_days"]},
    {"kind": "codebuild_project (Configuration projects[].environment.environmentVariables)", "api": "codebuild:BatchGetProjects (already called)",
     "fields": "environment.environmentVariables[].{name, type} only; the value member must stay dropped (today the whole list is omitted)", "checks": ["aws.c2b.codebuild.no_plaintext_sensitive_env_names"]},
    {"kind": "codebuild_source_credential", "api": "codebuild:ListSourceCredentials", "fields": "sourceCredentialsInfos[].{arn, serverType, authType}", "checks": ["aws.c2b.codebuild.source_repo_oauth"]},
    {"kind": "codebuild_report_group", "api": "codebuild:ListReportGroups + codebuild:BatchGetReportGroups", "fields": "reportGroups[].{arn, name, exportConfig.exportConfigType, exportConfig.s3Destination.{bucket, encryptionKey, encryptionDisabled}}",
     "checks": ["aws.c2b.codebuild.report_group_export_encrypted"]},
    {"kind": "cloudformation_stack", "api": "cloudformation:DescribeStacks", "fields": "Stacks[].{StackName, StackId, NotificationARNs, DisableRollback, EnableTerminationProtection, DriftInformation.StackDriftStatus, ParentId, RootId}; Outputs only for StackName == CDKToolkit and only the BootstrapVersion OutputKey/OutputValue",
     "checks": ["aws.c2b.cloudformation.drift_in_sync", "aws.c2b.cloudformation.notifications", "aws.c2b.cloudformation.rollback_enabled", "aws.c2b.cloudformation.termination_protection_all_stacks", "aws.c2b.cloudformation.termination_protection_root_stacks", "aws.c2b.cloudformation.cdktoolkit_bootstrap_version"]},
    {"kind": "codedeploy_deployment_group", "api": "codedeploy:ListApplications + codedeploy:ListDeploymentGroups + codedeploy:BatchGetDeploymentGroups", "fields": "deploymentGroupsInfo[].{applicationName, deploymentGroupName, deploymentGroupId, computePlatform, deploymentConfigName}",
     "checks": ["aws.c2b.codedeploy.lambda_not_all_at_once"]},
    {"kind": "ecr_repository (Images child list)", "api": "ecr:DescribeImages(repositoryName) + ecr:DescribeImageScanFindings(latest scannable imageDigest)",
     "fields": "Images = {collection_status, items:[{imageDigest, imageTags, imagePushedAt, artifactMediaType, ScanFindings:{collection_status, imageDigest, imageScanStatus.status, imageScanFindingsSummary.{findingSeverityCounts, imageScanCompletedAt}, source_api, pages}}]}", "checks": ["aws.c2b.ecr.latest_image_no_medium_plus_findings"]},
    {"kind": "eventbridge_bus", "api": "events:ListEventBuses (+ events:DescribeEventBus)", "fields": "EventBuses[].{Name, Arn, Policy}", "checks": ["aws.c2b.eventbridge.custom_bus_policy_attached", "aws.c2b.eventbridge.bus_policy_not_public", "aws.c2b.eventbridge.bus_policy_no_cross_account", "aws.c2b.eventbridge.bus_policy_prohibit_public_perimeter"]},
    {"kind": "eventbridge_endpoint", "api": "events:ListEndpoints", "fields": "Endpoints[].{Name, Arn, ReplicationConfig.State}", "checks": ["aws.c2b.eventbridge.global_endpoint_replication"]},
    {"kind": "eventbridge_schema_registry", "api": "schemas:ListRegistries + schemas:GetResourcePolicy(RegistryName) (NotFoundException = absent marker)", "fields": "Registries[].{RegistryName, RegistryArn}, Policy = {Policy, RevisionId}",
     "checks": ["aws.c2b.eventbridge.schema_registry_no_cross_account"]},
    {"kind": "codeartifact_domain", "api": "codeartifact:ListDomains + codeartifact:GetDomainPermissionsPolicy(domain) (ResourceNotFoundException = absent marker)", "fields": "domains[].{name, arn, owner}, Policy = {policy.document}",
     "checks": ["aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter"]},
    {"kind": "codeartifact_repository", "api": "codeartifact:ListRepositories + codeartifact:GetRepositoryPermissionsPolicy (ResourceNotFoundException = absent marker) + codeartifact:ListPackages + codeartifact:ListPackageVersions(sortBy=PUBLISHED_TIME, maxResults=1)",
     "fields": "repositories[].{name, arn, domainName, domainOwner}, Policy = {policy.document}, Packages = {collection_status, items:[{format, namespace, package, originConfiguration.restrictions.{publish, upstream}, LatestVersion:{collection_status, versions:[{version, status, origin.originType}]}}]}",
     "checks": ["aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter", "aws.c2b.codeartifact.internal_packages_block_upstream"]},
]


# =========================================================================== CodeBuild
def _project(item):
    container = detail(item, "Configuration")
    if container is None:
        raise Unavailable("CodeBuild project configuration not found")
    rows = list_of_objects(get(container, "projects", list))
    if len(rows) != 1:
        raise Unavailable("project response must contain one matched configuration")
    return rows[0]


def _proj(**fields):
    return {"name": "p1", "Configuration": {"collection_status": "collected", "projects": [{"name": "p1", "arn": "arn:aws:codebuild:us-east-1:111111111111:project/p1", **fields}]}}


_SRC = {"type": "CODECOMMIT", "location": "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/r"}


@install("aws.c2b.codebuild.project_private", "codebuild_project", "CodeBuild project visibility is private",
    _proj(projectVisibility="PRIVATE"), _proj(projectVisibility="PUBLIC_READ"), rows=[P + "codebuild_project_not_publicly_accessible"],
    severity="high", category="exposure", control="AC-3", docs=[D_CB_PROJECT, "https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html"],
    remediation="Set the project visibility to PRIVATE so build results, logs and artifacts are not publicly readable.",
    note="PASS only when projectVisibility is PRIVATE; a missing projectVisibility is UNKNOWN (prowler's empty-string default would FAIL).")
def project_private(item, index):
    visibility = get(_project(item), "projectVisibility", str)
    return result(visibility != "PRIVATE", project_visibility=visibility)


@install("aws.c2b.codebuild.s3_logs_encrypted_when_enabled", "codebuild_project", "CodeBuild project S3 logs, when enabled, are encrypted",
    _proj(logsConfig={"s3Logs": {"status": "ENABLED", "location": "b/p", "encryptionDisabled": False}}),
    _proj(logsConfig={"s3Logs": {"status": "ENABLED", "location": "b/p", "encryptionDisabled": True}}),
    rows=[P + "codebuild_project_s3_logs_encrypted"], severity="low", control="SC-28", docs=[D_CB_LOGS, D_SH_CB],
    remediation="Re-enable encryption of the project's S3 build logs (clear encryptionDisabled).",
    extra={"not_applicable": _proj(logsConfig={"s3Logs": {"status": "DISABLED", "encryptionDisabled": True}}),
           "default_pass": _proj(logsConfig={"s3Logs": {"status": "ENABLED", "location": "b/p"}}), "default_pass_expect": "PASS"},
    note="Prowler reports only projects whose s3Logs status is ENABLED (others NOT_APPLICABLE); an omitted encryptionDisabled is the documented default (encrypted). Differs from aws.b.codebuild.s3_log_encryption, which also evaluates disabled S3 log configs.")
def s3_logs_encrypted(item, index):
    data = _project(item)
    logs = optional(data, "logsConfig", {}, dict)
    s3 = optional(logs, "s3Logs", {}, dict)
    status = optional(s3, "status", "DISABLED", str)
    if status != "ENABLED":
        return "NOT_APPLICABLE", {"s3_logs_status": status}
    disabled = optional(s3, "encryptionDisabled", False, bool)
    return result(disabled, s3_logs_encryption_disabled=disabled)


_TOKEN = re.compile(r"https://x-token-auth:[^@]+@bitbucket\.org/.+\.git")
_BASIC = re.compile(r"https://[^:]+:[^@]+@bitbucket\.org/.+\.git")


def _url_credential(source):
    if get(source, "type", str) != "BITBUCKET":
        return None
    location = optional(source, "location", "", str)
    if _TOKEN.match(location):
        return "token"
    if _BASIC.match(location):
        return "basic_auth"
    return None


@install("aws.c2b.codebuild.source_url_no_credentials", "codebuild_project", "CodeBuild Bitbucket source repository URLs do not contain credentials",
    _proj(source={"type": "BITBUCKET", "location": "https://bitbucket.org/org/repo.git"}),
    _proj(source={"type": "CODECOMMIT", "location": "x"}, secondarySources=[{"type": "BITBUCKET", "location": "https://x-token-auth:abc@bitbucket.org/org/repo.git", "sourceIdentifier": "s2"}]),
    rows=[P + "codebuild_project_source_repo_url_no_sensitive_credentials"], severity="critical", control="IA-5", docs=[D_CB_SOURCE, D_SH_CB],
    remediation="Remove tokens or user name/password from Bitbucket source URLs and connect the source with OAuth or CodeConnections.",
    extra={"basic_auth": _proj(source={"type": "BITBUCKET", "location": "https://user:pw@bitbucket.org/org/repo.git"}), "basic_auth_expect": "FAIL",
           "no_source_pass": _proj(source={"type": "NO_SOURCE"})},
    note="Prowler regexes (re.match) for x-token-auth tokens and user:password URLs on BITBUCKET primary and secondary sources. Evidence names only the source position and credential kind, never the URL.")
def source_url_credentials(item, index):
    data = _project(item)
    hits = []
    primary = get(data, "source", dict)
    kind = _url_credential(primary)
    if kind:
        hits.append({"source": "primary", "credential": kind})
    for position, source in enumerate(list_of_objects(optional(data, "secondarySources", [], list))):
        kind = _url_credential(source)
        if kind:
            hits.append({"source": "secondary[" + str(position) + "]", "credential": kind})
    return result(bool(hits), credentials_in_source_urls=hits)


@install("aws.c2b.codebuild.buildspec_not_user_controlled", "codebuild_project", "CodeBuild project does not use a repository buildspec file (.yml/.yaml)",
    _proj(source={**_SRC, "buildspec": "version: 0.2\nphases: {}"}), _proj(source={**_SRC, "buildspec": "ci/buildspec.yaml"}),
    rows=[P + "codebuild_project_user_controlled_buildspec"], severity="medium", control="CM-5", docs=[D_CB_SOURCE],
    remediation="Define the buildspec inline in the project or load it from a location that build authors cannot modify.",
    extra={"default_pass": _proj(source=dict(_SRC)), "default_pass_expect": "PASS", "yml": _proj(source={**_SRC, "buildspec": "buildspec.yml"}), "yml_expect": "FAIL"},
    note="Prowler: FAIL when source.buildspec matches .*\\.yaml$ or .*\\.yml$ (re.search); an omitted buildspec (repository default) is PASS, as upstream.")
def buildspec_prowler(item, index):
    source = get(_project(item), "source", dict)
    spec = optional(source, "buildspec", None, str)
    failed = bool(spec) and (re.search(r".*\.yaml$", spec) is not None or re.search(r".*\.yml$", spec) is not None)
    return result(failed, buildspec_file=spec if failed else None)


@install("aws.c2b.codebuild.buildspec_not_yml_file", "codebuild_project", "CodeBuild project buildspec is not a .yml file reference",
    _proj(source={**_SRC, "buildspec": "ci/buildspec.yaml"}), _proj(source={**_SRC, "buildspec": "buildspec.yml"}),
    rows=[C + "codebuild_project_with_user_controlled_buildspec"], severity="medium", control="CM-5", docs=[D_CB_SOURCE],
    remediation="Define the buildspec inline in the project or load it from a location that build authors cannot modify.",
    extra={"default_pass": _proj(source=dict(_SRC)), "default_pass_expect": "PASS"},
    note="Steampipe: alarm when split_part(source.Buildspec, '.', -1) = 'yml' (only the .yml suffix; .yaml passes). Kept apart from the prowler predicate, which also flags .yaml.")
def buildspec_steampipe(item, index):
    source = get(_project(item), "source", dict)
    spec = optional(source, "buildspec", None, str)
    failed = spec is not None and spec.split(".")[-1] == "yml"
    return result(failed, buildspec_file=spec if failed else None)


_RISKY_FILTERS = {"ACTOR_ACCOUNT_ID", "HEAD_REF", "BASE_REF"}


def _anchored(pattern):
    if not pattern:
        return True
    for alternative in pattern.split("|"):
        alternative = alternative.strip()
        if alternative and not (alternative.startswith("^") and alternative.endswith("$")):
            return False
    return True


@install("aws.c2b.codebuild.webhook_filters_anchored", "codebuild_project", "CodeBuild webhook ACTOR_ACCOUNT_ID/HEAD_REF/BASE_REF filters use anchored patterns",
    _proj(webhook={"filterGroups": [[{"type": "EVENT", "pattern": "PUSH"}, {"type": "ACTOR_ACCOUNT_ID", "pattern": "^1234$|^5678$"}]]}),
    _proj(webhook={"filterGroups": [[{"type": "EVENT", "pattern": "PUSH"}, {"type": "HEAD_REF", "pattern": "refs/heads/main"}]]}),
    rows=[P + "codebuild_project_webhook_filters_use_anchored_patterns"], severity="high", control="CM-5", docs=[D_CB_WEBHOOK],
    remediation="Anchor every alternative of ACTOR_ACCOUNT_ID, HEAD_REF and BASE_REF webhook filter patterns with ^ and $.",
    extra={"no_webhook_pass": _proj(source=dict(_SRC))},
    note="Prowler: projects without a webhook or filter groups PASS; FAIL when any high-risk filter has an alternative not wrapped in ^...$.")
def webhook_anchored(item, index):
    data = _project(item)
    hook = optional(data, "webhook", None, dict)
    groups = [] if hook is None else optional(hook, "filterGroups", [], list)
    loose = []
    for group in groups:
        if not isinstance(group, list):
            raise Unavailable("malformed webhook filter group")
        for entry in list_of_objects(group):
            kind = get(entry, "type", str)
            pattern = optional(entry, "pattern", "", str)
            if kind in _RISKY_FILTERS and not _anchored(pattern):
                loose.append({"type": kind, "pattern": pattern})
    return result(bool(loose), unanchored_filters=loose)


_SENSITIVE_NAMES = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "PASSWORD")


@install("aws.c2b.codebuild.no_plaintext_sensitive_env_names", "codebuild_project", "CodeBuild project has no PLAINTEXT environment variables named like AWS keys or passwords",
    _proj(environment={"type": "LINUX_CONTAINER", "environmentVariables": [{"name": "DB_PASSWORD", "type": "SECRETS_MANAGER"}, {"name": "STAGE", "type": "PLAINTEXT"}]}),
    _proj(environment={"type": "LINUX_CONTAINER", "environmentVariables": [{"name": "aws_secret_access_key", "type": "PLAINTEXT"}]}),
    rows=[C + "codebuild_project_plaintext_env_variables_no_sensitive_aws_values", C + "foundational_security_codebuild_2"], severity="critical", control="IA-5",
    docs=[D_CB_ENV, D_SH_CB], remediation="Move AWS keys and passwords out of PLAINTEXT environment variables into Secrets Manager or Parameter Store references.",
    note="Steampipe: name ILIKE %AWS_ACCESS_KEY_ID%/%AWS_SECRET_ACCESS_KEY%/%PASSWORD% with Type PLAINTEXT. Only variable names and types are evaluated; values are never read. The collector currently omits environmentVariables, so this stays UNKNOWN until it projects {name, type}.")
def env_names(item, index):
    environment = get(_project(item), "environment", dict)
    hits = []
    for variable in list_of_objects(get(environment, "environmentVariables", list)):
        name = get(variable, "name", str)
        if optional(variable, "type", "PLAINTEXT", str) == "PLAINTEXT" and any(word in name.upper() for word in _SENSITIVE_NAMES):
            hits.append(name)
    return result(bool(hits), plaintext_sensitive_names=hits)


def _credentials(*rows):
    return inventory("codebuild_source_credential", [{"arn": "arn:aws:codebuild:us-east-1:111111111111:token/" + server.lower(), "serverType": server, "authType": auth} for server, auth in rows])


@install("aws.c2b.codebuild.source_repo_oauth", "codebuild_project", "CodeBuild GitHub or Bitbucket source uses OAuth source credentials",
    _proj(source={"type": "GITHUB", "location": "https://github.com/org/repo"}), _proj(source={"type": "BITBUCKET", "location": "https://bitbucket.org/org/repo.git"}),
    rows=[C + "codebuild_project_source_repo_oauth_configured", C + "foundational_security_codebuild_1"], severity="high", control="IA-5",
    dependencies=["codebuild_project", "codebuild_source_credential"], docs=[D_CB_CRED, D_SH_CB],
    remediation="Connect GitHub/Bitbucket sources with OAuth (or CodeConnections) instead of personal access tokens or basic authentication.",
    extra={"index": indexes(_credentials(("GITHUB", "OAUTH"), ("BITBUCKET", "BASIC_AUTH"))), "not_applicable": _proj(source=dict(_SRC)),
           "no_credential": _proj(source={"type": "GITHUB", "location": "https://github.com/org/repo"}), "no_credential_index": indexes(_credentials()), "no_credential_expect": "FAIL"},
    note="Steampipe left-joins aws_codebuild_source_credential on region and server type: no credential row alarms and every non-OAUTH row alarms, so PASS requires at least one matching credential and all of them OAUTH. Non GitHub/Bitbucket sources are NOT_APPLICABLE (skip).")
def source_oauth(item, index):
    kind = get(get(_project(item), "source", dict), "type", str)
    if kind not in ("GITHUB", "BITBUCKET"):
        return "NOT_APPLICABLE", {"source_type": kind}
    auths = [get(row, "authType", str) for row in complete_items(index, "codebuild_source_credential") if get(row, "serverType", str) == kind]
    return result(not auths or any(auth != "OAUTH" for auth in auths), source_type=kind, credential_auth_types=auths)


def _builds(*rows, status="collected"):
    return {"collection_status": status if rows or status != "collected" else "empty", "items": list(rows)}


def _with_builds(*rows):
    out = _proj(source=dict(_SRC))
    out["Builds"] = _builds(*rows)
    return out


def _build_rows(item):
    return detail_list(item, "Builds")


@install("aws.c2b.codebuild.invoked_last_90_days", "codebuild_project", "CodeBuild project has been invoked in the last 90 days (prowler)",
    _with_builds({"id": "p1:2", "buildStatus": "SUCCEEDED", "endTime": "2025-12-01T00:00:00+00:00"}),
    _with_builds({"id": "p1:2", "buildStatus": "SUCCEEDED", "endTime": "2025-09-01T00:00:00+00:00"}),
    rows=[P + "codebuild_project_older_90_days"], severity="medium", control="CM-7", docs=[D_CB_LISTB, D_CB_BUILD],
    remediation="Delete unused CodeBuild projects (and their service roles) or confirm they are still required.",
    extra={"index": CTX, "never": _with_builds(), "running_pass": _with_builds({"id": "p1:3", "buildStatus": "IN_PROGRESS"})},
    note="Prowler: the most recent build (first id of ListBuildsForProject) endTime older than 90 days (timedelta.days > 90) FAILs and no build FAILs. A most recent build that is still IN_PROGRESS is an invocation now and PASSes (prowler would report it as never built).")
def invoked_90(item, index):
    rows = _build_rows(item)
    if not rows:
        return result(True, last_build=None)
    latest = rows[0]
    end = optional(latest, "endTime", None, str)
    if end is None:
        status = get(latest, "buildStatus", str)
        if status != "IN_PROGRESS":
            raise Unavailable("latest build has no end time")
        return result(False, last_build_status=status)
    age = (clock(item, index) - parse_time(end)).days
    return result(age > 90, days_since_last_build=age)


@install("aws.c2b.codebuild.built_within_90_days", "codebuild_project", "CodeBuild project has a build finished less than 90 days ago (steampipe)",
    _with_builds({"id": "p1:2", "endTime": "2025-12-01T00:00:00+00:00"}, {"id": "p1:1", "endTime": "2025-01-01T00:00:00+00:00"}),
    _with_builds({"id": "p1:2", "endTime": "2025-10-03T00:00:00+00:00"}),
    rows=[C + "codebuild_project_build_greater_then_90_days"], severity="medium", control="CM-7", docs=[D_CB_LISTB, D_CB_BUILD],
    remediation="Delete unused CodeBuild projects (and their service roles) or confirm they are still required.",
    extra={"index": CTX, "never": _with_builds(), "running_pass": _with_builds({"id": "p1:3", "buildStatus": "IN_PROGRESS"})},
    note="Steampipe: min(date_part('day', now() - end_time)) over the project's builds; < 90 ok, >= 90 or no finished build alarms (kept apart from prowler's > 90). A running build counts as invoked now (PASS).")
def built_90(item, index):
    rows = _build_rows(item)
    now = clock(item, index)
    ages, running = [], False
    for row in rows:
        end = optional(row, "endTime", None, str)
        if end is None:
            running = running or optional(row, "buildStatus", None, str) == "IN_PROGRESS"
            continue
        ages.append((now - parse_time(end)).days)
    if running:
        return result(False, build_in_progress=True)
    if not ages:
        return result(True, builds=len(rows))
    return result(min(ages) >= 90, days_since_latest_build=min(ages))


def _group(**export):
    return {"arn": "arn:aws:codebuild:us-east-1:111111111111:report-group/g1", "name": "g1", "type": "TEST", **({"exportConfig": export} if export else {})}


@install("aws.c2b.codebuild.report_group_export_encrypted", "codebuild_report_group", "CodeBuild report group S3 exports are encrypted at rest",
    _group(exportConfigType="S3", s3Destination={"bucket": "b", "encryptionKey": "arn:aws:kms:us-east-1:111111111111:key/k", "encryptionDisabled": False}),
    _group(exportConfigType="S3", s3Destination={"bucket": "b", "encryptionDisabled": True}),
    rows=[P + "codebuild_report_group_export_encrypted", C + "codebuild_report_group_export_encryption_at_rest_enabled", C + "foundational_security_codebuild_7"],
    severity="medium", control="SC-28", docs=[D_CB_REPORT, D_SH_CB], remediation="Enable encryption for the report group's S3 export (clear encryptionDisabled, optionally set a KMS key).",
    extra={"not_applicable": _group(exportConfigType="NO_EXPORT")},
    note="Security Hub CodeBuild.7 evaluates only report groups exporting to S3, as prowler does; the steampipe query also alarms NO_EXPORT groups (null EncryptionDisabled), which the official control does not, so those are NOT_APPLICABLE here (corrected applicability). A missing encryptionDisabled is UNKNOWN.")
def report_group(item, index):
    get(item, "arn", str)
    config = optional(item, "exportConfig", None, dict)
    kind = "NO_EXPORT" if config is None else optional(config, "exportConfigType", "NO_EXPORT", str)
    if kind != "S3":
        return "NOT_APPLICABLE", {"export_type": kind}
    disabled = get(get(config, "s3Destination", dict), "encryptionDisabled", bool)
    return result(disabled, export_encryption_disabled=disabled)


# =========================================================================== CloudFormation
STACK_ID = "arn:aws:cloudformation:us-east-1:111111111111:stack/s1/1"


def _stack(**fields):
    return {"StackName": "s1", "StackId": STACK_ID, "StackStatus": "CREATE_COMPLETE", **fields}


@install("aws.c2b.cloudformation.drift_in_sync", "cloudformation_stack", "CloudFormation stack has not drifted from its template",
    _stack(DriftInformation={"StackDriftStatus": "IN_SYNC"}), _stack(DriftInformation={"StackDriftStatus": "DRIFTED"}),
    rows=[C + "cloudformation_stack_drift_detection_check"], severity="low", control="CM-3", docs=[D_CFN_DRIFT],
    remediation="Run drift detection and reconcile drifted resources with the stack template (update the stack or the resources).",
    extra={"not_applicable": _stack(DriftInformation={"StackDriftStatus": "NOT_CHECKED"})},
    note="Steampipe: IN_SYNC ok, DRIFTED alarm, NOT_CHECKED/UNKNOWN skip (NOT_APPLICABLE). The predicate reads the last drift result; it never starts drift detection.")
def drift(item, index):
    get(item, "StackName", str)
    status = get(item, "DriftInformation.StackDriftStatus", str)
    if status not in ("IN_SYNC", "DRIFTED"):
        return "NOT_APPLICABLE", {"stack_drift_status": status}
    return result(status == "DRIFTED", stack_drift_status=status)


@install("aws.c2b.cloudformation.notifications", "cloudformation_stack", "CloudFormation stack sends events to an SNS topic",
    _stack(NotificationARNs=["arn:aws:sns:us-east-1:111111111111:t"]), _stack(NotificationARNs=[]),
    rows=[C + "cloudformation_stack_notifications_enabled", C + "foundational_security_cloudformation_1"], severity="low", control="SI-4",
    docs=[D_CFN, "https://docs.aws.amazon.com/securityhub/latest/userguide/cloudformation-controls.html"],
    remediation="Configure an SNS notification topic for the stack (NotificationARNs).",
    extra={"absent": _stack(), "absent_expect": "FAIL"}, note="Steampipe: jsonb_array_length(notification_arns) > 0; an omitted NotificationARNs member means none and alarms.")
def notifications(item, index):
    arns = absent_or(item, "StackName", "NotificationARNs", [], list)
    return result(not arns, notification_arns=len(arns))


@install("aws.c2b.cloudformation.rollback_enabled", "cloudformation_stack", "CloudFormation stack keeps rollback on failure enabled",
    _stack(DisableRollback=False), _stack(DisableRollback=True), rows=[C + "cloudformation_stack_rollback_enabled"], severity="low", control="CP-10",
    docs=[D_CFN], remediation="Recreate or update the stack without --disable-rollback so failed operations roll back.",
    note="Steampipe: NOT disable_rollback is ok; a missing DisableRollback is UNKNOWN.")
def rollback(item, index):
    get(item, "StackName", str)
    disabled = get(item, "DisableRollback", bool)
    return result(disabled, disable_rollback=disabled)


@install("aws.c2b.cloudformation.termination_protection_all_stacks", "cloudformation_stack", "CloudFormation stack termination protection is enabled (all stacks)",
    _stack(EnableTerminationProtection=True), _stack(EnableTerminationProtection=False), rows=[C + "cloudformation_stack_termination_protection_enabled"],
    severity="medium", control="CP-10", docs=[D_CFN, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html"],
    remediation="Enable termination protection on the stack (on the root stack for nested stacks).",
    note="Steampipe evaluates every stack including nested stacks (kept apart from prowler, which skips nested stacks). Missing EnableTerminationProtection is UNKNOWN.")
def termination_all(item, index):
    get(item, "StackName", str)
    enabled = get(item, "EnableTerminationProtection", bool)
    return result(not enabled, termination_protection=enabled)


@install("aws.c2b.cloudformation.termination_protection_root_stacks", "cloudformation_stack", "CloudFormation root stack termination protection is enabled",
    _stack(EnableTerminationProtection=True), _stack(EnableTerminationProtection=False), rows=[P + "cloudformation_stacks_termination_protection_enabled"],
    severity="medium", control="CP-10", docs=[D_CFN, "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html"],
    remediation="Enable termination protection on the stack.",
    extra={"not_applicable": _stack(EnableTerminationProtection=False, RootId="arn:aws:cloudformation:us-east-1:111111111111:stack/root/0", ParentId="arn:aws:cloudformation:us-east-1:111111111111:stack/root/0")},
    note="Prowler skips nested stacks (non-empty RootId): NOT_APPLICABLE. Missing EnableTerminationProtection is UNKNOWN.")
def termination_root(item, index):
    root = absent_or(item, "StackName", "RootId", "", str)
    if root:
        return "NOT_APPLICABLE", {"root_stack": root}
    enabled = get(item, "EnableTerminationProtection", bool)
    return result(not enabled, termination_protection=enabled)


def _cdk(version):
    return _stack(StackName="CDKToolkit", Outputs=[{"OutputKey": "BucketName", "OutputValue": "cdk-assets"}, {"OutputKey": "BootstrapVersion", "OutputValue": str(version)}])


@install("aws.c2b.cloudformation.cdktoolkit_bootstrap_version", "cloudformation_stack", "CDKToolkit stack bootstrap version is 21 or higher",
    _cdk(25), _cdk(14), rows=[P + "cloudformation_stack_cdktoolkit_bootstrap_version"], severity="high", control="SI-2", docs=[D_CDK],
    remediation="Re-bootstrap the environment with a current AWS CDK version (cdk bootstrap) to reach bootstrap version 21 or later.",
    extra={"not_applicable": _stack(Outputs=[{"OutputKey": "BootstrapVersion", "OutputValue": "5"}]), "no_version": _stack(StackName="CDKToolkit"), "no_version_expect": "NOT_APPLICABLE"},
    note="Prowler default recommended_cdk_bootstrap_version = 21; only stacks named CDKToolkit with a BootstrapVersion output are reported (others NOT_APPLICABLE).")
def cdk_bootstrap(item, index):
    name = get(item, "StackName", str)
    if name != "CDKToolkit":
        return "NOT_APPLICABLE", {"stack": name}
    version = None
    for output in list_of_objects(absent_or(item, "StackName", "Outputs", [], list)):
        if get(output, "OutputKey", str) == "BootstrapVersion":
            version = int(get(output, "OutputValue", str))
            break
    if not version:
        return "NOT_APPLICABLE", {"stack": name, "bootstrap_version": None}
    return result(version < 21, bootstrap_version=version, recommended=21)


# =========================================================================== CodeDeploy
def _dgroup(platform, config):
    return {"applicationName": "app", "deploymentGroupName": "dg", "deploymentGroupId": "1", "computePlatform": platform, "deploymentConfigName": config}


@install("aws.c2b.codedeploy.lambda_not_all_at_once", "codedeploy_deployment_group", "CodeDeploy Lambda deployment group does not shift all traffic at once",
    _dgroup("Lambda", "CodeDeployDefault.LambdaCanary10Percent5Minutes"), _dgroup("Lambda", "CodeDeployDefault.LambdaAllAtOnce"),
    rows=[C + "codedeploy_deployment_group_lambda_allatonce_traffic_shift_disabled"], severity="medium", control="CM-3", docs=[D_CD, D_CD_CFG],
    remediation="Use a canary or linear deployment configuration for Lambda deployment groups.",
    extra={"not_applicable": _dgroup("Server", "CodeDeployDefault.AllAtOnce")},
    note="Steampipe joins the group to its application compute platform; BatchGetDeploymentGroups returns the same computePlatform on the group. Non-Lambda groups skip (NOT_APPLICABLE).")
def lambda_all_at_once(item, index):
    platform = get(item, "computePlatform", str)
    if platform != "Lambda":
        return "NOT_APPLICABLE", {"compute_platform": platform}
    config = get(item, "deploymentConfigName", str)
    return result(config == "CodeDeployDefault.LambdaAllAtOnce", deployment_config=config)


# =========================================================================== ECR
REPO_ARN = "arn:aws:ecr:us-east-1:111111111111:repository/app"
_ECR_PUB = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer"]}]}'
_ECR_COND = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:BatchGetImage","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}'
_ECR_PRIV = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:role/ci"},"Action":"ecr:*"}]}'


def _repo(policy=None, **fields):
    container = ABSENT if policy is None else {"collection_status": "collected", "registryId": "111111111111", "repositoryName": "app", "policyText": policy}
    return {"repositoryName": "app", "repositoryArn": REPO_ARN, "Policy": container, **fields}


def _repo_policy(item):
    container = detail(item, "Policy")
    if container is None:
        return None
    return policy_document(get(container, "policyText", (str, dict)))  # live collector stores the parsed document


def _aws_principal_values(statement):
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        value = principal.get("AWS")
        return value if isinstance(value, list) else ([] if value is None else [value])
    return []


@install("aws.c2b.ecr.repository_policy_no_wildcard_principal", "ecr_repository", "ECR repository policy has no Allow statement for a wildcard AWS principal",
    _repo(_ECR_PRIV), _repo(_ECR_PUB), rows=[C + "ecr_repository_prohibit_public_access"], severity="critical", category="exposure", control="AC-3",
    docs=[D_ECR_POLICY, "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html"],
    remediation="Remove the wildcard principal from the repository policy and grant pull/push only to named accounts or roles.",
    extra={"absent": _repo(), "conditioned": _repo(_ECR_COND), "conditioned_expect": "FAIL"},
    note="Steampipe: any Allow statement whose Principal.AWS contains '*' (and that has an Action list) alarms, conditions ignored; no policy is ok.")
def ecr_wildcard(item, index):
    statements = _repo_policy(item)
    if statements is None:
        return result(False, policy=None)
    hits = [s for s in statements if s.get("Effect") == "Allow" and "*" in _aws_principal_values(s) and s.get("Action")]
    return result(bool(hits), wildcard_statements=len(hits))


@install("aws.c2b.ecr.repository_not_public", "ecr_repository", "ECR repository policy does not allow public access (prowler)",
    _repo(_ECR_COND), _repo(_ECR_PUB), rows=[P + "ecr_repositories_not_publicly_accessible"], severity="critical", category="exposure", control="AC-3",
    docs=[D_ECR_POLICY], remediation="Remove public principals from the repository policy or restrict them with account or organization conditions.",
    extra={"index": CTX, "not_applicable": _repo()}, note="Prowler is_policy_public with the audited account; repositories without a policy are not reported (NOT_APPLICABLE).")
def ecr_public(item, index):
    statements = _repo_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    public = is_policy_public(statements, account(index))
    return result(public, statements=len(statements), public_policy=public)


@install("aws.c2b.ecr.repository_policy_prohibit_public_perimeter", "ecr_repository", "ECR repository policy does not allow public access (perimeter)",
    _repo(_ECR_COND), _repo(_ECR_PUB), rows=[X + "ecr_repository_policy_prohibit_public_access"], severity="critical", category="exposure", control="AC-3",
    docs=[D_ECR_POLICY], remediation="Remove wildcard principals or add restricting conditions (source account, organization, principal ARN) to the repository policy.",
    extra={"not_applicable": _repo()}, note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def ecr_perimeter(item, index):
    statements = _repo_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits), public_allow_statements=len(hits))


def _registry(scan_type="ENHANCED", rules=()):
    data = {"registryId": "111111111111", "scanningConfiguration": {"scanType": scan_type, "rules": list(rules)}}
    return inventory("ecr_registry_scanning_configuration", [data])


_REPOS = inventory("ecr_repository", [{"repositoryName": "app"}])
_NO_REPOS = inventory("ecr_repository", [])


def _registry_config(index):
    rows = complete_items(index, "ecr_registry_scanning_configuration")
    if len(rows) != 1:
        raise Unavailable("registry scanning configuration not uniquely resolved")
    return get(rows[0], "scanningConfiguration", dict)


@install("aws.c2b.ecr.registry_enhanced_scanning", "ecr_registry_scanning_configuration", "In-use ECR registry has enhanced scanning enabled",
    ANCHOR, ANCHOR, rows=[P + "ecr_registry_enhanced_scanning_enabled"], severity="medium", control="RA-5", target="scope",
    dependencies=["ecr_registry_scanning_configuration", "ecr_repository"], docs=[D_ECR_SCAN, "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html"],
    remediation="Switch the registry scanning configuration to ENHANCED (Amazon Inspector) scanning.",
    extra={"pass_index": indexes(_registry("ENHANCED"), _REPOS), "fail_index": indexes(_registry("BASIC"), _REPOS),
           "not_applicable": ANCHOR, "not_applicable_index": indexes(_registry("BASIC"), _NO_REPOS)},
    note="Prowler checks only registries with at least one repository (no repositories = NOT_APPLICABLE); scanType ENHANCED passes. An unreadable configuration is UNKNOWN (prowler MANUAL).")
def registry_enhanced(item, index):
    scope = scope_of(item)
    config = _registry_config(index)
    if not complete_items(index, "ecr_repository"):
        return "NOT_APPLICABLE", {"scope": scope, "reason": "registry holds no repositories"}
    mode = optional(config, "scanType", "BASIC", str)
    return result(mode != "ENHANCED", scope=scope, scan_type=mode)


_AUTOMATED = ("SCAN_ON_PUSH", "CONTINUOUS_SCAN")
_ALL = [{"filter": "*", "filterType": "WILDCARD"}]


@install("aws.c2b.ecr.registry_automated_scanning", "ecr_registry_scanning_configuration", "In-use ECR registry scans all repositories automatically",
    ANCHOR, ANCHOR, rows=[P + "ecr_registry_scan_images_on_push_enabled"], severity="medium", control="RA-5", target="scope",
    dependencies=["ecr_registry_scanning_configuration", "ecr_repository"], docs=[D_ECR_SCAN, "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_RegistryScanningRule.html"],
    remediation="Add a registry scanning rule with SCAN_ON_PUSH or CONTINUOUS_SCAN frequency and a '*' repository filter.",
    extra={"pass_index": indexes(_registry("BASIC", [{"scanFrequency": "SCAN_ON_PUSH", "repositoryFilters": _ALL}]), _REPOS),
           "fail_index": indexes(_registry("ENHANCED", [{"scanFrequency": "CONTINUOUS_SCAN", "repositoryFilters": [{"filter": "prod-*", "filterType": "WILDCARD"}]}]), _REPOS),
           "manual_only": ANCHOR, "manual_only_index": indexes(_registry("BASIC", [{"scanFrequency": "MANUAL", "repositoryFilters": _ALL}]), _REPOS), "manual_only_expect": "FAIL",
           "not_applicable": ANCHOR, "not_applicable_index": indexes(_registry("BASIC"), _NO_REPOS)},
    note="The pinned Prowler row mixed frequencies and filters across different rules. AWS GetRegistryScanningConfiguration rules are evaluated together: an automated SCAN_ON_PUSH or CONTINUOUS_SCAN rule needs its own literal '*' WILDCARD filter. A complete ENHANCED config with an explicit empty rules list defaults to continuous scanning for all repositories; this is configured scanning, not proof of completed scans or no vulnerabilities. Registries without repositories are NOT_APPLICABLE.")
def registry_automated(item, index):
    scope = scope_of(item)
    config = _registry_config(index)
    if not complete_items(index, "ecr_repository"):
        return "NOT_APPLICABLE", {"scope": scope, "reason": "registry holds no repositories"}
    mode = get(config, "scanType", str)
    if mode not in ("BASIC", "ENHANCED"):
        return unknown("unrecognized ECR registry scan type", scan_type=mode)
    rules = list_of_objects(get(config, "rules", list))
    if not rules:
        return result(mode != "ENHANCED", scope=scope, scan_type=mode,
                      default_continuous_all_repositories=mode == "ENHANCED")
    automated = []
    for rule in rules:
        frequency = get(rule, "scanFrequency", str)
        if frequency not in (*_AUTOMATED, "MANUAL") or (mode == "BASIC" and frequency == "CONTINUOUS_SCAN"):
            return unknown("unrecognized ECR registry scan frequency", scan_frequency=frequency, scan_type=mode)
        filters = list_of_objects(get(rule, "repositoryFilters", list))
        if not filters:
            return unknown("ECR registry scan rule has no observed repository filters")
        wildcard = False
        for entry in filters:
            value = get(entry, "filter", str)
            filter_type = get(entry, "filterType", str)
            if filter_type != "WILDCARD" or not value:
                return unknown("unrecognized ECR registry scan filter", filter_type=filter_type)
            wildcard = wildcard or value == "*"
        if frequency in _AUTOMATED:
            automated.append((frequency, wildcard))
    all_repos = any(wildcard for _, wildcard in automated)
    return result(not all_repos, scope=scope, scan_type=mode,
                  automated_frequencies=sorted({frequency for frequency, _ in automated}),
                  automated_all_repository_rule=all_repos)


_SCANNABLE = {"application/vnd.docker.container.image.v1+json", "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip",
              "application/vnd.oci.image.config.v1+json", "application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip"}


def _image(pushed, status="COMPLETE", counts=None, media="application/vnd.docker.container.image.v1+json", tags=("v1",)):
    row = {"imageDigest": "sha256:" + pushed[:10], "imageTags": list(tags), "imagePushedAt": pushed, "artifactMediaType": media}
    if status is not None:
        row["imageScanStatus"] = {"status": status}
        row["imageScanFindingsSummary"] = {"findingSeverityCounts": dict(counts or {})}
    return row


def _scanned(*images, push=True):
    return {"repositoryName": "app", "repositoryArn": REPO_ARN, "imageScanningConfiguration": {"scanOnPush": push}, "Images": {"collection_status": "collected" if images else "empty", "items": list(images)}}


def _scannable(image):
    media = optional(image, "artifactMediaType", None, str)
    tags = optional(image, "imageTags", [], list)
    if media is None:
        raise Unavailable("image artifact media type not collected")
    from peaso.collectors.aws_ecr_image_rows import is_referrer
    if is_referrer(image):
        return False
    return media in _SCANNABLE


@install("aws.c2b.ecr.latest_image_no_medium_plus_findings", "ecr_repository", "ECR repository latest scannable image is scanned without MEDIUM or higher findings",
    _scanned(_image("2025-11-01T00:00:00+00:00", counts={"HIGH": 2}), _image("2025-12-01T00:00:00+00:00", counts={"LOW": 3})),
    _scanned(_image("2025-12-01T00:00:00+00:00", counts={"CRITICAL": 1})),
    rows=[P + "ecr_repositories_scan_vulnerabilities_in_latest_image"], severity="medium", control="RA-5", docs=[D_ECR_IMAGES, D_ECR_FINDINGS, "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"],
    remediation="Rebuild and push the image with patched packages, then confirm the new scan has no MEDIUM, HIGH or CRITICAL findings.",
    extra={"not_applicable": _scanned(_image("2025-12-01T00:00:00+00:00"), push=False), "failed_scan": _scanned(_image("2025-12-01T00:00:00+00:00", status="FAILED")), "failed_scan_expect": "FAIL",
           "no_images": _scanned(), "no_images_expect": "NOT_APPLICABLE"},
    note="Prowler pinned default threshold is MEDIUM; scan-on-push repositories, scannable media and latest imagePushedAt scope are preserved. AWS current Basic scanning omits status/counts from DescribeImages, so the collector reads DescribeImageScanFindings for that exact digest. Only COMPLETE with observed aggregate counts can PASS; FAILED FAILS; pending, unavailable, denied, malformed or incomplete facts stay UNKNOWN. Historical snapshots with valid DescribeImages status/counts remain evaluable.")
def latest_image(item, index):
    if get(item, "imageScanningConfiguration.scanOnPush", bool) is not True:
        return "NOT_APPLICABLE", {"scan_on_push": False}
    images = [image for image in detail_list(item, "Images") if _scannable(image)]
    if not images:
        return "NOT_APPLICABLE", {"scannable_images": 0}
    latest = sorted(images, key=lambda image: parse_time(get(image, "imagePushedAt", str)))[-1]
    scan = latest.get("ScanFindings")
    if scan is not None:
        if not isinstance(scan, dict) or scan.get("collection_status") != "collected" or scan.get("imageDigest") != latest.get("imageDigest"):
            raise Unavailable("latest image scan detail incomplete or target mismatch")
        if not isinstance(scan.get("pages"), int) or isinstance(scan["pages"], bool) or scan["pages"] < 1:
            raise Unavailable("latest image scan pagination incomplete")
        source = "ecr:DescribeImageScanFindings"
    else:
        scan = latest
        source = "ecr:DescribeImages (historical snapshot)"
    status = optional(scan, "imageScanStatus", None, dict)
    if status is None:
        raise Unavailable("latest image scan status not collected")
    state = get(status, "status", str)
    if state == "FAILED":
        return result(True, image_digest=latest.get("imageDigest"), scan_status=state, source_api=source)
    if state != "COMPLETE":
        raise Unavailable("latest image scan not complete: " + state)
    summary = get(scan, "imageScanFindingsSummary", dict)
    counts = get(summary, "findingSeverityCounts", dict)
    if any(key not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED"}
           or isinstance(value, bool) or not isinstance(value, int) or value < 0 for key, value in counts.items()):
        raise Unavailable("malformed finding severity counts")
    completed_at = summary.get("imageScanCompletedAt")
    if source == "ecr:DescribeImageScanFindings":
        if isinstance(completed_at, str):
            parse_time(completed_at)
        elif isinstance(completed_at, bool) or not isinstance(completed_at, (int, float)) or not math.isfinite(completed_at) or completed_at <= 0:
            raise Unavailable("scan completion time not observed")
    severe = {key: counts.get(key, 0) for key in ("CRITICAL", "HIGH", "MEDIUM")}
    return result(any(severe.values()), image_digest=latest.get("imageDigest"), scan_status=state, severity_counts=counts,
        scan_completed_at=completed_at, source_api=source)


# =========================================================================== EventBridge
BUS_ARN = "arn:aws:events:us-east-1:111111111111:event-bus/custom"
_BUS_PUB = '{"Version":"2012-10-17","Statement":[{"Sid":"all","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"' + BUS_ARN + '"}]}'
_BUS_ORG = '{"Version":"2012-10-17","Statement":[{"Sid":"org","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"' + BUS_ARN + '","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}'
_BUS_XACCT = '{"Version":"2012-10-17","Statement":[{"Sid":"x","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"events:PutEvents","Resource":"' + BUS_ARN + '"}]}'
_BUS_SELF = '{"Version":"2012-10-17","Statement":[{"Sid":"self","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"events:PutEvents","Resource":"' + BUS_ARN + '"}]}'


def _bus(policy=None, name="custom"):
    return {"Name": name, "Arn": BUS_ARN, **({"Policy": policy} if policy is not None else {})}


def _bus_policy(item):
    value = absent_or(item, "Name", "Policy", None)
    return None if value is None else policy_document(value)


@install("aws.c2b.eventbridge.custom_bus_policy_attached", "eventbridge_bus", "EventBridge custom event bus has a resource-based policy attached",
    _bus(_BUS_SELF), _bus(), rows=[C + "eventbridge_custom_bus_resource_based_policy_attached", C + "foundational_security_eventbridge_3"], severity="low", control="AC-3",
    docs=[D_EB_BUS, "https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html"],
    remediation="Attach a resource-based policy to the custom event bus that limits which principals can put events.",
    extra={"not_applicable": _bus(name="default")}, note="Steampipe: the default bus skips (NOT_APPLICABLE); a custom bus without Policy alarms.")
def bus_policy_attached(item, index):
    name = get(item, "Name", str)
    if name == "default":
        return "NOT_APPLICABLE", {"bus": name}
    return result(_bus_policy(item) is None, policy_attached=_bus_policy(item) is not None)


@install("aws.c2b.eventbridge.bus_policy_not_public", "eventbridge_bus", "EventBridge event bus policy does not allow public access",
    _bus(_BUS_ORG), _bus(_BUS_PUB), rows=[P + "eventbridge_bus_exposed"], severity="high", category="exposure", control="AC-3", docs=[D_EB_BUS],
    remediation="Remove the wildcard principal from the event bus policy or restrict it with organization or account conditions.",
    extra={"index": CTX, "absent": _bus()}, note="Prowler is_policy_public with the audited account; prowler reads DescribeEventBus Policy with a '{}' default, so a bus without a policy PASSes.")
def bus_public(item, index):
    statements = _bus_policy(item) or []
    public = is_policy_public(statements, account(index))
    return result(public, statements=len(statements), public_policy=public)


@install("aws.c2b.eventbridge.bus_policy_no_cross_account", "eventbridge_bus", "EventBridge event bus policy does not allow cross-account access",
    _bus(_BUS_SELF), _bus(_BUS_XACCT), rows=[P + "eventbridge_bus_cross_account_access"], severity="high", category="exposure", control="AC-3", docs=[D_EB_BUS],
    remediation="Limit the event bus policy to principals of the audited account (or document the trusted accounts).",
    extra={"index": CTX, "absent": _bus()}, note="Prowler is_policy_public(is_cross_account_allowed=False) with the default empty trusted_account_ids; a bus without a policy PASSes.")
def bus_cross_account(item, index):
    statements = _bus_policy(item) or []
    external = is_policy_public(statements, account(index), is_cross_account_allowed=False)
    return result(external, statements=len(statements), cross_account_policy=external)


@install("aws.c2b.eventbridge.bus_policy_prohibit_public_perimeter", "eventbridge_bus", "EventBridge event bus policy does not allow public access (perimeter)",
    _bus(_BUS_ORG), _bus(_BUS_PUB), rows=[X + "eventbridge_bus_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3", docs=[D_EB_BUS],
    remediation="Remove wildcard principals or add restricting conditions to the event bus policy.",
    extra={"not_applicable": _bus()}, note="aws-perimeter resource_policy_public_sql; no policy is info (NOT_APPLICABLE).")
def bus_perimeter(item, index):
    statements = _bus_policy(item)
    if statements is None:
        return "NOT_APPLICABLE", {"policy": None}
    hits = turbot_public_statements(statements)
    return result(bool(hits), statements=len(hits), public_allow_statements=len(hits))


def _endpoint(state=None):
    return {"Name": "ep", "Arn": "arn:aws:events:us-east-1:111111111111:endpoint/ep", **({"ReplicationConfig": {"State": state}} if state else {})}


@install("aws.c2b.eventbridge.global_endpoint_replication", "eventbridge_endpoint", "EventBridge global endpoint has event replication enabled",
    _endpoint("ENABLED"), _endpoint("DISABLED"), rows=[P + "eventbridge_global_endpoint_event_replication_enabled"], severity="medium", control="CP-10", docs=[D_EB_ENDPOINT],
    remediation="Enable event replication on the global endpoint so events reach the secondary Region.",
    extra={"absent_fail": _endpoint(), "absent_fail_expect": "FAIL"}, note="Prowler: ReplicationConfig.State defaults to DISABLED when omitted; DISABLED FAILs.")
def endpoint_replication(item, index):
    state = absent_or(item, "Arn", "ReplicationConfig.State", "DISABLED", str)
    return result(state == "DISABLED", replication_state=state)


def _schema(policy=None, name="reg"):
    container = ABSENT if policy is None else {"collection_status": "collected", "Policy": policy, "RevisionId": "1"}
    return {"RegistryName": name, "RegistryArn": "arn:aws:schemas:us-east-1:111111111111:registry/" + name, "Policy": container}


@install("aws.c2b.eventbridge.schema_registry_no_cross_account", "eventbridge_schema_registry", "EventBridge schema registry policy does not allow cross-account access",
    _schema(_BUS_SELF), _schema(_BUS_XACCT), rows=[P + "eventbridge_schema_registry_cross_account_access"], severity="high", category="exposure", control="AC-3", docs=[D_SCHEMA],
    remediation="Limit the schema registry policy to principals of the audited account.",
    extra={"index": CTX, "not_applicable": _schema(), "aws_owned": {"RegistryName": "aws.events", "RegistryArn": "arn:aws:schemas:us-east-1:111111111111:registry/aws.events"}, "aws_owned_expect": "NOT_APPLICABLE"},
    note="Prowler skips AWS-owned registries (name starts with 'aws.') and registries without a policy (NotFoundException): NOT_APPLICABLE. is_policy_public(is_cross_account_allowed=False), empty trusted_account_ids.")
def schema_cross_account(item, index):
    name = get(item, "RegistryName", str)
    if name.startswith("aws."):
        return "NOT_APPLICABLE", {"registry": name, "reason": "AWS-owned registry"}
    container = detail(item, "Policy")
    if container is None:
        return "NOT_APPLICABLE", {"policy": None}
    statements = policy_document(get(container, "Policy"))
    external = is_policy_public(statements, account(index), is_cross_account_allowed=False)
    return result(external, statements=len(statements), cross_account_policy=external)


# =========================================================================== CodeArtifact
def _ca(kind, policy=None):
    container = ABSENT if policy is None else {"collection_status": "collected", "policy": {"resourceArn": "arn", "document": policy}}
    base = {"name": "d", "arn": "arn:aws:codeartifact:us-east-1:111111111111:domain/d"} if kind == "domain" else \
        {"name": "r", "domainName": "d", "arn": "arn:aws:codeartifact:us-east-1:111111111111:repository/d/r"}
    return {**base, "Policy": container}


_CA_PUB = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"codeartifact:ReadFromRepository","Resource":"*"}]}'
_CA_ORG = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"codeartifact:ReadFromRepository","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}'


def _ca_perimeter(cid, kind, row, title, docs):
    @install(cid, kind, title, _ca(kind.split("_")[1], _CA_ORG), _ca(kind.split("_")[1], _CA_PUB), rows=[X + row], severity="high", category="exposure", control="AC-3",
        docs=[docs], remediation="Remove wildcard principals or add restricting conditions (organization, account, principal ARN) to the CodeArtifact permissions policy.",
        extra={"not_applicable": _ca(kind.split("_")[1])}, note="aws-perimeter resource_policy_public_sql; no permissions policy is info (NOT_APPLICABLE).")
    def evaluate(item, index):
        get(item, "arn", str)
        container = detail(item, "Policy")
        if container is None:
            return "NOT_APPLICABLE", {"policy": None}
        statements = policy_document(get(container, "policy.document"))
        hits = turbot_public_statements(statements)
        return result(bool(hits), statements=len(hits), public_allow_statements=len(hits))
    evaluate.__name__ = cid.replace(".", "_")
    return evaluate


_ca_perimeter("aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter", "codeartifact_domain", "codeartifact_domain_policy_prohibit_public_access",
              "CodeArtifact domain policy does not allow public access (perimeter)", D_CA_DOMAIN)
_ca_perimeter("aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter", "codeartifact_repository", "codeartifact_repository_policy_prohibit_public_access",
              "CodeArtifact repository policy does not allow public access (perimeter)", D_CA_REPO)


def _package(name, upstream, origin="INTERNAL", versions=True):
    latest = {"collection_status": "collected", "versions": [{"version": "1.0.0", "status": "Published", "origin": {"originType": origin}}] if versions else []}
    return {"format": "npm", "package": name, "originConfiguration": {"restrictions": {"publish": "ALLOW", "upstream": upstream}}, "LatestVersion": latest}


def _repo_pkgs(*packages):
    out = _ca("repository")
    out["Packages"] = {"collection_status": "collected" if packages else "empty", "items": list(packages)}
    return out


@install("aws.c2b.codeartifact.internal_packages_block_upstream", "codeartifact_repository", "Internal CodeArtifact packages block upstream (external) versions",
    _repo_pkgs(_package("internal-lib", "BLOCK"), _package("left-pad", "ALLOW", origin="EXTERNAL")), _repo_pkgs(_package("internal-lib", "ALLOW")),
    rows=[P + "codeartifact_packages_external_public_publishing_disabled"], severity="critical", control="SA-12", docs=[D_CA_PKG, D_CA_ORIGIN],
    remediation="Set the package origin controls of internal packages to upstream=BLOCK to prevent dependency confusion.",
    extra={"not_applicable": _repo_pkgs(_package("left-pad", "ALLOW", origin="EXTERNAL")), "no_versions": _repo_pkgs(_package("new-lib", "ALLOW", versions=False)), "no_versions_expect": "FAIL"},
    note="Prowler reports each package whose latest version (ListPackageVersions sortBy PUBLISHED_TIME, first result) has origin INTERNAL or UNKNOWN (no version = UNKNOWN); FAIL when restrictions.upstream is ALLOW. Aggregated per repository: any such package FAILs; repositories without internal packages are NOT_APPLICABLE.")
def internal_packages(item, index):
    get(item, "arn", str)
    internal, exposed = 0, []
    for package in detail_list(item, "Packages"):
        latest = get(package, "LatestVersion", dict)
        if latest.get("collection_status") not in (None, "collected", "empty"):
            raise Unavailable("package versions not collected")
        versions = list_of_objects(optional(latest, "versions", [], list))
        origin = optional(optional(versions[0], "origin", {}, dict), "originType", "UNKNOWN", str) if versions else "UNKNOWN"
        if origin not in ("INTERNAL", "UNKNOWN"):
            continue
        internal += 1
        if get(package, "originConfiguration.restrictions.upstream", str) == "ALLOW":
            exposed.append(get(package, "package", str))
    if not internal:
        return "NOT_APPLICABLE", {"internal_packages": 0}
    return result(bool(exposed), internal_packages=internal, upstream_allowed=exposed)


# =========================================================================== merges, manual, rejected
MERGED = {
    P + "codebuild_project_logging_enabled": (["aws.b.codebuild.logs_enabled"],
        "CloudWatch or S3 logs status ENABLED; omitted log blocks are DISABLED, as prowler's defaults."),
    P + "ecr_repositories_scan_images_on_push_enabled": (["aws.ecr.scan_on_push"],
        "Repository imageScanningConfiguration.scanOnPush true, as prowler's repository.scan_on_push."),
}

MANUAL = {
    P + "codebuild_project_uses_allowed_github_organizations": {
        "question": "Does every CodeBuild project with a GitHub or GitHub Enterprise source (whose service role trusts codebuild.amazonaws.com) build only from a GitHub organization on your approved list?",
        "title": "CodeBuild GitHub sources use approved GitHub organizations",
        "guidance": "Prowler compares the organization segment of the source URL with the operator-supplied codebuild_github_allowed_organizations list (empty by default, so every GitHub project would fail). The approved list is organisation-specific; review each GitHub-sourced project's source.location organization against it.",
        "docs": [D_CB_SOURCE, "https://docs.aws.amazon.com/codebuild/latest/userguide/access-tokens-github.html"],
    },
    P + "codepipeline_project_repo_private": {
        "question": "Are the GitHub/GitLab repositories used as CodeStarSourceConnection sources by CodePipeline pipelines private?",
        "title": "CodePipeline source repositories are private",
        "guidance": "Prowler decides visibility by sending anonymous HTTP requests to github.com and gitlab.com for each FullRepositoryId. PEASO reads only the AWS control plane and makes no requests to third-party sites, so confirm each connection source repository's visibility in the source provider.",
        "docs": ["https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-CodestarConnectionSource.html"],
    },
}

_SECRET_SCAN = ("Upstream runs a secret-content scanner over the payload (detect-secrets/Kingfisher or regex heuristics on values). PEASO is a read-only configuration CSPM that does not collect or scan secret material; "
                "collecting stack output values, plaintext variable values or repository file contents to grep for credentials is intrusive and unsuitable for the snapshot.")
REJECTED = {
    P + "cloudformation_stack_outputs_find_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Output.html"]},
    C + "cloudformation_stack_output_no_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Output.html"]},
    P + "codebuild_project_no_secrets_in_variables": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN,
        "replacement": ["aws.c2b.codebuild.no_plaintext_sensitive_env_names"], "docs": [D_CB_ENV]},
    P + "codecommit_repository_no_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN + " This check also downloads every file of the default branch (GetFile/GetBlob).", "replacement": [],
        "docs": ["https://docs.aws.amazon.com/codecommit/latest/APIReference/API_GetFile.html"]},
}

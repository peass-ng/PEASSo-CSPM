"""Allowlisted BatchGetProjects metadata, projected before the shared request cache.

Preserve only resource references and fields used by defensive native checks.
Executable buildspec and literal credential/environment values never leave the
SDK response. Unclassifiable source URLs make the detail unavailable.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit


_ARN = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+")
_BB_HOST = "bitbucket.org"


def project_batch_get_sandboxes(response):
    """Keep only sandbox identity, running state, and role before the shared cache."""
    from .aws import ReadFailure
    if not isinstance(response, dict) or not isinstance(response.get("sandboxes"), list):
        raise ReadFailure("malformed", "malformed_codebuild_sandboxes")
    rows = []
    for row in response["sandboxes"]:
        if not isinstance(row, dict):
            raise ReadFailure("malformed", "malformed_codebuild_sandbox")
        rows.append(_pick(row, ("id", "arn", "projectName", "status", "serviceRole")))
    missing = response.get("sandboxesNotFound", [])
    if not isinstance(missing, list):
        raise ReadFailure("malformed", "malformed_codebuild_sandboxes_not_found")
    return {"sandboxes": rows, "sandboxesNotFound": missing}


def _pick(source, names):
    return {key: source[key] for key in names if key in source} if isinstance(source, dict) else {}


def _reference(value):
    """Keep a concrete AWS resource ARN; fingerprint any opaque auth reference."""
    if not isinstance(value, str):
        return None
    if _ARN.fullmatch(value):
        return value
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _location(value):
    """Keep safe source identity and native Bitbucket credential classification."""
    from .aws import ReadFailure
    if not isinstance(value, str):
        raise ReadFailure("malformed", "malformed_codebuild_source_location")
    if not value.startswith(("http://", "https://")):
        if any(marker in value.lower() for marker in ("@", "?token", "?access", "password=", "secret=")):
            raise ReadFailure("malformed", "unclassified_source_credentials")
        return "[source location redacted]"
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        _ = parsed.port  # Reject malformed port syntax from urlsplit.
    except ValueError:
        raise ReadFailure("malformed", "malformed_codebuild_source_location") from None
    if not host or parsed.query or parsed.fragment:
        raise ReadFailure("malformed", "unclassified_source_credentials")
    if parsed.username is not None or parsed.password is not None:
        if host != _BB_HOST or parsed.password is None:
            raise ReadFailure("malformed", "unclassified_source_credentials")
        if parsed.username == "x-token-auth":
            return "https://x-token-auth:[redacted]@bitbucket.org/redacted.git"
        if parsed.username:
            return "https://redacted:[redacted]@bitbucket.org/redacted.git"
        raise ReadFailure("malformed", "unclassified_source_credentials")
    if parsed.scheme not in ("http", "https"):
        raise ReadFailure("malformed", "malformed_codebuild_source_location")
    path = "/redacted.git" if host == _BB_HOST else "/redacted"
    return urlunsplit((parsed.scheme, host, path, "", ""))


def _buildspec(value):
    from .aws import ReadFailure
    if not isinstance(value, str):
        raise ReadFailure("malformed", "malformed_codebuild_buildspec")
    if not value:
        return "", {"BuildSpecPresent": False, "BuildSpecSuffix": "none"}
    suffix = "yml" if value.endswith(".yml") else "yaml" if value.endswith(".yaml") else "other"
    # These surrogates preserve the two existing suffix-based native checks.
    surrogate = "redacted." + suffix if suffix in ("yml", "yaml") else "[buildspec redacted]"
    return surrogate, {"BuildSpecPresent": True, "BuildSpecSuffix": suffix}


def _source(source):
    from .aws import ReadFailure
    if not isinstance(source, dict):
        raise ReadFailure("malformed", "malformed_codebuild_source")
    out = _pick(source, ("type", "sourceIdentifier", "gitCloneDepth", "gitSubmodulesConfig",
                         "insecureSsl", "reportBuildStatus"))
    if "location" in source:
        out["location"] = _location(source["location"])
        out["LocationSha256"] = hashlib.sha256(source["location"].encode()).hexdigest()
        out["LocationPresent"] = bool(source["location"])
    if "buildspec" in source:
        out["buildspec"], flags = _buildspec(source["buildspec"])
        out.update(flags)
    auth = source.get("auth")
    if auth is not None:
        if not isinstance(auth, dict):
            raise ReadFailure("malformed", "malformed_codebuild_source_auth")
        out["auth"] = _pick(auth, ("type",))
        if "resource" in auth:
            if not isinstance(auth["resource"], str):
                raise ReadFailure("malformed", "malformed_codebuild_source_auth")
            out["auth"]["resource"] = _reference(auth["resource"])
            out["auth"]["ResourceReferenceKind"] = "arn" if _ARN.fullmatch(auth["resource"]) else "opaque_sha256"
    return out


def _environment(environment):
    from .aws import ReadFailure
    if not isinstance(environment, dict):
        raise ReadFailure("malformed", "malformed_codebuild_environment")
    out = _pick(environment, ("type", "image", "computeType", "privilegedMode",
                              "imagePullCredentialsType", "certificate"))
    if "environmentVariables" in environment:
        variables = environment["environmentVariables"]
        if not isinstance(variables, list) or any(not isinstance(v, dict) for v in variables):
            raise ReadFailure("malformed", "malformed_codebuild_environment_variables")
        out["environmentVariables"] = [_pick(v, ("name", "type")) for v in variables]
    registry = environment.get("registryCredential")
    if registry is not None:
        if not isinstance(registry, dict):
            raise ReadFailure("malformed", "malformed_codebuild_registry_credential")
        out["registryCredential"] = _pick(registry, ("credentialProvider",))
        if "credential" in registry:
            if not isinstance(registry["credential"], str):
                raise ReadFailure("malformed", "malformed_codebuild_registry_credential")
            out["registryCredential"]["credential"] = _reference(registry["credential"])
    return out


def _webhook(webhook):
    from .aws import ReadFailure
    if not isinstance(webhook, dict):
        raise ReadFailure("malformed", "malformed_codebuild_webhook")
    out = _pick(webhook, ("status", "buildType"))
    if "filterGroups" in webhook:
        groups = webhook["filterGroups"]
        if not isinstance(groups, list) or any(not isinstance(group, list) for group in groups):
            raise ReadFailure("malformed", "malformed_codebuild_webhook_filters")
        safe_groups = []
        for group in groups:
            safe = []
            for entry in group:
                if not isinstance(entry, dict):
                    raise ReadFailure("malformed", "malformed_codebuild_webhook_filters")
                row = _pick(entry, ("type", "excludeMatchedPattern"))
                pattern = entry.get("pattern")
                if pattern is not None:
                    if not isinstance(pattern, str):
                        raise ReadFailure("malformed", "malformed_codebuild_webhook_filters")
                    row["pattern"] = "|".join("^redacted$" if part.strip().startswith("^") and part.strip().endswith("$")
                                              else "redacted" for part in pattern.split("|"))
                safe.append(row)
            safe_groups.append(safe)
        out["filterGroups"] = safe_groups
    return out


def project_batch_get_projects(response):
    """Return only safe CodeBuild configuration, preserving missing-field shape."""
    from .aws import ReadFailure
    rows = response.get("projects") if isinstance(response, dict) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ReadFailure("malformed", "malformed_codebuild_projects")
    output = []
    for project in rows:
        from .aws_additional_secret_indicators import codebuild_indicator
        indicator = codebuild_indicator(project)
        row = _pick(project, ("name", "arn", "serviceRole", "projectVisibility", "publicProjectAlias", "encryptionKey",
                              "created", "lastModified", "concurrentBuildLimit"))
        for field in ("source",):
            if field in project:
                row[field] = _source(project[field])
        if "secondarySources" in project:
            values = project["secondarySources"]
            if not isinstance(values, list):
                raise ReadFailure("malformed", "malformed_codebuild_secondary_sources")
            row["secondarySources"] = [_source(value) for value in values]
        if "environment" in project:
            row["environment"] = _environment(project["environment"])
        if "webhook" in project:
            row["webhook"] = _webhook(project["webhook"])
        for field in ("artifacts", "secondaryArtifacts"):
            if field in project:
                fields = ("type", "location", "name", "namespaceType", "path", "packaging",
                          "encryptionDisabled", "bucketOwnerAccess", "artifactIdentifier")
                value = project[field]
                if field == "artifacts" and isinstance(value, dict):
                    row[field] = _pick(value, fields)
                elif field == "secondaryArtifacts" and isinstance(value, list) and all(isinstance(v, dict) for v in value):
                    row[field] = [_pick(v, fields) for v in value]
                else:
                    raise ReadFailure("malformed", "malformed_codebuild_artifacts")
        if "logsConfig" in project:
            logs = project["logsConfig"]
            if not isinstance(logs, dict):
                raise ReadFailure("malformed", "malformed_codebuild_logs")
            row["logsConfig"] = {key: _pick(logs[key], ("status", "groupName", "streamName", "location",
                                                     "encryptionDisabled", "bucketOwnerAccess"))
                                 for key in ("cloudWatchLogs", "s3Logs") if key in logs}
        for field, names in (("vpcConfig", ("vpcId", "subnets", "securityGroupIds")),
                             ("cache", ("type", "location", "modes")),
                             ("buildBatchConfig", ("serviceRole", "combineArtifacts", "timeoutInMins"))):
            if field in project:
                if not isinstance(project[field], dict):
                    raise ReadFailure("malformed", "malformed_codebuild_" + field)
                row[field] = _pick(project[field], names)
        row["AdditionalSecretIndicators"] = indicator
        output.append(row)
    return {"projects": output, "projectsNotFound": response.get("projectsNotFound", [])}

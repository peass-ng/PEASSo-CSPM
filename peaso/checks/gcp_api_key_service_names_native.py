"""Conservative DNS identity join for API Keys and Service Usage native facts."""

import re
import json
from copy import deepcopy
from pathlib import Path
from .facts import get


_DNS = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)

CHECK_ID = "gcp.apikeys.active_service_restrictions"
# Identifier of the historical spec this erratum supersedes.
PRIOR_SPEC_SHA256 = "7c91d652644f5e1644dacb522fc4fd15d2f30eabdbe7ec4c9481e87fa85c69db"


def source_correction(signed_spec_sha256=None):
    """Return the one-check schema erratum record and its corrected spec."""
    row = json.loads(Path(__file__).with_name("gcp_api_key_service_name_erratum.json").read_text())
    provenance = {key: deepcopy(value) for key, value in row.items()
                  if key not in ("prior_frozen_spec", "corrected_spec")}
    return deepcopy(row["corrected_spec"]), provenance


def canonical_target(value):
    """ApiTarget.service is case-insensitive; retain only a valid DNS join key."""
    if not isinstance(value, str) or not _DNS.fullmatch(value):
        raise ValueError("malformed API target service")
    return value.lower()


def canonical_service(row, scope):
    """Validate one Service Usage row without discarding its raw identity."""
    if not isinstance(row, dict) or not isinstance(scope, str):
        raise ValueError("malformed or foreign Service Usage fact")
    get(row, "name", str)
    coverage = row.get("_coverage", {})
    for field, kind in (("parent", str), ("config", dict), ("rawNativeName", str)):
        if field in row or field in coverage:
            get(row, field, kind)
    name = row.get("name")
    prefix = scope + "/services/"
    if not isinstance(name, str) or not name.startswith(prefix):
        raise ValueError("malformed or foreign Service Usage fact")
    service = canonical_target(name[len(prefix):])

    if "config" in row:
        config = row["config"]
        if not isinstance(config, dict):
            raise ValueError("malformed or foreign Service Usage fact")
        if "name" in config or "name" in config.get("_coverage", {}):
            get(config, "name", str)
        if "name" in config and canonical_target(config["name"]) != service:
            raise ValueError("Service Usage config name contradicts resource name")

    raw = row.get("rawNativeName")
    parent = row.get("parent")
    provenance = row.get("_provenance")
    alias = provenance.get("derived_project_alias") if isinstance(provenance, dict) else None
    if isinstance(provenance, dict) and ("derived_project_alias" in provenance or
            "derived_project_alias" in provenance.get("_coverage", {})):
        alias = get(provenance, "derived_project_alias", dict)
        for field, kind in (("canonical_name", str), ("native_name", str), ("basis", str),
                            ("project_identity_source_requests", list)):
            get(alias, field, kind)
    if raw is not None or alias is not None:
        if (not isinstance(raw, str) or not isinstance(alias, dict) or
                alias.get("canonical_name") != name or alias.get("native_name") != raw or
                row.get("native_id") != raw or row.get("_resource_id") != raw or
                alias.get("basis") != "complete same-scope Cloud Resource Manager project identity" or
                not isinstance(alias.get("project_identity_source_requests"), list) or
                not alias["project_identity_source_requests"] or
                any(not isinstance(ref, str) or not ref for ref in alias["project_identity_source_requests"])):
            raise ValueError("unproved Service Usage project alias")
        native_parent, separator, native_service = raw.partition("/services/")
        if (not separator or not re.fullmatch(r"projects/[0-9]+", native_parent) or
                canonical_target(native_service) != service or
                (parent is not None and parent != native_parent)):
            raise ValueError("Service Usage native identity contradicts alias")
    elif parent is not None and parent != scope:
        raise ValueError("foreign Service Usage parent")
    return service

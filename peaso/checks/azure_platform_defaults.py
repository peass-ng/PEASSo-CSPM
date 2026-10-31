"""Documented Azure defaults for properties ARM leaves out of a resource.

ARM omits many properties that still hold their default value. A check that
reads such a property through ``facts.get`` receives the documented default
instead of an unknown result, and the evaluator records that the value was
not set on the resource. Only defaults Microsoft documents for the API are
listed; any other missing property stays unknown.
"""
from __future__ import annotations

import contextvars
import copy

# One table per ARM resource type. "sentence" is the plain first evidence line.
DEFAULTS = {
    "microsoft.storage/storageaccounts": {
        # Storage REST: "If not specified, the default value is null, which is equivalent to true."
        "properties.allowSharedKeyAccess": {
            "value": True, "null_is_default": True,
            "sentence": "Shared Key access is not set on this storage account, so Azure allows it by default."},
        # Storage REST: "The default interpretation is false for this property."
        "properties.defaultToOAuthAuthentication": {
            "value": False,
            "sentence": "Default Microsoft Entra authorization is not set on this storage account, so Azure leaves it off by default."},
        # Storage network security: accounts accept connections from any network by default.
        "properties.publicNetworkAccess": {
            "value": "Enabled",
            "sentence": "Public network access is not set on this storage account, so Azure enables it by default."},
        # Infrastructure encryption is off unless chosen when the account is created.
        "properties.encryption.requireInfrastructureEncryption": {
            "value": False,
            "sentence": "Infrastructure encryption is not set on this storage account, so Azure leaves it off by default."},
    },
    "microsoft.storage/storageaccounts/blobservices": {
        # Blob versioning is disabled by default.
        "properties.isVersioningEnabled": {
            "value": False,
            "sentence": "Blob versioning is not set on this storage account, so Azure leaves it off by default."},
        # Container and blob soft delete are disabled unless a retention policy is set.
        "properties.containerDeleteRetentionPolicy": {
            "value": {"enabled": False},
            "sentence": "Container soft delete is not set on this storage account, so Azure leaves it off by default."},
        "properties.deleteRetentionPolicy": {
            "value": {"enabled": False},
            "sentence": "Blob soft delete is not set on this storage account, so Azure leaves it off by default."},
    },
    "microsoft.storage/storageaccounts/fileservices": {
        # Azure Files SMB security settings: all versions and channel ciphers are allowed by default.
        "properties.protocolSettings.smb.versions": {
            "value": "SMB2.1;SMB3.0;SMB3.1.1;",
            "sentence": "Allowed SMB versions are not set on this file service, so Azure allows SMB 2.1, 3.0 and 3.1.1 by default."},
        "properties.protocolSettings.smb.channelEncryption": {
            "value": "AES-128-CCM;AES-128-GCM;AES-256-GCM;",
            "sentence": "SMB channel encryption is not set on this file service, so Azure allows AES-128-CCM, AES-128-GCM and AES-256-GCM by default."},
    },
    "microsoft.keyvault/vaults": {
        # Key Vault REST: purge protection is on only when set to true.
        "properties.enablePurgeProtection": {
            "value": False,
            "sentence": "Purge protection is not set on this key vault, so Azure leaves it off by default."},
        # Key Vault network security: a vault without network rules allows all networks;
        # REST: bypass "If not specified the default is 'AzureServices'".
        "properties.networkAcls": {
            "value": {"bypass": "AzureServices", "defaultAction": "Allow", "ipRules": [], "virtualNetworkRules": []},
            "sentence": "Network rules are not set on this key vault, so Azure allows access from all networks by default."},
        # Read-only list; ARM leaves it out when the vault has no private endpoint connection.
        "properties.privateEndpointConnections": {
            "value": [],
            "sentence": "No private endpoint connection is recorded on this key vault."},
    },
}

_USED = contextvars.ContextVar("peaso_azure_platform_defaults", default=None)


def _table(root):
    if not isinstance(root, dict) or not isinstance(root.get("type"), str):
        return None
    if not isinstance(root.get("properties"), dict):
        return None
    proof = root.get("_provenance")
    if isinstance(proof, dict) and proof.get("representation") not in (None, "full"):
        return None
    return DEFAULTS.get(root["type"].casefold())


def lookup(root, path, *, null=False):
    """Return (True, default) when ``path`` has a documented default for ``root``."""
    table = _table(root)
    entry = table.get(path) if table else None
    if entry is None or (null and not entry.get("null_is_default")):
        return False, None
    used = _USED.get()
    if used is not None and all(row["field"] != path for row in used):
        used.append({"field": path, "value": copy.deepcopy(entry["value"]),
                     "note": "not set; Azure default is " + _plain(entry["value"]),
                     "sentence": entry["sentence"]})
    return True, copy.deepcopy(entry["value"])


def _plain(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        import json
        return json.dumps(value, sort_keys=True)
    return str(value)


def track():
    return _USED.set([])


def finish(token):
    used = _USED.get()
    _USED.reset(token)
    return used or []


def first_lines(evidence):
    rows = evidence.get("platform_defaults") if isinstance(evidence, dict) else None
    if not isinstance(rows, list):
        return []
    return [row["sentence"] for row in rows if isinstance(row, dict) and isinstance(row.get("sentence"), str)]

"""Legacy Azure database controls stay bounded by complete subscription reads."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw04 as new


SCOPE = "/subscriptions/sub"
PROVIDERS = {
    "postgresql_single_server": "Microsoft.DBforPostgreSQL",
    "mysql_single_server": "Microsoft.DBforMySQL",
    "mariadb_server": "Microsoft.DBforMariaDB",
}


def server(kind, *, config=None, firewall=None, **properties):
    rid = f"{SCOPE}/resourceGroups/rg/providers/{PROVIDERS[kind]}/servers/db"
    row = {"id": rid, "properties": properties,
           "_provenance": {"source_operation": "GET", "read_only": True}}
    if config is not None:
        row["configurations"] = [
            {"id": rid + "/configurations/" + name, "name": name,
             "properties": {"value": value}} for name, value in config.items()]
        row.setdefault("_coverage", {})["configurations"] = {
            "status": "collected" if config else "empty"}
    if firewall is not None:
        row["firewallRules"] = [
            {"id": rid + "/firewallRules/" + str(n), "name": str(n),
             "properties": {"startIpAddress": start, "endIpAddress": end}}
            for n, (start, end) in enumerate(firewall)]
        row.setdefault("_coverage", {})["firewallRules"] = {
            "status": "collected" if firewall else "empty"}
    return row


def indexed(kind, rows, *, status=None, scope=SCOPE):
    if status is None:
        status = "collected" if rows else "empty"
    return {"context": {"provider": "azure", "scope": scope},
            "collections": {kind: [{"type": kind, "scope": scope,
                                     "status": status, "items": deepcopy(rows)}]},
            kind: [{"type": kind, "scope": scope, "data": deepcopy(row)}
                   for row in rows]}


CASES = {'azure.cis.postgresql_single_connection_throttling': ('postgresql_single_server',
                                                       {'config': {'connection_throttling': 'ON'}},
                                                       {'config': {'connection_throttling': 'OFF'}}),
 'azure.cis.postgresql_single_log_checkpoints': ('postgresql_single_server',
                                                 {'config': {'log_checkpoints': 'ON'}},
                                                 {'config': {'log_checkpoints': 'OFF'}}),
 'azure.cis.postgresql_single_log_connections': ('postgresql_single_server',
                                                 {'config': {'log_connections': 'On'}},
                                                 {'config': {'log_connections': 'off'}}),
 'azure.cis.postgresql_single_log_disconnections': ('postgresql_single_server',
                                                    {'config': {'log_disconnections': 'ON'}},
                                                    {'config': {'log_disconnections': 'Off'}}),
 'azure.cis.postgresql_single_no_azure_services_rule': ('postgresql_single_server',
                                                        {'firewall': [('10.0.0.1', '10.0.0.2')]},
                                                        {'firewall': [('0.0.0.0', '0.0.0.0')]}),
 'azure.cis.public_network_access_should_mariadb_servers': ('mariadb_server',
                                                            {'publicNetworkAccess': 'Disabled'},
                                                            {'publicNetworkAccess': 'Enabled'})}


def outcome(check_id, row, *, index=None):
    kind = CASES[check_id][0]
    facts = indexed(kind, [row]) if index is None else index
    return evaluate_check(check_id, {"scope": SCOPE}, facts)[0]


@pytest.mark.parametrize("check_id", CASES)
def test_signed_pass_fail_and_empty_scope(check_id):
    kind, good, bad = CASES[check_id]
    assert outcome(check_id, server(kind, **good)) == "PASS"
    assert outcome(check_id, server(kind, **bad)) == "FAIL"
    assert evaluate_check(check_id, {"scope": SCOPE}, indexed(kind, []))[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id", CASES)
def test_incomplete_malformed_missing_and_foreign_scope_are_unknown(check_id):
    kind, good, _ = CASES[check_id]
    row = server(kind, **good)
    assert outcome(check_id, row, index=indexed(kind, [row], status="partial")) == "UNKNOWN"
    bad_row = deepcopy(row)
    if "config" in good:
        bad_row["configurations"][0]["properties"]["value"] = ["invalid"]
    elif "firewall" in good:
        bad_row["firewallRules"][0]["properties"]["startIpAddress"] = "not-an-ip"
    else:
        key = next(iter(good))
        bad_row["properties"][key] = ["invalid"]
    assert outcome(check_id, bad_row) == "UNKNOWN"
    absent = deepcopy(row)
    if "config" in good:
        del absent["configurations"]
    elif "firewall" in good:
        del absent["firewallRules"]
    else:
        del absent["properties"][next(iter(good))]
    assert outcome(check_id, absent) == "UNKNOWN"
    foreign = indexed(kind, [row], scope="/subscriptions/other")
    assert outcome(check_id, row, index=foreign) == "UNKNOWN"


def test_missing_named_settings_follow_each_signed_predicate():
    kind = "postgresql_single_server"
    empty = server(kind, config={})
    assert outcome("azure.cis.postgresql_single_connection_throttling", empty) == "FAIL"
    assert outcome("azure.cis.postgresql_single_log_checkpoints", empty) == "FAIL"
    assert outcome("azure.cis.postgresql_single_log_connections", empty) == "UNKNOWN"


def test_positive_failure_survives_other_server_unknown():
    kind = "postgresql_single_server"
    first = server(kind, config={"log_connections": "off"})
    second = server(kind, config={"log_connections": "on"})
    second["id"] = second["id"].replace("/db", "/db2")
    second["configurations"] = []
    second["_coverage"]["configurations"]["status"] = "empty"
    assert evaluate_check("azure.cis.postgresql_single_log_connections", {"scope": SCOPE},
                          indexed(kind, [first, second]))[0] == "FAIL"


NOW = datetime(2026, 10, 12, tzinfo=timezone.utc).isoformat()
ML_ID = SCOPE + "/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws/computes/ci"
ML_CASES = {
    "azure.other.ml_compute_file_download_restricted": "fileDownload",
    "azure.other.ml_sensitive_root_disabled": "rootAccess",
    "azure.other.ml_sensitive_terminal_disabled": "terminalAccess",
}


def ml_observation(field, *, bad=False):
    common = {"status": "collected", "observed_at": NOW, "max_age_seconds": 600,
              "source": "mlde_data_plane" if field == "fileDownload" else "mlde_guest_host",
              "read_only": True}
    if field == "fileDownload":
        return {**common, "verified_successful_download": bad,
                "configuration_enabled": False, "all_users_disabled": not bad}
    names = (["console", "ssh", "local_privilege"] if field == "rootAccess"
             else ["studio_terminal", "private_ssh"])
    return {**common, "complete_paths": True,
            "paths": [{"name": name, "enabled": bad and i == 0}
                      for i, name in enumerate(names)]}


def ml_compute(field, *, bad=False):
    return {"id": ML_ID, "_provenance": {"source_operation": "LIST", "read_only": True},
            "securityObservations": {field: ml_observation(field, bad=bad)}}


def ml_index(rows, *, classification="sensitive", status="collected", policy_status="collected"):
    policy = {"status": policy_status, "observed_at": NOW, "max_age_seconds": 600,
              "source": "owner_approved_classification", "read_only": True,
              "assignments": [{"resource_id": row["id"], "classification": classification} for row in rows]}
    return {"context": {"provider": "azure", "scope": SCOPE, "created_at": NOW,
                        "metadata": {"ml_compute_classification": policy}},
            "collections": {"ml_compute": [{"type": "ml_compute", "scope": SCOPE,
                                             "status": status, "items": deepcopy(rows)}]},
            "ml_compute": [{"type": "ml_compute", "scope": SCOPE, "data": deepcopy(row)}
                           for row in rows]}


@pytest.mark.parametrize("check_id,field", ML_CASES.items())
def test_ml_authoritative_observation_pass_fail_and_not_applicable(check_id, field):
    good = ml_compute(field)
    bad = ml_compute(field, bad=True)
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([good]))[0] == "PASS"
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([bad]))[0] == "FAIL"
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([good], classification="non_sensitive"))[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("check_id,field", ML_CASES.items())
def test_ml_missing_malformed_stale_and_partial_evidence_unknown(check_id, field):
    row = ml_compute(field)
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([row], status="partial"))[0] == "UNKNOWN"
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([row], policy_status="partial"))[0] == "UNKNOWN"
    absent = deepcopy(row)
    del absent["securityObservations"][field]
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([absent]))[0] == "UNKNOWN"
    malformed = deepcopy(row)
    if field == "fileDownload":
        malformed["securityObservations"][field]["configuration_enabled"] = ["invalid"]
    else:
        malformed["securityObservations"][field]["paths"][0]["enabled"] = ["invalid"]
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([malformed]))[0] == "UNKNOWN"
    stale = deepcopy(row)
    stale["securityObservations"][field]["observed_at"] = "2020-01-01T00:00:00Z"
    assert evaluate_check(check_id, {"scope": SCOPE}, ml_index([stale]))[0] == "UNKNOWN"
    foreign = ml_index([row]); foreign["ml_compute"][0]["scope"] = "/subscriptions/other"
    assert evaluate_check(check_id, {"scope": SCOPE}, foreign)[0] == "UNKNOWN"


AKS_ID = SCOPE + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks"


def aks_cluster(*, http_accepted=False):
    return {"id": AKS_ID, "properties": {"fqdn": "aks.example.test", "privateFQDN": None},
            "securityObservations": {"apiTransport": {
                "status": "collected", "observed_at": NOW, "max_age_seconds": 600,
                "source": "authorized_api_probe", "read_only": True,
                "complete_endpoints": True,
                "probes": [{"endpoint_fqdn": "aks.example.test", "vantage_id": "probe-vantage-1",
                            "dns_proxy_unambiguous": True, "http_probe_completed": True,
                            "http_api_request_accepted": http_accepted,
                            "https_authenticated_api_success": True}]}}}


def aks_index(rows, *, status=None):
    if status is None:
        status = "collected" if rows else "empty"
    return {"context": {"provider": "azure", "scope": SCOPE, "created_at": NOW},
            "collections": {"aks_cluster": [{"type": "aks_cluster", "scope": SCOPE,
                                              "status": status, "items": deepcopy(rows)}]},
            "aks_cluster": [{"type": "aks_cluster", "scope": SCOPE, "data": deepcopy(row)}
                            for row in rows]}


def test_aks_https_runtime_probe_pass_fail_and_empty_scope():
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([aks_cluster()]))[0] == "PASS"
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([aks_cluster(http_accepted=True)]))[0] == "FAIL"
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([]))[0] == "NOT_APPLICABLE"


def test_aks_https_unknown_for_incomplete_malformed_missing_and_foreign_probe():
    row = aks_cluster()
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([row], status="partial"))[0] == "UNKNOWN"
    absent = deepcopy(row); del absent["securityObservations"]
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([absent]))[0] == "UNKNOWN"
    malformed = deepcopy(row)
    malformed["securityObservations"]["apiTransport"]["probes"][0]["http_probe_completed"] = "false"
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([malformed]))[0] == "UNKNOWN"
    foreign = aks_index([row]); foreign["aks_cluster"][0]["scope"] = "/subscriptions/other"
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, foreign)[0] == "UNKNOWN"
    unreachable = deepcopy(row)
    unreachable["securityObservations"]["apiTransport"]["probes"][0]["http_probe_completed"] = False
    assert evaluate_check(new.AKS_HTTPS_ID, {"scope": SCOPE}, aks_index([unreachable]))[0] == "UNKNOWN"


@pytest.mark.parametrize('check_id,field', ML_CASES.items())
def test_ml_envelope_type_cannot_be_relabelled(check_id, field):
    facts = ml_index([ml_compute(field)])
    facts['collections']['ml_compute'][0]['type'] = 'foreign'
    assert evaluate_check(check_id, {'scope': SCOPE}, facts)[0] == 'UNKNOWN'


def test_legacy_and_aks_envelope_type_is_required():
    cid = 'azure.cis.postgresql_single_log_connections'
    row = server('postgresql_single_server', config={'log_connections': 'on'})
    facts = indexed('postgresql_single_server', [row])
    facts['collections']['postgresql_single_server'][0]['type'] = 'foreign'
    assert outcome(cid, row, index=facts) == 'UNKNOWN'
    facts = aks_index([aks_cluster()])
    facts['collections']['aks_cluster'][0]['type'] = 'foreign'
    assert evaluate_check(new.AKS_HTTPS_ID, {'scope': SCOPE}, facts)[0] == 'UNKNOWN'


@pytest.mark.parametrize('check_id,field', [(cid, field) for cid, field in ML_CASES.items() if field != 'fileDownload'])
def test_enabled_ml_path_proves_failure_without_complete_other_paths(check_id, field):
    row = ml_compute(field, bad=True)
    observation = row['securityObservations'][field]
    observation['complete_paths'] = False
    observation['paths'] = observation['paths'][:1]
    assert evaluate_check(check_id, {'scope': SCOPE}, ml_index([row]))[0] == 'FAIL'
    observation['paths'][0]['enabled'] = False
    assert evaluate_check(check_id, {'scope': SCOPE}, ml_index([row]))[0] == 'UNKNOWN'


def test_unavailable_download_probe_cannot_prove_failure():
    row = ml_compute('fileDownload', bad=True)
    row['securityObservations']['fileDownload']['_coverage'] = {'verified_successful_download': {'status': 'denied'}}
    assert evaluate_check('azure.other.ml_compute_file_download_restricted', {'scope': SCOPE}, ml_index([row]))[0] == 'UNKNOWN'


def test_proven_http_acceptance_survives_missing_https_evidence():
    row = aks_cluster(http_accepted=True)
    del row['securityObservations']['apiTransport']['probes'][0]['https_authenticated_api_success']
    assert evaluate_check(new.AKS_HTTPS_ID, {'scope': SCOPE}, aks_index([row]))[0] == 'FAIL'
    row['securityObservations']['apiTransport']['probes'][0]['http_api_request_accepted'] = False
    assert evaluate_check(new.AKS_HTTPS_ID, {'scope': SCOPE}, aks_index([row]))[0] == 'UNKNOWN'


def test_postgresql_sentinel_failure_survives_other_unknown_rule():
    cid = 'azure.cis.postgresql_single_no_azure_services_rule'
    for rules in ([('invalid', '10.0.0.1'), ('0.0.0.0', '0.0.0.0')],
                  [('0.0.0.0', '0.0.0.0'), ('invalid', '10.0.0.1')]):
        assert outcome(cid, server('postgresql_single_server', firewall=rules)) == 'FAIL'
    assert outcome(cid, server('postgresql_single_server', firewall=[('invalid', '10.0.0.1')])) == 'UNKNOWN'


def test_plaintext_api_acceptance_does_not_require_complete_https_endpoint_coverage():
    row = aks_cluster(http_accepted=True)
    row['properties']['privateFQDN'] = 'private.example.test'
    row['securityObservations']['apiTransport']['complete_endpoints'] = False
    assert evaluate_check(new.AKS_HTTPS_ID, {'scope': SCOPE}, aks_index([row]))[0] == 'FAIL'
    row['securityObservations']['apiTransport']['probes'][0]['http_api_request_accepted'] = False
    assert evaluate_check(new.AKS_HTTPS_ID, {'scope': SCOPE}, aks_index([row]))[0] == 'UNKNOWN'

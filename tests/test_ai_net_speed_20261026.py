"""Indexed exposure lookups and lighter AI stage preparation keep exact outputs."""
import json
import random
import sys

import pytest

from peaso.analysis import internet_exposure as ie
from peaso.analysis.common import as_list
from peaso.snapshot import make_snapshot, resources


# ------------------------------------------------- original per-call scans

def original_gcp_firewall(inventory, instance, interface, assessment):
    data = instance["data"]
    network = interface.get("network")
    tags = set(as_list((data.get("tags") or {}).get("items")))
    accounts = {s.get("email") for s in as_list(data.get("serviceAccounts")) if isinstance(s, dict)}
    allowed, decided = {}, {}
    policies = inventory.items("firewall_policy")
    for policy in policies:
        rules = sorted((r for r in as_list(policy["data"].get("rules")) if isinstance(r, dict) and r.get("direction", "INGRESS") == "INGRESS"
                        and not r.get("disabled")), key=lambda r: int(r.get("priority", 1000)))
        for rule in rules:
            match = rule.get("match") or {}
            if not any(ie._internet(x) for x in as_list(match.get("srcIpRanges"))):
                continue
            targets = as_list(rule.get("targetResources"))
            if targets and network not in targets:
                continue
            if rule.get("targetSecureTags") or rule.get("targetServiceAccounts"):
                assessment.gap("firewall", f"firewall policy {ie.native_id(policy)} rule {rule.get('priority')} targets tags/service accounts", None)
                assessment.unresolved[-1]["decisive"] = False
                continue
            ports = ie._gcp_rule_ports(match.get("layer4Configs"))
            fresh = ie.subtract(ports, decided)
            if rule.get("action") == "allow":
                allowed = ie.union(allowed, fresh)
                decided = ie.union(decided, ports)
            elif rule.get("action") == "deny":
                decided = ie.union(decided, ports)
    if policies:
        assessment.step("firewall_policy", "evaluated", policies=[ie.native_id(p) for p in policies], allowed=ie.describe(allowed))
    elif inventory.state("firewall_policy").startswith("missing"):
        assessment.gap("firewall_policy", "hierarchical/network firewall policies not collected", "compute firewallPolicies")
        assessment.unresolved[-1]["decisive"] = False
    candidates = []
    for rule in inventory.items("firewall"):
        r = rule["data"]
        if r.get("network") != network or r.get("direction", "INGRESS") != "INGRESS" or r.get("disabled"):
            continue
        sources = as_list(r.get("sourceRanges"))
        if not sources and (r.get("sourceTags") or r.get("sourceServiceAccounts")):
            continue
        if sources and not any(ie._internet(x) for x in sources):
            continue
        if r.get("targetTags") and not tags & set(r["targetTags"]):
            continue
        if r.get("targetServiceAccounts") and not accounts & set(r["targetServiceAccounts"]):
            continue
        candidates.append(rule)
    if inventory.state("firewall").startswith("missing"):
        assessment.gap("firewall", f"VPC firewall rules {inventory.state('firewall')}", "compute firewalls.list")
        return None
    matched = []
    for rule in sorted(candidates, key=lambda x: (int(x["data"].get("priority", 1000)), 0 if x["data"].get("denied") else 1)):
        r = rule["data"]
        ports = ie._gcp_rule_ports(r.get("denied") or r.get("allowed"))
        fresh = ie.subtract(ports, decided)
        if r.get("allowed") and not ie.empty(fresh):
            allowed = ie.union(allowed, fresh)
            matched.append({"rule": r.get("name"), "priority": r.get("priority", 1000), "action": "allow", "ports": ie.describe(fresh)})
        elif r.get("denied") and not ie.empty(fresh):
            matched.append({"rule": r.get("name"), "priority": r.get("priority", 1000), "action": "deny", "ports": ie.describe(fresh)})
        decided = ie.union(decided, ports)
    assessment.step("firewall", "allow" if not ie.empty(allowed) else "block", network=network, matched_rules=matched,
                    implied="deny ingress", allowed=ie.describe(allowed))
    return allowed


def original_azure_backend_nics(inventory, pool_ids):
    pools = {str(p).lower() for p in pool_ids}
    for nic in inventory.items("nic"):
        for config in as_list(ie._props(nic).get("ipConfigurations")):
            cp = (config or {}).get("properties") or {}
            refs = {str(x.get("id", "")).lower() for x in as_list(cp.get("loadBalancerBackendAddressPools")) + as_list(cp.get("applicationGatewayBackendAddressPools")) if isinstance(x, dict)}
            if refs & pools:
                yield nic, config


def run_both(monkeypatch, snapshot):
    rows = resources(snapshot)
    fresh = json.dumps(ie.internet_findings(snapshot, rows), sort_keys=True, default=str)
    with monkeypatch.context() as patch:
        patch.setattr(ie, "_gcp_firewall", original_gcp_firewall)
        patch.setattr(ie, "_azure_backend_nics", original_azure_backend_nics)
        patch.setattr(ie, "_azure_nic_config_index", lambda inventory: None)
        reference = json.dumps(ie.internet_findings(snapshot, rows), sort_keys=True, default=str)
    return fresh, reference


def gcp_snapshot(seed):
    rng = random.Random(seed)
    base = "https://www.googleapis.com/compute/v1/projects/p"
    nets = [f"{base}/global/networks/n{n}" for n in range(3)]
    sources = ["0.0.0.0/0", "::/0", "10.0.0.0/8", "0.0.0.0", "*", "bad-cidr", "0::0/0", "192.168.1.0/24"]
    firewalls = []
    for f in range(40):
        rule = {"name": f"fw{f}", "id": str(f), "selfLink": f"{base}/global/firewalls/fw{f}",
                "network": rng.choice(nets), "priority": rng.choice([100, 500, 1000, 1000, 65534]),
                "direction": rng.choice(["INGRESS", "INGRESS", "EGRESS"]), "disabled": rng.random() < .1}
        if rng.random() < .85:
            rule["sourceRanges"] = rng.sample(sources, rng.randint(1, 2))
        elif rng.random() < .5:
            rule["sourceTags"] = ["peer"]
        if rng.random() < .5:
            rule["targetTags"] = [f"t{rng.randint(0, 4)}"]
        if rng.random() < .2:
            rule["targetServiceAccounts"] = [f"sa{rng.randint(0, 2)}@p.iam.gserviceaccount.com"]
        spec = [{"IPProtocol": rng.choice(["tcp", "udp", "all"]), "ports": [str(rng.choice([22, 80, 443, "1000-2000"]))]}]
        rule["denied" if rng.random() < .25 else "allowed"] = spec
        firewalls.append(rule)
    policy = {"name": "pol", "id": "pol", "rules": [
        {"priority": rng.choice([10, 20, 30]), "direction": "INGRESS", "action": rng.choice(["allow", "deny"]),
         "match": {"srcIpRanges": rng.sample(sources, 2), "layer4Configs": [{"ipProtocol": "tcp", "ports": ["22"]}]},
         **({"targetResources": [rng.choice(nets)]} if rng.random() < .5 else {}),
         **({"targetServiceAccounts": ["sa0@p.iam.gserviceaccount.com"]} if rng.random() < .2 else {})}
        for _ in range(6)]}
    instances = [{"name": f"vm{i}", "id": str(100 + i), "selfLink": f"{base}/zones/z/instances/vm{i}", "status": "RUNNING",
                  "tags": {"items": [f"t{rng.randint(0, 4)}"]},
                  "serviceAccounts": [{"email": f"sa{rng.randint(0, 2)}@p.iam.gserviceaccount.com"}],
                  "networkInterfaces": [{"network": rng.choice(nets), "networkIP": f"10.0.0.{i}",
                                         "accessConfigs": [{"type": "ONE_TO_ONE_NAT", "natIP": f"34.1.1.{i}"}]}
                                        for _ in range(rng.randint(1, 2))]}
                 for i in range(25)]
    collections = [{"type": "firewall", "scope": "projects/p", "status": "collected", "items": firewalls},
                   {"type": "instance", "scope": "projects/p", "status": "collected", "items": instances}]
    if seed % 2:
        collections.append({"type": "firewall_policy", "scope": "projects/p", "status": "collected", "items": [policy]})
    return make_snapshot("gcp", ["projects/p"], collections, created_at="2026-10-26T00:00:00+00:00")


@pytest.mark.parametrize("seed", range(6))
def test_gcp_firewall_index_matches_per_interface_scan(monkeypatch, seed):
    fresh, reference = run_both(monkeypatch, gcp_snapshot(seed))
    assert fresh == reference
    assert '"analysis.internet_exposure"' in fresh


def azure_snapshot(seed):
    rng = random.Random(seed)
    sub = "/subscriptions/s/resourceGroups/g/providers/Microsoft.Network"
    pools = [f"{sub}/loadBalancers/lb/backendAddressPools/pool{p}" for p in range(3)]
    nsg = {"id": f"{sub}/networkSecurityGroups/nsg", "name": "nsg", "properties": {"securityRules": [
        {"name": "allow", "properties": {"access": "Allow", "direction": "Inbound", "priority": 100, "protocol": "Tcp",
                                         "sourceAddressPrefix": "*", "destinationAddressPrefix": "*", "destinationPortRange": "*"}}]}}
    nics, configs = [], []
    for n in range(8):
        nic_configs = []
        for c in range(rng.randint(1, 2)):
            ident = f"{sub}/networkInterfaces/nic{n}/ipConfigurations/c{c}"
            configs.append(ident)
            nic_configs.append({"id": ident.upper() if rng.random() < .3 else ident, "name": f"c{c}", "properties": {
                "privateIPAddress": f"10.0.{n}.{c + 4}",
                "loadBalancerBackendAddressPools": [{"id": rng.choice(pools).upper() if rng.random() < .3 else rng.choice(pools)}
                                                    for _ in range(rng.randint(0, 2))]}})
        nics.append({"id": f"{sub}/networkInterfaces/nic{n}", "name": f"nic{n}",
                     "properties": {"ipConfigurations": nic_configs, "networkSecurityGroup": {"id": nsg["id"]}}})
    front = f"{sub}/loadBalancers/lb/frontendIPConfigurations/f"
    lb = {"id": f"{sub}/loadBalancers/lb", "name": "lb", "sku": {"name": "Standard"}, "properties": {
        "frontendIPConfigurations": [{"id": front, "properties": {"publicIPAddress": {"id": f"{sub}/publicIPAddresses/ip"}}}],
        "loadBalancingRules": [{"name": f"r{r}", "properties": {"frontendIPConfiguration": {"id": front}, "protocol": "Tcp",
                                                               "frontendPort": 80 + r, "backendPort": 8080,
                                                               "backendAddressPool": {"id": rng.choice(pools)}}} for r in range(3)],
        "inboundNatRules": [{"name": f"nat{r}", "properties": {"frontendIPConfiguration": {"id": front}, "protocol": "Tcp",
                                                              "frontendPort": 5000 + r, "backendPort": 22,
                                                              "backendIPConfiguration": ({"id": rng.choice(configs).upper()} if r else {})}}
                            for r in range(3)]}}
    public_ip = {"id": f"{sub}/publicIPAddresses/ip", "name": "ip", "properties": {"ipAddress": "20.1.1.1"}}
    collections = [{"type": kind, "scope": "/subscriptions/s", "status": "collected", "items": items}
                   for kind, items in (("nic", nics), ("load_balancer", [lb]), ("public_ip", [public_ip]), ("nsg", [nsg]))]
    return make_snapshot("azure", ["/subscriptions/s"], collections, created_at="2026-10-26T00:00:00+00:00")


@pytest.mark.parametrize("seed", range(6))
def test_azure_nic_index_matches_per_rule_scan(monkeypatch, seed):
    fresh, reference = run_both(monkeypatch, azure_snapshot(seed))
    assert fresh == reference
    assert "backend" in fresh


def test_malformed_nic_configuration_keeps_original_scan():
    snapshot = azure_snapshot(0)
    rows = resources(snapshot)
    inventory = ie.Inventory(snapshot, rows)
    inventory.by_type["nic"] = inventory.by_type["nic"] + [{"type": "nic", "data": {"properties": {"ipConfigurations": ["text"]}}}]
    assert ie._azure_nic_config_index(inventory) is None
    with pytest.raises(AttributeError):
        list(ie._azure_backend_nics(inventory, ["x"]))


# ------------------------------------------------- AI stage preparation

def test_static_evidence_summary_is_used_without_native_registry(monkeypatch):
    from peaso.ai import pipeline
    from peaso.server import evidence_static
    monkeypatch.setattr(pipeline, "_STATIC_EVIDENCE", None)
    monkeypatch.delitem(sys.modules, "peaso.checks", raising=False)
    assert pipeline._evidence_summary() is evidence_static.evidence_summary
    monkeypatch.setitem(sys.modules, "peaso.checks", object())
    from peaso.finding_observation import evidence_summary
    assert pipeline._evidence_summary() is evidence_summary


def test_static_evidence_drift_falls_back_to_native(monkeypatch):
    from peaso.ai import pipeline
    from peaso.server import evidence_static
    from peaso.finding_observation import evidence_summary
    monkeypatch.setattr(pipeline, "_STATIC_EVIDENCE", None)
    monkeypatch.delitem(sys.modules, "peaso.checks", raising=False)
    def drift():
        raise ImportError("reviewed presentation source changed")
    monkeypatch.setattr(evidence_static, "verify_closure", drift)
    assert pipeline._evidence_summary() is evidence_summary
    assert pipeline._STATIC_EVIDENCE is False


def test_single_stage_proves_and_prepares_only_its_own_stage(monkeypatch, tmp_path):
    from test_progressive_analyzer_20261022 import _exact_reuse_fixture
    from peaso.ai import network, pipeline
    _exact_reuse_fixture(monkeypatch, tmp_path)
    prepared = []
    original = network.prepare
    monkeypatch.setattr(network, "prepare", lambda *args: prepared.append(1) or original(*args))
    rows = [{"id": f"{category}-1", "check_id": category, "category": category, "status": "FAIL",
             "resource_id": f"r-{category}", "scope": "123456789012/us-east-1"}
            for category in ("hardening", "exposure")]
    report = {"provider": "aws", "created_at": "t", "snapshot_id": "s", "findings": rows, "graphs": {}}
    early = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None, stages=("hardening",))
    assert prepared == [] and early["review_fingerprints"]["exposure"] == {}
    full = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None)
    assert prepared == [1]
    assert early["review_fingerprints"]["hardening"] == full["review_fingerprints"]["hardening"]
    assert set(full["review_fingerprints"]["exposure"]) == {"exposure-1"}
    reused = pipeline.review_scan(report, {}, {}, tenant="tenant", artifacts=None,
                                  reused_stages={"hardening": early})
    assert reused["reviews"] == full["reviews"]


def _expand(document):
    return [{**document.get('checks', {}).get(item.get('check_id'), {}), **item} for item in document['items']]


@pytest.mark.parametrize('seed', range(8))
def test_shared_check_section_restores_every_reviewer_item_exactly(seed):
    import copy
    import random
    from peaso.ai import pipeline
    rng = random.Random(seed)
    items = []
    for position in range(rng.randint(1, 40)):
        check = rng.choice(['c1', 'c2', 'c3', None, 7])
        item = {'id': f'f{position}', 'resource_id': f'r{position}', 'evidence': {'fact': rng.choice(['a', 'b'])},
                'supporting_resources': [{'id': f'r{position}'}], 'evidence_summary': 'same text'}
        if check is not None:
            item['check_id'] = check
        for field in pipeline.SHARED_CHECK_FIELDS:
            if rng.random() < .8:
                item[field] = {'severity': rng.choice(['high', 'high', 'low'])}.get(field, f'{check}-{field}') \
                    if rng.random() < .9 else [rng.random()]
        items.append(item)
    document = {'scan': {'provider': 'gcp'}, 'items': items}
    original = copy.deepcopy(document)
    compact = pipeline.compact_document(document)
    assert document == original
    assert compact['scan'] == original['scan'] and _expand(compact) == original['items']
    assert [item['id'] for item in compact['items']] == [item['id'] for item in original['items']]
    for shared in compact.get('checks', {}).values():
        assert set(shared) <= set(pipeline.SHARED_CHECK_FIELDS)
    for item in compact['items']:
        assert {'id', 'resource_id', 'evidence', 'supporting_resources', 'evidence_summary'} <= set(item)


def test_differing_control_text_stays_on_each_item():
    from peaso.ai import pipeline
    document = {'scan': {}, 'items': [{'id': 'a', 'check_id': 'c', 'title': 'T', 'severity': 'high'},
                                      {'id': 'b', 'check_id': 'c', 'title': 'T', 'severity': 'low'},
                                      {'id': 'c', 'check_id': 'c', 'title': 'T'}]}
    compact = pipeline.compact_document(document)
    assert compact['checks'] == {'c': {'title': 'T'}}
    assert compact['items'] == [{'id': 'a', 'check_id': 'c', 'severity': 'high'},
                                {'id': 'b', 'check_id': 'c', 'severity': 'low'}, {'id': 'c', 'check_id': 'c'}]
    assert pipeline.compact_document({'scan': {}, 'items': [{'id': 'x'}]}) == {'scan': {}, 'items': [{'id': 'x'}]}


@pytest.mark.parametrize('stage', ['hardening', 'exposure'])
def test_reviewer_prompt_explains_shared_check_section(stage):
    from pathlib import Path
    import yaml
    from peaso.ai import pipeline
    prompt = yaml.safe_load((Path(pipeline.__file__).parent / f'agents/{stage}.yaml').read_text())['system_prompt']
    assert "checks[item.check_id] merged with the item's own fields" in prompt
    assert 'supporting_resources always stay in each item' in prompt


def test_review_fingerprints_do_not_depend_on_the_written_shared_section(monkeypatch):
    from peaso.ai import pipeline
    rows = [{'id': f'f{i}', 'check_id': 'c', 'title': 'T', 'status': 'FAIL', 'category': 'hardening',
             'resource_id': f'r{i}', 'evidence': {}} for i in range(3)]
    report = {'provider': 'gcp', 'findings': rows}
    before = pipeline.review_fingerprints(report, {}, rows, identity='i', entries=[])
    monkeypatch.setattr(pipeline, 'compact_document', lambda document: {'changed': True})
    assert pipeline.review_fingerprints(report, {}, rows, identity='i', entries=[]) == before

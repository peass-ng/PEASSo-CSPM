"""The indexed GCP firewall target attribution equals the full pairwise scan."""
import random
from copy import deepcopy

import pytest

from peaso.checks import gcp_firewall_targets
from peaso.checks.facts import MemoIndex, get, optional

# The pre-index pairwise implementation, kept verbatim as the oracle.
def reference_targets(item, index):
    """Source-bound declaration attribution only; incomplete facts never lower risk."""
    from peaso.checks.facts import Unavailable, complete_items, guard

    missing = object()

    def selected(row, key, expected, default=missing):
        # An empty read can carry an empty array, but cannot authenticate a
        # retained nonempty value from a prior or partial projection.
        guard(row)
        parent_coverage = row.get("_coverage", {})
        if "collection_status" in parent_coverage:
            proof = parent_coverage["collection_status"]
            if not isinstance(proof, dict) or proof.get("status") not in ("collected", "empty"):
                raise Unavailable("target parent status unavailable")
            if (proof["status"] == "empty") != ("collection_status" not in row):
                raise Unavailable("target parent status contradicts field coverage")
        if "collection_status" in row and row["collection_status"] != "collected":
            raise Unavailable("target parent unavailable")
        coverage = row.get("_coverage", {}).get(key)
        if (isinstance(coverage, dict) and coverage.get("status") == "empty"
                and key in row and bool(row[key])):
            raise Unavailable("nonempty selected field contradicts empty coverage: " + key)
        if default is missing:
            return get(row, key, expected)
        return optional(row, key, default, expected)

    def string_set(values):
        if any(not isinstance(value, str) or not value for value in values):
            raise Unavailable("malformed target selector")
        return set(values)

    def network(link):
        if not isinstance(link, str) or not link:
            raise Unavailable("network identity unavailable")
        return link.split("/projects/", 1)[-1].removeprefix("projects/")

    try:
        instances = complete_items(index, "instance")
        wanted_network = network(selected(item, "network", str))
        tags = string_set(selected(item, "targetTags", list, []))
        accounts = string_set(selected(item, "targetServiceAccounts", list, []))
    except Unavailable:
        return {"target_instances": "unknown (instance inventory or rule attribution unavailable)",
                "target_instances_running": "unknown (target attribution unavailable)",
                "target_instances_complete": False}

    matched, unresolved = [], False
    for instance in instances:
        try:
            nics = selected(instance, "networkInterfaces", list)
        except Unavailable:
            unresolved = True
            continue
        on_network, network_unknown = False, False
        for nic in nics:
            try:
                if network(selected(nic, "network", str)) == wanted_network:
                    on_network = True
            except Unavailable:
                network_unknown = True
        if not on_network:
            if network_unknown:
                unresolved = True
            continue
        selectors = []
        if tags:
            try:
                observed_tags = selected(instance, "tags", dict, {})
                selectors.append(bool(tags & string_set(selected(observed_tags, "items", list, []))))
            except Unavailable:
                selectors.append(None)
        if accounts:
            try:
                observed_accounts = selected(instance, "serviceAccounts", list, [])
                account_match, account_unknown = False, False
                for account in observed_accounts:
                    try:
                        email = selected(account, "email", str)
                        if not email:
                            raise Unavailable("service account identity unavailable")
                        account_match = account_match or email in accounts
                    except Unavailable:
                        account_unknown = True
                selectors.append(True if account_match else None if account_unknown else False)
            except Unavailable:
                selectors.append(None)
        if False in selectors:
            continue
        if None in selectors:
            unresolved = True
            continue
        try:
            name = selected(instance, "name", str, None)
        except Unavailable:
            name = None
        try:
            status = selected(instance, "status", str)
            if status not in ("PROVISIONING", "STAGING", "RUNNING", "STOPPING", "SUSPENDING", "SUSPENDED", "REPAIRING", "TERMINATED"):
                raise Unavailable("unrecognized instance status")
        except Unavailable:
            status = None
        external, external_unknown = False, False
        for nic in nics:
            for field in ("accessConfigs", "ipv6AccessConfigs"):
                try:
                    configs = selected(nic, field, list, [])
                    for config in configs:
                        try:
                            selected(config, "collection_status", str, None)
                            external = True
                        except Unavailable:
                            external_unknown = True
                except Unavailable:
                    external_unknown = True
        matched.append({"name": name, "status": status,
                        "external_ip": True if external else "unknown (external access configuration unavailable)" if external_unknown else False,
                        "external_ip_semantics": "Configured external access, not observed address delivery or reachability."})
    running = sum(row["status"] == "RUNNING" for row in matched)
    running_unknown = unresolved or any(row["status"] is None for row in matched)
    evidence = {"target_instances": "unknown (target attribution incomplete)" if unresolved else len(matched),
                "target_instances_complete": not unresolved,
                "target_instances_running": "unknown (running target count incomplete)" if running_unknown else running,
                "target_instance_sample": matched[:10],
                "target_attribution_semantics": "Declared network and target selectors in the scoped inventory; not effective reachability."}
    if unresolved:
        evidence["target_instances_lower_bound"] = len(matched)
    if running_unknown:
        evidence["target_instances_running_lower_bound"] = running
    if not matched and not unresolved:
        evidence.update(practical_severity="low", practical_severity_reason="No VM in this project matches the rule's network and targets; the exposure is latent")
    return evidence


NETWORKS = ["https://www.googleapis.com/compute/v1/projects/p/global/networks/a",
            "projects/p/global/networks/b", "projects/q/global/networks/a"]
TAGS = ["ssh", "web", "db", ""]
EMAILS = ["a@p.iam.gserviceaccount.com", "b@p.iam.gserviceaccount.com", ""]
STATUSES = ["RUNNING", "TERMINATED", "STAGING", "BOGUS"]


def _maybe_deny(rng, row, key):
    roll = rng.random()
    if roll < 0.06:
        row.setdefault("_coverage", {})[key] = {"status": "denied"}
    elif roll < 0.1:
        row.setdefault("_coverage", {})[key] = {"status": "empty"}


def _instance(rng, position):
    nics = []
    for _ in range(rng.choice([0, 1, 1, 2])):
        nic = {"network": rng.choice(NETWORKS + [None])}
        if nic["network"] is None:
            nic.pop("network")
        if rng.random() < 0.5:
            nic["accessConfigs"] = [{"natIP": "203.0.113.%d" % position}]
            if rng.random() < 0.2:
                nic["accessConfigs"][0]["collection_status"] = rng.choice(["collected", "denied"])
        _maybe_deny(rng, nic, "network")
        _maybe_deny(rng, nic, "accessConfigs")
        nics.append(nic)
    vm = {"name": "vm-%d" % position, "status": rng.choice(STATUSES), "networkInterfaces": nics}
    if rng.random() < 0.8:
        vm["tags"] = {"items": rng.sample(TAGS, rng.randint(0, 2))}
        _maybe_deny(rng, vm["tags"], "items")
    if rng.random() < 0.8:
        vm["serviceAccounts"] = [{"email": rng.choice(EMAILS)} for _ in range(rng.randint(0, 2))]
        for account in vm["serviceAccounts"]:
            _maybe_deny(rng, account, "email")
    for key in ("tags", "serviceAccounts", "networkInterfaces", "status", "name"):
        _maybe_deny(rng, vm, key)
    if rng.random() < 0.03:
        vm["collection_status"] = "denied"
    return vm


def _rule(rng):
    rule = {"network": rng.choice(NETWORKS)}
    if rng.random() < 0.7:
        rule["targetTags"] = rng.sample(TAGS[:3], rng.randint(1, 2))
    if rng.random() < 0.4:
        rule["targetServiceAccounts"] = rng.sample(EMAILS[:2], rng.randint(1, 2))
    return rule


def _index(instances):
    return {"collections": {"instance": [{"status": "collected"}]},
            "instance": [{"data": vm} for vm in instances]}


@pytest.mark.parametrize("seed", range(40))
def test_indexed_attribution_matches_pairwise_scan(seed):
    rng = random.Random(seed)
    instances = [_instance(rng, position) for position in range(rng.randint(0, 25))]
    rules = [_rule(rng) for _ in range(12)]
    plain = _index(instances)
    memo = MemoIndex(deepcopy(plain))
    for rule in rules:
        expected = reference_targets(rule, plain)
        assert gcp_firewall_targets(rule, plain) == expected
        # One shared memo across rules, as in a native evaluation.
        assert gcp_firewall_targets(rule, memo) == expected


def test_returned_samples_are_not_shared_between_rules():
    vm = {"name": "vm", "status": "RUNNING", "tags": {"items": ["ssh"]},
          "networkInterfaces": [{"network": NETWORKS[0]}]}
    memo = MemoIndex(_index([vm]))
    rule = {"network": NETWORKS[0], "targetTags": ["ssh"]}
    first = gcp_firewall_targets(rule, memo)
    first["target_instance_sample"][0]["name"] = "changed"
    assert gcp_firewall_targets(rule, memo)["target_instance_sample"][0]["name"] == "vm"

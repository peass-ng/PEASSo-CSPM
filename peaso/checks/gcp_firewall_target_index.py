"""Per-evaluation instance index for GCP firewall target attribution.

Every failing firewall rule attributes its declared network and target
selectors to the same scoped instance inventory.  The facts read from each
instance do not depend on the rule, so they are read once per evaluation
index, and each rule then visits only the instances that can still match:
those on its network whose tag and service-account selectors are matched or
unresolved.  Instances skipped this way are exactly the ones the full scan
skipped with a ``False`` selector, so the attribution, its order and its
completeness are unchanged.
"""
from .facts import Unavailable, memoized

_STATUSES = ("PROVISIONING", "STAGING", "RUNNING", "STOPPING", "SUSPENDING", "SUSPENDED", "REPAIRING", "TERMINATED")


class _Instance:
    __slots__ = ("instance", "nics", "networks", "network_unknown", "tags", "emails", "account_unknown", "row")

    def __init__(self, instance, nics, networks, network_unknown, tags, emails, account_unknown):
        self.instance, self.nics = instance, nics
        self.networks, self.network_unknown = networks, network_unknown
        self.tags, self.emails, self.account_unknown = tags, emails, account_unknown
        self.row = None


class _Profile:
    __slots__ = ("rows", "nics_unavailable", "network_unknown", "by_network", "by_tag", "tag_unknown",
                 "by_email", "account_maybe")

    def __init__(self, instances, selected, network, string_set):
        self.rows, self.nics_unavailable, self.network_unknown = [], False, []
        self.by_network, self.by_tag, self.tag_unknown = {}, {}, set()
        self.by_email, self.account_maybe = {}, set()
        for position, instance in enumerate(instances):
            try:
                nics = selected(instance, "networkInterfaces", list)
            except Unavailable:
                self.nics_unavailable = True
                self.rows.append(None)
                continue
            networks, network_unknown = set(), False
            for nic in nics:
                try:
                    networks.add(network(selected(nic, "network", str)))
                except Unavailable:
                    network_unknown = True
            try:
                observed_tags = selected(instance, "tags", dict, {})
                tags = string_set(selected(observed_tags, "items", list, []))
            except Unavailable:
                tags = None
            try:
                observed_accounts = selected(instance, "serviceAccounts", list, [])
                emails, account_unknown = set(), False
                for account in observed_accounts:
                    try:
                        email = selected(account, "email", str)
                        if not email:
                            raise Unavailable("service account identity unavailable")
                        emails.add(email)
                    except Unavailable:
                        account_unknown = True
            except Unavailable:
                emails, account_unknown = None, True
            self.rows.append(_Instance(instance, nics, networks, network_unknown, tags, emails, account_unknown))
            if network_unknown:
                self.network_unknown.append(networks)
            for name in networks:
                self.by_network.setdefault(name, []).append(position)
            if tags is None:
                self.tag_unknown.add(position)
            else:
                for tag in tags:
                    self.by_tag.setdefault(tag, set()).add(position)
            if account_unknown:
                self.account_maybe.add(position)
            for email in emails or ():
                self.by_email.setdefault(email, set()).add(position)

    def candidates(self, wanted_network, tags, accounts):
        """Positions on the network whose selectors are matched or unresolved, in inventory order."""
        positions = self.by_network.get(wanted_network, [])
        if tags:
            allowed = set(self.tag_unknown)
            for tag in tags:
                allowed |= self.by_tag.get(tag, set())
            positions = [position for position in positions if position in allowed]
        if accounts:
            allowed = set(self.account_maybe)
            for email in accounts:
                allowed |= self.by_email.get(email, set())
            positions = [position for position in positions if position in allowed]
        return positions


def _matched_row(entry, selected):
    if entry.row is None:
        instance = entry.instance
        try:
            name = selected(instance, "name", str, None)
        except Unavailable:
            name = None
        try:
            status = selected(instance, "status", str)
            if status not in _STATUSES:
                raise Unavailable("unrecognized instance status")
        except Unavailable:
            status = None
        external, external_unknown = False, False
        for nic in entry.nics:
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
        entry.row = {"name": name, "status": status,
                     "external_ip": True if external else "unknown (external access configuration unavailable)" if external_unknown else False,
                     "external_ip_semantics": "Configured external access, not observed address delivery or reachability."}
    return dict(entry.row)


def attributed(index, instances, wanted_network, tags, accounts, selected, network, string_set):
    """Return ``(matched, unresolved)`` for one rule over the scoped instance inventory."""
    profile = memoized(index, ("gcp_firewall_target_profile",),
                       lambda: _Profile(instances, selected, network, string_set))
    unresolved = profile.nics_unavailable or any(wanted_network not in networks
                                                 for networks in profile.network_unknown)
    matched = []
    for position in profile.candidates(wanted_network, tags, accounts):
        entry = profile.rows[position]
        selectors = []
        if tags:
            selectors.append(None if entry.tags is None else bool(tags & entry.tags))
        if accounts:
            if entry.emails is None:
                selectors.append(None)
            else:
                selectors.append(True if entry.emails & accounts else None if entry.account_unknown else False)
        if False in selectors:
            continue
        if None in selectors:
            unresolved = True
            continue
        matched.append(_matched_row(entry, selected))
    return matched, unresolved

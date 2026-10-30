"""Exact signed Azure VM, storage, and AKS snapshot checks.

The nine reviewed draft families are isolated in lexical namespaces. Only the
50 IDs in the frozen partition enter the public native registry.
"""
from . import CHECKS as _GLOBAL_CHECKS, register as _BASE_REGISTER, Check as _BatchCheck
from dataclasses import replace as _batch_replace
from types import SimpleNamespace as _BatchNamespace

# Reviewed source family: compliance_new_sw02.py
def _load_02():
    _ALLOWED = {'azure.gap.compute_vm_attached_with_network', 'azure.gap.compute_vm_scale_set_system_updates_installed'}
    _CHECKS = []

    def register(*args, **kwargs):
        ident = args[0]

        def decorate(function):
            if ident in _ALLOWED:
                out = _BASE_REGISTER(*args, **kwargs)(function)
                check = _GLOBAL_CHECKS.pop()
            else:
                out = function
                check = _BatchCheck(*args[:8], function, kwargs.get('target', 'resource'), tuple(kwargs.get('dependencies') or ()))
            _CHECKS.append(check)
            return out
        return decorate
    CHECKS = _CHECKS
    'Signed Azure sw02 checks over complete, same-subscription snapshots.\n\nEmbedded Firewall Policy groups and VMSS patch assessments use the collector\nwave facts. Missing or partial embedded reads never establish a safe configuration.\n'
    from datetime import datetime, timezone
    import re
    from . import result, unknown
    from .facts import Unavailable, complete_items, get, list_of_objects
    VM_VNET_ID = 'azure.gap.compute_vm_attached_with_network'
    FIREWALL_HAS_RULES_ID = 'azure_firewall_policy_1_2_8_23_59ad733'
    FIREWALL_GROUP_RULES_ID = 'azure_firewall_policy_1_2_8_24_cc7cb8a'
    VMSS_PATCH_ID = 'azure.gap.compute_vm_scale_set_system_updates_installed'
    MG_DESCENDANT_ID = 'azure_management_group_7_2_1_1_af95df1'
    IDS = (VM_VNET_ID, FIREWALL_HAS_RULES_ID, FIREWALL_GROUP_RULES_ID, VMSS_PATCH_ID, MG_DESCENDANT_ID)
    SPEC_SHA256 = {VM_VNET_ID: '0a3b74aa472b7e331bb0230fbbef71b5e61e9f659c35d6a16f2e16b0bb2c6bda', FIREWALL_HAS_RULES_ID: '2d5acd04c5e345e9622fcc966fc4c16c8924c808ea3b816495dfbf9d3436e17c', FIREWALL_GROUP_RULES_ID: 'fb7fef2975812a5d28069e1ff3b32ea7740aef79930717e75bf3d090fca7517f', VMSS_PATCH_ID: 'b46b78955982732e1d6101a8719f54328c85202e00b63ec2c86cdf7a3c77a69e', MG_DESCENDANT_ID: '86c29ca5873996326553742c1ab0df7426a27ac52d222a2f128d52ed1c691985'}
    _SUB = re.compile('/subscriptions/[^/?#]+\\Z', re.I)
    _ARM = re.compile('/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*\\Z', re.I)

    def _identity(value, *, prefix=None):
        if not isinstance(value, str) or not _ARM.fullmatch(value):
            raise Unavailable('malformed Azure resource ID')
        if prefix is not None and (not value.casefold().startswith(prefix.casefold() + '/')):
            raise Unavailable('foreign Azure child resource ID')
        return value.casefold()

    def _inventory(index, kind):
        context = get(index, 'context', dict)
        scope = get(context, 'scope', str)
        if get(context, 'provider', str) != 'azure' or not _SUB.fullmatch(scope):
            raise Unavailable('Azure subscription scope unavailable')
        envelopes = get(index, 'collections', dict).get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1 or (not isinstance(envelopes[0], dict)) or (envelopes[0].get('type') != kind) or (envelopes[0].get('scope', '').casefold() != scope.casefold()):
            raise Unavailable('Azure collection scope unavailable')
        rows = complete_items(index, kind)
        native = get(envelopes[0], 'items', list)
        wrapped = get(index, kind, list)
        if (envelopes[0]['status'] == 'empty') != (not rows):
            raise Unavailable('Azure collection status conflicts with items')
        if len(rows) != len(native) or len(rows) != len(wrapped) or any((not isinstance(w, dict) or w.get('type') != kind or str(w.get('scope', '')).casefold() != scope.casefold() or (w.get('data') != n) for w, n in zip(wrapped, native))):
            raise Unavailable('Azure collection and scoped index disagree')
        seen = set()
        arm_kind = {'vm': 'Microsoft.Compute/virtualMachines', 'nic': 'Microsoft.Network/networkInterfaces', 'vnet': 'Microsoft.Network/virtualNetworks', 'firewall_policy': 'Microsoft.Network/firewallPolicies', 'vm_scale_set': 'Microsoft.Compute/virtualMachineScaleSets'}[kind]
        for row in rows:
            rid = _identity(get(row, 'id', str))
            if not rid.startswith(scope.casefold() + '/') or rid in seen or (not re.fullmatch(re.escape(scope) + '/resourceGroups/[^/?#]+/providers/' + re.escape(arm_kind) + '/[^/?#]+', rid, re.I)):
                raise Unavailable('foreign or duplicate Azure resource')
            seen.add(rid)
        return rows

    def _member(item, rows):
        rid = _identity(get(item, 'id', str))
        if sum((_identity(get(row, 'id', str)) == rid and row == item for row in rows)) != 1:
            raise Unavailable('resource is not the unique collected item')
        return rid

    def _policy(index, field):
        metadata = get(get(index, 'context', dict), 'metadata', dict)
        policy = get(metadata, 'sw02', dict)
        if get(policy, 'status', str) != 'collected':
            raise Unavailable('approved Azure policy unavailable')
        return get(policy, field)

    @register(VM_VNET_ID, 'azure', 'hardening', 'vm', 'Connect VMs only to approved VNets', 'medium', 'CM-6', 'Azure portal > Virtual machines > Networking: Move or recreate VM NICs on approved VNet subnets.', dependencies=['vm', 'nic', 'vnet'])
    def vm_attached_to_approved_vnet(item, index):
        vms = _inventory(index, 'vm')
        vm_id = _member(item, vms)
        nics = {_identity(get(nic, 'id', str)): nic for nic in _inventory(index, 'nic')}
        vnets = {_identity(get(vnet, 'id', str)): vnet for vnet in _inventory(index, 'vnet')}
        approved = _policy(index, 'approvedVnetIds')
        if not isinstance(approved, list) or not approved:
            raise Unavailable('approved VNet set unavailable')
        approved_ids = {_identity(value) for value in approved}
        if len(approved_ids) != len(approved) or any((not re.fullmatch('/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\\.Network/virtualNetworks/[^/?#]+', value, re.I) for value in approved_ids)):
            raise Unavailable('duplicate approved VNet identity')
        references = list_of_objects(get(item, 'properties.networkProfile.networkInterfaces', list))
        if not references:
            return ('NOT_APPLICABLE', {'vm_id': vm_id, 'reason': 'Complete VM declaration has no NIC attachment'})
        attached = set()
        observed, uncertain = ([], [])
        for reference in references:
            try:
                nic_id = _identity(get(reference, 'id', str))
                if nic_id in attached or nic_id not in nics:
                    raise Unavailable('duplicate or unresolved VM NIC')
                attached.add(nic_id)
                nic = nics[nic_id]
                if _identity(get(nic, 'properties.virtualMachine.id', str)) != vm_id:
                    raise Unavailable('NIC is not attached to assessed VM')
                configs = list_of_objects(get(nic, 'properties.ipConfigurations', list))
                if not configs:
                    raise Unavailable('NIC IP configurations unavailable')
                for config in configs:
                    subnet = _identity(get(config, 'properties.subnet.id', str))
                    if not re.fullmatch('/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\\.Network/virtualNetworks/[^/?#]+/subnets/[^/?#]+', subnet, re.I):
                        raise Unavailable('NIC subnet is not a direct VNet child')
                    marker = '/subnets/'
                    if subnet.count(marker) != 1:
                        raise Unavailable('NIC subnet ID malformed')
                    vnet_id = subnet.split(marker)[0]
                    vnet = vnets.get(vnet_id)
                    if vnet is None:
                        raise Unavailable('NIC VNet unresolved')
                    known_subnets = list_of_objects(get(vnet, 'properties.subnets', list))
                    if subnet not in {_identity(get(row, 'id', str)) for row in known_subnets}:
                        raise Unavailable('NIC subnet missing from complete VNet')
                    observed.append(vnet_id)
            except Unavailable as exc:
                uncertain.append(str(exc))
        unapproved = sorted(set(observed) - approved_ids)
        if unapproved:
            return result(True, vm_id=vm_id, vnet_ids=sorted(set(observed)), unapproved_vnet_ids=unapproved, uncertain_attachments=uncertain)
        if uncertain or not observed:
            return unknown('VM VNet attachment unresolved', vm_id=vm_id, uncertain_attachments=uncertain)
        return result(False, vm_id=vm_id, vnet_ids=sorted(set(observed)), unapproved_vnet_ids=[])

    def _firewall_policies(item, index):
        rows = _inventory(index, 'firewall_policy')
        rid = _member(item, rows)
        return (rid, {_identity(get(row, 'id', str)): row for row in rows})

    def _groups(policy):
        coverage = get(policy, '_coverage.ruleCollectionGroups.status', str)
        if coverage not in ('collected', 'empty'):
            raise Unavailable('Firewall Policy group pages incomplete')
        policy_id = _identity(get(policy, 'id', str))
        rows = list_of_objects(get(policy, 'ruleCollectionGroups', list))
        if (coverage == 'empty') != (not rows):
            raise Unavailable('Firewall Policy group coverage conflicts with rows')
        seen = set()
        for group in rows:
            gid = _identity(get(group, 'id', str), prefix=policy_id + '/ruleCollectionGroups')
            if not re.fullmatch(re.escape(policy_id) + '/rulecollectiongroups/[^/?#]+', gid):
                raise Unavailable('Firewall Policy group is not a direct child')
            provenance = get(group, '_provenance', dict)
            if gid in seen or get(provenance, 'representation', str) != 'full' or get(provenance, 'source_operation', str) != 'get_rule_collection_group' or (get(provenance, 'read_only', bool) is not True) or (get(provenance, 'parent_policy_id', str).casefold() != policy_id):
                raise Unavailable('duplicate or partial Firewall Policy group')
            seen.add(gid)
        return rows

    def _rules(group):
        collections = list_of_objects(get(group, 'properties.ruleCollections', list))
        all_rules = []
        for collection in collections:
            kind = get(collection, 'ruleCollectionType', str)
            if kind not in ('FirewallPolicyFilterRuleCollection', 'FirewallPolicyNatRuleCollection'):
                raise Unavailable('unsupported Firewall Policy collection type')
            rules = list_of_objects(get(collection, 'rules', list))
            for rule in rules:
                rule_type = get(rule, 'ruleType', str)
                if rule_type not in ({'ApplicationRule', 'NetworkRule'} if kind == 'FirewallPolicyFilterRuleCollection' else {'NatRule'}):
                    raise Unavailable('rule type conflicts with Firewall Policy collection')
                if not get(rule, 'name', str):
                    raise Unavailable('Firewall Policy rule name unavailable')
                all_rules.append(rule)
        return all_rules

    @register(FIREWALL_HAS_RULES_ID, 'azure', 'network', 'firewall_policy', 'Azure Firewall Policies contain configured rules', 'medium', 'CM-6', 'Add a filter or NAT rule collection containing an applicable rule to the policy or its effective base policy.', dependencies=['firewall_policy'])
    def firewall_policy_has_rules(item, index):
        policy_id, policies = _firewall_policies(item, index)
        current, visited, count = (policy_id, set(), 0)
        while current:
            if current in visited or current not in policies:
                raise Unavailable('Firewall Policy base ancestry cyclic or unresolved')
            visited.add(current)
            policy = policies[current]
            for group in _groups(policy):
                count += len(_rules(group))
            base = get(policy, 'properties.basePolicy')
            if base is None:
                if get(policy, '_provenance.representation', str) != 'full' or get(policy, '_provenance.source_operation', str) != 'get' or get(policy, '_provenance.read_only', bool) is not True:
                    raise Unavailable('absent base policy lacks full read-only GET authority')
                current = None
            else:
                current = _identity(get(base, 'id', str))
        return result(count == 0, policy_id=policy_id, rule_count=count, ancestry_count=len(visited))

    @register(FIREWALL_GROUP_RULES_ID, 'azure', 'network', 'firewall_policy', 'Firewall Policy contains at least one rule', 'medium', 'CM-6', 'In each empty Firewall Policy Rule Collection Group, add the approved filtering rule or remove the unused group after confirming its intended scope.', dependencies=['firewall_policy'])
    def firewall_policy_groups_have_rules(item, index):
        policy_id, _ = _firewall_policies(item, index)
        groups = _groups(item)
        if not groups:
            return ('NOT_APPLICABLE', {'policy_id': policy_id, 'reason': 'Complete group inventory is empty'})
        empty, uncertain = ([], [])
        for group in groups:
            try:
                if not _rules(group):
                    empty.append(get(group, 'id', str))
            except Unavailable:
                uncertain.append(get(group, 'id', str))
        if uncertain and (not empty):
            return unknown('Firewall Policy group rules unresolved', uncertain_group_ids=uncertain)
        return result(bool(empty), policy_id=policy_id, group_count=len(groups), empty_group_ids=sorted(empty), uncertain_group_ids=uncertain)

    def _instant(value):
        if not isinstance(value, str):
            raise Unavailable('patch timestamp malformed')
        try:
            when = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('patch timestamp malformed') from exc
        if when.tzinfo is None or when.utcoffset() is None:
            raise Unavailable('patch timestamp lacks timezone')
        return when.astimezone(timezone.utc)

    @register(VMSS_PATCH_ID, 'azure', 'hardening', 'vm_scale_set', 'VM scale set instances have no pending critical or security patches', 'medium', 'SI-2', 'Use Azure Update Manager to install Critical and Security patches on affected VMSS instances, then rerun patch assessment.', dependencies=['vm_scale_set'])
    def vmss_system_updates(item, index):
        vmss_id = _member(item, _inventory(index, 'vm_scale_set'))
        if get(item, '_coverage.instances.status', str) not in ('collected', 'empty'):
            raise Unavailable('VMSS instance pages incomplete')
        instances = list_of_objects(get(item, 'instances', list))
        if (get(item, '_coverage.instances.status', str) == 'empty') != (not instances):
            raise Unavailable('VMSS instance coverage conflicts with rows')
        if not instances:
            return ('NOT_APPLICABLE', {'vmss_id': vmss_id, 'reason': 'Complete VMSS instance inventory is empty'})
        age = _policy(index, 'maxAssessmentAgeSeconds')
        if type(age) is not int or age <= 0:
            raise Unavailable('patch assessment freshness policy malformed')
        now = _instant(get(get(index, 'context', dict), 'created_at', str))
        seen, pending, uncertain = (set(), [], [])
        for instance in instances:
            instance_id = _identity(get(instance, 'id', str), prefix=vmss_id + '/virtualMachines')
            if instance_id in seen:
                raise Unavailable('duplicate VMSS instance')
            seen.add(instance_id)
            try:
                patch = get(instance, 'patchAssessment', dict)
                if get(patch, 'resourceId', str).casefold() != instance_id:
                    raise Unavailable('patch summary belongs to another VMSS instance')
                provenance = get(patch, '_provenance', dict)
                if get(provenance, 'source', str) != 'ResourceGraph.patchassessmentresources.summary' or get(provenance, 'latest', bool) is not True:
                    raise Unavailable('latest patch summary provenance unavailable')
                if get(patch, 'status', str) != 'Succeeded':
                    raise Unavailable('patch assessment not successful')
                elapsed = (now - _instant(get(patch, 'lastModifiedDateTime', str))).total_seconds()
                if not 0 <= elapsed <= age:
                    raise Unavailable('patch assessment stale or future dated')
                counts = get(patch, 'availablePatchCountByClassification', dict)
                critical, security = (get(counts, 'critical', int), get(counts, 'security', int))
                if critical < 0 or security < 0:
                    raise Unavailable('patch counts malformed')
                if critical or security:
                    pending.append(instance_id)
                else:
                    errors = get(patch, 'errorDetails', list)
                    if errors or get(patch, 'unresolvedClassification', bool):
                        raise Unavailable('patch assessment has unresolved errors or classification')
            except Unavailable:
                uncertain.append(instance_id)
        if pending:
            return result(True, vmss_id=vmss_id, pending_instance_ids=sorted(pending), uncertain_instance_ids=sorted(uncertain))
        if uncertain:
            return unknown('VMSS patch assessments incomplete or stale', vmss_id=vmss_id, uncertain_instance_ids=sorted(uncertain))
        return result(False, vmss_id=vmss_id, assessed_instance_count=len(seen))

    @register(MG_DESCENDANT_ID, 'azure', 'hardening', 'management_group', 'Subscriptions belong to the expected Management Group', 'medium', 'AC-2', 'In Management groups, move the subscription under expectedManagementGroupId and refresh the descendants inventory.', target='scope', dependencies=['subscription', 'management_group_descendant'])
    def subscription_under_master_group(item, index):
        context = get(index, 'context', dict)
        scope = get(context, 'scope', str)
        if get(context, 'provider', str) != 'azure' or not _SUB.fullmatch(scope):
            raise Unavailable('subscription scope unavailable')
        if item != context:
            raise Unavailable('scope context differs from evaluation context')
        master = _policy(index, 'expectedManagementGroupId')
        if not isinstance(master, str) or not re.fullmatch('/providers/Microsoft\\.Management/managementGroups/[^/?#]+', master, re.I):
            raise Unavailable('expected Management Group policy malformed')
        subscriptions = get(index, 'collections', dict).get('subscription')
        if not isinstance(subscriptions, list) or len(subscriptions) != 1 or (not isinstance(subscriptions[0], dict)) or (subscriptions[0].get('type') != 'subscription') or (subscriptions[0].get('scope', '').casefold() != scope.casefold()):
            raise Unavailable('subscription collection scope unavailable')
        subscription_rows = complete_items(index, 'subscription')
        wrapped_subscriptions = get(index, 'subscription', list)
        declared_subscriptions = get(subscriptions[0], 'items', list)
        if len(wrapped_subscriptions) != len(declared_subscriptions) or any((get(w, 'type', str) != 'subscription' or get(w, 'scope', str).casefold() != scope.casefold() or get(w, 'data', dict) != n for w, n in zip(wrapped_subscriptions, declared_subscriptions))):
            raise Unavailable('subscription inventory index disagrees with envelope')
        if len(subscription_rows) != len(get(subscriptions[0], 'items', list)) or len(subscription_rows) > 1:
            raise Unavailable('subscription inventory malformed')
        if not subscription_rows:
            if subscriptions[0].get('status') != 'empty':
                raise Unavailable('subscription empty status unavailable')
            return ('NOT_APPLICABLE', {'scope': scope, 'reason': 'Complete subscription scope is empty'})
        if subscriptions[0].get('status') != 'collected':
            raise Unavailable('subscription inventory status conflicts with item')
        if get(subscription_rows[0], 'id', str).casefold() != scope.casefold():
            raise Unavailable('subscription item is foreign to assessed scope')
        descendants = get(index, 'collections', dict).get('management_group_descendant')
        if not isinstance(descendants, list) or len(descendants) != 1 or (not isinstance(descendants[0], dict)) or (descendants[0].get('type') != 'management_group_descendant') or (descendants[0].get('scope', '').casefold() != scope.casefold()):
            raise Unavailable('Management Group descendants scope unavailable')
        envelope = descendants[0]
        provenance = get(envelope, '_provenance', dict)
        if get(provenance, 'source_operation', str) != 'get_descendants' or get(provenance, 'parent_management_group_id', str).casefold() != master.casefold() or get(provenance, 'pages_complete', bool) is not True:
            raise Unavailable('Management Group descendants source incomplete')
        rows = complete_items(index, 'management_group_descendant')
        if (envelope['status'] == 'empty') != (not rows):
            raise Unavailable('Management Group descendant status conflicts with items')
        wrapped = get(index, 'management_group_descendant', list)
        if len(wrapped) != len(rows) or len(get(envelope, 'items', list)) != len(rows) or any((not isinstance(w, dict) or w.get('type') != 'management_group_descendant' or str(w.get('scope', '')).casefold() != scope.casefold() or (w.get('data') != n) for w, n in zip(wrapped, rows))):
            raise Unavailable('Management Group descendants index disagrees with collection')
        subscription_name = scope.rsplit('/', 1)[-1]
        seen, subscription_names, present = (set(), set(), False)
        for row in rows:
            descendant_id = get(row, 'id', str)
            name = get(row, 'name', str)
            kind = get(row, 'type', str)
            if kind.casefold() == 'microsoft.management/managementgroups/subscriptions':
                if not re.fullmatch('[^/?#]+', name) or not re.fullmatch('(?:/providers/Microsoft\\.Management/managementGroups/[^/?#]+)?/subscriptions/' + re.escape(name), descendant_id, re.I):
                    raise Unavailable('Management Group subscription descendant malformed')
                if name.casefold() in subscription_names:
                    raise Unavailable('duplicate Management Group subscription descendant')
                subscription_names.add(name.casefold())
            elif kind.casefold() == 'microsoft.management/managementgroups':
                if not re.fullmatch('/providers/Microsoft\\.Management/managementGroups/[^/?#]+', descendant_id, re.I):
                    raise Unavailable('Management Group descendant identity malformed')
            else:
                raise Unavailable('Management Group descendant type unsupported')
            key = descendant_id.casefold()
            if key in seen:
                raise Unavailable('duplicate Management Group descendant')
            seen.add(key)
            if kind.casefold().endswith('/subscriptions') and name.casefold() == subscription_name.casefold():
                present = True
        return result(not present, subscription_id=scope, expected_management_group_id=master, descendant_count=len(rows))
    from .facts import memoized as _batch_memoized
    _batch_original = _inventory

    def _inventory(index, *args, **kwargs):
        key = ('azure_remaining_02', args, tuple(sorted(kwargs.items())))
        return _batch_memoized(index, key, lambda: _batch_original(index, *args, **kwargs))
    for _batch_check in _CHECKS:
        if _batch_check.id in _ALLOWED:
            if _batch_check.category not in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}:
                _batch_check = _batch_replace(_batch_check, category='hardening')
            _GLOBAL_CHECKS.append(_batch_check)
_load_02()

# Reviewed source family: compliance_new_sw03.py
def _load_03():
    _ALLOWED = {'azure.cis.legacy_vhds_encrypted', 'azure.cis.resource_manager_delete_locks_applied_storage_accounts', 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794'}
    _CHECKS = []

    def register(*args, **kwargs):
        ident = args[0]

        def decorate(function):
            if ident in _ALLOWED:
                out = _BASE_REGISTER(*args, **kwargs)(function)
                check = _GLOBAL_CHECKS.pop()
            else:
                out = function
                check = _BatchCheck(*args[:8], function, kwargs.get('target', 'resource'), tuple(kwargs.get('dependencies') or ()))
            _CHECKS.append(check)
            return out
        return decorate
    CHECKS = _CHECKS
    'Signed Azure compliance predicates over complete, scoped native facts.'
    from dataclasses import replace
    from datetime import datetime, timezone
    from urllib.parse import urlsplit
    import re
    from . import result, unknown
    from .facts import Unavailable, complete_items, get
    IDS = ('azure.cis.legacy_vhds_encrypted', 'azure.cis.resource_manager_delete_locks_applied_storage_accounts', 'azure.gap.machine_learning_workspace_private_link_used', 'azure_c5_ops_15_02b', 'azure.cis.endpoint_protection_vms_installed', 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled', 'azure.gap.compute_vm_image_builder_uses_private_link', 'azure.gap.automation_account_encrypted_with_cmk', 'azure.gap.stream_analytics_job_encrypted_with_cmk', 'azure.cis.auto_provisioning_log_analytics_agent_vms', 'azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3', 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794')
    _META = {'azure.cis.legacy_vhds_encrypted': {'resource_kind': 'storage_account', 'category': 'encryption', 'severity': 'high', 'title': '[Legacy] Ensure that VHDs are Encrypted', 'remediation_hint': 'Migrate unmanaged VHDs to managed disks; while retained, enable Blob service encryption on each backing storage account in Storage account > Encryption.', 'spec_sha': '782daf2a0cca5ca5b5f5fcc413fa7c48776768c83de5539a36ecbec597ebc990'}, 'azure.cis.resource_manager_delete_locks_applied_storage_accounts': {'resource_kind': 'storage_account', 'category': 'hardening', 'severity': 'medium', 'title': 'Ensure Azure Resource Manager Delete locks are applied to Azure Storage Accounts', 'remediation_hint': 'Azure portal > Storage account > Locks > Add, choose Delete (CanNotDelete); alternatively apply a suitable resource-group or subscription lock.', 'spec_sha': '7580aac3a6012476e3dd8169d336b4ff0816fe65929eb64203dba1869e8425e3'}, 'azure.gap.machine_learning_workspace_private_link_used': {'resource_kind': 'ml_workspace', 'category': 'network', 'severity': 'medium', 'title': 'Azure Machine Learning workspaces should use private link', 'remediation_hint': 'Azure portal > Machine Learning workspace > Networking > Private endpoint connections: create a private endpoint and approve its connection.', 'spec_sha': '7d4efbf397f021c41066a0030bf4fd8d3ebda3e035f4666945dfcdc088aeba20'}, 'azure_c5_ops_15_02b': {'resource_kind': 'activity_log', 'category': 'hardening', 'severity': 'medium', 'title': 'Azure Activity Log events carry a usable timestamp', 'remediation_hint': 'In Azure Monitor > Activity log, inspect malformed events and verify the collection query has a bounded time window and follows every continuation page.', 'spec_sha': 'a40dff6e15c01ef634e8850d44d4ad63c8e98453962dd3cbb7ed5053210df05c'}, 'azure.cis.endpoint_protection_vms_installed': {'resource_kind': 'virtual_machine', 'category': 'vulnerability', 'severity': 'medium', 'title': 'Ensure that the endpoint protection for all Virtual Machines is installed', 'remediation_hint': 'In Defender for Cloud > Recommendations, open the endpoint protection assessment for the unhealthy VM; install or repair the approved endpoint agent and confirm that VM reports Healthy.', 'spec_sha': 'f746aca26f88aebf6f83b408f4536aaf48ac96d38a3eb5653c47c4832a77eba6'}, 'azure.gap.monitor_log_cluster_infrastructure_encryption_enabled': {'resource_kind': 'log_analytics_cluster', 'category': 'encryption', 'severity': 'medium', 'title': 'Enable infrastructure encryption for Log Analytics clusters', 'remediation_hint': 'Azure portal > Log Analytics dedicated clusters: enable infrastructure encryption where supported, or create a double-encrypted replacement cluster and move linked workspaces.', 'spec_sha': '93f62300dd7e0eb862e878d68807b367e2468436ba9828f6ba4d177636fddfcb'}, 'azure.gap.compute_vm_image_builder_uses_private_link': {'resource_kind': 'image_template', 'category': 'network', 'severity': 'medium', 'title': 'VM Image Builder uses an approved isolated build subnet', 'remediation_hint': 'Set properties.vmProfile.vnetConfig.subnetId on the image template to an approved isolated subnet; apply NSG and route controls to that subnet.', 'spec_sha': '941d9ce7ed99a7b7ed2034cfabbf550f93a282d8c8ca6167c76b9d72da73f82e'}, 'azure.gap.automation_account_encrypted_with_cmk': {'resource_kind': 'automation_account', 'category': 'encryption', 'severity': 'medium', 'title': 'Automation account encrypts with a customer-managed key', 'remediation_hint': 'Automation account > Encryption: enable a system or user-assigned managed identity, select Customer-managed key, and choose a Key Vault key with access granted to that identity.', 'spec_sha': '4d53cc4cd46d6cb003c58792cbbcc91028a3b77adfec45eec891949a199a0875'}, 'azure.gap.stream_analytics_job_encrypted_with_cmk': {'resource_kind': 'stream_analytics_job', 'category': 'encryption', 'severity': 'medium', 'title': 'Azure Stream Analytics jobs should use customer-managed keys to encrypt data', 'remediation_hint': 'Configure jobStorageAccount on the Stream Analytics job and select an approved storage account using Key Vault customer-managed encryption.', 'spec_sha': '94cabf518ccef18ebb9acad05fa51300154ce978ace8e3e8376e191adf3eb2b0'}, 'azure.cis.auto_provisioning_log_analytics_agent_vms': {'resource_kind': 'defender_auto_provisioning_setting', 'category': 'logging', 'severity': 'medium', 'title': "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'", 'remediation_hint': 'Azure portal > Defender for Cloud > Environment settings: If the legacy agent is required by the approved baseline, set autoProvisioningSettings/default autoProvision to On; otherwise retire this legacy requirement.', 'spec_sha': '8958eedb4b5a9b93625782e67202efb4e49764053f5c0d71eb6514cdcbaa59c3'}, 'azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3': {'resource_kind': 'security_pricing', 'category': 'hardening', 'severity': 'medium', 'title': 'Required Defender for Cloud plans use Standard tier', 'remediation_hint': 'In Defender for Cloud > Environment settings > Defender plans, enable Standard pricing for each supported plan listed in requiredPlans.', 'spec_sha': 'd9f0362e5d8b705dd480647b588e41c53ff2c955123706a3274e8f485987c77d'}, 'azure_storage_account_storage_blob_public_access_level_is_disabled_4211794': {'resource_kind': 'storage_account', 'category': 'network', 'severity': 'high', 'title': 'Storage account network and blob access match approved settings', 'remediation_hint': 'Storage account > Configuration and Networking: set blob public access, public network access and default network action to the approved values in expectedSettings.', 'spec_sha': '222fe45d4ac3a7cf978fb27a85af9760aea2b5c1b1fa9e085ac4bb846bae6d6f'}}

    def _signed(check_id, *, dependencies=None, target='resource'):
        """Register via the native wrapper, retaining the signed proposal category."""
        spec = _META[check_id]
        native_category = spec['category'] if spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'

        def decorate(function):
            registered = register(check_id, 'azure', native_category, spec['resource_kind'], spec['title'], spec['severity'], 'CM-6', spec['remediation_hint'], target=target, dependencies=dependencies)(function)
            if native_category != spec['category']:
                CHECKS[-1] = replace(CHECKS[-1], category=spec['category'])
            return registered
        return decorate

    def _context(index):
        context = get(index, 'context', dict)
        if get(context, 'provider', str) != 'azure':
            raise Unavailable('foreign provider context')
        scope = get(context, 'scope', str)
        if not re.fullmatch('/subscriptions/[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', scope):
            raise Unavailable('subscription scope authority unavailable')
        return (context, scope.casefold())

    def _items(index, kind):
        _, scope = _context(index)
        collections = get(index, 'collections', dict)
        envelopes = collections.get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable('missing or ambiguous scoped collection: ' + kind)
        envelope = get(envelopes[0], 'type', str)
        if envelope != kind or get(envelopes[0], 'scope', str).casefold() != scope:
            raise Unavailable('foreign collection scope: ' + kind)
        status = get(envelopes[0], 'status', str)
        rows = complete_items(index, kind)
        wrappers = get(index, kind, list)
        native = get(envelopes[0], 'items', list)
        if len(wrappers) != len(rows) or len(native) != len(rows) or (status == 'empty') != (not rows) or (rows != native):
            raise Unavailable('collection cardinality inconsistent: ' + kind)
        arm_kinds = {'vm': 'Microsoft.Compute/virtualMachines', 'storage_account': 'Microsoft.Storage/storageAccounts', 'ml_workspace': 'Microsoft.MachineLearningServices/workspaces', 'log_analytics_cluster': 'Microsoft.OperationalInsights/clusters', 'image_template': 'Microsoft.VirtualMachineImages/imageTemplates', 'automation_account': 'Microsoft.Automation/automationAccounts', 'stream_analytics_job': 'Microsoft.StreamAnalytics/streamingjobs'}
        for wrapper, row in zip(wrappers, rows):
            if get(wrapper, 'type', str) != kind or get(wrapper, 'scope', str).casefold() != scope:
                raise Unavailable('foreign resource scope: ' + kind)
            if get(wrapper, 'data', dict) != row:
                raise Unavailable('resource projection inconsistent: ' + kind)
            if kind in arm_kinds and (not re.fullmatch(re.escape(scope) + '/resourceGroups/[^/?#]+/providers/' + re.escape(arm_kinds[kind]) + '/[^/?#]+', get(row, 'id', str), re.I)):
                raise Unavailable('resource identity malformed or wrong native kind: ' + kind)
            if kind == 'security_assessment' and (not re.fullmatch(re.escape(scope) + '(?:/resourceGroups/[^/?#]+/providers/[^/?#]+/[^/?#]+/[^/?#]+(?:/[^/?#]+/[^/?#]+)*)?/providers/Microsoft\\.Security/assessments/[^/?#]+', get(row, 'id', str), re.I)):
                raise Unavailable('security assessment ARM identity malformed')
            if kind != 'activity_log' and 'id' in row and (not get(row, 'id', str).casefold().startswith(scope + '/')):
                raise Unavailable('foreign resource identity: ' + kind)
            if kind == 'activity_log' and 'resourceId' in row:
                rid = get(row, 'resourceId', str)
                if rid.casefold().startswith('/subscriptions/') and (not rid.casefold().startswith(scope + '/')):
                    raise Unavailable('foreign Activity Log resource identity')
        return rows

    def _unique(rows, key='id'):
        result_by_id = {}
        for row in rows:
            identity = get(row, key, str)
            if not identity or identity.casefold() in result_by_id:
                raise Unavailable('missing or duplicate resource identity')
            result_by_id[identity.casefold()] = row
        return result_by_id

    def _own(item, index, kind):
        rows = _unique(_items(index, kind))
        identity = get(item, 'id', str).casefold()
        if identity not in rows or rows[identity] != item:
            raise Unavailable('resource absent or different from scoped inventory')
        _, scope = _context(index)
        if not identity.startswith(scope + '/'):
            raise Unavailable('resource outside subscription')
        return rows

    def _policy(index, name):
        context, scope = _context(index)
        policy = get(context, 'metadata.compliance_policy.sw03', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != scope:
            raise Unavailable('owner policy unavailable or foreign to subscription')
        return get(policy, name, dict)

    def _scope_item(item, index):
        _, scope = _context(index)
        if get(item, 'scope', str).casefold() != scope:
            raise Unavailable('foreign scope target')

    def _has(item, key):
        """Inspect API omission only after rejecting a field-level failed read."""
        if not isinstance(item, dict):
            raise Unavailable('malformed fact parent')
        coverage = item.get('_coverage', {})
        if not isinstance(coverage, dict):
            raise Unavailable('malformed field coverage')
        marker = coverage.get(key)
        if marker is not None and (not isinstance(marker, dict) or marker.get('status') not in ('collected', 'empty')):
            raise Unavailable('fact unavailable or malformed coverage: ' + key)
        return key in item

    def _utc(value):
        if not isinstance(value, str):
            raise Unavailable('timestamp missing or malformed')
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError as exc:
            raise Unavailable('timestamp malformed') from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise Unavailable('timestamp has no timezone')
        return parsed.astimezone(timezone.utc)

    def _vault_uri(value):
        if not isinstance(value, str):
            raise Unavailable('Key Vault URI malformed')
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise Unavailable('Key Vault URI malformed')
        return value

    def _not_applicable(reason):
        return ('NOT_APPLICABLE', {'reason': reason})

    def _aggregate(rows, evaluate, **evidence):
        outcomes, uncertain = ([], [])
        for row in rows:
            try:
                status, _ = evaluate(row)
                outcomes.append(status)
            except Unavailable as exc:
                uncertain.append(str(exc))
        if 'FAIL' in outcomes:
            return result(True, uncertain_resources=uncertain, **evidence)
        if uncertain or 'UNKNOWN' in outcomes:
            return unknown('one or more resource observations unresolved', uncertain_resources=uncertain, **evidence)
        return result(False, **evidence)

    def _ml_private_link_one(item, index):
        _own(item, index, 'ml_workspace')
        workspace = get(item, 'id', str)
        if get(item, '_coverage.privateEndpointConnections.status', str) not in ('collected', 'empty'):
            raise Unavailable('ML private endpoint child read incomplete')
        connections = get(item, 'privateEndpointConnections', list)
        if (get(item, '_coverage.privateEndpointConnections.status', str) == 'empty') != (not connections):
            raise Unavailable('ML private endpoint coverage contradicts rows')
        if any((not isinstance(c, dict) for c in connections)):
            raise Unavailable('malformed ML private endpoint connection')
        found = False
        seen = set()
        for connection in connections:
            identity = get(connection, 'id', str)
            prefix = workspace.rstrip('/') + '/privateEndpointConnections/'
            if not identity.casefold().startswith(prefix.casefold()) or identity.casefold() in seen or (not re.fullmatch('[^/?#]+', identity[len(prefix):])):
                raise Unavailable('foreign or duplicate ML private endpoint connection')
            seen.add(identity.casefold())
            status = get(connection, 'properties.privateLinkServiceConnectionState.status', str)
            if status not in ('Approved', 'Pending', 'Rejected', 'Disconnected'):
                raise Unavailable('unrecognized ML private endpoint status')
            if status == 'Approved':
                endpoint = get(connection, 'properties.privateEndpoint.id', str)
                if not re.fullmatch('/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\\.Network/privateEndpoints/[^/?#]+', endpoint, re.I):
                    raise Unavailable('approved ML connection has no valid private endpoint ID')
                found = True
        return result(not found, workspace_id=workspace, approved_connections=int(found), semantics='Private Link presence only; exclusive private ingress unverified')

    @_signed('azure.gap.machine_learning_workspace_private_link_used', dependencies=['ml_workspace'], target='scope')
    def ml_private_link(item, index):
        _scope_item(item, index)
        workspaces = _unique(_items(index, 'ml_workspace'))
        if not workspaces:
            return _not_applicable('complete ML workspace inventory is empty')
        return _aggregate(workspaces.values(), lambda row: _ml_private_link_one(row, index), workspaces=len(workspaces), semantics='Approved Private Link presence only; exclusive private ingress unverified')

    @_signed('azure.gap.monitor_log_cluster_infrastructure_encryption_enabled', dependencies=['log_analytics_cluster'], target='scope')
    def log_cluster_infrastructure_encryption(item, index):
        _scope_item(item, index)
        clusters = _unique(_items(index, 'log_analytics_cluster'))
        if not clusters:
            return _not_applicable('complete Logs cluster inventory is empty')
        return _aggregate(clusters.values(), lambda row: result(get(row, 'properties.isDoubleEncryptionEnabled', bool) is False, cluster_id=get(row, 'id', str)), cluster_count=len(clusters))

    @_signed('azure.cis.auto_provisioning_log_analytics_agent_vms', dependencies=['defender_auto_provisioning_setting'], target='scope')
    def legacy_agent_auto_provisioning(item, index):
        _scope_item(item, index)
        if get(_policy(index, 'legacyAgentBaseline'), 'required', bool) is not True:
            return _not_applicable('legacy Log Analytics agent baseline is not required')
        rows = _items(index, 'defender_auto_provisioning_setting')
        names = _unique(rows, 'name')
        for row in rows:
            identity = get(row, 'id', str)
            if identity.casefold() != (get(item, 'scope', str) + '/providers/Microsoft.Security/autoProvisioningSettings/' + get(row, 'name', str)).casefold():
                raise Unavailable('foreign auto provisioning setting')
        default = names.get('default')
        if default is None:
            return result(True, reason='complete settings list has no default')
        setting = get(default, 'properties.autoProvision', str)
        if setting not in ('On', 'Off'):
            raise Unavailable('unrecognized auto provisioning value')
        return result(setting == 'Off', configured=setting)

    @_signed('azure_security_pricing_policy_ensure_asc_enforcement_enabled_70150a3', dependencies=['security_pricing'], target='scope')
    def defender_required_plans(item, index):
        _scope_item(item, index)
        policy = _policy(index, 'defenderPlans')
        if get(policy, 'representsSecurityCenterEnablement', bool) is not True:
            raise Unavailable('selected Defender plan set does not represent frozen Security Center requirement')
        required = get(policy, 'requiredPlans', list)
        supported = get(policy, 'supportedPlans', list)
        if not required or any((not isinstance(x, str) or not x for x in required + supported)) or len(set(required)) != len(required) or (len(set(supported)) != len(supported)) or (not set(required) <= set(supported)):
            raise Unavailable('required Defender plan policy unresolved')
        rows = _items(index, 'security_pricing')
        plans = _unique(rows, 'name')
        for row in rows:
            if get(row, 'id', str).casefold() != (get(item, 'scope', str) + '/providers/Microsoft.Security/pricings/' + get(row, 'name', str)).casefold():
                raise Unavailable('foreign Defender pricing record')
        weak, uncertain = ([], [])
        for plan in required:
            record = plans.get(plan.casefold())
            if record is None:
                weak.append(plan)
                continue
            try:
                tier = get(record, 'properties.pricingTier', str)
                if tier not in ('Free', 'Standard'):
                    raise Unavailable('unrecognized Defender pricing tier')
                if tier == 'Free':
                    weak.append(plan)
            except Unavailable:
                uncertain.append(plan)
        if uncertain and (not weak):
            return unknown('required Defender pricing tier unresolved', uncertain_plans=uncertain)
        return result(bool(weak), required_plans=required, unsupported_or_free_plans=weak, uncertain_plans=uncertain, semantics='Configured plan tiers; tenant-wide Defender state unproven')

    @_signed('azure_c5_ops_15_02b', dependencies=['activity_log'], target='scope')
    def activity_timestamps(item, index):
        _scope_item(item, index)
        policy = _policy(index, 'activityLogWindow')
        start, end = (_utc(get(policy, 'start', str)), _utc(get(policy, 'end', str)))
        if not start < end:
            raise Unavailable('invalid activity log query window')
        rows = _items(index, 'activity_log')
        envelope = index['collections']['activity_log'][0]
        query = get(envelope, 'queryWindow', dict)
        if _utc(get(query, 'start', str)) != start or _utc(get(query, 'end', str)) != end or get(query, 'endExclusive', bool) is not True:
            raise Unavailable('activity log collection window differs from policy')
        if not rows:
            return unknown('no Activity Log events in bounded window')
        seen = set()
        missing = []
        for row in rows:
            rid = get(row, 'id', str)
            if not rid or rid in seen:
                raise Unavailable('missing or duplicate Activity Log event ID')
            seen.add(rid)
            present = False
            malformed = False
            for field in ('eventTimestamp', 'submissionTimestamp'):
                if _has(row, field):
                    try:
                        timestamp = _utc(get(row, field, str))
                    except Unavailable:
                        malformed = True
                        continue
                    if field == 'eventTimestamp' and (not start <= timestamp < end):
                        raise Unavailable('Activity Log event outside verified query window')
                    present = True
            if not present:
                if malformed:
                    raise Unavailable('Activity Log timestamp malformed')
                missing.append(rid)
        return result(bool(missing), events=len(rows), missing_timestamp_ids=missing)

    @_signed('azure.cis.endpoint_protection_vms_installed', dependencies=['vm', 'security_assessment'], target='scope')
    def vm_endpoint_protection(item, index):
        _scope_item(item, index)
        key = get(_policy(index, 'endpointProtection'), 'assessmentKey', str)
        if not key:
            raise Unavailable('endpoint protection assessment key unavailable')
        vms = _unique(_items(index, 'vm'))
        assessments = _items(index, 'security_assessment')
        if not vms:
            return _not_applicable('complete VM inventory is empty')
        observed, uncertain = ({}, [])
        for assessment in assessments:
            assessment_key = get(assessment, 'name', str)
            if assessment_key != key:
                continue
            vm_id = get(assessment, 'properties.resourceDetails.id', str).casefold()
            if vm_id not in vms:
                continue
            if vm_id in observed:
                raise Unavailable('duplicate endpoint protection assessment for VM')
            try:
                status = get(assessment, 'properties.status.code', str)
                if status not in ('Healthy', 'Unhealthy', 'NotApplicable'):
                    raise Unavailable('unrecognized endpoint protection status')
            except Unavailable:
                uncertain.append(vm_id)
                continue
            observed[vm_id] = status
        if any((status == 'Unhealthy' for status in observed.values())):
            return result(True, unhealthy_vm_ids=sorted((x for x, s in observed.items() if s == 'Unhealthy')), semantics='Current assessment state, not independent agent verification')
        if uncertain or len(observed) != len(vms) or any((status != 'Healthy' for status in observed.values())):
            return unknown('VM assessment missing or NotApplicable', assessed=len(observed), vm_count=len(vms))
        return result(False, vm_count=len(vms), semantics='Every VM reports Healthy for the selected assessment key')

    def _image_builder_one(item, index):
        _own(item, index, 'image_template')
        policy = _policy(index, 'imageBuilder')
        approved = get(policy, 'approvedBuildSubnetIds', list)
        isolated = get(policy, 'isolatedSubnetIds', list)
        subnet_pattern = '/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\\.Network/virtualNetworks/[^/?#]+/subnets/[^/?#]+'
        if not approved or any((not isinstance(x, str) or not re.fullmatch(subnet_pattern, x, re.I) for x in approved + isolated)) or len({x.casefold() for x in approved}) != len(approved) or (len({x.casefold() for x in isolated}) != len(isolated)):
            raise Unavailable('approved isolated build subnet policy unavailable')
        profile = get(item, 'properties.vmProfile', dict)
        vnet = get(profile, 'vnetConfig', dict) if _has(profile, 'vnetConfig') else None
        if vnet is None or not _has(vnet, 'subnetId'):
            if get(item, '_provenance.representation', str) != 'full':
                raise Unavailable('template subnet omission not proven by full GET')
            return result(True, reason='fully read template has no build subnet')
        subnet = get(vnet, 'subnetId', str)
        if not re.fullmatch(subnet_pattern, subnet, re.I):
            raise Unavailable('malformed image builder subnet ID')
        if subnet.casefold() not in {x.casefold() for x in approved}:
            return result(True, configured_subnet=subnet, reason='subnet outside approved set')
        if subnet.casefold() not in {x.casefold() for x in isolated}:
            return unknown('approved subnet isolation unverified', configured_subnet=subnet)
        evidence = get(item, '_subnetIsolation', dict)
        if get(evidence, 'status', str) != 'collected' or get(evidence, 'subnetId', str).casefold() != subnet.casefold():
            raise Unavailable('independent build subnet isolation evidence unavailable')
        if get(evidence, 'isolated', bool) is not True:
            return unknown('approved build subnet is not independently verified isolated', configured_subnet=subnet)
        return result(False, configured_subnet=subnet, semantics='Approved isolated build subnet signal; dependency Private Link paths unverified')

    @_signed('azure.gap.compute_vm_image_builder_uses_private_link', dependencies=['image_template'], target='scope')
    def image_builder_subnet(item, index):
        _scope_item(item, index)
        templates = _unique(_items(index, 'image_template'))
        if not templates:
            return _not_applicable('complete image template inventory is empty')
        return _aggregate(templates.values(), lambda row: _image_builder_one(row, index), templates=len(templates), semantics='Approved isolated build subnet signal only')

    def _storage_delete_lock_one(item, index):
        _own(item, index, 'storage_account')
        rid = get(item, 'id', str)
        match = re.fullmatch('(/subscriptions/[0-9a-fA-F-]{36})/(resourceGroups/[^/]+)/providers/Microsoft\\.Storage/storageAccounts/[^/]+', rid, re.I)
        if match is None:
            raise Unavailable('storage account ARM identity malformed')
        evidence = get(item, 'effectiveLockChain', dict)
        if get(evidence, 'status', str) != 'collected' or get(evidence, 'managementGroupAncestorsComplete', bool) is not True:
            raise Unavailable('effective lock ancestry incomplete')
        chain = get(evidence, 'scopes', list)
        expected = [rid.casefold(), (match.group(1) + '/' + match.group(2)).casefold(), match.group(1).casefold()]
        if len(chain) < 3 or any((not isinstance(x, dict) for x in chain)):
            raise Unavailable('lock chain incomplete or malformed')
        identities = [get(x, 'scope', str).casefold() for x in chain]
        if identities[:3] != expected or len(set(identities)) != len(identities) or any((not x.startswith('/providers/microsoft.management/managementgroups/') for x in identities[3:])):
            raise Unavailable('lock chain does not match storage ancestry')
        effective = []
        for scope_row in chain:
            if get(scope_row, 'status', str) not in ('collected', 'empty'):
                raise Unavailable('lock list incomplete for ancestor')
            locks = get(scope_row, 'locks', list)
            if any((not isinstance(x, dict) for x in locks)) or (scope_row['status'] == 'empty') != (not locks):
                raise Unavailable('lock list malformed')
            for lock in locks:
                level = get(lock, 'properties.level', str)
                if level not in ('CanNotDelete', 'ReadOnly'):
                    raise Unavailable('unrecognized management lock level')
                lock_id = get(lock, 'id', str)
                if not re.fullmatch(re.escape(scope_row['scope'].rstrip('/')) + '/providers/Microsoft\\.Authorization/locks/[^/?#]+', lock_id, re.I):
                    raise Unavailable('foreign management lock')
                effective.append(lock_id)
        return result(not effective, account_id=rid, effective_lock_ids=effective)

    @_signed('azure.cis.resource_manager_delete_locks_applied_storage_accounts', dependencies=['storage_account'], target='scope')
    def storage_delete_lock(item, index):
        _scope_item(item, index)
        accounts = _unique(_items(index, 'storage_account'))
        if not accounts:
            return _not_applicable('complete storage account inventory is empty')
        return _aggregate(accounts.values(), lambda row: _storage_delete_lock_one(row, index), accounts=len(accounts))

    @_signed('azure.gap.automation_account_encrypted_with_cmk', dependencies=['automation_account'])
    def automation_cmk(item, index):
        _own(item, index, 'automation_account')
        encryption = get(item, 'properties.encryption', dict)
        source = get(encryption, 'keySource', str)
        if source == 'Microsoft.Automation':
            return result(True, reason='platform-managed encryption key configured')
        if source != 'Microsoft.Keyvault':
            raise Unavailable('unrecognized Automation encryption key source')
        vault = get(encryption, 'keyVaultProperties', dict)
        key_name = get(vault, 'keyName', str)
        uri = get(vault, 'keyvaultUri', str)
        if not key_name or not uri:
            return result(True, reason='complete CMK configuration lacks a usable key reference')
        _vault_uri(uri)
        selected = get(encryption, 'identity', dict)
        assigned = get(item, 'identity', dict)
        identity_type = get(assigned, 'type', str)
        modes = {part.strip() for part in identity_type.split(',')}
        if not modes <= {'SystemAssigned', 'UserAssigned', 'None'} or not modes or ('None' in modes and len(modes) > 1):
            raise Unavailable('unrecognized Automation identity type')
        user_identity = get(selected, 'userAssignedIdentity') if _has(selected, 'userAssignedIdentity') else None
        if user_identity is not None:
            if not isinstance(user_identity, str) or not user_identity:
                raise Unavailable('malformed selected user-assigned identity')
            if not re.fullmatch('/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\\.ManagedIdentity/userAssignedIdentities/[^/?#]+', user_identity, re.I):
                raise Unavailable('selected CMK identity is not a managed identity ARM ID')
            if 'UserAssigned' not in modes:
                return result(True, reason='selected CMK user identity is not assigned')
            identities = get(assigned, 'userAssignedIdentities', dict)
            matches = [value for key, value in identities.items() if isinstance(key, str) and key.casefold() == user_identity.casefold()]
            if len(matches) > 1:
                raise Unavailable('ambiguous selected CMK identity')
            if not matches:
                return result(True, reason='selected CMK identity is not assigned')
            principal = get(matches[0], 'principalId', str)
        else:
            if 'SystemAssigned' not in modes:
                return result(True, reason='CMK system identity is not assigned')
            principal = get(assigned, 'principalId', str)
        if not principal:
            raise Unavailable('selected identity principal unresolved')
        access = get(item, '_cmkKeyAccess', dict)
        if get(access, 'status', str) != 'collected' or get(access, 'principalId', str).casefold() != principal.casefold() or get(access, 'keyName', str) != key_name or (get(access, 'keyvaultUri', str) != uri):
            raise Unavailable('current Key Vault key access unverified')
        allowed = get(access, 'usable', bool)
        return result(not allowed, key_name=key_name, principal_id=principal, semantics='Current selected identity and key access; rotation not assessed')

    @_signed('azure.gap.stream_analytics_job_encrypted_with_cmk', dependencies=['stream_analytics_job'])
    def stream_analytics_storage_cmk(item, index):
        _own(item, index, 'stream_analytics_job')
        applicability = get(item, '_externalStorageRequirement', dict)
        if get(applicability, 'status', str) != 'collected':
            raise Unavailable('Stream Analytics external storage applicability unresolved')
        required = get(applicability, 'required', bool)
        if not required:
            return _not_applicable('job has no private assets requiring external storage')
        accounts = _unique(_items(index, 'storage_account'))
        properties = get(item, 'properties', dict)
        if not _has(properties, 'jobStorageAccount'):
            if get(item, '_provenance.representation', str) != 'full' or get(item, '_provenance.source_operation', str) != 'get' or get(item, '_provenance.read_only', bool) is not True:
                raise Unavailable('job storage absence lacks full GET authority')
            return result(True, reason='required job storage account absent')
        job_storage = get(properties, 'jobStorageAccount', dict)
        name = get(job_storage, 'accountName', str)
        if not name:
            return result(True, reason='required job storage account absent')
        matches = [row for row in accounts.values() if get(row, 'name', str).casefold() == name.casefold()]
        if len(matches) != 1:
            raise Unavailable('job storage account identity unresolved or ambiguous')
        account = matches[0]
        if not get(account, 'id', str).casefold().startswith(get(item, 'id', str).casefold().split('/resourcegroups/')[0] + '/'):
            raise Unavailable('job storage account outside scoped subscription')
        source = get(account, 'properties.encryption.keySource', str)
        if source == 'Microsoft.Storage':
            return result(True, storage_account_id=get(account, 'id', str), reason='platform-managed key configured')
        if source != 'Microsoft.Keyvault':
            raise Unavailable('unrecognized storage encryption key source')
        key = get(account, 'properties.encryption.keyVaultProperties', dict)
        if not get(key, 'keyName', str):
            raise Unavailable('storage CMK reference unavailable')
        _vault_uri(get(key, 'keyVaultUri', str))
        access = get(account, '_cmkKeyAccess', dict)
        if get(access, 'status', str) != 'collected':
            raise Unavailable('storage CMK key access unverified')
        if get(access, 'keyName', str) != key['keyName'] or get(access, 'keyVaultUri', str) != key['keyVaultUri']:
            raise Unavailable('storage CMK access belongs to another key')
        assigned = get(account, 'identity', dict)
        selected = get(account, 'properties.encryption', dict).get('identity', {})
        if not isinstance(selected, dict):
            raise Unavailable('storage encryption identity malformed')
        user_identity = get(selected, 'userAssignedIdentity', str) if _has(selected, 'userAssignedIdentity') else None
        modes = {part.strip() for part in get(assigned, 'type', str).split(',')}
        if user_identity is not None:
            if 'UserAssigned' not in modes:
                raise Unavailable('storage CMK user identity is not assigned')
            identities = get(assigned, 'userAssignedIdentities', dict)
            matches = [value for rid, value in identities.items() if rid.casefold() == user_identity.casefold()]
            if len(matches) != 1:
                raise Unavailable('storage CMK identity ambiguous or unavailable')
            principal = get(matches[0], 'principalId', str)
        else:
            if 'SystemAssigned' not in modes:
                raise Unavailable('storage CMK system identity is not assigned')
            principal = get(assigned, 'principalId', str)
        if not principal or get(access, 'principalId', str).casefold() != principal.casefold():
            raise Unavailable('storage CMK access belongs to another principal')
        if get(access, 'usable', bool) is False:
            return result(True, storage_account_id=get(account, 'id', str), reason='configured CMK is unusable')
        return result(False, storage_account_id=get(account, 'id', str), semantics='Job storage account CMK only; internal service data unassessed')

    @_signed('azure.cis.legacy_vhds_encrypted', dependencies=['vm', 'storage_account'], target='scope')
    def unmanaged_vhd_blob_encryption(item, index):
        _scope_item(item, index)
        vms = _unique(_items(index, 'vm'))
        accounts = _unique(_items(index, 'storage_account'))
        uri_list, unresolved_vms = ([], [])
        for vm in vms.values():
            try:
                if get(vm, '_provenance.representation', str) != 'full':
                    raise Unavailable('VM storage profile completeness unverified')
                profile = get(vm, 'properties.storageProfile', dict)
                os_disk = get(profile, 'osDisk', dict)
                disks = get(profile, 'dataDisks', list) if _has(profile, 'dataDisks') else []
                if any((not isinstance(x, dict) for x in disks)):
                    raise Unavailable('malformed VM data disk')
                for disk in [os_disk, *disks]:
                    if _has(disk, 'vhd'):
                        uri_list.append(get(disk, 'vhd.uri', str))
                    elif _has(disk, 'managedDisk'):
                        if not get(disk, 'managedDisk.id', str).casefold().startswith(get(item, 'scope', str).casefold() + '/'):
                            raise Unavailable('VM managed disk identity unresolved')
                    else:
                        raise Unavailable('VM disk attachment type unresolved')
            except Unavailable as exc:
                unresolved_vms.append(str(exc))
        if not uri_list:
            if unresolved_vms:
                return unknown('VM disk attachment details unresolved', uncertain_vms=unresolved_vms)
            return _not_applicable('complete VM inventory has no unmanaged VHD')
        endpoints = {}
        for account in accounts.values():
            account_id = get(account, 'id', str)
            if not account_id.casefold().startswith(get(item, 'scope', str).casefold() + '/'):
                raise Unavailable('foreign storage account identity')
            endpoint = get(account, 'properties.primaryEndpoints.blob', str)
            parsed = urlsplit(endpoint)
            if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password or (not parsed.hostname):
                raise Unavailable('malformed storage Blob endpoint')
            origin = (parsed.scheme.casefold(), parsed.hostname.casefold(), parsed.port, parsed.path.rstrip('/'))
            if origin in endpoints:
                raise Unavailable('ambiguous Blob endpoint')
            endpoints[origin] = account
        weak, uncertain = ([], list(unresolved_vms))
        for uri in uri_list:
            try:
                parsed = urlsplit(uri)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or (not parsed.path.strip('/')):
                    raise Unavailable('unmanaged VHD URI malformed')
                matching = [account for origin, account in endpoints.items() if origin[:3] == (parsed.scheme.casefold(), parsed.hostname.casefold(), parsed.port) and parsed.path.startswith(origin[3] + '/')]
                if len(matching) != 1:
                    raise Unavailable('unmanaged VHD backing account unresolved')
                account = matching[0]
                if get(account, 'properties.encryption.services.blob.enabled', bool) is False:
                    weak.append(get(account, 'id', str))
            except (Unavailable, ValueError) as exc:
                uncertain.append(str(exc))
        if uncertain and (not weak):
            return unknown('one or more unmanaged VHDs unresolved', uncertain_vhds=uncertain)
        return result(bool(weak), unmanaged_vhd_count=len(uri_list), unencrypted_backing_account_ids=sorted(set(weak)), uncertain_vhds=uncertain, semantics='Blob service encryption for unmanaged VHD storage; guest BitLocker unassessed')

    @_signed('azure_storage_account_storage_blob_public_access_level_is_disabled_4211794', dependencies=['storage_account'])
    def storage_expected_access_settings(item, index):
        _own(item, index, 'storage_account')
        policy = _policy(index, 'storageAccess')
        expected = get(policy, 'expectedSettings', dict)
        allowed = {'allowBlobPublicAccess', 'publicNetworkAccess', 'networkAcls.defaultAction'}
        if not expected or set(expected) - allowed:
            raise Unavailable('expected storage access settings absent or unsupported')
        if 'allowBlobPublicAccess' in expected and type(expected['allowBlobPublicAccess']) is not bool or ('publicNetworkAccess' in expected and expected['publicNetworkAccess'] not in ('Enabled', 'Disabled', 'SecuredByPerimeter')) or ('networkAcls.defaultAction' in expected and expected['networkAcls.defaultAction'] not in ('Allow', 'Deny')):
            raise Unavailable('expected storage access setting malformed')
        properties = get(item, 'properties', dict)
        provenance = item.get('_provenance', {})
        full = isinstance(provenance, dict) and provenance.get('representation') == 'full' and (provenance.get('api_version') in ('2023-05-01', '2026-06-01')) and (provenance.get('source_operation') == 'get') and (provenance.get('read_only') is True)
        defaults = {'allowBlobPublicAccess': False, 'publicNetworkAccess': 'Enabled', 'networkAcls.defaultAction': 'Allow'}
        actual = {}
        for field in expected:
            parent = properties
            parts = field.split('.')
            for part in parts[:-1]:
                if not _has(parent, part):
                    if not full:
                        raise Unavailable('storage setting parent omitted without full representation')
                    parent = {}
                    break
                parent = get(parent, part, dict)
            name = parts[-1]
            if not _has(parent, name):
                if not full:
                    raise Unavailable('storage setting omission not authoritative')
                actual[field] = defaults[field]
            else:
                actual[field] = get(parent, name, bool if field == 'allowBlobPublicAccess' else str)
            if field == 'publicNetworkAccess' and actual[field] not in ('Enabled', 'Disabled', 'SecuredByPerimeter'):
                raise Unavailable('unrecognized public network access enum')
            if field == 'networkAcls.defaultAction' and actual[field] not in ('Allow', 'Deny'):
                raise Unavailable('unrecognized network default action enum')
        mismatches = {name: {'expected': expected[name], 'actual': actual[name]} for name in expected if expected[name] != actual[name]}
        return result(bool(mismatches), account_id=get(item, 'id', str), mismatches=mismatches, semantics='Typed storage account API settings; data-plane reachability unverified')
    from .facts import memoized as _batch_memoized
    _batch_original = _items

    def _items(index, *args, **kwargs):
        key = ('azure_remaining_03', args, tuple(sorted(kwargs.items())))
        return _batch_memoized(index, key, lambda: _batch_original(index, *args, **kwargs))
    for _batch_check in _CHECKS:
        if _batch_check.id in _ALLOWED:
            if _batch_check.category not in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}:
                _batch_check = _batch_replace(_batch_check, category='hardening')
            _GLOBAL_CHECKS.append(_batch_check)
_load_03()

# Reviewed source family: compliance_new_sw17.py
def _load_17():
    _ALLOWED = {'azure.gap.compute_vm_tcp_udp_access_restricted_internet', 'azure.gap.compute_vm_remote_access_restricted_all_ports'}
    _CHECKS = []

    def register(*args, **kwargs):
        ident = args[0]

        def decorate(function):
            if ident in _ALLOWED:
                out = _BASE_REGISTER(*args, **kwargs)(function)
                check = _GLOBAL_CHECKS.pop()
            else:
                out = function
                check = _BatchCheck(*args[:8], function, kwargs.get('target', 'resource'), tuple(kwargs.get('dependencies') or ()))
            _CHECKS.append(check)
            return out
        return decorate
    CHECKS = _CHECKS
    'Signed Azure VM compliance predicates over scoped, read-only snapshot facts.\n\nAdditional fact contracts and normalization rules are documented in the sw17\ncollector requests. No evaluator makes API calls or infers safety from absence.\n'
    from dataclasses import replace
    from datetime import datetime
    import ipaddress
    import itertools
    import re
    from . import result, unknown
    from .facts import Unavailable, complete_items, get, guard, list_of_objects, memoized
    SPECS = {'azure.gap.compute_vm_adaptive_application_controls_enabled': {'category': 'vulnerability', 'data_source': 'Paged ARM Microsoft.Security/assessments LIST 2020-01-01 and Microsoft.Security/locations/{location}/applicationWhitelistings group inventory; properties.resourceDetails.id/status.code for assessment, group VM recommendations and allowlist policy details; paged VM inventory and stable assessment key. Join by full VM ARM ID.', 'description': 'Checks current adaptive application-control group policy and per-VM assessment health; recommendation status alone is insufficient.', 'id': 'azure.gap.compute_vm_adaptive_application_controls_enabled', 'predicate': 'For each in-scope VM, join a configured stable assessment key and properties.resourceDetails.id, then verify membership in a current Microsoft.Security/applicationWhitelistings group with a configured active allowlist/audit policy and evidence that unknown applications generate alerts. Healthy assessment alone is insufficient. FAIL on a measured Unhealthy assessment or a complete group inventory proving no active applicable policy. PASS only with measured policy, alert behavior and Healthy assessment. UNKNOWN if group applicability, group schema/availability, alert evidence, assessment key, inventory, status or policy details cannot be resolved; NotApplicable requires independently established inapplicability.', 'provider': 'azure', 'remediation_hint': 'In Defender for Cloud > Adaptive application controls, assign each applicable VM to an active application allow-list policy, configure alerts for unknown applications, and verify its recommendation becomes Healthy.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Adaptive application controls are enabled on applicable VMs'}, 'azure.gap.compute_vm_adaptive_network_hardening_recommendation_applied': {'category': 'vulnerability', 'data_source': 'Paged VM and Microsoft.Security/assessments LIST 2020-01-01 plus Microsoft.Security/adaptiveNetworkHardenings GET/LIST recommendations and effective NSG rules; stable assessment key policy. Join on full VM ARM ID.', 'description': 'Checks applied effective NSG recommendations and per-VM assessment health for applicable Internet-facing VMs.', 'id': 'azure.gap.compute_vm_adaptive_network_hardening_recommendation_applied', 'predicate': 'For each Internet-facing applicable VM, join a current adaptive network hardening assessment by stable key and properties.resourceDetails.id. Healthy is recommendation-health evidence; PASS for applied recommendations requires the corresponding approved NSG rule recommendation to be applied and effective for that VM. FAIL on a measured Unhealthy recommendation or unapplied required rule. UNKNOWN for missing assessment, recommendation rule details, VM applicability, NSG join, freshness or inventory. NotApplicable is NOT_APPLICABLE only when applicability is established.', 'provider': 'azure', 'remediation_hint': 'In Defender for Cloud > Adaptive network hardening, apply each recommended NSG rule for affected Internet-facing VMs and verify effective rules and assessment health.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Adaptive network hardening recommendations are applied'}, 'azure.gap.compute_vm_administrators_group_with_extra_accounts_windows': {'category': 'hardening', 'data_source': 'Collector azure.py embeds VM guestConfigurationAssignments, but no reports. NEW: for each Windows VM and matching named assignment GET {assignment-id}/reports?api-version=2024-04-05, follow nextLink; join the report by its parent assignment ARM ID, properties.assignment.name, properties.vm.id, and properties.assignment.configuration name/version. Inspect properties.details.resources and effective assignment parameters against the approved member set.', 'description': 'Remove unapproved Windows Administrators group members. A finding is raised when a current named Administrators-membership assignment reports NonCompliant against the approved member set.', 'id': 'azure.gap.compute_vm_administrators_group_with_extra_accounts_windows', 'predicate': 'For each Windows VM, PASS only if a latest fresh successful report for that exact VM and approved Administrators baseline/version has the approved member parameter set, a complete nonempty set of relevant properties.details.resources, and each relevant resource is Compliant with no unapproved member. FAIL on a fresh report identifying an unapproved member or relevant NonCompliant resource, or a complete inventory proving the required baseline absent. UNKNOWN if approved set, assignment parameters, report, freshness, result detail, or inventory is incomplete. Assignment summary alone never proves PASS.', 'provider': 'azure', 'remediation_hint': 'Azure portal > Machine configuration: assign the approved Windows Administrators membership baseline, inspect its latest report, and remove each unapproved local group member.', 'resource_kind': 'vm', 'severity': 'high', 'title': 'Remove unapproved Windows Administrators group members'}, 'azure.gap.compute_vm_administrators_group_with_no_specified_members_windows': {'category': 'hardening', 'data_source': 'Paged per-VM Guest Configuration assignment GET/LIST 2024-04-05: properties.latestReportId and assignment parameters for approved local Administrators members; GET {assignmentId}/reports/{latestReportId}: properties.details.resources[].complianceStatus/reasons. Include complete Windows VM inventory and report-age policy.', 'description': 'Checks required members of Windows local Administrators through guest configuration evidence.', 'id': 'azure.gap.compute_vm_administrators_group_with_no_specified_members_windows', 'predicate': 'For each in-scope Windows VM, PASS only if the current report for the exact membership assignment demonstrates every policy-specified required member is present. FAIL only when specific current report detail proves a required member absent. UNKNOWN for missing policy parameter, assignment, latestReportId, report detail, freshness or VM/assignment paging. Assignment-level complianceStatus alone is insufficient.', 'provider': 'azure', 'remediation_hint': 'Azure Policy > Guest Configuration: assign the approved local Administrators membership policy with expected members; add missing members on the VM and rerun the guest assignment.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Audit Windows machines missing any of specified members in the Administrators group'}, 'azure.gap.compute_vm_administrators_group_with_specified_members_windows': {'category': 'hardening', 'data_source': 'Existing azure.py Windows vm.items[] and guest_configuration_assignment.items[]; new paged assignment report GET /guestConfigurationAssignments/{name}/reports?api-version=2022-01-25 for purpose-built local Administrators membership baseline. Report must contain observed membership and assigned parameter values.', 'description': 'Uses an explicit guest configuration assignment to audit prohibited members in the local Administrators group.', 'id': 'azure.gap.compute_vm_administrators_group_with_specified_members_windows', 'predicate': 'For each Windows VM, FAIL if a current report identifies a prohibited Administrators member. PASS only if the assigned baseline is Compliant, report confirms evaluated group membership against the exact prohibitedAdministrators input, and report freshness is within policy. UNKNOWN if list, assignment, report, parameter binding or freshness is absent; never infer clean membership from missing assignment.', 'provider': 'azure', 'remediation_hint': 'Azure Policy > Guest Configuration: assign the local Administrators membership audit with prohibited principals; inspect assignment report and remove those members from each VM.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Audit Windows machines that have the specified members in the Administrators group'}, 'azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated': {'category': 'vulnerability', 'data_source': 'Collector peaso/collectors/azure.py: vm and security_assessment are collected; assessment fields are properties.resourceDetails.id, properties.status.code (Healthy/Unhealthy/NotApplicable), name (stable assessment key). Require policy set of Docker-host assessment keys, and a complete assessment page for each VM.', 'description': 'Checks Defender for Cloud Docker host configuration assessment results on VMs.', 'id': 'azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated', 'predicate': 'PASS if every VM proven to host containers has a Healthy result for every required Docker-host assessment key at that VM resource ID. FAIL if any required assessment is Unhealthy. UNKNOWN if host applicability, assessment keys, complete assessment results or VM inventory are unknown; NotApplicable is not PASS.', 'provider': 'azure', 'remediation_hint': 'Defender for Cloud > Recommendations: open each Unhealthy Docker host assessment on the VM, apply its configuration fix and rescan.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Docker host security configuration findings are resolved'}, 'azure.gap.compute_vm_malware_agent_automatic_upgrade_enabled': {'category': 'vulnerability', 'data_source': 'Paged Windows VM and antimalware-extension inventory; guest Run Command executes Get-MpComputerStatus and Get-MpPreference, and reads effective Defender signature-update policy/registry including SignatureScheduleDay and SignatureUpdateInterval. Determine whether Microsoft Defender or the Microsoft Antimalware extension is the applicable protection agent; vendor evidence is required for other agents.', 'description': 'Checks effective automatic antimalware signature-update configuration on Windows VMs.', 'id': 'azure.gap.compute_vm_malware_agent_automatic_upgrade_enabled', 'predicate': 'For each scoped Windows VM using Microsoft Defender/Microsoft Antimalware, PASS only when automatic signature updates are enabled by effective guest policy and the protection service is operational. FAIL when a complete guest read proves automatic signature updates disabled or the required agent absent/disabled. UNKNOWN for unreadable guest policy, ambiguous agent applicability, incomplete VM inventory, or a third-party agent without vendor evidence. Signature age is a health signal and must not by itself turn a configured automatic-update control into FAIL or PASS.', 'provider': 'azure', 'remediation_hint': 'On affected Windows VMs, enable Microsoft Defender Antivirus and automatic signature updates via policy, restore update source connectivity, then run Update-MpSignature and confirm Get-MpComputerStatus freshness.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Windows VM antimalware signatures update automatically'}, 'azure.gap.compute_vm_meet_firewall_properties_windows': {'category': 'network', 'data_source': 'Paged Windows VM and guestConfigurationAssignments inventory plus GET {assignment-id}/reports?api-version=2024-04-05; report properties.details.resources[].resourceId, complianceStatus, properties and reasons; policy names the required Windows Firewall Properties baseline, expected settings, assignment and report freshness.', 'description': 'Checks every required Windows Firewall Properties setting in current guest configuration reports.', 'id': 'azure.gap.compute_vm_meet_firewall_properties_windows', 'predicate': 'For each applicable Windows VM, compare every named Group Policy setting in the Windows Firewall Properties baseline, including firewall state, inbound/outbound connections, rule management and notifications, with the latest fresh report for that VM. PASS only when all required setting results are Compliant. FAIL if any required setting is explicitly NonCompliant. UNKNOWN for missing assignment/report, unmeasured settings, ambiguous resource IDs, stale report or incomplete pages. Three profile states alone cannot pass.', 'provider': 'azure', 'remediation_hint': 'Deploy the Windows Firewall Properties machine configuration assignment and remediate every reported setting for firewall state, connections, rule management and notifications; rerun the report.', 'resource_kind': 'vm', 'severity': 'high', 'title': 'Windows Firewall Properties baseline is compliant'}, 'azure.gap.compute_vm_password_file_permissions_0644_linux': {'category': 'identity', 'data_source': 'Microsoft.GuestConfiguration/guestConfigurationAssignments GET for each Linux VM: properties.complianceStatus,properties.latestReportId; GET or LIST /guestConfigurationAssignments/{assignmentName}/reports using latestReportId: properties.details.resources[].resourceId,complianceStatus,reasons. Require an assignment whose configuration explicitly checks /etc/passwd mode 0644. Read assignment/report timestamps and an approved maxReportAge; correlate latestReportId to the exact report and VM. Read assignment/report timestamps and an approved maxReportAge; correlate latestReportId to the exact report and VM.', 'description': 'Checks /etc/passwd permissions using an explicit Linux guest configuration assignment.', 'id': 'azure.gap.compute_vm_password_file_permissions_0644_linux', 'predicate': 'For each inventoried Linux VM, PASS only if the latest report matching its exact assignment and latestReportId has a file-level Compliant result explicitly proving /etc/passwd mode 0644 and is within approved maxReportAge. FAIL if a current matching report proves a different mode, or a complete current assignment inventory proves the required assignment absent. UNKNOWN if policy age, assignment identity, latestReportId, report timestamp, file-level evidence, pagination or Linux VM inventory is missing or stale. Aggregate FAIL before UNKNOWN.', 'provider': 'azure', 'remediation_hint': 'On the Linux VM run sudo chmod 0644 /etc/passwd, then rerun the Azure Machine Configuration assignment and confirm the file-level report.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Audit Linux machines that do not have the passwd file permissions set to 0644'}, 'azure.gap.compute_vm_rdp_service_disabled': {'category': 'hardening', 'data_source': 'Windows VM inventory; Guest Configuration assignment reports for TermService; time-bounded officer approval register keyed by VM ID; Windows RDP sign-in/session log routing and monitored-alert evidence for approved enabled instances.', 'description': 'Measures Windows Remote Desktop Services state through guest evidence, with time-bounded exceptions.', 'id': 'azure.gap.compute_vm_rdp_service_disabled', 'predicate': 'For every Windows VM, require a current guest report proving TermService disabled or a VM-specific current approved exception for enabled RDP. For any approved enabled RDP path, also require enabled and monitored remote-access logs as the frozen requirement states. FAIL for proved enabled RDP without approval or proved missing required logging; PASS only when all applicable service, approval and monitoring evidence is complete. UNKNOWN for absent assignment/report, stale report, exception, log-routing or monitoring evidence.', 'provider': 'azure', 'remediation_hint': 'Disable TermService unless an authorized exception is current; for exceptions, enable remote-access logs and monitored alerts.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Windows VM RDP service is disabled unless explicitly approved'}, 'azure.gap.compute_vm_remote_access_restricted_all_ports': {'category': 'hardening', 'data_source': 'Collected vm, nic, subnet and nsg items: NIC/subnet networkSecurityGroup.id and each associated NSG properties.securityRules/defaultSecurityRules (sourceAddressPrefix(es), destinationPortRange(s), protocol, access, priority).', 'description': 'Checks each VM-associated NIC and subnet NSG for effective permissive inbound rules from Any or Internet source ranges across all protocols and ports.', 'id': 'azure.gap.compute_vm_remote_access_restricted_all_ports', 'predicate': 'For each VM-associated NIC and subnet NSG independently, evaluate inbound securityRules and defaultSecurityRules in priority order. FAIL if a complete effective rule path within either associated NSG permits any inbound traffic from Any, Internet, 0.0.0.0/0 or ::/0; a deny in the other NSG does not excuse the permissive associated NSG under the frozen rule. PASS only when every associated NSG is fully resolved and none has such an effective public allow. UNKNOWN for missing associations, unresolved service tags/ASGs, rule priorities, VM/NIC/subnet joins or incomplete inventories. If a VM has no associated NSG, report that as a separate unprotected-path signal and UNKNOWN for this NSG-rule control unless the source explicitly includes absence.', 'provider': 'azure', 'remediation_hint': 'On VM NIC and subnet NSGs, remove or narrow inbound Allow rules from Any/Internet and verify effective security rules in Network Watcher.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'VM associated NSGs restrict internet ingress'}, 'azure.gap.compute_vm_system_updates_installed': {'category': 'hardening', 'data_source': 'Paged VM inventory and each VM GET 2023-09-01 with $expand=instanceView: properties.instanceView.patchStatus.availablePatchSummary.status,lastModifiedTime,criticalAndSecurityPatchCount. For PCI references, collect Azure Update Manager patch-installation compliance state and correlate the exact VM and operation.', 'description': 'Install missing security system updates. A finding is raised when a recent successful assessment has positive criticalAndSecurityPatchCount.', 'id': 'azure.gap.compute_vm_system_updates_installed', 'predicate': 'For the missing-security-updates references, PASS only on a fresh successful assessment with criticalAndSecurityPatchCount=0; FAIL on a fresh successful assessment with count>0. For PCI references, also require an exact VM post-installation COMPLIANT status; NON_COMPLIANT is FAIL. UNKNOWN if freshness threshold, status, count, PCI compliance record, VM join or inventory is missing; a zero available count alone cannot establish post-installation PCI compliance.', 'provider': 'azure', 'remediation_hint': 'Azure portal > Azure Update Manager > Machines: run a patch assessment, install Critical and Security updates, and reassess.', 'resource_kind': 'vm', 'severity': 'high', 'title': 'Install missing security system updates'}, 'azure.gap.compute_vm_tcp_udp_access_restricted_internet': {'category': 'network', 'data_source': 'Paged VM, NIC, subnet, public-IP, NSG, load-balancer and effective security rule reads; join by full ARM IDs. NSG association on NIC or subnet is the frozen requirement signal; policy prohibitedPorts is optional extra reachability analysis.', 'description': 'Checks inbound TCP/UDP exposure of public VM interfaces using attached NSG rules.', 'id': 'azure.gap.compute_vm_tcp_udp_access_restricted_internet', 'predicate': 'For each internet-facing VM NIC, PASS only if a valid NSG is attached to that NIC or its subnet, as required by the frozen rule. FAIL if complete NIC, public-IP and subnet evidence proves neither association. UNKNOWN if inventory or joins are incomplete. If policy additionally requires prohibited port analysis, evaluate effective rules and NAT separately; do not use that stricter test to change this source-rule result.', 'provider': 'azure', 'remediation_hint': 'Attach an NSG to the public VM NIC or its subnet and configure appropriate inbound restrictions; separately review NAT and effective rules for prohibited ports.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'Internet-facing VM interfaces and subnets have NSG protection'}, 'azure.gap.compute_vm_vulnerability_findings_resolved_for_sql_server': {'category': 'vulnerability', 'data_source': 'Paged Microsoft.SqlVirtualMachine/sqlVirtualMachines LIST with properties.virtualMachineResourceId; paged Microsoft.Security/assessments LIST 2020-01-01 with properties.resourceDetails.id and properties.status.code; policy stable SQL VM assessment names plus all applicable finding/subassessment identifiers; complete VM join and assessment freshness.', 'description': 'Uses Defender assessment status for SQL Server on Azure VMs.', 'id': 'azure.gap.compute_vm_vulnerability_findings_resolved_for_sql_server', 'predicate': 'For each SQL VM, FAIL if a current applicable SQL vulnerability finding or assessment joined by normalized properties.resourceDetails.id is Unhealthy. PASS only when the complete applicable finding set is resolved and current Healthy evidence covers the VM; UNKNOWN for NotApplicable, missing or stale findings, assessment-key ambiguity, SQL VM join or incomplete paging. One healthy umbrella assessment cannot prove all findings resolved.', 'provider': 'azure', 'remediation_hint': 'Defender for Cloud > Recommendations > SQL Server on machines: enable the assessment on the SQL VM and resolve every reported unhealthy finding.', 'resource_kind': 'vm', 'severity': 'medium', 'title': 'SQL Server VM vulnerability assessment is healthy'}, 'azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows': {'category': 'encryption', 'data_source': 'Paged Windows VM and Guest Configuration assignment LIST 2024-04-05; read assignment parameter containing required trusted-root certificate thumbprints, properties.latestReportId, then GET the corresponding assignment report with evaluated certificate-store resources and freshness. Policy requiredThumbprints and maximum report age.', 'description': 'Remove prohibited trusted-root certificates. A finding is raised when a current assignment reports a prohibited trusted-root certificate.', 'id': 'azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows', 'predicate': 'For each scoped Windows VM, FAIL when a current complete trusted-root report proves one or more policy-required certificates absent from LocalMachine\\Root. PASS only when the exact required thumbprint set is bound to the assignment and a current complete report proves every required certificate present. UNKNOWN when assignment, parameter binding, report, freshness, required set or pages are incomplete. Empty required set is UNKNOWN without an explicit policy decision.', 'provider': 'azure', 'remediation_hint': 'Install each policy-required trusted-root certificate in LocalMachine\\Root on the affected Windows VM, rerun the Guest Configuration assignment and verify its current report.', 'resource_kind': 'vm', 'severity': 'high', 'title': 'Ensure specified trusted-root certificates are present on Windows VMs'}}
    PROPOSED_SPEC_SHA256 = {'azure.gap.compute_vm_adaptive_application_controls_enabled': '1872760f3f139ac7dc07e71f35163badd905542faca6030271ba686af26dffad', 'azure.gap.compute_vm_adaptive_network_hardening_recommendation_applied': '6354fdd5eb6555cdf88abddbd89eade5f16208919aa3d84e62861d93fafab8e7', 'azure.gap.compute_vm_administrators_group_with_extra_accounts_windows': '9e9ff64872733346b39cecedfd14b0ecf17603c12d6344fb0a107c005e701039', 'azure.gap.compute_vm_administrators_group_with_no_specified_members_windows': 'c2142abd320e4871f5f3d5a87bf4becae9297174d4d11976035164b928f911bf', 'azure.gap.compute_vm_administrators_group_with_specified_members_windows': '7e0a8fade49b857e31582a84ea75951adabf8fd3c8b0cd68f09fbe4d80c59783', 'azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated': '0706f1f8e7c9877f9a79c0ea9fce38774bc8ca3a663be8bd49692c5af148f8d6', 'azure.gap.compute_vm_malware_agent_automatic_upgrade_enabled': '1827828f0938da1ef402f4021742a789ed27eca0a49e5ae629292ec234773437', 'azure.gap.compute_vm_meet_firewall_properties_windows': '3d02fa713fa458e171a7907628ccbe74e43cd24a5d84b76d1e23fa1a8da4d5b7', 'azure.gap.compute_vm_password_file_permissions_0644_linux': 'ce2ff19ec5f8125021978c554a903f15d0888fe631228dc97e96bb021e492929', 'azure.gap.compute_vm_rdp_service_disabled': '71586a89013dcd5493e762ccd3c5179957b0829dffe8edc78d48be8594dc8757', 'azure.gap.compute_vm_remote_access_restricted_all_ports': '6e10cf4c0485e2893cb3e90624438dd2c7554c322ae828ad8ade5cc1ec731831', 'azure.gap.compute_vm_system_updates_installed': 'b3a73217dc27723294918c2b17562f1950c81832ced40eb691c8350adebc030a', 'azure.gap.compute_vm_tcp_udp_access_restricted_internet': '7158155ba1be9916eabc41e24e5a484b29bcb4d89633c5b7b69447d9e74e0a92', 'azure.gap.compute_vm_vulnerability_findings_resolved_for_sql_server': '991d582b97b79361e6ada4dc290b9d5086143e5746b127fdcc1664f04d0aa696', 'azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows': '4b5ebbbdab959dc9d8b2dbae98866a5aa589f3cf8502e11765143d8f1ea21039'}
    PREFIX = 'azure.gap.compute_vm_'
    VM_ARM = re.compile('/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Compute/virtualMachines/[^/]+', re.I)
    KINDS = {'vm': 'Microsoft.Compute/virtualMachines', 'nic': 'Microsoft.Network/networkInterfaces', 'nsg': 'Microsoft.Network/networkSecurityGroups', 'public_ip': 'Microsoft.Network/publicIPAddresses', 'load_balancer': 'Microsoft.Network/loadBalancers', 'sql_vm': 'Microsoft.SqlVirtualMachine/sqlVirtualMachines'}

    def _scope(index):
        context = get(index, 'context', dict)
        scope = get(context, 'scope', str)
        if get(context, 'provider', str) != 'azure' or not re.fullmatch('/subscriptions/[^/]+', scope, re.I):
            raise Unavailable('Azure subscription scope authority unavailable')
        return scope.casefold()

    def _arm(value, scope, kind=None):
        if not isinstance(value, str) or not re.fullmatch('/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/(?:[^/]+/[^/]+)(?:/[^/]+/[^/]+)*', value, re.I):
            raise Unavailable('malformed ARM resource identity')
        if not value.casefold().startswith(scope + '/resourcegroups/'):
            raise Unavailable('foreign subscription resource identity')
        if kind in KINDS and (not re.fullmatch(re.escape(scope) + '/resourcegroups/[^/]+/providers/' + re.escape(KINDS[kind]) + '/[^/]+', value, re.I)):
            raise Unavailable('ARM resource type does not match snapshot kind')
        if kind == 'subnet' and (not re.fullmatch(re.escape(scope) + '/resourcegroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+', value, re.I)):
            raise Unavailable('malformed subnet identity')
        return value.casefold()

    def _inventory(index, kind):

        def compute():
            scope = _scope(index)
            envelopes = get(index, 'collections', dict).get(kind)
            if not isinstance(envelopes, list) or not envelopes:
                raise Unavailable('missing collection: ' + kind)
            for envelope in envelopes:
                escope = get(envelope, 'scope', str).casefold()
                if get(envelope, 'type', str) != kind or not (escope == scope or escope.startswith(scope + '/')):
                    raise Unavailable('foreign or malformed collection scope: ' + kind)
            rows = complete_items(index, kind)
            listed = []
            for envelope in envelopes:
                values = list_of_objects(get(envelope, 'items', list))
                if get(envelope, 'status', str) == 'empty' and values:
                    raise Unavailable('empty inventory conflicts with listed rows: ' + kind)
                listed.extend(values)
            if len(listed) != len(rows) or sorted((get(row, 'id', str).casefold() for row in listed)) != sorted((get(row, 'id', str).casefold() for row in rows)):
                raise Unavailable('native index differs from complete collection inventory: ' + kind)
            for wrapper in get(index, kind, list):
                wscope = get(wrapper, 'scope', str).casefold()
                if get(wrapper, 'type', str) != kind or not (wscope == scope or wscope.startswith(scope + '/')):
                    raise Unavailable('foreign or malformed resource wrapper: ' + kind)
            identities = set()
            for row in rows:
                rid = get(row, 'id', str)
                if kind in KINDS or kind == 'subnet':
                    rid = _arm(rid, scope, kind)
                elif not rid or not rid.casefold().startswith(scope + '/'):
                    raise Unavailable('foreign or missing fact identity: ' + kind)
                else:
                    rid = rid.casefold()
                if rid in identities:
                    raise Unavailable('duplicate resource identity: ' + kind)
                identities.add(rid)
            return rows
        return memoized(index, ('sw17_inventory', kind), compute)

    def _vm(item, index):
        scope = _scope(index)
        rid = _arm(get(item, 'id', str), scope, 'vm')
        rows = [row for row in _inventory(index, 'vm') if get(row, 'id', str).casefold() == rid]
        if len(rows) != 1 or rows[0] != item:
            raise Unavailable('VM differs from complete scoped VM inventory')
        return rid

    def _os(item):
        value = get(item, 'properties.storageProfile.osDisk.osType', str)
        if value not in ('Windows', 'Linux'):
            raise Unavailable('VM operating system unknown')
        return value

    def _map_value(mapping, key):
        guard(mapping)
        coverage = mapping.get('_coverage', {}).get(key)
        if coverage is not None and (not isinstance(coverage, dict) or coverage.get('status') not in ('collected', 'empty')):
            raise Unavailable('map value coverage incomplete')
        value = mapping.get(key)
        if not isinstance(value, dict):
            raise Unavailable('map value missing or malformed: ' + key)
        guard(value)
        return value

    def _policy(index, check_id):
        policy = get(index, 'context.metadata.compliance_policy', dict)
        if get(policy, 'status', str) != 'collected' or get(policy, 'scope', str).casefold() != _scope(index):
            raise Unavailable('policy unavailable or foreign scope')
        checks = get(policy, 'checks', dict)
        return _map_value(checks, check_id)

    def _time(value):
        if not isinstance(value, str):
            raise Unavailable('timestamp missing')
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if dt.tzinfo is None or dt.utcoffset() is None:
                raise ValueError('timezone missing')
            return dt
        except ValueError as exc:
            raise Unavailable('malformed timestamp') from exc

    def _fresh(at, index, policy):
        maximum = get(policy, 'maxReportAgeSeconds', int)
        if maximum <= 0:
            raise Unavailable('report age policy malformed')
        elapsed = (_time(get(index, 'context.created_at', str)) - _time(at)).total_seconds()
        if not 0 <= elapsed <= maximum:
            raise Unavailable('report stale or future dated')

    def _observed(row, index, policy):
        provenance = get(row, '_provenance', dict)
        if get(provenance, 'read_only', bool) is not True or not get(provenance, 'source_operation', str):
            raise Unavailable('read-only observation provenance unavailable')
        _fresh(get(provenance, 'observed_at', str), index, policy)

    def _strings(value, *, empty=False):
        if not isinstance(value, list) or (not value and (not empty)) or any((not isinstance(x, str) or not x.strip() for x in value)):
            raise Unavailable('required string set missing or malformed')
        normalized = [x.casefold() for x in value]
        if len(normalized) != len(set(normalized)):
            raise Unavailable('duplicate set member')
        return set(normalized)

    def _fact(index, kind, vm_id, policy, *, check_id=None):
        rows = _inventory(index, kind)
        matched = []
        for row in rows:
            bound = _arm(get(row, 'vm_id', str), _scope(index), 'vm')
            if bound == vm_id and (check_id is None or get(row, 'check_id', str) == check_id):
                matched.append(row)
        if len(matched) != 1:
            raise Unavailable('fact missing or ambiguous: ' + kind)
        _observed(matched[0], index, policy)
        return matched[0]

    def _applicable(index, vm_id, policy, check_id):
        fact = _fact(index, 'vm_compliance_applicability', vm_id, policy, check_id=check_id)
        if not get(fact, 'basis', str):
            raise Unavailable('applicability basis absent')
        return get(fact, 'applicable', bool)

    def _na(reason):
        return ('NOT_APPLICABLE', {'reason': reason})

    def _assignment(item, index, policy):
        coverage = get(item, '_coverage.guestConfigurationAssignments', dict)
        if get(coverage, 'status', str) not in ('collected', 'empty'):
            raise Unavailable('assignment inventory incomplete')
        rows = list_of_objects(get(item, 'guestConfigurationAssignments', list))
        if coverage['status'] == 'empty' and rows:
            raise Unavailable('empty assignment inventory conflicts with rows')
        expected_name = get(policy, 'assignmentName', str)
        baseline, version = (get(policy, 'configurationName', str), get(policy, 'configurationVersion', str))
        if not all((expected_name, baseline, version)):
            raise Unavailable('baseline identity missing')
        candidates, seen = ([], set())
        vm_id = get(item, 'id', str).casefold()
        for row in rows:
            name = get(row, 'name', str)
            rid = get(row, 'id', str).casefold()
            if rid != vm_id + '/providers/microsoft.guestconfiguration/guestconfigurationassignments/' + name.casefold() or rid in seen:
                raise Unavailable('assignment identity foreign, malformed or duplicate')
            seen.add(rid)
            if name == expected_name:
                config = get(row, 'properties.guestConfiguration', dict)
                if get(config, 'name', str) != baseline or get(config, 'version', str) != version:
                    raise Unavailable('assignment baseline/version differs from policy')
                candidates.append(row)
        if len(candidates) > 1:
            raise Unavailable('assignment ambiguous')
        if not candidates:
            _observed(coverage, index, policy)
            return None
        return candidates[0]

    def _parameter(assignment, name, expected):
        params = list_of_objects(get(assignment, 'properties.guestConfiguration.configurationParameter', list))
        found, seen = ([], set())
        for param in params:
            key = get(param, 'name', str)
            if not key or key in seen:
                raise Unavailable('assignment parameter ambiguous')
            seen.add(key)
            if key == name:
                import json
                try:
                    value = json.loads(get(param, 'value', str))
                except ValueError as exc:
                    raise Unavailable('assignment parameter is not a JSON string set') from exc
                found.append(_strings(value, empty=True))
        if len(found) != 1 or found[0] != expected:
            raise Unavailable('assignment parameter binding differs from policy')

    def _report(item, index, policy, assignment):
        latest = get(assignment, 'properties.latestReportId', str)
        aid = get(assignment, 'id', str)
        if not latest:
            raise Unavailable('latest report ID absent')
        expected_id = latest if latest.startswith('/') else aid + '/reports/' + latest
        if not expected_id.casefold().startswith(aid.casefold() + '/reports/') or '/' in expected_id[len(aid + '/reports/'):]:
            raise Unavailable('latest report identity malformed or foreign')
        rows = _inventory(index, 'guest_configuration_report')
        matching = [row for row in rows if get(row, 'id', str).casefold() == expected_id.casefold()]
        if len(matching) != 1:
            raise Unavailable('latest guest report absent or ambiguous')
        report = matching[0]
        _observed(report, index, policy)
        if get(report, 'properties.vm.id', str).casefold() != get(item, 'id', str).casefold() or get(report, 'properties.assignment.name', str) != get(assignment, 'name', str) or get(report, 'properties.assignment.configuration.name', str) != get(policy, 'configurationName', str) or (get(report, 'properties.assignment.configuration.version', str) != get(policy, 'configurationVersion', str)):
            raise Unavailable('report VM/assignment/baseline identity mismatch')
        _fresh(get(report, 'properties.endTime', str), index, policy)
        if get(report, 'properties.operationStatus', str) != 'Succeeded':
            raise Unavailable('guest report operation not successful')
        coverage = get(report, '_coverage.resources', dict)
        if get(coverage, 'status', str) != 'collected':
            raise Unavailable('guest report resources incomplete')
        resources = list_of_objects(get(report, 'properties.details.resources', list))
        if not resources:
            raise Unavailable('guest report lacks resource details')
        seen = set()
        for resource in resources:
            key = get(resource, 'resourceId', str)
            if not key or key in seen:
                raise Unavailable('guest report resource identity missing or ambiguous')
            seen.add(key)
        return (report, resources)

    def _status(row, path='complianceStatus'):
        value = get(row, path, str)
        if value not in ('Compliant', 'NonCompliant'):
            raise Unavailable('compliance status not measured')
        return value

    def _exact(left, right):
        """Type-preserving JSON value equality, including frozen snapshot containers."""
        if isinstance(left, dict) and isinstance(right, dict):
            return set(left) == set(right) and all((_exact(left[k], right[k]) for k in left))
        if isinstance(left, list) and isinstance(right, list):
            return len(left) == len(right) and all((_exact(a, b) for a, b in zip(left, right)))
        return type(left) is type(right) and left == right

    def _guest(check_id, item, index):
        _vm(item, index)
        suffix = check_id.removeprefix(PREFIX)
        required_os = 'Linux' if suffix == 'password_file_permissions_0644_linux' else 'Windows'
        if _os(item) != required_os:
            return _na('VM operating system outside this baseline')
        policy = _policy(index, check_id)
        member_field = {'administrators_group_with_extra_accounts_windows': 'approvedAdministrators', 'administrators_group_with_no_specified_members_windows': 'requiredAdministrators', 'administrators_group_with_specified_members_windows': 'prohibitedAdministrators', 'with_no_specified_certificates_in_trusted_root_windows': 'requiredThumbprints'}.get(suffix)
        expected = _strings(get(policy, member_field, list), empty=member_field == 'requiredThumbprints') if member_field else None
        if member_field == 'requiredThumbprints' and (not expected) and (get(policy, 'emptyRequiredSetApproved', bool) is not True):
            raise Unavailable('empty required certificate set lacks explicit policy approval')
        if member_field == 'requiredThumbprints' and any((not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', x) for x in expected)):
            raise Unavailable('certificate thumbprint malformed')
        settings = get(policy, 'requiredSettings', dict) if suffix == 'meet_firewall_properties_windows' else None
        if settings is not None:
            categories = {'firewallState', 'inboundConnections', 'outboundConnections', 'ruleManagement', 'notifications'}
            actual_categories = set()
            if not settings:
                raise Unavailable('firewall baseline empty')
            for key, setting in settings.items():
                if not key or not isinstance(setting, dict) or get(setting, 'category', str) not in categories:
                    raise Unavailable('firewall baseline malformed')
                if type(get(setting, 'expected')) not in (str, bool, int):
                    raise Unavailable('firewall expected value is not a typed scalar')
                actual_categories.add(setting['category'])
            if actual_categories != categories:
                raise Unavailable('firewall baseline omits frozen setting categories')
        assignment = _assignment(item, index, policy)
        if assignment is None:
            if suffix in ('administrators_group_with_extra_accounts_windows', 'password_file_permissions_0644_linux'):
                return result(True, reason='complete current inventory proves required assignment absent')
            return unknown('required guest assignment absent')
        if member_field:
            _parameter(assignment, member_field, expected)
        if suffix == 'meet_firewall_properties_windows':
            import json
            params = list_of_objects(get(assignment, 'properties.guestConfiguration.configurationParameter', list))
            bound = [get(p, 'value', str) for p in params if get(p, 'name', str) == 'requiredSettings']
            if len(bound) != 1 or not _exact(json.loads(bound[0]), settings):
                raise Unavailable('firewall settings not bound to exact assignment')
        if suffix == 'password_file_permissions_0644_linux':
            _parameter(assignment, 'filePaths', {'/etc/passwd'})
            _parameter(assignment, 'requiredModes', {'0644'})
        report, resources = _report(item, index, policy, assignment)
        bad, uncertain, measured = ([], [], set())
        for row in resources:
            try:
                props = get(row, 'properties', dict)
                if member_field and member_field != 'requiredThumbprints':
                    if get(props, 'group', str) != 'Administrators':
                        continue
                    if get(props, 'membershipComplete', bool) is not True:
                        raise Unavailable('membership observation incomplete')
                    observed = _strings(get(props, 'observedMembers', list), empty=True)
                    compliance = _status(row)
                    measured.add('Administrators')
                    violations = observed - expected if member_field == 'approvedAdministrators' else expected - observed if member_field == 'requiredAdministrators' else observed & expected
                    if violations or (member_field == 'approvedAdministrators' and compliance == 'NonCompliant'):
                        bad.append(row['resourceId'])
                    elif compliance != 'Compliant':
                        uncertain.append(row['resourceId'])
                elif member_field == 'requiredThumbprints':
                    if get(props, 'store', str) != 'LocalMachine\\Root':
                        continue
                    if get(props, 'certificateSetComplete', bool) is not True:
                        raise Unavailable('certificate store observation incomplete')
                    observed = _strings(get(props, 'observedThumbprints', list), empty=True)
                    if any((not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', x) for x in observed)):
                        raise Unavailable('observed certificate thumbprint malformed')
                    measured.add('LocalMachine\\Root')
                    compliance = _status(row)
                    if expected - observed:
                        bad.append(row['resourceId'])
                    elif compliance != 'Compliant':
                        uncertain.append(row['resourceId'])
                elif settings is not None:
                    key = get(props, 'settingName', str)
                    if key not in settings:
                        continue
                    if key in measured:
                        raise Unavailable('duplicate firewall setting observation')
                    measured.add(key)
                    if not _exact(get(props, 'expected'), get(settings[key], 'expected')):
                        raise Unavailable('firewall setting expected value differs from policy')
                    if _status(row) == 'NonCompliant':
                        bad.append(row['resourceId'])
                    elif not _exact(get(props, 'observed'), settings[key]['expected']):
                        uncertain.append(row['resourceId'])
                elif suffix == 'password_file_permissions_0644_linux':
                    if get(props, 'path', str) != '/etc/passwd':
                        continue
                    mode = get(props, 'mode', str)
                    if not re.fullmatch('0[0-7]{3}', mode):
                        raise Unavailable('file mode malformed')
                    measured.add('/etc/passwd')
                    if mode != '0644':
                        bad.append(row['resourceId'])
                    elif _status(row) != 'Compliant':
                        uncertain.append(row['resourceId'])
            except Unavailable:
                uncertain.append(row['resourceId'])
        if bad:
            return result(True, violating_resources=bad)
        required = set(settings) if settings is not None else {'LocalMachine\\Root'} if member_field == 'requiredThumbprints' else {'Administrators'} if member_field else {'/etc/passwd'}
        if uncertain or measured != required:
            return unknown('required guest resource details missing or unmeasured', uncertain_resources=uncertain)
        if member_field == 'prohibitedAdministrators' and _status(assignment, 'properties.complianceStatus') != 'Compliant':
            return unknown('assigned prohibited-members baseline is not Compliant')
        if suffix == 'administrators_group_with_extra_accounts_windows' and _status(report, 'properties.details.complianceStatus') != 'Compliant':
            return unknown('approved-members report summary contradicts resource results')
        return result(False, evaluated_resources=sorted(measured))

    def _assessments(index, vm_id, keys, policy):
        matches = {key: [] for key in keys}
        for row in _inventory(index, 'security_assessment'):
            key = get(row, 'name', str).casefold()
            bound = _arm(get(row, 'properties.resourceDetails.id', str), _scope(index))
            if bound == vm_id and key in keys:
                matches[key].append(row)
        bad, uncertain = ([], [])
        for key, rows in matches.items():
            if len(rows) != 1:
                uncertain.append(key)
                continue
            try:
                _observed(rows[0], index, policy)
                status = get(rows[0], 'properties.status.code', str)
                if status == 'Unhealthy':
                    bad.append(key)
                elif status != 'Healthy':
                    uncertain.append(key)
            except Unavailable:
                uncertain.append(key)
        return (bad, uncertain)

    def _defender(check_id, item, index):
        vm_id = _vm(item, index)
        policy = _policy(index, check_id)
        suffix = check_id.removeprefix(PREFIX)
        if suffix == 'vulnerability_findings_resolved_for_sql_server':
            sqls = _inventory(index, 'sql_vm')
            joined = []
            for row in sqls:
                target = _arm(get(row, 'properties.virtualMachineResourceId', str), _scope(index), 'vm')
                if target == vm_id:
                    joined.append(row)
            if len(joined) > 1:
                raise Unavailable('ambiguous SQL VM join')
            if not joined:
                return _na('complete SQL VM inventory proves VM is not a SQL VM')
        elif not _applicable(index, vm_id, policy, check_id):
            return _na('current independent applicability evidence excludes VM')
        keys = _strings(get(policy, 'assessmentKeys', list))
        bad, uncertain = _assessments(index, vm_id, keys, policy)
        if bad:
            return result(True, unhealthy_assessment_keys=bad)
        if suffix == 'container_security_configurations_vulnerabilities_remediated':
            return unknown('required Docker host assessments absent or not Healthy', uncertain_assessment_keys=uncertain) if uncertain else result(False, healthy_assessment_keys=sorted(keys))
        if suffix == 'adaptive_application_controls_enabled':
            groups = _inventory(index, 'application_whitelisting')
            active, alerts, group_uncertain = (False, False, False)
            for group in groups:
                try:
                    _observed(group, index, policy)
                    members = _strings(get(group, 'properties.vmIds', list), empty=True)
                    for member in members:
                        _arm(member, _scope(index), 'vm')
                    if vm_id not in members:
                        continue
                    applicable = get(group, 'properties.policyApplicable', bool)
                    enabled = get(group, 'properties.policyActive', bool)
                    mode = get(group, 'properties.enforcementMode', str)
                    rules = list_of_objects(get(group, 'properties.pathRecommendations', list))
                    if mode not in ('Audit', 'Enforce', 'None'):
                        raise Unavailable('allowlist mode unresolved')
                    if applicable and enabled and (mode in ('Audit', 'Enforce')):
                        if not rules:
                            raise Unavailable('active allowlist has no measured policy rules')
                        for rule in rules:
                            if not get(rule, 'ruleId', str):
                                raise Unavailable('allowlist rule identity missing')
                        active = True
                        observation = get(group, 'properties.unknownApplicationAlerts', dict)
                        _observed(observation, index, policy)
                        alerts |= get(observation, 'enabled', bool) and get(observation, 'behaviorVerified', bool)
                except Unavailable:
                    group_uncertain = True
            if not active:
                if group_uncertain:
                    return unknown('allowlist group policy/applicability not fully resolved')
                return result(True, reason='complete current group inventory proves no active applicable policy')
            if group_uncertain or uncertain or (not alerts):
                return unknown('Healthy assessment, complete group policy, and measured unknown-application alert behavior required')
            return result(False, healthy_assessment_keys=sorted(keys), unknown_application_alerts_verified=True)
        if suffix == 'adaptive_network_hardening_recommendation_applied':
            evidence = _fact(index, 'adaptive_network_hardening', vm_id, policy)
            if not get(evidence, 'internetFacing', bool):
                return unknown('applicability conflicts with network evidence')
            rules = list_of_objects(get(evidence, 'requiredRules', list))
            if get(evidence, 'rulesComplete', bool) is not True:
                return unknown('required recommendation set incomplete')
            nsgs = {get(row, 'id', str).casefold(): row for row in _inventory(index, 'nsg')}
            seen, unapplied, unresolved = (set(), [], [])
            associated = {get(nsg, 'id', str).casefold() for _, _, path in _network_paths(item, index) for nsg in path}
            for rule in rules:
                try:
                    rule_id = get(rule, 'recommendationId', str)
                    if not rule_id or rule_id in seen:
                        raise Unavailable('duplicate recommendation identity')
                    seen.add(rule_id)
                    nsg_id = _arm(get(rule, 'nsgId', str), _scope(index), 'nsg')
                    if nsg_id not in nsgs or nsg_id not in associated:
                        raise Unavailable('recommended NSG is not joined to VM')
                    if not get(rule, 'approved', bool):
                        raise Unavailable('required recommendation approval unresolved')
                    applied = get(rule, 'applied', bool)
                    effective = get(rule, 'effective', bool)
                    if not applied or not effective:
                        unapplied.append(rule_id)
                    elif get(rule, 'effectiveRuleEvidence.vm_id', str).casefold() != vm_id or get(rule, 'effectiveRuleEvidence.nsg_id', str).casefold() != nsg_id:
                        raise Unavailable('effective rule evidence is not VM/NSG bound')
                    else:
                        proof = get(rule, 'effectiveRuleEvidence', dict)
                        _observed(proof, index, policy)
                        if get(proof, 'recommendationId', str) != rule_id or get(proof, 'matchesRecommendation', bool) is not True:
                            raise Unavailable('effective rule does not match recommendation')
                except Unavailable:
                    unresolved.append(rule.get('recommendationId'))
            if unapplied:
                return result(True, unapplied_required_recommendations=unapplied)
            if uncertain or unresolved:
                return unknown('recommendation/assessment/effective-rule evidence incomplete')
            return result(False, applied_recommendations=sorted(seen))
        if suffix == 'vulnerability_findings_resolved_for_sql_server':
            required = _strings(get(policy, 'requiredFindingIds', list), empty=True)
            if get(policy, 'findingSetComplete', bool) is not True:
                raise Unavailable('applicable SQL finding identifiers not complete')
            rows = _inventory(index, 'security_subassessment')
            found, unresolved, unhealthy = (set(), [], [])
            for row in rows:
                bound = _arm(get(row, 'properties.resourceDetails.id', str), _scope(index))
                if bound != vm_id:
                    continue
                try:
                    key = get(row, 'assessment_key', str).casefold()
                    finding = get(row, 'name', str).casefold()
                    if key not in keys or finding in found:
                        raise Unavailable('SQL finding assessment key ambiguous')
                    found.add(finding)
                    _observed(row, index, policy)
                    status = get(row, 'properties.status.code', str)
                    if status == 'Unhealthy':
                        unhealthy.append(finding)
                    elif status != 'Healthy':
                        unresolved.append(finding)
                except Unavailable:
                    unresolved.append(row.get('name'))
            if unhealthy:
                return result(True, unhealthy_finding_ids=unhealthy)
            if uncertain or unresolved or found != required:
                return unknown('complete current Healthy SQL assessment and finding coverage unavailable')
            return result(False, healthy_assessment_keys=sorted(keys), healthy_finding_ids=sorted(found))
        raise Unavailable('unsupported Defender predicate')

    def _malware(check_id, item, index):
        vm_id = _vm(item, index)
        if _os(item) != 'Windows':
            return _na('VM is not Windows')
        policy = _policy(index, check_id)
        evidence = _fact(index, 'vm_antimalware_policy', vm_id, policy)
        agent = get(evidence, 'agent', str)
        if agent not in ('MicrosoftDefender', 'MicrosoftAntimalware', 'ThirdParty'):
            raise Unavailable('protection agent applicability ambiguous')
        if get(evidence, 'effectivePolicyComplete', bool) is not True:
            raise Unavailable('effective signature-update guest policy incomplete')
        if agent == 'ThirdParty':
            if get(evidence, 'vendorEvidenceVerified', bool) is not True or not get(evidence, 'vendor', str):
                return unknown('third-party agent vendor evidence unavailable')
        present, operational = (get(evidence, 'agentPresent', bool), get(evidence, 'serviceOperational', bool))
        automatic = get(evidence, 'automaticSignatureUpdatesEnabled', bool)
        return result(not present or not operational or (not automatic), agent=agent, agent_present=present, service_operational=operational, automatic_signature_updates_enabled=automatic)

    def _rdp(check_id, item, index):
        vm_id = _vm(item, index)
        if _os(item) != 'Windows':
            return _na('VM is not Windows')
        policy = _policy(index, check_id)
        assignment = _assignment(item, index, policy)
        if assignment is None:
            return unknown('RDP service guest assignment absent')
        _, resources = _report(item, index, policy, assignment)
        states = []
        for row in resources:
            props = get(row, 'properties', dict)
            if get(props, 'serviceName', str) == 'TermService':
                states.append(get(props, 'state', str))
        if len(states) != 1 or states[0] not in ('Disabled', 'Enabled'):
            return unknown('TermService state missing, ambiguous or unrecognized')
        if states[0] == 'Disabled':
            return result(False, term_service='Disabled')
        exceptions = _inventory(index, 'vm_rdp_exception')
        for envelope in get(index, 'collections', dict)['vm_rdp_exception']:
            _observed(envelope, index, policy)
        approvals = []
        for row in exceptions:
            if _arm(get(row, 'vm_id', str), _scope(index), 'vm') == vm_id:
                approvals.append(row)
        if len(approvals) > 1:
            return unknown('RDP exception register ambiguous')
        if not approvals:
            return result(True, reason='enabled TermService has no approval in complete exception register')
        approval = approvals[0]
        _observed(approval, index, policy)
        if not get(approval, 'approved', bool):
            return result(True, reason='enabled TermService exception explicitly unapproved')
        if not get(approval, 'officer', str):
            raise Unavailable('approving officer evidence absent')
        now = _time(get(index, 'context.created_at', str))
        start, end = (_time(get(approval, 'valid_from', str)), _time(get(approval, 'valid_until', str)))
        if not start <= now < end:
            return unknown('RDP exception is not current')
        logs = _fact(index, 'vm_remote_access_monitoring', vm_id, policy)
        enabled = get(logs, 'routingEnabled', bool)
        monitored = get(logs, 'monitoredAlerts', bool)
        if not enabled or not monitored:
            return result(True, reason='approved enabled RDP lacks required logging or monitored alerts')
        if not {'rdp-sign-in', 'rdp-session'} <= _strings(get(logs, 'eventCategories', list)):
            return unknown('required RDP log categories not completely evidenced')
        return result(False, term_service='Enabled', approval_officer=approval['officer'], monitored_remote_access_logs=True)

    def _updates(check_id, item, index):
        vm_id = _vm(item, index)
        policy = _policy(index, check_id)
        summary = get(item, 'properties.instanceView.patchStatus.availablePatchSummary', dict)
        if get(summary, 'status', str) != 'Succeeded':
            return unknown('patch assessment did not succeed')
        _fresh(get(summary, 'lastModifiedTime', str), index, policy)
        count = get(summary, 'criticalAndSecurityPatchCount', int)
        if count < 0:
            raise Unavailable('negative patch count')
        if count > 0:
            return result(True, critical_and_security_patch_count=count)
        pci = get(policy, 'requirePciCompliance', bool)
        if pci:
            record = _fact(index, 'vm_patch_installation_compliance', vm_id, policy)
            if not get(record, 'operationId', str):
                raise Unavailable('patch installation operation identity absent')
            _fresh(get(record, 'installedAt', str), index, policy)
            status = get(record, 'status', str)
            if status not in ('COMPLIANT', 'NON_COMPLIANT'):
                return unknown('post-installation PCI compliance not measured')
            return result(status == 'NON_COMPLIANT', critical_and_security_patch_count=count, post_installation_status=status, operation_id=record['operationId'])
        return result(False, critical_and_security_patch_count=count, require_pci_compliance=False)

    def _nullable(properties, key, owner=None):
        if key in properties or key in properties.get('_coverage', {}):
            value = get(properties, key)
        elif (isinstance(owner, dict) and isinstance(owner.get('_provenance'), dict)
              and str(owner.get('type', '')).casefold() in ('microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/loadbalancers')
              and owner['_provenance'].get('representation') == 'full'
              and owner['_provenance'].get('source_operation') == 'get'
              and owner['_provenance'].get('read_only') is True
              and owner['_provenance'].get('api_version') == '2023-09-01'):
            value = None
        else:
            raise Unavailable('association absence not measured: ' + key)
        if value is not None and (not isinstance(value, dict)):
            raise Unavailable('malformed association: ' + key)
        return value

    def _join(rows, rid, index, kind):
        target = _arm(rid, _scope(index), kind)
        matches = [row for row in rows if get(row, 'id', str).casefold() == target]
        if len(matches) != 1:
            raise Unavailable('unresolved or ambiguous ARM join: ' + kind)
        return matches[0]

    def _network_paths(item, index):
        vm_id = get(item, 'id', str).casefold()
        refs = list_of_objects(get(item, 'properties.networkProfile.networkInterfaces', list))
        if not refs:
            raise Unavailable('VM NIC associations absent')
        nics, subnets, nsgs = (_inventory(index, 'nic'), _inventory(index, 'subnet'), _inventory(index, 'nsg'))
        paths, seen = ([], set())
        for ref in refs:
            nic = _join(nics, get(ref, 'id', str), index, 'nic')
            nic_id = get(nic, 'id', str).casefold()
            if nic_id in seen or get(nic, 'properties.virtualMachine.id', str).casefold() != vm_id:
                raise Unavailable('duplicate NIC or NIC/VM reverse join mismatch')
            seen.add(nic_id)
            configurations = list_of_objects(get(nic, 'properties.ipConfigurations', list))
            if not configurations:
                raise Unavailable('NIC IP configurations unavailable')
            config_seen = set()
            for config in configurations:
                cid = get(config, 'id', str).casefold()
                if not cid.startswith(nic_id + '/ipconfigurations/') or not cid[len(nic_id + '/ipconfigurations/'):] or '/' in cid[len(nic_id + '/ipconfigurations/'):] or (cid in config_seen):
                    raise Unavailable('IP configuration identity malformed or duplicate')
                config_seen.add(cid)
                subnet = _join(subnets, get(config, 'properties.subnet.id', str), index, 'subnet')
                associated = []
                for parent in (nic, subnet):
                    link = _nullable(get(parent, 'properties', dict), 'networkSecurityGroup', parent)
                    if link is not None:
                        associated.append(_join(nsgs, get(link, 'id', str), index, 'nsg'))
                paths.append((nic, config, associated))
        return paths

    def _public_nics(paths, index):
        pips = _inventory(index, 'public_ip')
        lbs = _inventory(index, 'load_balancer')
        facing = set()
        config_map = {get(config, 'id', str).casefold(): get(nic, 'id', str).casefold() for nic, config, _ in paths}

        def public(ref):
            if ref is None:
                return False
            pip = _join(pips, get(ref, 'id', str), index, 'public_ip')
            address = get(pip, 'properties.ipAddress', str)
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise Unavailable('public IP allocation unavailable') from exc
            if not ip.is_global:
                raise Unavailable('public-IP allocation is not an Internet address')
            return True
        for nic, config, _ in paths:
            if public(_nullable(get(config, 'properties', dict), 'publicIPAddress', nic)):
                facing.add(get(config, 'id', str).casefold())
        for lb in lbs:
            props = get(lb, 'properties', dict)
            frontends = list_of_objects(get(props, 'frontendIPConfigurations', list))
            public_frontends = set()
            for front in frontends:
                if public(_nullable(get(front, 'properties', dict), 'publicIPAddress', lb)):
                    public_frontends.add(get(front, 'id', str).casefold())
            if not public_frontends:
                continue
            pools = list_of_objects(get(props, 'backendAddressPools', list))
            pool_map = {}
            for pool in pools:
                pool_id = get(pool, 'id', str).casefold()
                if pool_id in pool_map:
                    raise Unavailable('duplicate LB backend pool')
                pprops = get(pool, 'properties', dict)
                addresses = list_of_objects(get(pprops, 'loadBalancerBackendAddresses', list))
                members = [get(ref, 'id', str).casefold() for ref in list_of_objects(get(pprops, 'backendIPConfigurations', list))]
                for address in addresses:
                    ap = get(address, 'properties', dict)
                    vnet = _arm(get(ap, 'virtualNetwork.id', str), _scope(index))
                    if not re.fullmatch(re.escape(_scope(index)) + '/resourcegroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+', vnet, re.I):
                        raise Unavailable('IP-based LB backend VNet identity malformed')
                    try:
                        ip = ipaddress.ip_address(get(ap, 'ipAddress', str))
                    except ValueError as exc:
                        raise Unavailable('IP-based LB backend address malformed') from exc
                    joined = [get(config, 'id', str).casefold() for _, config, _ in paths if get(config, 'properties.subnet.id', str).casefold().rsplit('/subnets/', 1)[0] == vnet and ipaddress.ip_address(get(config, 'properties.privateIPAddress', str)) == ip]
                    if len(joined) > 1:
                        raise Unavailable('IP-based LB backend VM join ambiguous')
                    members.extend(joined)
                pool_map[pool_id] = members
            rules = list_of_objects(get(props, 'loadBalancingRules', list))
            for rule in rules:
                rp = get(rule, 'properties', dict)
                front_id = get(rp, 'frontendIPConfiguration.id', str).casefold()
                if front_id not in {get(front, 'id', str).casefold() for front in frontends}:
                    raise Unavailable('LB frontend unresolved')
                if front_id not in public_frontends:
                    continue
                pool_id = get(rp, 'backendAddressPool.id', str).casefold()
                if pool_id not in pool_map:
                    raise Unavailable('LB backend pool unresolved')
                for cid in pool_map[pool_id]:
                    if cid in config_map:
                        facing.add(cid)
            for rule in list_of_objects(get(props, 'inboundNatRules', list)):
                rp = get(rule, 'properties', dict)
                if get(rp, 'frontendIPConfiguration.id', str).casefold() not in public_frontends:
                    continue
                backend = _nullable(rp, 'backendIPConfiguration', lb)
                if backend is None:
                    raise Unavailable('LB NAT backend association unavailable')
                cid = get(backend, 'id', str).casefold()
                if cid in config_map:
                    facing.add(cid)
            if get(props, 'inboundNatPools', list):
                raise Unavailable('LB NAT pool VM join unavailable')
        return facing

    def _nsg_attached(check_id, item, index):
        _vm(item, index)
        paths = _network_paths(item, index)
        facing = _public_nics(paths, index)
        if not facing:
            return _na('complete direct-public-IP and load-balancer inventory proves no Internet-facing NIC')
        unprotected = []
        for nic, config, associated in paths:
            if get(config, 'id', str).casefold() in facing and (not associated):
                unprotected.append(get(config, 'id', str))
        return result(bool(unprotected), internet_facing_ip_configurations=sorted(facing), unprotected_ip_configurations=unprotected)

    def _ranges(properties, singular, plural, *, ports=False, tags=None, version=None):
        values = []
        if singular in properties or singular in properties.get('_coverage', {}):
            value = get(properties, singular, str)
            if value:
                values.append(value)
        if plural in properties or plural in properties.get('_coverage', {}):
            array = get(properties, plural, list)
            if any((not isinstance(v, str) or not v for v in array)):
                raise Unavailable('malformed rule ranges')
            if values and array:
                raise Unavailable('ambiguous singular/plural rule range')
            values.extend(array)
        if not values:
            raise Unavailable('rule range unavailable')
        intervals = []
        for value in values:
            if ports:
                if value == '*':
                    intervals.append((0, 65535))
                    continue
                match = re.fullmatch('(\\d{1,5})(?:-(\\d{1,5}))?', value)
                if not match:
                    raise Unavailable('malformed rule port range')
                lo, hi = (int(match[1]), int(match[2] or match[1]))
                if not 0 <= lo <= hi <= 65535:
                    raise Unavailable('rule port out of range')
                intervals.append((lo, hi))
            else:
                if value in ('*', 'Any'):
                    intervals.append((0, 2 ** (32 if version == 4 else 128) - 1))
                    continue
                try:
                    network = ipaddress.ip_network(value, strict=False)
                    if network.version == version:
                        intervals.append((int(network.network_address), int(network.broadcast_address)))
                except ValueError:
                    if tags is None or value not in tags:
                        raise Unavailable('unresolved NSG service tag or ASG: ' + value)
                    tag = _map_value(tags, value)
                    if get(tag, 'status', str) != 'collected':
                        raise Unavailable('service tag range inventory incomplete')
                    prefixes = get(tag, 'prefixes', list)
                    if not prefixes:
                        raise Unavailable('resolved service tag ranges absent')
                    for prefix in prefixes:
                        try:
                            network = ipaddress.ip_network(prefix, strict=False)
                        except (ValueError, TypeError) as exc:
                            raise Unavailable('service tag prefix malformed') from exc
                        if network.version == version:
                            intervals.append((int(network.network_address), int(network.broadcast_address)))
        return (intervals, any((value in ('*', 'Any', 'Internet') or value == ('0.0.0.0/0' if version == 4 else '::/0') for value in values)))

    def _subtract(box, blocker):
        overlap = tuple(((max(a[0], b[0]), min(a[1], b[1])) for a, b in zip(box, blocker)))
        if any((lo > hi for lo, hi in overlap)):
            return [box]
        residual, core = ([], list(box))
        for dimension, (lo, hi) in enumerate(overlap):
            if core[dimension][0] < lo:
                part = list(core)
                part[dimension] = (core[dimension][0], lo - 1)
                residual.append(tuple(part))
            if hi < core[dimension][1]:
                part = list(core)
                part[dimension] = (hi + 1, core[dimension][1])
                residual.append(tuple(part))
            core[dimension] = (lo, hi)
        return residual

    def _permissive_nsg(nsg, destination):
        proof = get(nsg, '_provenance', dict)
        if (proof.get('representation') != 'full' or proof.get('source_operation') != 'get'
                or proof.get('read_only') is not True or proof.get('api_version') != '2023-09-01'):
            raise Unavailable('complete native NSG rule representation unavailable')
        props = get(nsg, 'properties', dict)
        rules = list_of_objects(get(props, 'securityRules', list)) + list_of_objects(get(props, 'defaultSecurityRules', list))
        if not rules:
            raise Unavailable('NSG rule inventory absent')
        tags = get(props, 'resolvedServiceTags', dict) if 'resolvedServiceTags' in props else {}
        ordered, priorities = [], set()
        for row in rules:
            rp = get(row, 'properties', dict)
            direction = get(rp, 'direction', str)
            if direction not in ('Inbound', 'Outbound'):
                raise Unavailable('NSG direction unrecognized')
            if direction == 'Outbound':
                continue
            priority = get(rp, 'priority', int)
            if priority in priorities or not 100 <= priority <= 65535:
                raise Unavailable('NSG priority missing, duplicate or malformed')
            priorities.add(priority)
            access = get(rp, 'access', str)
            protocol = get(rp, 'protocol', str).casefold()
            if access not in ('Allow', 'Deny') or protocol not in ('*', 'tcp', 'udp', 'icmp', 'ah', 'esp'):
                raise Unavailable('NSG access or protocol unrecognized')
            kind = get(row, 'type', str).casefold()
            rid = get(row, 'id', str)
            if (kind not in ('microsoft.network/networksecuritygroups/securityrules', 'microsoft.network/networksecuritygroups/defaultsecurityrules')
                    or re.fullmatch(re.escape(get(nsg, 'id', str)) + r'/(?:securityRules|defaultSecurityRules)/[^/?#%\\\s]+', rid, re.I) is None
                    or any(part in ('.', '..') for part in rid.split('/'))
                    or kind.rsplit('/', 1)[-1] != rid.rsplit('/', 2)[-2].casefold()):
                raise Unavailable('NSG native rule identity/type contradictory')
            ordered.append((priority, access, protocol, rp))
        if not priorities:
            raise Unavailable('NSG inbound rule inventory absent')
        previous = []
        for priority, access, protocol, rp in sorted(ordered, key=lambda row: row[0]):
            for key in ('sourceApplicationSecurityGroups', 'destinationApplicationSecurityGroups'):
                if key in rp and get(rp, key, list):
                    raise Unavailable('NSG ASG membership unresolved')
            sources, public = _ranges(rp, 'sourceAddressPrefix', 'sourceAddressPrefixes', tags=tags, version=destination.version)
            destinations, _ = _ranges(rp, 'destinationAddressPrefix', 'destinationAddressPrefixes', tags=tags, version=destination.version)
            source_ports, _ = _ranges(rp, 'sourcePortRange', 'sourcePortRanges', ports=True)
            dest_ports, _ = _ranges(rp, 'destinationPortRange', 'destinationPortRanges', ports=True)
            if not any(lo <= int(destination) <= hi for lo, hi in destinations):
                continue
            protocols = range(5) if protocol == '*' else [('tcp', 'udp', 'icmp', 'ah', 'esp').index(protocol)]
            boxes = [tuple(parts) for parts in itertools.product(sources, source_ports, dest_ports, [(p, p) for p in protocols])]
            if access == 'Allow' and public:
                residual = list(boxes)
                for blocker in previous:
                    residual = [part for box in residual for part in _subtract(box, blocker)]
                    if len(residual) > 20000:
                        raise Unavailable('NSG effective-rule partition too complex')
                    if not residual:
                        break
                if residual:
                    # Later unknown selectors cannot override this priority decision.
                    return priority
            if (access == 'Deny' and protocol == '*'
                    and all(rp.get(key) == '*' for key in ('sourceAddressPrefix', 'destinationAddressPrefix', 'sourcePortRange', 'destinationPortRange'))):
                # Native wildcard declarations cover both IP families, all destinations,
                # ports and protocols; any earlier uncertainty has already stopped us.
                return None
            previous.extend(boxes)
        raise Unavailable('no decisive public allow or complete all-family wildcard deny')

    def _public_rules(check_id, item, index):
        _vm(item, index)
        paths = _network_paths(item, index)
        bad, unresolved, unprotected = ([], [], [])
        for nic, config, associated in paths:
            if not associated:
                unprotected.append(get(config, 'id', str))
            try:
                destination = ipaddress.ip_address(get(config, 'properties.privateIPAddress', str))
            except ValueError as exc:
                raise Unavailable('NIC private IP missing or malformed') from exc
            for nsg in associated:
                try:
                    priority = _permissive_nsg(nsg, destination)
                    if priority is not None:
                        bad.append({'nsg_id': get(nsg, 'id', str), 'priority': priority, 'ip_configuration': config['id']})
                except Unavailable:
                    unresolved.append(get(nsg, 'id', str))
        if bad:
            return result(True, permissive_associated_nsgs=bad)
        if unresolved or unprotected:
            return unknown('NSG rules unresolved or path has no NSG', unresolved_nsgs=sorted(set(unresolved)), unprotected_paths=unprotected)
        return result(False, evaluated_ip_configurations=len(paths))
    GUEST_SUFFIXES = {'administrators_group_with_extra_accounts_windows', 'administrators_group_with_no_specified_members_windows', 'administrators_group_with_specified_members_windows', 'meet_firewall_properties_windows', 'password_file_permissions_0644_linux', 'with_no_specified_certificates_in_trusted_root_windows'}
    DEFENDER_SUFFIXES = {'adaptive_application_controls_enabled', 'adaptive_network_hardening_recommendation_applied', 'container_security_configurations_vulnerabilities_remediated', 'vulnerability_findings_resolved_for_sql_server'}
    EVALUATORS = {}
    REGISTERED_CHECKS = {}
    DEPENDENCIES = {}
    for _identifier, _spec in SPECS.items():
        _suffix = _identifier.removeprefix(PREFIX)
        if _suffix in GUEST_SUFFIXES:
            _function, _deps = (_guest, ['vm', 'guest_configuration_report'])
        elif _suffix in DEFENDER_SUFFIXES:
            _function, _deps = (_defender, ['vm', 'security_assessment'])
            if _suffix == 'vulnerability_findings_resolved_for_sql_server':
                _deps += ['sql_vm', 'security_subassessment']
            else:
                _deps += ['vm_compliance_applicability']
                if _suffix == 'adaptive_application_controls_enabled':
                    _deps += ['application_whitelisting']
                elif _suffix == 'adaptive_network_hardening_recommendation_applied':
                    _deps += ['adaptive_network_hardening', 'nic', 'subnet', 'nsg']
        elif _suffix == 'malware_agent_automatic_upgrade_enabled':
            _function, _deps = (_malware, ['vm', 'vm_antimalware_policy'])
        elif _suffix == 'rdp_service_disabled':
            _function, _deps = (_rdp, ['vm', 'guest_configuration_report', 'vm_rdp_exception', 'vm_remote_access_monitoring'])
        elif _suffix == 'system_updates_installed':
            _function, _deps = (_updates, ['vm', 'vm_patch_installation_compliance'])
        elif _suffix == 'tcp_udp_access_restricted_internet':
            _function, _deps = (_nsg_attached, ['vm', 'nic', 'subnet', 'nsg', 'public_ip', 'load_balancer'])
        else:
            _function, _deps = (_public_rules, ['vm', 'nic', 'subnet', 'nsg'])
        DEPENDENCIES[_identifier] = tuple(_deps)
        _category = _spec['category'] if _spec['category'] in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'} else 'hardening'

        @register(_identifier, _spec['provider'], _category, _spec['resource_kind'], _spec['title'], _spec['severity'], 'CM-6', _spec['remediation_hint'], dependencies=_deps)
        def _evaluate(item, index, check_id=_identifier, evaluator=_function):
            return evaluator(check_id, item, index)
        _check = CHECKS[-1]
        if _check.id != _identifier:
            raise RuntimeError('unexpected registration order')
        if _category != _spec['category']:
            _check = replace(_check, category=_spec['category'])
            CHECKS[-1] = _check
        REGISTERED_CHECKS[_identifier] = _check
        EVALUATORS[_identifier] = _check.evaluate
    for _batch_check in _CHECKS:
        if _batch_check.id in _ALLOWED:
            if _batch_check.category not in {'hardening', 'exposure', 'least_privilege', 'iam_graph', 'network'}:
                _batch_check = _batch_replace(_batch_check, category='hardening')
            _GLOBAL_CHECKS.append(_batch_check)
_load_17()


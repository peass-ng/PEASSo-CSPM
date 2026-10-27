"""Sanitized adjudication of the 25 saved AWS Exposure AI downgrades.

Reads only SHA-verified local 992 inputs. Output contains check IDs, field
names, predicates and counts; no finding IDs, resource IDs, reasons or policy
bodies leave memory.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path

from replay_aws_exposure_verdicts_992 import _observations, _read, replay
from peaso.aws_exposure_applicability_evidence import (
    CUSTOMER_SG, PUBLIC_RANGE_SG, SETTING_ID, SSM, SUBNET,
    _specific_public_rule,
)
from peaso.snapshot import resource_id

SOURCE = Path('/Users/carlospolop/peaso-work/replay/source-receipt.json')
OUTPUT = Path('outputs/aws-exposure-ai-adjudication-992.json')


def adjudicate(source=SOURCE):
    source_receipt = json.loads(Path(source).read_text())
    snapshot = _read(source_receipt, 'snapshot')
    pre = _read(source_receipt, 'pre_ai_report')
    final = _read(source_receipt, 'final_report')
    replayed = replay(source)
    observations = _observations(pre)
    resources = {r['id']: r for r in pre['resources']}
    reviews = {r['finding_id']: r for r in final['ai']['reviews']['exposure']
               if r['finding_id'] in observations}
    changed = [(observations[fid], review) for fid, review in reviews.items()
               if review['verdict'] != observations[fid]['status']]
    changed = [(row, review) for row, review in changed
               if row['check_id'] in (SUBNET, CUSTOMER_SG, PUBLIC_RANGE_SG, SSM)]
    if len(changed) != 25 or replayed['changed_ai_mismatch'] != 25:
        raise ValueError('the exact mismatch cohort changed')
    wanted = {(resources[row['resource_id']]['scope'], resources[row['resource_id']]['type'],
               resources[row['resource_id']]['native_id']) for row, _ in changed
              if row['resource_id'] in resources}
    raw = {}
    scoped = defaultdict(lambda: defaultdict(list))
    for collection in snapshot['collections']:
        kind = collection['type']
        if kind not in ('subnet', 'security_group', 'network_interface', 'ssm_service_settings'):
            continue
        scope = collection['scope']
        if kind in ('network_interface', 'ssm_service_settings'):
            scoped[scope][kind].extend(collection['items'])
        if kind not in ('subnet', 'security_group'):
            continue
        for item in collection['items']:
            key = (scope, kind, resource_id('aws', kind, scope, item))
            if key in wanted:
                raw[key] = item
    counts = defaultdict(Counter)
    eni_per_subnet = []
    for row, review in changed:
        cid = row['check_id']
        evidence = row['evidence']
        scope = row['scope']
        resource = resources.get(row['resource_id'])
        item = raw.get((resource['scope'], resource['type'], resource['native_id'])) if resource else None
        if row['status'] != 'FAIL' or not review.get('reason'):
            raise ValueError('changed review lacks the expected saved verdict/reason')
        counts[cid]['saved_ai_downgrades'] += 1
        if cid == SUBNET:
            if item is None or item.get('MapPublicIpOnLaunch') is not True or evidence.get('map_public_ip_on_launch') is not True:
                raise ValueError('subnet predicate is not recorded')
            count = sum(eni.get('SubnetId') == item['SubnetId'] for eni in scoped[scope]['network_interface'])
            if count < 1:
                raise ValueError('saved in-use subnet has no collected matching ENI')
            eni_per_subnet.append(count)
            counts[cid]['map_public_ip_on_launch_true'] += 1
            counts[cid]['matching_eni_present'] += 1
            counts[cid]['finding_evidence_omits_eni_count'] += 'matching_network_interface_count' not in evidence
        elif cid == CUSTOMER_SG:
            if item is None or evidence.get('world_ingress_rule_found') is not True or not evidence.get('customer_enis'):
                raise ValueError('customer-SG predicate is not recorded')
            matches = [eni for eni in scoped[scope]['network_interface']
                       if any(isinstance(group, dict) and group.get('GroupId') == item['GroupId']
                              for group in eni.get('Groups', []))
                       and eni.get('InterfaceType') not in ('api_gateway_managed', 'vpc_endpoint')
                       and (eni.get('Attachment') or {}).get('InstanceOwnerId') != 'amazon-elb']
            if not matches:
                raise ValueError('saved customer SG has no matching non-exempt ENI')
            counts[cid]['world_rule_and_customer_eni_present'] += 1
            counts[cid]['finding_evidence_has_eni_ids'] += isinstance(evidence.get('customer_enis'), list)
            counts[cid]['finding_evidence_omits_eni_type_owner'] += 'customer_network_interface_count' not in evidence
        elif cid == SSM:
            matches = [setting.get('ServiceSetting') for setting in scoped[scope]['ssm_service_settings']
                       if isinstance(setting.get('ServiceSetting'), dict)
                       and setting['ServiceSetting'].get('SettingId') == SETTING_ID]
            if len(matches) != 1 or matches[0].get('SettingValue') != 'Enable' or evidence.get('setting_value') != 'Enable':
                raise ValueError('exact SSM enable setting is not recorded')
            counts[cid]['exact_setting_enable'] += 1
            counts[cid]['finding_evidence_omits_setting_id'] += 'setting_id' not in evidence
        elif cid == PUBLIC_RANGE_SG:
            if item is None or evidence.get('specific_public_range_match') is not True:
                raise ValueError('public-range SG predicate is not recorded')
            witness = _specific_public_rule(item)
            if witness is None:
                raise ValueError('specific public range rule has no recorded port witness')
            counts[cid]['specific_public_cidr_with_any_port'] += 1
            counts[cid]['finding_evidence_omits_protocol_ports'] += 'matched_public_range_rule' not in evidence
    if Counter(cid for cid in counts for _ in range(counts[cid]['saved_ai_downgrades'])) != {
            SUBNET: 17, CUSTOMER_SG: 4, SSM: 2, PUBLIC_RANGE_SG: 2}:
        raise ValueError('check-level mismatch counts changed')
    return {
        'schema': 'aws-exposure-ai-adjudication-992-v1',
        'sha256_verified_inputs': 3,
        'changed_saved_reviews': replayed['ai_changed'],
        'native_corrected_to_ai': replayed['changed_ai_parity'],
        'unsupported_saved_ai_downgrades': len(changed),
        'other_six_check_rows_changed': replayed['unchanged_reviewed_native_changes'] + replayed['unreviewed_native_changes'],
        'subnet_matching_eni_count_min': min(eni_per_subnet),
        'subnet_matching_eni_count_max': max(eni_per_subnet),
        'checks': {cid: dict(sorted(counter.items())) for cid, counter in sorted(counts.items())},
        'adjudication': {
            SUBNET: 'Prompt-context gap: native ENI join proves in-use, but finding evidence omitted its count; saved AI UNKNOWN was unsupported by full recorded facts.',
            CUSTOMER_SG: 'Prompt-context gap: finding evidence named customer ENIs but omitted their type/owner classification; saved AI UNKNOWN was unsupported by full recorded facts.',
            SSM: 'Prompt-context gap: finding evidence had Enable but omitted the fixed setting ID; saved AI UNKNOWN was unsupported by full recorded facts.',
            PUBLIC_RANGE_SG: 'Irreducible AI predicate error: saved PASS contradicts the any-port control; prompt evidence also omitted protocol and port witness.',
        },
        'limits': 'This adjudicates saved 992 reviews. No model was called; a future AI response to richer evidence is unknown.',
    }


def main():
    result = adjudicate()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('changed_saved_reviews', 'native_corrected_to_ai',
                                                   'unsupported_saved_ai_downgrades', 'other_six_check_rows_changed')}, sort_keys=True))


if __name__ == '__main__':
    main()

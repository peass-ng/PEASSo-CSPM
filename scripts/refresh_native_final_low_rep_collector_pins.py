#!/usr/bin/env python3
"""Refresh the five AWS collector pins of the 190-ID low-representative audit.

The audit (scripts/audit_native_final_low_reps.py) pins whole collector files
and cites exact collector line ranges. Later reviewed collector work moved or
extended those files. This refresh re-proves every cited range against the
audit commit: an unchanged range must be byte-identical at its new location;
a range with reviewed additive changes is listed with the exact reason. Any
unlisted change, a moved anchor, or an unexpected pin fails closed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
AUDIT_COMMIT = 'a9d62a01'
RECEIPT = ROOT / 'docs/ai-review/native-final-low-rep-collector-pin-refresh-20261030.json'
OLD_PINS = {
    'peaso/collectors/aws_b_services.py': '5fb58e5f02d8a05f41a70258a2a5108b88334bc165f59b443e5910b7689c10a3',
    'peaso/collectors/aws.py': '6ddea9d93b1a925503c712660dd9df98e63e460833d156deac9bd8a00ba3fde5',
    'peaso/collectors/aws_facts_data_identity.py': '0f71935bc917f2bce269f5158e68e8a7adedb84fc289aca86a7bda058deca1a0',
    'peaso/collectors/aws_facts_compute_edge.py': '33132a9fd900a55e6e7a259abcbb9af7b9a978a3ceb1cc589d78c4e754de2671',
    'peaso/collectors/aws_facts_cb_ca.py': '6d0e922b4bd80b371a0ff51bbd0efb1337e309c2c38564163fc4ab1a3b5fe3fe',
}
IDENTICAL = 'byte_identical_moved'
# (path, old range, new range, status, reviewed note)
RANGES = (
    ('peaso/collectors/aws.py', '952-961', '964-973', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1060-1130', '1072-1142', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1234-1500', '1246-1520', 'reviewed_additive',
     'Adds only the DescribeLoadBalancers State.Code enum as LoadBalancerStateCode; '
     'no audited kind or predicate field changes.'),
    ('peaso/collectors/aws.py', '1321-1324', '1333-1336', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1424-1430', '1436-1442', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1484-1503', '1504-1523', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1525-1558', '1545-1578', IDENTICAL, None),
    ('peaso/collectors/aws.py', '1654-1701', '1674-1722', 'reviewed_additive',
     'GetBucketPolicy now sends ExpectedBucketOwner for the scanned account; the '
     'audited S3 detail reads, absent codes and status recording are unchanged.'),
    ('peaso/collectors/aws.py', '2799-2920', '2820-2941', 'reviewed_additive',
     'Passes the scanned account to _buckets and labels the runtime span; '
     'job dispatch for audited kinds is unchanged.'),
    ('peaso/collectors/aws.py', '2908-2911', '2929-2932', IDENTICAL, None),
    ('peaso/collectors/aws.py', '2947-2957', '2968-2978', IDENTICAL, None),
    ('peaso/collectors/aws_b_services.py', '129-275', '141-312', 'reviewed_additive',
     '_detail carries only admitted ECS container environment names into '
     'DescribeTaskDefinition output; ACM, Cognito, CodeBuild and stage reads are unchanged.'),
    ('peaso/collectors/aws_b_services.py', '252-264', '289-301', IDENTICAL, None),
    ('peaso/collectors/aws_b_services.py', '447-535', '494-602', 'reviewed_additive',
     'Adds Backup restore-access, MQ shared-resource and ActiveMQ revision reads for '
     'other kinds; task definitions keep their single Definition projection.'),
    ('peaso/collectors/aws_b_services.py', '458-465', '505-512', IDENTICAL, None),
    ('peaso/collectors/aws_b_services.py', '458-481', '505-528', 'reviewed_additive',
     'Each DescribeTaskDefinition revision is still read; _ecs_definition_metadata '
     'avoids a second filter that dropped environment names. Mount fields are unchanged.'),
    ('peaso/collectors/aws_b_services.py', '475-476', '522-523', IDENTICAL, None),
    ('peaso/collectors/aws_b_services.py', '480-490', '527-537', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '821-837', '875-891', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '854-860', '908-914', IDENTICAL, None),
    # The audit's 887-909 also spanned six FETCHERS registry lines after
    # _incident_manager; the function (887-903) is the cited proof.
    ('peaso/collectors/aws_facts_cb_ca.py', '887-903', '941-957', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '965-975', '1069-1079', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '1092-1103', '1198-1209', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '1092-1105', '1198-1211', IDENTICAL, None),
    ('peaso/collectors/aws_facts_cb_ca.py', '1316-1330', '1422-1436', IDENTICAL, None),
    ('peaso/collectors/aws_facts_compute_edge.py', '554-569', '752-864', 'reviewed_additive',
     'Adds CloudFront tenant, connection-group, continuous-deployment, OAC and OAI '
     'detail fields; the LogDeliveries projection lines are byte-identical.'),
    ('peaso/collectors/aws_facts_data_identity.py', '714-722', '1124-1132', IDENTICAL, None),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lines(data, span):
    rows = data.splitlines(True)
    first, last = map(int, span.split('-'))
    if not 1 <= first <= last <= len(rows):
        raise ValueError('cited range outside source: ' + span)
    return b''.join(rows[first - 1:last])


def build():
    entries, pins = [], {}
    for path, old_sha in OLD_PINS.items():
        old = subprocess.check_output(['git', 'show', AUDIT_COMMIT + ':' + path], cwd=ROOT)
        if sha(old) != old_sha:
            raise ValueError('audit-commit source does not match its old pin: ' + path)
        pins[path] = {'old_source_sha256': old_sha, 'new_source_sha256': sha((ROOT / path).read_bytes())}
    for path, old_span, new_span, status, note in RANGES:
        old = subprocess.check_output(['git', 'show', AUDIT_COMMIT + ':' + path], cwd=ROOT)
        before, after = lines(old, old_span), lines((ROOT / path).read_bytes(), new_span)
        if status == IDENTICAL and before != after:
            raise ValueError(f'cited range changed: {path}:{old_span}->{new_span}')
        if status != IDENTICAL and (before == after or not note):
            raise ValueError(f'reviewed change record is wrong: {path}:{old_span}')
        # Anchor the start line so a shifted reviewed range cannot silently drift.
        if before.splitlines()[0] != after.splitlines()[0]:
            raise ValueError(f'cited range start moved: {path}:{new_span}')
        entries.append({'path': path, 'old_lines': old_span, 'new_lines': new_span,
                        'status': status, 'review_note': note,
                        'old_range_sha256': sha(before), 'new_range_sha256': sha(after)})
    return {'schema_version': 1, 'audit_commit': AUDIT_COMMIT,
            'audit_script': 'scripts/audit_native_final_low_reps.py',
            'scope': 'whole-file collector pin refresh; evaluators, field specs, snapshot and decisions unchanged',
            'sources': pins, 'ranges': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    value = build()
    data = json.dumps(value, indent=2, sort_keys=True) + '\n'
    if args.write:
        RECEIPT.write_text(data)
    elif not RECEIPT.exists() or RECEIPT.read_text() != data:
        raise SystemExit('collector pin refresh receipt is stale; rerun with --write')
    print(json.dumps({path: row['new_source_sha256'] for path, row in value['sources'].items()}, indent=1))


if __name__ == '__main__':
    main()

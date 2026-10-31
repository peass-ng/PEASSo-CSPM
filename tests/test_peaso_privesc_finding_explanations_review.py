"""All technique contracts use reviewed, bounded prose without changing verdicts."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from peaso.privesc import catalog, analyze
from peaso.privesc.graph import GraphBuilder
from peaso.privesc.effective_permissions import Grant, Node
from peaso.privesc.finding_explanation import REVIEWED, evidence_summary
from peaso.privesc.aws_observed_evidence_v3 import evidence_summary as aws_observed
from peaso.privesc.gcp_observed_impact import evidence_summary as gcp_observed

ENTRIES=catalog()['entries']
ROOT=Path(__file__).resolve().parents[1]


def displayed_summary(finding):
    # These are the privilege-path formatters selected by finding_observation.
    # Calling them directly avoids importing unrelated check admission bundles.
    return {'aws': aws_observed, 'gcp': gcp_observed}.get(finding['provider'], evidence_summary)(finding)


def projected(entry,confidence='derived'):
    source=Node('source-id','user',entry['provider'],'scope','alice')
    target={'id':'target-id','label':'reviewed-target','type':entry['target']['kind'],'kind':'principal','scope':'scope','underlying_count':0 if confidence=='unknown' else 1}
    grant=Grant(confidence,[{'policy':'reviewed-policy','statement':0,'effect':'Allow'}],
                ['runtime_condition_not_evaluated'] if confidence=='conditional' else ['target_inventory_missing'] if confidence=='unknown' else [])
    return GraphBuilder(SimpleNamespace(provider=entry['provider']))._finding(
        'finding',entry['id'],entry['title'],source,entry['service'],entry['severity'],'',grant,[target],
        0 if confidence=='unknown' else 1,entry,entry.get('blockers',[]),edge_ids=['edge-id'])



def admin_projected(provider,confidence='derived'):
    source=Node('source-id','user',provider,'scope','alice')
    target={'id':'administrator-id','label':'scope administrator','kind':'entity','type':'scope_owner','underlying_count':0 if confidence=='unknown' else 1}
    grant=Grant(confidence,[{'effect':'Allow','policy':'admin-policy'}],['condition_unverified'] if confidence=='conditional' else ['facts_missing'] if confidence=='unknown' else [])
    return GraphBuilder(SimpleNamespace(provider=provider))._finding('admin-finding','admin-equivalent','Administrative control',source,'iam','high','',grant,[target],0 if confidence=='unknown' else 1,None,[])


def test_browser_line_measurement_fixture_matches_current_projectors():
    rows=[]
    for entry in ENTRIES:
        for confidence in ['derived','conditional','unknown']:
            finding=projected(entry,confidence)
            rows.append(dict(id=entry['id'],provider=entry['provider'],status=finding['status'],summary=displayed_summary(finding)))
    for provider in ['aws','gcp','azure','k8s']:
        for confidence in ['derived','conditional','unknown']:
            finding=admin_projected(provider,confidence)
            rows.append(dict(id='admin-equivalent',provider=provider,status=finding['status'],summary=displayed_summary(finding)))
    assert json.loads((ROOT/'tests/fixtures/shared_evidence_review.json').read_text())[:len(rows)]==rows


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
@pytest.mark.parametrize('confidence',['derived','conditional','unknown'])
def test_every_technique_status_has_brief_source_bound_explanation(entry,confidence):
    finding=projected(entry,confidence);before=deepcopy(finding)
    text=displayed_summary(finding)
    assert text and ('alice' in text or 'source' in text.lower())
    lines=text.splitlines()
    assert 3<=len(lines)<=5,text
    assert all(line and line.endswith('.') for line in lines),text
    assert 'scan' not in text.lower() and 'assessment' not in text.lower(),text
    assert finding==before


@pytest.mark.parametrize('change',[
    lambda f:f.update(provider='other'),
    lambda f:f['evidence']['technique'].update(id='different-id'),
    lambda f:f['evidence']['technique'].update(source='wrong-source'),
    lambda f:f['evidence'].update(source={}),
    lambda f:f['evidence'].update(targets=[]),
    lambda f:f['evidence'].update(target_count=True),
    lambda f:f['evidence'].update(target_count=0),
    lambda f:f['evidence'].update(granting_statements=[],granting_permissions=[]),
    lambda f:f['evidence']['granting_statements'][0].update(effect='Deny'),
    lambda f:f['evidence'].update(conditions=[False]),
    lambda f:f['evidence'].update(confidence='derived') or f.update(status='UNKNOWN'),
])
def test_false_malformed_or_mismatched_projection_cannot_create_a_path_claim(change):
    finding=projected(ENTRIES[0]);change(finding)
    assert displayed_summary(finding)is None


def test_aggregate_targets_are_counted_without_dumping_or_truncating_identifiers():
    finding=projected(ENTRIES[0]);finding['evidence']['target_count']=42
    finding['evidence']['targets']=[{'id':'aggregate-id','label':'recorded target aggregate','kind':'aggregate'}]
    assert '42 recorded targets' in displayed_summary(finding)


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
def test_real_native_snapshot_paths_preserve_conditions_and_source_identity(provider):
    # Reuse native integration producers, rather than mirroring permission evaluation.
    from test_peaso_privesc_integration import privesc_snapshot
    from test_peaso_privesc import gcp_snapshot,gcp_sa,SA1,k8s_snapshot,azure_snapshot,WRITER_ROLE,SUB
    if provider=='aws':snapshot=privesc_snapshot()
    elif provider=='gcp':snapshot=gcp_snapshot([{'role':'roles/iam.serviceAccountTokenCreator','members':['user:alice@example.com']}],[gcp_sa(SA1)])
    elif provider=='azure':snapshot=azure_snapshot([('u-alice',SUB,WRITER_ROLE)])
    else:snapshot=k8s_snapshot()
    result=analyze(snapshot,include_unknown=True)
    assert result['findings'],provider
    for finding in result['findings']:
        original=deepcopy(finding);text=displayed_summary(finding)
        if evidence_summary(finding) is None:
            # A conditional path with no recorded granting statement cannot
            # support a source-to-target claim in observed evidence.
            assert text is None
            assert finding==original
            continue
        assert text,(provider,finding)
        label=finding['evidence']['source']['label']
        if label=='2 principals':
            assert 'source identity' in text
        else:
            assert label in text
        assert finding==original


@pytest.mark.parametrize('confidence',['derived','conditional','unknown'])
def test_long_complete_identity_labels_use_structural_references_without_clipping(confidence):
    finding=projected(next(e for e in ENTRIES if e['id']=='gcp-gkehub-memberships-setiampolicy-membership-self-grant'),confidence)
    source='source-'+('a'*450)
    target='arn:aws:iam::111111111111:role/'+('b'*450)
    finding['evidence']['source']['label']=source
    finding['evidence']['targets'][0]['label']=target
    before=deepcopy(finding)
    text=displayed_summary(finding)
    assert 3<=len(text.splitlines())<=5
    assert 'source' in text
    assert source not in text and target not in text
    assert '...' not in text and '…' not in text
    assert finding==before


@pytest.mark.parametrize('provider',['aws','gcp','azure','k8s'])
@pytest.mark.parametrize('confidence',['derived','conditional','unknown'])
def test_generated_admin_summary_distinguishes_existing_grants_from_unresolved_control(provider,confidence):
    finding=admin_projected(provider,confidence);before=deepcopy(finding)
    text=displayed_summary(finding)
    assert text and 3<=len(text.splitlines())<=5
    assert 'alice' in text
    if confidence=='derived':assert 'administrat' in text.lower()
    elif confidence=='conditional':assert 'may' in text.lower() or 'conditions' in text.lower()
    else:assert any(word in text.lower() for word in ('unresolved','missing','lacks needed facts'))
    assert finding==before


def test_zero_unresolved_target_count_is_not_reported_as_no_possible_access():
    finding=projected(ENTRIES[0],'unknown')
    assert finding['evidence']['target_count']==0
    text=displayed_summary(finding)
    assert any(word in text.lower() for word in ('unresolved target','no target','missing target'))
    assert '0 targets' not in text and 'no possible access' not in text.lower()


@pytest.mark.parametrize('entry',ENTRIES,ids=lambda e:e['id'])
def test_projected_prose_does_not_dump_internal_condition_or_confidence_codes(entry):
    for confidence in ('derived','conditional','unknown'):
        text=displayed_summary(projected(entry,confidence))
        assert text and 'Recorded grants link' not in text
        assert 'runtime_condition_not_evaluated' not in text
        assert 'target_inventory_missing' not in text
        assert 'confidence:' not in text

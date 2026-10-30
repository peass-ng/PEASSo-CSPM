"""Atomic source/native-case admission of a bounded SAS-policy declaration."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
from . import azure_sas_expiry_policy_declaration_proposal_20261020 as candidate
from . import azure_native_contract_closure_20261020 as native
from . import facts

RECEIPT_SHA256 = 'deaef643ddfeb758dc53f9172998d056b4ed708c1073633af6eba63e8a072102'
RECEIPT = 'azure_sas_policy_declaration_admission_20261020.json'


def reviewed_inputs(root=None):
    root=Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw=(root/'peaso/checks'/RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=RECEIPT_SHA256:
        raise RuntimeError('SAS policy declaration receipt changed')
    receipt=json.loads(raw)
    if receipt['schema_version']!=1 or receipt['check']!=candidate.DECLARATION:
        raise RuntimeError('SAS policy declaration metadata changed')
    for name,digest in receipt['sources'].items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('SAS policy declaration source changed')
    if (candidate._owned is not native._owned or candidate.get is not facts.get
            or candidate.evaluate.__globals__ is not vars(candidate)
            or candidate.evaluate.__module__!=candidate.__name__
            or hashlib.sha256(inspect.getsource(candidate.evaluate).encode()).hexdigest()!=receipt['predicate_sha256']):
        raise RuntimeError('SAS policy declaration function binding changed')
    fixture=receipt['fixture'];path=(root/fixture['path']).resolve()
    if not path.is_relative_to(root/'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest()!=fixture['sha256']:
        raise RuntimeError('SAS policy native fixtures changed')
    cases=json.loads(path.read_text())
    if set(cases)!={candidate.CHECK}:raise RuntimeError('SAS policy native identity changed')
    for branch in ('pass','fail','unknown'):
        case=cases[candidate.CHECK]
        if candidate.evaluate(deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]!=branch.upper():
            raise RuntimeError('SAS policy native branch changed')
    return receipt,cases


def signature(check):
    return (check.provider,check.category,check.kind,check.title,check.severity,check.control,
            check.remediation,check.target,tuple(check.declared_dependencies))


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    receipt,cases=reviewed_inputs();d=receipt['check'];cid=d['id']
    matches=[c for c in CHECKS if c.id==cid]
    expected=(d['provider'],d['category'],d['kind'],d['title'],d['severity'],'security_configuration',
              d['remediation'],'resource',tuple(d['dependencies']))
    if len(matches)>1 or matches and (inspect.unwrap(matches[0].evaluate) is not candidate.evaluate or signature(matches[0])!=expected):
        raise RuntimeError('SAS policy declaration registration conflict')
    if cid in CASES and CASES[cid]!=cases[cid]:
        raise RuntimeError('SAS policy declaration CASES conflict')
    before=tuple(CHECKS);old=deepcopy(CASES.get(cid));existed=cid in CASES
    try:
        if not matches:
            register(cid,d['provider'],d['category'],d['kind'],d['title'],d['severity'],
                     'security_configuration',d['remediation'],dependencies=d['dependencies'])(candidate.evaluate)
        CASES[cid]=deepcopy(cases[cid])
    except Exception:
        CHECKS[:]=before
        if existed:CASES[cid]=old
        else:CASES.pop(cid,None)
        raise

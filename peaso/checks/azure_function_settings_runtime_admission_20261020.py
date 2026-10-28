"""Atomic admission of the two selected Function declaration contracts."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path
from . import azure_function_settings_runtime_consumer_20261020 as candidate
from . import azure_function_settings_review_20261020 as original_consumer
from peaso.collectors import azure_function_settings_runtime_hooks_20261020 as runtime_hooks
from peaso.collectors import azure_ml_selected_asset_secret_indicators as current_union
from . import azure_function_settings_admission_20261020 as predecessor
from peaso.collectors import azure_function_settings_declarations_20261020 as producer

RECEIPT_SHA256 = '239d2ad906d06d515eb39496a9d16cc0b4f6ac6740f7ecbfd87faf11dc0f60ba'
RECEIPT = 'azure_function_settings_runtime_admission_20261020.json'


def reviewed_inputs(root=None):
    root=Path(root or Path(__file__).resolve().parents[2]).resolve()
    raw=(root/'peaso/checks'/RECEIPT).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=RECEIPT_SHA256:
        raise RuntimeError('Function declaration admission receipt changed')
    receipt=json.loads(raw)
    if receipt.get('schema_version')!=1 or receipt.get('checks')!=[
            {k:v for k,v in d.items()if k!='evaluate'}for d in candidate.PROPOSALS]:
        raise RuntimeError('Function declaration metadata changed')
    predecessor.validate_proposal()
    for name,digest in receipt['sources'].items():
        path=(root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('Function declaration reviewed source changed')
    if (candidate.source is not producer or candidate.telemetry.__globals__ is not vars(candidate)
            or candidate.runtime.__globals__ is not vars(candidate)
            or candidate._evaluate.__globals__ is not vars(candidate)
            or candidate._bound.__globals__ is not vars(candidate)):
        raise RuntimeError('Function declaration evaluator binding changed')
    if candidate.predecessor is not original_consumer or runtime_hooks.source is not producer or runtime_hooks.current is not current_union:
        raise RuntimeError('Function declaration successor binding changed')
    for name,digest in receipt['runtime_callables'].items():
        function=getattr(candidate,name)
        if (function is not inspect.unwrap(function) or function.__name__!=name
                or function.__module__!=candidate.__name__
                or hashlib.sha256(inspect.getsource(function).encode()).hexdigest()!=digest):
            raise RuntimeError('Function declaration successor callable changed')
    if hashlib.sha256(inspect.getsource(runtime_hooks.final_snapshot).encode()).hexdigest()!=receipt['runtime_finalizer_sha256']:
        raise RuntimeError('Function declaration finalizer changed')
    fixture=receipt['fixture'];path=(root/fixture['path']).resolve()
    if not path.is_relative_to(root/'peaso/checks') or hashlib.sha256(path.read_bytes()).hexdigest()!=fixture['sha256']:
        raise RuntimeError('Function declaration native cases changed')
    cases=json.loads(path.read_text());declarations=[]
    if set(cases)!={d['id']for d in candidate.PROPOSALS}:
        raise RuntimeError('Function declaration native IDs changed')
    for d in candidate.PROPOSALS:
        function=d['evaluate']
        if function is not getattr(candidate,receipt['functions'][d['id']]) or function is not inspect.unwrap(function):
            raise RuntimeError('Function declaration callable changed')
        case=cases[d['id']]
        for branch in('pass','fail','unknown'):
            if function(deepcopy(case[branch]),deepcopy(case[branch+'_index']))[0]!=branch.upper():
                raise RuntimeError('Function declaration native branch changed')
        for branch in('missing','malformed'):
            if function(deepcopy(case[branch]),deepcopy(case['index']))[0]!='UNKNOWN':
                raise RuntimeError('Function declaration malformed branch changed')
        declarations.append((d,function))
    return receipt,cases,declarations


def _signature(check):
    return(check.provider,check.category,check.kind,check.title,check.severity,check.control,
           check.remediation,check.target,tuple(check.declared_dependencies))


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    receipt,cases,declarations=reviewed_inputs()
    for d,function in declarations:
        cid=d['id'];matches=[c for c in CHECKS if c.id==cid]
        expected=(d['provider'],d['category'],d['kind'],d['title'],d['severity'],
                  'security_configuration','\n'.join(d['remediation']),'resource',tuple(d['dependencies']))
        if len(matches)>1 or matches and(inspect.unwrap(matches[0].evaluate)is not function or _signature(matches[0])!=expected):
            raise RuntimeError('Function declaration registration conflict')
        if cid in CASES and CASES[cid]!=cases[cid]:
            raise RuntimeError('Function declaration native CASES conflict')
    before=tuple(CHECKS);prior={cid:deepcopy(CASES[cid])for cid in cases if cid in CASES}
    try:
        for d,function in declarations:
            cid=d['id']
            if not any(c.id==cid for c in CHECKS):
                register(cid,d['provider'],d['category'],d['kind'],d['title'],d['severity'],
                         'security_configuration','\n'.join(d['remediation']),dependencies=d['dependencies'])(function)
            CASES[cid]=deepcopy(cases[cid])
    except Exception:
        CHECKS[:]=before
        for cid in cases:
            if cid in prior:CASES[cid]=prior[cid]
            else:CASES.pop(cid,None)
        raise

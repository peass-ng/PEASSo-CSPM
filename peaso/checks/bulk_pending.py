"""Install the pending compliance definitions without replacing published callbacks.

Each wave is loaded in its own registrar namespace. Only the listed pending IDs
are registered; original runtime objects and aliases remain intact.
"""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys
from . import CHECKS,CHECK_ALIASES

MANIFEST=json.loads(Path(__file__).with_suffix('.json').read_text())


def install():
    import peaso.checks as registry
    baseline=tuple(CHECKS);baseline_ids={c.id for c in baseline};aliases=dict(CHECK_ALIASES);register=registry.register
    # Check equality includes its ID; unrelated IDs cannot compare equal.
    # Keep all same-ID candidates to preserve equality even with duplicates.
    baseline_by_id={}
    for check in baseline:baseline_by_id.setdefault(check.id,[]).append(check)
    expected=set(MANIFEST['checks'])
    if expected & baseline_ids:raise RuntimeError('bulk admission overlaps a published native ID')
    captured={};namespace='peaso.checks._bulk_pending_'
    for name in MANIFEST['modules']:
        path=Path(__file__).with_name(name+'.py')
        alias=namespace+name
        def isolated_register(ident,*args,**kwargs):
            decorate=register(ident,*args,**kwargs)
            def isolated(function):
                if function.__module__==alias:
                    if ident in baseline_by_id:
                        CHECKS[:]=[c for c in CHECKS if c.id!=ident or c not in baseline_by_id[ident]]
                    if ident in aliases:CHECK_ALIASES.pop(ident,None)
                return decorate(function)
            return isolated
        registry.register=isolated_register
        try:
            spec=importlib.util.spec_from_file_location(alias,path);module=importlib.util.module_from_spec(spec);sys.modules[alias]=module;spec.loader.exec_module(module)
            for check in CHECKS:
                if check.id not in expected or check.evaluate.__module__!=alias:continue
                contract=MANIFEST['checks'][check.id]
                if check.id in captured or (check.provider,check.kind,check.severity)!=(contract['provider'],contract['kind'],contract['severity']):raise RuntimeError('duplicate or mismatched bulk native '+check.id)
                def callback(item,index,_evaluate=check.evaluate):return _evaluate(item,index)
                callback.__name__=check.evaluate.__name__;callback.__wrapped__=check.evaluate
                captured[check.id]=replace(check,evaluate=callback)
        finally:
            registry.register=register;CHECKS[:]=baseline;CHECK_ALIASES.clear();CHECK_ALIASES.update(aliases)
    if set(captured)!=expected:raise RuntimeError('bulk definitions missing: '+', '.join(sorted(expected-set(captured))))
    CHECKS.extend(captured[i]for i in MANIFEST['checks'])
    if tuple(CHECKS[:len(baseline)])!=baseline or CHECK_ALIASES!=aliases:raise RuntimeError('published registry changed during bulk admission')
    from . import azure_gateway_cidr_evidence_successor_20261021 as gateway_cidr_evidence
    gateway_cidr_evidence.install()

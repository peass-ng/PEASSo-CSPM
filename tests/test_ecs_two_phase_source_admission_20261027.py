"""Canonical finite producer, dependency and original witness conservation gates."""
import contextlib,contextvars,hashlib,inspect,json
from pathlib import Path
import pytest
import peaso.checks
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import aws_selected_configuration_secret_indicators as selected,aws,workload_environment_discovery as fold,gcp_configuration_secret_indicators as gcp
from peaso.checks import private_secret_shared_source_successor_20261021 as shared
ROOT=Path(__file__).resolve().parents[1]
P='peaso/collectors/aws_selected_configuration_secret_indicators.py'

def prove():return epoch.trusted_definition(selected.collect_selected,ROOT)

@contextlib.contextmanager
def fresh_shared():
    old=list(shared._PRIVATE_SELF_PROVEN);prior=shared._PRIVATE_PROVEN.copy()
    shared._PRIVATE_SELF_PROVEN.clear();shared._PRIVATE_PROVEN.clear()
    try:yield
    finally:
        shared._PRIVATE_SELF_PROVEN[:]=old;shared._PRIVATE_PROVEN.clear();shared._PRIVATE_PROVEN.update(prior)


def test_current_producers_gcp_alias_and_original_archive_witnesses():
    assert len(peaso.checks.CHECKS)==4179 and len(epoch.source_rows())==50
    row=epoch.source_rows()[P]
    assert [d['after']for d in row['definitions']]==[
        '4195b98a93b1ea4f6da19e3ec2fb643a30cbcca7017ff4ebdf6a92a6cb316833',
        'd40433c09b2d51929e5fd65fd8f846e6716f29d8845962e126243090f0ae09ee',
        '58b9602631ff07b6ea73c8d96a3cb123334a7cf27a1386b4971606a852f84cb9']
    for fn in[selected.collect_selected,selected.project_response,gcp.project_response]:epoch.trusted_definition(fn,ROOT)
    before=epoch.predecessor_bytes(P,(ROOT/P).read_bytes(),row['before_sha256'],ROOT)
    assert hashlib.sha256(before).hexdigest()=='c7a87afb1fc02740979a34efa2a03141d4e0daddbfdda1e45c604507c31c450f'
    assert hashlib.sha256((ROOT/'peaso/private_secret_source_epoch_20261021.zip').read_bytes()).hexdigest()=='3eb403fa363c559f7053060d409f60ac8c693350350423a6dc775412df4300c0'


@pytest.mark.parametrize('name',['_complete_content','_ecs_phase_remaining','_defer_ecs_content','_record_read_failure'])
@pytest.mark.parametrize('change',['code','defaults'])
def test_each_new_top_level_helper_code_and_defaults_rejected(monkeypatch,name,change):
    fn=getattr(selected,name)
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with pytest.raises(epoch.AdmissionError):prove()


METHODS=[name for name,value in vars(selected._DeferredEcsContent).items()if inspect.isfunction(value)]
@pytest.mark.parametrize('name',METHODS)
@pytest.mark.parametrize('change',['code','defaults'])
def test_every_new_consumer_method_code_and_defaults_rejected(monkeypatch,name,change):
    fn=getattr(selected._DeferredEcsContent,name)
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with pytest.raises(epoch.AdmissionError):prove()


@pytest.mark.parametrize('context',[object(),contextvars.ContextVar('foreign',default=None),contextvars.ContextVar('selected_ecs_content_phase',default=object())])
def test_context_type_name_and_default_are_bound(monkeypatch,context):
    monkeypatch.setattr(selected,'_DEFERRED_ECS',context)
    with pytest.raises(epoch.AdmissionError):prove()


def test_class_roster_tamper_rejected(monkeypatch):
    monkeypatch.setattr(selected._DeferredEcsContent,'foreign',lambda self:None,raising=False)
    with pytest.raises(epoch.AdmissionError):prove()


@pytest.mark.parametrize('change',['code','defaults'])
def test_diagnostic_fold_actual_code_and_defaults_still_bound(monkeypatch,change):
    fn=fold.fold_collections
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with fresh_shared(),pytest.raises(RuntimeError):shared._private_self()


@pytest.mark.parametrize('change',['code','defaults'])
def test_requests_catch_actual_code_and_defaults_still_bound(monkeypatch,change):
    fn=aws.Requests.call
    row=shared._private_receipt()['provider_group_callables']['peaso/collectors/aws.py:Requests.call']
    expected={'path':'peaso/collectors/aws.py','qualname':'Requests.call','sha256':row['predecessor_sha256'],'defaults':None,'kwdefaults':None}
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with fresh_shared(),pytest.raises(RuntimeError):shared._check_function(fn,expected,ROOT,{})

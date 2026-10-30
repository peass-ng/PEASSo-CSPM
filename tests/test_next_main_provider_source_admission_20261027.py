"""Finite next-main runtime dependencies preserve current and historical authority."""
import contextvars,inspect,re
from pathlib import Path
import pytest
import peaso.checks
from peaso import private_secret_source_epoch_20261021 as epoch,private_reviewed_collector_successor_20261022 as current
from peaso.collectors import azure,azure_graph_batch as graph,k8s,aws_code_log_content_indicators as logs,aws_selected_configuration_secret_indicators as selected,gcp_configuration_secret_indicators as gcp
ROOT=Path(__file__).resolve().parents[1]
def graph_proof():current.trusted_definition(azure.AzureTransport.request,ROOT)
LOG_PATH='peaso/collectors/aws_code_log_content_indicators.py'
def log_proof():
    # c2e6a793 changed scan_logs after this receipt; production proves the
    # unchanged project_response through the finite current-source successor.
    before=next(row['before'] for row in epoch.source_rows()[LOG_PATH]['definitions'] if row['name']=='project_response')
    current._finite_source().unchanged_callable_projection(logs.project_response,{'path':LOG_PATH,'sha256':before},ROOT)
def k8s_proof():current.verify_k8s_literal_current(k8s,ROOT)

def test_next_main_and_existing_current_producers_admit():
    assert len(peaso.checks.CHECKS)==4179 and len(epoch.source_rows())==50
    graph_proof();log_proof();k8s_proof()
    for fn in[selected.collect_selected,selected.project_response,gcp.project_response]:epoch.trusted_definition(fn,ROOT)

@pytest.mark.parametrize('name',['relative','valid_body','first_pages','_retry_after'])
@pytest.mark.parametrize('change',['code','defaults'])
def test_graph_function_code_and_defaults_bound(monkeypatch,name,change):
    fn=getattr(graph,name)
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with pytest.raises(epoch.AdmissionError):graph_proof()

METHODS=[(cls.__name__,name)for cls in[graph.FirstPages,graph._Direct]for name,fn in vars(cls).items()if inspect.isfunction(fn)]
@pytest.mark.parametrize('cls_name,name',METHODS)
def test_graph_each_method_actual_code_bound(monkeypatch,cls_name,name):
    fn=getattr(getattr(graph,cls_name),name)
    monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    with pytest.raises(epoch.AdmissionError):graph_proof()

@pytest.mark.parametrize('name,value',[('ROUTES',(re.compile(r'.*'),)),('MAX_REQUESTS',21),('_MISSING',None)])
def test_graph_routes_bound_and_sentinel_bound(monkeypatch,name,value):
    monkeypatch.setattr(graph,name,value)
    with pytest.raises(epoch.AdmissionError):graph_proof()

@pytest.mark.parametrize('kind',['code','parallel','scanner'])
def test_log_callback_actual_code_and_closure_bound(monkeypatch,kind):
    fn=logs.ENRICHERS['log_group']
    if kind=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    elif kind=='parallel':monkeypatch.setattr(fn.__closure__[0],'cell_contents',False)
    else:monkeypatch.setattr(fn.__closure__[1],'cell_contents',logs.scan_repository)
    with pytest.raises(epoch.AdmissionError):log_proof()

@pytest.mark.parametrize('name',['scan_logs','scan_repository','_enricher'])
def test_log_helper_actual_code_bound(monkeypatch,name):
    fn=getattr(logs,name);monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    with pytest.raises(epoch.AdmissionError):log_proof()

@pytest.mark.parametrize('name,value',[('LOG_GROUP_WORKERS',3),('_LOG_SCANNER_GATE',contextvars.ContextVar('foreign',default=None))])
def test_log_fanout_limit_and_context_bound(monkeypatch,name,value):
    monkeypatch.setattr(logs,name,value)
    with pytest.raises(epoch.AdmissionError):log_proof()

@pytest.mark.parametrize('kind',['helper','reader_init','reader_getattr','grant_get','grant_set'])
@pytest.mark.parametrize('change',['code','defaults'])
def test_k8s_new_literal_helpers_and_grant_accessors_bound(monkeypatch,kind,change):
    fn={'helper':k8s._automatic_literal_group,'reader_init':k8s._LiteralReader.__init__,'reader_getattr':k8s._LiteralReader.__getattr__,'grant_get':k8s._BoundedPool.literal_paths.fget,'grant_set':k8s._BoundedPool.literal_paths.fset}[kind]
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with pytest.raises(epoch.AdmissionError):k8s_proof()

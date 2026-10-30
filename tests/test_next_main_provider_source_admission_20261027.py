"""Finite next-main runtime dependencies preserve current and historical authority."""
import contextvars, inspect
from pathlib import Path
import pytest
from peaso import private_secret_source_epoch_20261021 as epoch,private_reviewed_collector_successor_20261022 as current
from peaso.collectors import azure, azure_graph_batch as graph, k8s, aws_code_log_content_indicators as logs
ROOT=Path(__file__).resolve().parents[1]
def graph_proof():current.trusted_definition(azure.AzureTransport.request,ROOT)
LOG_PATH='peaso/collectors/aws_code_log_content_indicators.py'
def log_proof():
    # c2e6a793 changed scan_logs after this receipt; production proves the
    # unchanged project_response through the finite current-source successor.
    before=next(row['before'] for row in epoch.source_rows()[LOG_PATH]['definitions'] if row['name']=='project_response')
    current._finite_source().unchanged_callable_projection(logs.project_response,{'path':LOG_PATH,'sha256':before},ROOT)
def k8s_proof():current.verify_k8s_literal_current(k8s,ROOT)


METHODS=[(cls.__name__,name)for cls in[graph.FirstPages,graph._Direct]for name,fn in vars(cls).items()if inspect.isfunction(fn)]


@pytest.mark.parametrize('name,value',[('LOG_GROUP_WORKERS',3),('_LOG_SCANNER_GATE',contextvars.ContextVar('foreign',default=None))])
def test_log_fanout_limit_and_context_bound(monkeypatch,name,value):
    monkeypatch.setattr(logs,name,value)
    with pytest.raises(epoch.AdmissionError):log_proof()


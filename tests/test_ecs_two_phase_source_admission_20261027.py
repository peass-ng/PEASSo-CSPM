"""Canonical finite producer, dependency and original witness conservation gates."""
from pathlib import Path
import pytest
from peaso import private_secret_source_epoch_20261021 as epoch
from peaso.collectors import aws_selected_configuration_secret_indicators as selected
ROOT=Path(__file__).resolve().parents[1]

def prove():return epoch.trusted_definition(selected.collect_selected,ROOT)


@pytest.mark.parametrize('name',['_complete_content','_ecs_phase_remaining','_defer_ecs_content','_record_read_failure'])
@pytest.mark.parametrize('change',['code','defaults'])
def test_each_new_top_level_helper_code_and_defaults_rejected(monkeypatch,name,change):
    fn=getattr(selected,name)
    if change=='code':monkeypatch.setattr(fn,'__code__',fn.__code__.replace(co_consts=fn.__code__.co_consts+('foreign',)))
    else:monkeypatch.setattr(fn,'__defaults__',('foreign',))
    with pytest.raises(epoch.AdmissionError):prove()



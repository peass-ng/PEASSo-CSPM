"""Current proposal admission preserves the signed historical callable lineage."""
import pytest

from peaso.rawv2_private_source_successor_20261021 import install_admission
from peaso.collectors import azure_selected_secret_integration_20261020 as union


@pytest.mark.parametrize('kind', ['function', 'apim'])
def test_changed_finalizer_code_is_rejected(kind):
    function = union.final_snapshot
    original = function.__code__
    try:
        function.__code__ = original.replace(co_consts=original.co_consts + ('tampered',))
        with pytest.raises(RuntimeError, match='executing callable changed'):
            install_admission('azure_' + ('function_settings' if kind == 'function' else 'apim_operation_window') + '_admission_20261020')
    finally:
        function.__code__ = original



"""Register the selected Dataflow and Batch referenced-source secret checks and their native cases."""
from peaso.collectors import gcp_dataflow_batch_source_runtime_20261020 as runtime
from . import gcp_dataflow_batch_source_runtime_consumer_20261020 as candidate
from . import selected_admission

CASES = 'gcp_dataflow_batch_source_runtime_cases_20261020.json'


def install():
    declarations = [(declaration, getattr(candidate, profile + '_source'))
                    for profile, declaration in zip(runtime.PROFILES, candidate.DECLARATIONS)]
    selected_admission.install('gcp', declarations, selected_admission.load_cases(CASES))

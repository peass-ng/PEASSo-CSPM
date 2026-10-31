"""Register the selected Function package source secret check and its native cases."""
from copy import deepcopy
import json
from pathlib import Path

from . import azure_function_package_integrated_consumer_20261020 as consumer
from peaso.collectors import azure_function_package_integration_20261020 as runtime
from peaso import azure_function_package_index_20261020 as owner

CASES = 'azure_function_package_integration_cases_20261020.json'
_INSTALLED = None


def native_case(case):
    snapshot, expected = deepcopy(case['snapshot']), deepcopy(case['expected_index_context'])
    package = deepcopy(snapshot)
    snapshot['metadata'][owner.EXPORT] = {k: package[k] for k in ('created_at', 'snapshot_id')}
    scope = expected['scopes'][0]
    index = {'context': {'provider': 'azure', 'scope': scope, 'metadata': snapshot['metadata']},
             'collections': {runtime.KIND: snapshot['collections']}}
    with owner.owner_admission(expected):
        owner.attach(index, snapshot, scope)
    return snapshot['collections'][0]['items'][0], index


def native_cases():
    """Return the packaged native package captures."""
    return json.loads(Path(__file__).with_name(CASES).read_text())


def install():
    global _INSTALLED
    from . import CHECKS, register
    from .fixtures import CASES as store
    d = consumer.DECLARATION
    if any(c.id == runtime.CHECK for c in CHECKS):
        return
    selected = {c['name']: native_case(c) for c in native_cases()}
    fixtures = {}
    for branch, name in (('pass', 'clean'), ('fail', 'positive'), ('unknown', 'denied')):
        fixtures[branch], fixtures[branch + '_index'] = selected[name]
    fixtures.update(missing={}, malformed={}, index={})
    register(runtime.CHECK, 'azure', d['category'], runtime.KIND, d['title'], d['severity'],
             d['control'], d['remediation'], dependencies=d['dependencies'],
             allow_incomplete_failure=True)(consumer.evaluate)
    store[runtime.CHECK] = fixtures
    _INSTALLED = CHECKS[-1].evaluate

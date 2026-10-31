"""The three provider-group checks reproduce their packaged native cases."""
from copy import deepcopy
import json
import unittest

from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.snapshot import freeze, make_snapshot
from peaso.checks.provider_group_install_20261021 import (
    RUNTIME, GCP, AWS, _default_cases)


class ProviderGroupFixtureClosure(unittest.TestCase):
    def test_default_cases_reproduce_registered_checks(self):
        self.assertEqual(set(_default_cases()), {RUNTIME, GCP, AWS})
        for check_id in (RUNTIME, GCP, AWS):
            check, = [c for c in CHECKS if c.id == check_id]
            cases = CASES[check_id]
            self.assertEqual(cases, _default_cases()[check_id])
            self.assertEqual(set(cases), {'pass', 'pass_index', 'fail', 'fail_index',
                                          'unknown', 'unknown_index', 'missing', 'malformed', 'index'})
            for branch, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
                item = freeze(deepcopy(cases[branch]))
                index = freeze(deepcopy(cases[branch + '_index']))
                before = json.dumps([item, index], sort_keys=True)
                self.assertEqual(check.evaluate(item, index)[0], expected)
                self.assertEqual(json.dumps([item, index], sort_keys=True), before)
                provider = check.provider
                kind = check.kind
                context = cases[branch + '_index']['context']
                snapshot = make_snapshot(provider, [context['scope']], [
                    {'type': kind, 'scope': context['scope'], 'status': 'collected',
                     'items': [deepcopy(cases[branch])]}],
                    metadata=deepcopy(context.get('metadata', {})))
                findings = engine.evaluate_snapshot(snapshot, checks=[check_id])['findings']
                self.assertEqual([(f['check_id'], f['status']) for f in findings],
                                 [(check_id, expected)])
            self.assertEqual(check.evaluate(deepcopy(cases['missing']), deepcopy(cases['index']))[0], 'UNKNOWN')
            self.assertEqual(check.evaluate(cases['malformed'], deepcopy(cases['index']))[0], 'UNKNOWN')
            foreign = deepcopy(cases['pass_index'])
            foreign['context']['scope'] += '-foreign'
            self.assertEqual(check.evaluate(freeze(cases['pass']), freeze(foreign))[0], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()

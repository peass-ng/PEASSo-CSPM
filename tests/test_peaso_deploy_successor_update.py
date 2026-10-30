"""Successor live-state comparison accepts only reordering, never changed rows."""
from __future__ import annotations

import copy
import unittest

from scripts import peaso_deploy as deploy
from scripts import peaso_deploy_successor_update as successor


class SuccessorStateSerialization(unittest.TestCase):
    def test_full_validation_row_multiset_and_only_proven_two_object_order(self):
        rows = [{'object_kind': 'var', 'config_addr': f'var.owned_{index}', 'status': 'pass',
                 'objects': [{'object_addr': f'var.owned_{index}', 'status': 'pass'}]}
                for index in range(6)]
        rows.append({'object_kind': 'resource', 'config_addr': 'aws_s3_object.customer_role_template',
                     'status': 'pass', 'objects': [
                         {'object_addr': 'aws_s3_object.customer_role_template["old-a"]', 'status': 'pass'},
                         {'object_addr': 'aws_s3_object.customer_role_template["old-b"]', 'status': 'pass'}]})
        state = {'lineage': successor.STATE_LINEAGE, 'serial': successor.STATE_SERIAL,
                 'resources': [{'instances': [{'attributes': {'id': 'owned', 'enabled': False}}]}],
                 'check_results': rows}
        reordered = copy.deepcopy(state)
        reordered['check_results'].reverse()
        reordered['check_results'][0]['objects'].reverse()
        self.assertTrue(deploy.successor_live_state_matches(reordered, state))
        for mutation in ('status', 'object', 'duplicate', 'serial', 'resource', 'five-objects'):
            changed = copy.deepcopy(reordered)
            if mutation == 'status': changed['check_results'][0]['status'] = 'fail'
            elif mutation == 'object': changed['check_results'][0]['objects'][0]['status'] = 'fail'
            elif mutation == 'duplicate': changed['check_results'][1] = copy.deepcopy(changed['check_results'][0])
            elif mutation == 'serial': changed['serial'] += 1
            elif mutation == 'resource': changed['resources'][0]['instances'][0]['attributes']['enabled'] = 0
            else:
                extra = [{'object_addr': f'aws_s3_object.customer_role_template["new-{i}"]', 'status': 'pass'}
                         for i in range(3)]
                changed['check_results'][0]['objects'].extend(extra)
                baseline = copy.deepcopy(state)
                baseline['check_results'][-1]['objects'].extend(extra)
                self.assertFalse(deploy.successor_live_state_matches(changed, baseline))
                continue
            with self.subTest(mutation=mutation):
                self.assertFalse(deploy.successor_live_state_matches(changed, state))


if __name__ == '__main__':
    unittest.main()

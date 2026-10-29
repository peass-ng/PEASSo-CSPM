import unittest

from profile_saved_startup import profile


class StartupProfileTest(unittest.TestCase):
    def receipt(self):
        return {'provider': 'test', 'scan_id': 'saved',
                'times_utc': {'queued': '2026-10-28T00:00:00Z',
                              'collecting': '2026-10-28T00:02:00Z'},
                'workflow': {'start_utc': '2026-10-28T00:00:40Z'}}

    def test_missing_ecs_never_becomes_measured_pull(self):
        result = profile(self.receipt())
        self.assertFalse(result['ecs_decomposition_available'])
        self.assertNotIn('image_pull', result['seconds'])
        self.assertEqual(result['seconds']['dispatch_elimination_upper_bound'], 40)

    def test_ecs_intervals_reconcile_exactly(self):
        task = dict(zip(['createdAt', 'pullStartedAt', 'pullStoppedAt', 'startedAt'],
                        ['2026-10-28T00:00:41Z', '2026-10-28T00:00:50Z',
                         '2026-10-28T00:01:30Z', '2026-10-28T00:01:40Z']))
        result = profile(self.receipt(), task)['seconds']
        self.assertEqual(result['image_pull'], 40)
        self.assertEqual(result['started_to_collect'], 20)
        keys = ['workflow_to_task_created', 'created_to_pull_start', 'image_pull',
                'pull_stop_to_started', 'started_to_collect']
        self.assertEqual(sum(result[key] for key in keys), result['workflow_to_collect'])

    def test_incomplete_or_reversed_timestamps_refuse_attribution(self):
        with self.assertRaisesRegex(ValueError, 'Missing ECS'):
            profile(self.receipt(), {'createdAt': '2026-10-28T00:00:41Z'})
        receipt = self.receipt()
        receipt['workflow']['start_utc'] = '2026-10-28T00:02:01Z'
        with self.assertRaisesRegex(ValueError, 'chronological'):
            profile(receipt)


if __name__ == '__main__':
    unittest.main()

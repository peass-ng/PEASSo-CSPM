"""Reviewed Calico CRD alias remains list-only and scope bounded."""
import unittest

from peaso.collectors.k8s import _BoundedPool, _allowed_calico_alias, _inventory_read_path


class Pool:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return object()


class CalicoAliasTests(unittest.TestCase):
    def test_reviewed_served_alias_metadata_lists(self):
        for path in (
            '/apis/crd.projectcalico.org/v1/bgpconfigurations',
            '/apis/crd.projectcalico.org/v1/ippools',
            '/apis/crd.projectcalico.org/v1/networkpolicies',
            '/apis/crd.projectcalico.org/v1/namespaces/qa-ns/networkpolicies',
            '/apis/crd.projectcalico.org/v1/namespaces/qa-ns/networksets',
        ):
            with self.subTest(path=path):
                self.assertTrue(_allowed_calico_alias(path))
                self.assertTrue(_inventory_read_path(path, '', {}))
                pool = Pool()
                _BoundedPool(pool, server='https://cluster.example').request(
                    'GET', 'https://cluster.example' + path)
                self.assertEqual(len(pool.calls), 1)

    def test_foreign_plurals_versions_subresources_and_wrong_scopes_are_denied(self):
        for path in (
            '/apis/crd.projectcalico.org/v1/secrets',
            '/apis/crd.projectcalico.org/v1/bgpconfigurations/status',
            '/apis/crd.projectcalico.org/v1/namespaces/qa-ns/bgpconfigurations',
            '/apis/crd.projectcalico.org/v1/namespaces/qa-ns/ippools',
            '/apis/other.example/v1/ippools',
            '/apis/crd.projectcalico.org/v1/namespaces/Bad/networkpolicies',
        ):
            with self.subTest(path=path):
                self.assertFalse(_allowed_calico_alias(path))
                self.assertFalse(_inventory_read_path(path, '', {}))
                pool = Pool()
                with self.assertRaises(ValueError):
                    _BoundedPool(pool, server='https://cluster.example').request(
                        'GET', 'https://cluster.example' + path)
                self.assertEqual(pool.calls, [])

    def test_alias_never_allows_mutation(self):
        pool = Pool()
        with self.assertRaisesRegex(ValueError, 'read-only'):
            _BoundedPool(pool, server='https://cluster.example').request(
                'POST', 'https://cluster.example/apis/crd.projectcalico.org/v1/ippools')
        self.assertEqual(pool.calls, [])


if __name__ == '__main__':
    unittest.main()

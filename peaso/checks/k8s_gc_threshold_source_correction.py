"""Explicit erratum for nine historical kubelet-labelled GC-threshold checks.

The original query and descriptions remain historical evidence.
Runtime applicability is corrected to kube-controller-manager, the flag owner.
No cloud or cluster mutation is performed by this source correction.
"""
from copy import deepcopy

VERSION = "k8s-gc-threshold-component-erratum-v1"
PRIOR_SPEC = ("kubelet", ["terminated-pod-gc-threshold"], "gt", 0, "0")
CURRENT_SPEC = ("kube-controller-manager", ["terminated-pod-gc-threshold"], "gt", 0, "0")
ROWS = {'k8s.ports.cronjob.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                               'captured '
                                                                                                                               'kube-controller-manager '
                                                                                                                               'terminated-pod-gc-threshold '
                                                                                                                               'declarations '
                                                                                                                               'for '
                                                                                                                               'a '
                                                                                                                               'positive '
                                                                                                                               'integer.',
                                                                                                                'fail_when': 'An '
                                                                                                                             'applicable '
                                                                                                                             'complete '
                                                                                                                             'kube-controller-manager '
                                                                                                                             'declaration '
                                                                                                                             'explicitly '
                                                                                                                             'sets '
                                                                                                                             'terminated-pod-gc-threshold '
                                                                                                                             'to '
                                                                                                                             'zero; '
                                                                                                                             'malformed '
                                                                                                                             'or '
                                                                                                                             'missing '
                                                                                                                             'required '
                                                                                                                             'declarations '
                                                                                                                             'remain '
                                                                                                                             'UNKNOWN.',
                                                                                                                'not_applicable_when': 'No '
                                                                                                                                       'applicable '
                                                                                                                                       'kube-controller-manager '
                                                                                                                                       'declaration '
                                                                                                                                       'is '
                                                                                                                                       'captured '
                                                                                                                                       'and '
                                                                                                                                       'component '
                                                                                                                                       'applicability '
                                                                                                                                       'is '
                                                                                                                                       'otherwise '
                                                                                                                                       'complete. '
                                                                                                                                       'A '
                                                                                                                                       'kubelet '
                                                                                                                                       'declaration '
                                                                                                                                       'alone '
                                                                                                                                       'is '
                                                                                                                                       'outside '
                                                                                                                                       'this '
                                                                                                                                       'corrected '
                                                                                                                                       'control.',
                                                                                                                'pass_when': 'At '
                                                                                                                             'least '
                                                                                                                             'one '
                                                                                                                             'applicable '
                                                                                                                             'kube-controller-manager '
                                                                                                                             'declaration '
                                                                                                                             'is '
                                                                                                                             'captured; '
                                                                                                                             'every '
                                                                                                                             'applicable '
                                                                                                                             'declaration '
                                                                                                                             'has '
                                                                                                                             'complete '
                                                                                                                             'flags '
                                                                                                                             'and '
                                                                                                                             'an '
                                                                                                                             'explicitly '
                                                                                                                             'declared '
                                                                                                                             'positive '
                                                                                                                             'integer '
                                                                                                                             'threshold.',
                                                                                                                'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                     'source '
                                                                                                                                                                     'query '
                                                                                                                                                                     'also '
                                                                                                                                                                     'inspects '
                                                                                                                                                                     'read-only-port '
                                                                                                                                                                     'rather '
                                                                                                                                                                     'than '
                                                                                                                                                                     'its '
                                                                                                                                                                     'named '
                                                                                                                                                                     'terminated-pod-gc-threshold '
                                                                                                                                                                     'setting.',
                                                                                                                                      'current_component': 'kube-controller-manager',
                                                                                                                                      'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                      'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                      'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                      'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/cronjob.pp',
                                                                                                                                      'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                      'prior_component': 'kubelet',
                                                                                                                                      'prior_description_sha256': '6a6472f3c8f874c6bd238c898e81dbd6571f3c232b5af1c3bab4f044a201b2a8',
                                                                                                                                      'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                      'prior_remediation_sha256': '72256566fd57893f13c6700ace97a0ada4c19615cdf2c3ae9d01e990cc0e1e20',
                                                                                                                                      'reason': 'The '
                                                                                                                                                'pinned '
                                                                                                                                                'upstream '
                                                                                                                                                'query '
                                                                                                                                                'incorrectly '
                                                                                                                                                'tests '
                                                                                                                                                'a '
                                                                                                                                                'kubelet '
                                                                                                                                                'command '
                                                                                                                                                'for '
                                                                                                                                                'a '
                                                                                                                                                'kube-controller-manager '
                                                                                                                                                'flag. '
                                                                                                                                                'Retain '
                                                                                                                                                'historical '
                                                                                                                                                'IDs '
                                                                                                                                                'and '
                                                                                                                                                'source '
                                                                                                                                                'evidence; '
                                                                                                                                                'correct '
                                                                                                                                                'the '
                                                                                                                                                'native '
                                                                                                                                                'component '
                                                                                                                                                'binding.',
                                                                                                                                      'source_relationship': 'Corrected '
                                                                                                                                                             'native '
                                                                                                                                                             'criterion '
                                                                                                                                                             'derived '
                                                                                                                                                             'from '
                                                                                                                                                             'documented '
                                                                                                                                                             'controller-manager '
                                                                                                                                                             'behavior; '
                                                                                                                                                             'not '
                                                                                                                                                             'literal '
                                                                                                                                                             'upstream '
                                                                                                                                                             'SQL '
                                                                                                                                                             'parity.',
                                                                                                                                      'status': 'source_erratum_successor',
                                                                                                                                      'upstream_document_sha256': '26c1dd5965e9e2dcfdc7517f2a152ce09486332f75d6e484cda6c92b966f082b',
                                                                                                                                      'upstream_inspected_flag': 'read-only-port',
                                                                                                                                      'upstream_query_block_sha256': '60ad72a42bc4871362763643b07e40e35071172fdc814b4275a73b1b92db0194',
                                                                                                                                      'upstream_query_source': 'query/cronjob.pp:2343',
                                                                                                                                      'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/cronjob.pp#L631',
                                                                                                                                      'upstream_sql_sha256': '52de4904687c31db179eb6270eb24c2b1be784245d38ff72afe4e12b250d1091',
                                                                                                                                      'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                         'provenance': {'additional_upstream_erratum': 'This '
                                                                                                                                       'source '
                                                                                                                                       'query '
                                                                                                                                       'also '
                                                                                                                                       'inspects '
                                                                                                                                       'read-only-port '
                                                                                                                                       'rather '
                                                                                                                                       'than '
                                                                                                                                       'its '
                                                                                                                                       'named '
                                                                                                                                       'terminated-pod-gc-threshold '
                                                                                                                                       'setting.',
                                                                                                        'current_component': 'kube-controller-manager',
                                                                                                        'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                        'historical_source_status': 'historical_invalid_component_binding',
                                                                                                        'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                        'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/cronjob.pp',
                                                                                                        'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                        'prior_component': 'kubelet',
                                                                                                        'prior_description_sha256': '6a6472f3c8f874c6bd238c898e81dbd6571f3c232b5af1c3bab4f044a201b2a8',
                                                                                                        'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                        'prior_remediation_sha256': '72256566fd57893f13c6700ace97a0ada4c19615cdf2c3ae9d01e990cc0e1e20',
                                                                                                        'reason': 'The '
                                                                                                                  'pinned '
                                                                                                                  'upstream '
                                                                                                                  'query '
                                                                                                                  'incorrectly '
                                                                                                                  'tests '
                                                                                                                  'a '
                                                                                                                  'kubelet '
                                                                                                                  'command '
                                                                                                                  'for '
                                                                                                                  'a '
                                                                                                                  'kube-controller-manager '
                                                                                                                  'flag. '
                                                                                                                  'Retain '
                                                                                                                  'historical '
                                                                                                                  'IDs '
                                                                                                                  'and '
                                                                                                                  'source '
                                                                                                                  'evidence; '
                                                                                                                  'correct '
                                                                                                                  'the '
                                                                                                                  'native '
                                                                                                                  'component '
                                                                                                                  'binding.',
                                                                                                        'source_relationship': 'Corrected '
                                                                                                                               'native '
                                                                                                                               'criterion '
                                                                                                                               'derived '
                                                                                                                               'from '
                                                                                                                               'documented '
                                                                                                                               'controller-manager '
                                                                                                                               'behavior; '
                                                                                                                               'not '
                                                                                                                               'literal '
                                                                                                                               'upstream '
                                                                                                                               'SQL '
                                                                                                                               'parity.',
                                                                                                        'status': 'source_erratum_successor',
                                                                                                        'upstream_document_sha256': '26c1dd5965e9e2dcfdc7517f2a152ce09486332f75d6e484cda6c92b966f082b',
                                                                                                        'upstream_inspected_flag': 'read-only-port',
                                                                                                        'upstream_query_block_sha256': '60ad72a42bc4871362763643b07e40e35071172fdc814b4275a73b1b92db0194',
                                                                                                        'upstream_query_source': 'query/cronjob.pp:2343',
                                                                                                        'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/cronjob.pp#L631',
                                                                                                        'upstream_sql_sha256': '52de4904687c31db179eb6270eb24c2b1be784245d38ff72afe4e12b250d1091',
                                                                                                        'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                         'remediation_fields': {'caveats': ['The '
                                                                                                                            'default '
                                                                                                                            '12500 '
                                                                                                                            'already '
                                                                                                                            'enables '
                                                                                                                            'garbage '
                                                                                                                            'collection; '
                                                                                                                            'this '
                                                                                                                            'check '
                                                                                                                            'needs '
                                                                                                                            'an '
                                                                                                                            'explicit '
                                                                                                                            'captured '
                                                                                                                            'value '
                                                                                                                            'and '
                                                                                                                            'does '
                                                                                                                            'not '
                                                                                                                            'read '
                                                                                                                            'the '
                                                                                                                            'running '
                                                                                                                            'controller '
                                                                                                                            'configuration.'],
                                                                                                                'cli': [],
                                                                                                                'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                  'expected': 0,
                                                                                                                                  'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                  'kind': 'cronjob',
                                                                                                                                  'operation': 'gt',
                                                                                                                                  'target': 'resource'},
                                                                                                                'references': [{'title': 'Kubernetes '
                                                                                                                                         'controller-manager '
                                                                                                                                         'GC '
                                                                                                                                         'threshold',
                                                                                                                                'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                'review_status': 'approved',
                                                                                                                'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                     'source '
                                                                                                                                                                     'query '
                                                                                                                                                                     'also '
                                                                                                                                                                     'inspects '
                                                                                                                                                                     'read-only-port '
                                                                                                                                                                     'rather '
                                                                                                                                                                     'than '
                                                                                                                                                                     'its '
                                                                                                                                                                     'named '
                                                                                                                                                                     'terminated-pod-gc-threshold '
                                                                                                                                                                     'setting.',
                                                                                                                                      'current_component': 'kube-controller-manager',
                                                                                                                                      'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                      'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                      'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                      'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/cronjob.pp',
                                                                                                                                      'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                      'prior_component': 'kubelet',
                                                                                                                                      'prior_description_sha256': '6a6472f3c8f874c6bd238c898e81dbd6571f3c232b5af1c3bab4f044a201b2a8',
                                                                                                                                      'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                      'prior_remediation_sha256': '72256566fd57893f13c6700ace97a0ada4c19615cdf2c3ae9d01e990cc0e1e20',
                                                                                                                                      'reason': 'The '
                                                                                                                                                'pinned '
                                                                                                                                                'upstream '
                                                                                                                                                'query '
                                                                                                                                                'incorrectly '
                                                                                                                                                'tests '
                                                                                                                                                'a '
                                                                                                                                                'kubelet '
                                                                                                                                                'command '
                                                                                                                                                'for '
                                                                                                                                                'a '
                                                                                                                                                'kube-controller-manager '
                                                                                                                                                'flag. '
                                                                                                                                                'Retain '
                                                                                                                                                'historical '
                                                                                                                                                'IDs '
                                                                                                                                                'and '
                                                                                                                                                'source '
                                                                                                                                                'evidence; '
                                                                                                                                                'correct '
                                                                                                                                                'the '
                                                                                                                                                'native '
                                                                                                                                                'component '
                                                                                                                                                'binding.',
                                                                                                                                      'source_relationship': 'Corrected '
                                                                                                                                                             'native '
                                                                                                                                                             'criterion '
                                                                                                                                                             'derived '
                                                                                                                                                             'from '
                                                                                                                                                             'documented '
                                                                                                                                                             'controller-manager '
                                                                                                                                                             'behavior; '
                                                                                                                                                             'not '
                                                                                                                                                             'literal '
                                                                                                                                                             'upstream '
                                                                                                                                                             'SQL '
                                                                                                                                                             'parity.',
                                                                                                                                      'status': 'source_erratum_successor',
                                                                                                                                      'upstream_document_sha256': '26c1dd5965e9e2dcfdc7517f2a152ce09486332f75d6e484cda6c92b966f082b',
                                                                                                                                      'upstream_inspected_flag': 'read-only-port',
                                                                                                                                      'upstream_query_block_sha256': '60ad72a42bc4871362763643b07e40e35071172fdc814b4275a73b1b92db0194',
                                                                                                                                      'upstream_query_source': 'query/cronjob.pp:2343',
                                                                                                                                      'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/cronjob.pp#L631',
                                                                                                                                      'upstream_sql_sha256': '52de4904687c31db179eb6270eb24c2b1be784245d38ff72afe4e12b250d1091',
                                                                                                                                      'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                'steps': ['Set '
                                                                                                                          'a '
                                                                                                                          'positive '
                                                                                                                          'controller-manager '
                                                                                                                          'garbage-collection '
                                                                                                                          'threshold '
                                                                                                                          'suitable '
                                                                                                                          'for '
                                                                                                                          'the '
                                                                                                                          'cluster.'],
                                                                                                                'summary': 'Set '
                                                                                                                           'a '
                                                                                                                           'positive '
                                                                                                                           'controller-manager '
                                                                                                                           'garbage-collection '
                                                                                                                           'threshold '
                                                                                                                           'suitable '
                                                                                                                           'for '
                                                                                                                           'the '
                                                                                                                           'cluster.'}},
 'k8s.ports.daemonset.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                 'captured '
                                                                                                                                 'kube-controller-manager '
                                                                                                                                 'terminated-pod-gc-threshold '
                                                                                                                                 'declarations '
                                                                                                                                 'for '
                                                                                                                                 'a '
                                                                                                                                 'positive '
                                                                                                                                 'integer.',
                                                                                                                  'fail_when': 'An '
                                                                                                                               'applicable '
                                                                                                                               'complete '
                                                                                                                               'kube-controller-manager '
                                                                                                                               'declaration '
                                                                                                                               'explicitly '
                                                                                                                               'sets '
                                                                                                                               'terminated-pod-gc-threshold '
                                                                                                                               'to '
                                                                                                                               'zero; '
                                                                                                                               'malformed '
                                                                                                                               'or '
                                                                                                                               'missing '
                                                                                                                               'required '
                                                                                                                               'declarations '
                                                                                                                               'remain '
                                                                                                                               'UNKNOWN.',
                                                                                                                  'not_applicable_when': 'No '
                                                                                                                                         'applicable '
                                                                                                                                         'kube-controller-manager '
                                                                                                                                         'declaration '
                                                                                                                                         'is '
                                                                                                                                         'captured '
                                                                                                                                         'and '
                                                                                                                                         'component '
                                                                                                                                         'applicability '
                                                                                                                                         'is '
                                                                                                                                         'otherwise '
                                                                                                                                         'complete. '
                                                                                                                                         'A '
                                                                                                                                         'kubelet '
                                                                                                                                         'declaration '
                                                                                                                                         'alone '
                                                                                                                                         'is '
                                                                                                                                         'outside '
                                                                                                                                         'this '
                                                                                                                                         'corrected '
                                                                                                                                         'control.',
                                                                                                                  'pass_when': 'At '
                                                                                                                               'least '
                                                                                                                               'one '
                                                                                                                               'applicable '
                                                                                                                               'kube-controller-manager '
                                                                                                                               'declaration '
                                                                                                                               'is '
                                                                                                                               'captured; '
                                                                                                                               'every '
                                                                                                                               'applicable '
                                                                                                                               'declaration '
                                                                                                                               'has '
                                                                                                                               'complete '
                                                                                                                               'flags '
                                                                                                                               'and '
                                                                                                                               'an '
                                                                                                                               'explicitly '
                                                                                                                               'declared '
                                                                                                                               'positive '
                                                                                                                               'integer '
                                                                                                                               'threshold.',
                                                                                                                  'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                       'source '
                                                                                                                                                                       'query '
                                                                                                                                                                       'also '
                                                                                                                                                                       'inspects '
                                                                                                                                                                       'read-only-port '
                                                                                                                                                                       'rather '
                                                                                                                                                                       'than '
                                                                                                                                                                       'its '
                                                                                                                                                                       'named '
                                                                                                                                                                       'terminated-pod-gc-threshold '
                                                                                                                                                                       'setting.',
                                                                                                                                        'current_component': 'kube-controller-manager',
                                                                                                                                        'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                        'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                        'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                        'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/daemonset.pp',
                                                                                                                                        'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                        'prior_component': 'kubelet',
                                                                                                                                        'prior_description_sha256': '5d5b8748ef56ff665e6d42f7e2d655e6ca77b1e9710bca056e93db183d13e1d0',
                                                                                                                                        'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                        'prior_remediation_sha256': 'be239666924e3383ef4a8cb58f0a6145569bc2aba373f0db99f42c3da2512e20',
                                                                                                                                        'reason': 'The '
                                                                                                                                                  'pinned '
                                                                                                                                                  'upstream '
                                                                                                                                                  'query '
                                                                                                                                                  'incorrectly '
                                                                                                                                                  'tests '
                                                                                                                                                  'a '
                                                                                                                                                  'kubelet '
                                                                                                                                                  'command '
                                                                                                                                                  'for '
                                                                                                                                                  'a '
                                                                                                                                                  'kube-controller-manager '
                                                                                                                                                  'flag. '
                                                                                                                                                  'Retain '
                                                                                                                                                  'historical '
                                                                                                                                                  'IDs '
                                                                                                                                                  'and '
                                                                                                                                                  'source '
                                                                                                                                                  'evidence; '
                                                                                                                                                  'correct '
                                                                                                                                                  'the '
                                                                                                                                                  'native '
                                                                                                                                                  'component '
                                                                                                                                                  'binding.',
                                                                                                                                        'source_relationship': 'Corrected '
                                                                                                                                                               'native '
                                                                                                                                                               'criterion '
                                                                                                                                                               'derived '
                                                                                                                                                               'from '
                                                                                                                                                               'documented '
                                                                                                                                                               'controller-manager '
                                                                                                                                                               'behavior; '
                                                                                                                                                               'not '
                                                                                                                                                               'literal '
                                                                                                                                                               'upstream '
                                                                                                                                                               'SQL '
                                                                                                                                                               'parity.',
                                                                                                                                        'status': 'source_erratum_successor',
                                                                                                                                        'upstream_document_sha256': '7f6e297898a3e56985f1381e7e62435b55cd03c1cd18d30c05bde15b29d72710',
                                                                                                                                        'upstream_inspected_flag': 'read-only-port',
                                                                                                                                        'upstream_query_block_sha256': '16b6d5f552256a2af8d1045faf7e0eed90786faa7572b576d533c4deb5ebe2f9',
                                                                                                                                        'upstream_query_source': 'query/daemonset.pp:2341',
                                                                                                                                        'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/daemonset.pp#L631',
                                                                                                                                        'upstream_sql_sha256': '05980664e2d7e0121fbcb31c908d01f664e8932202a6bad9f7d12fb9863f277a',
                                                                                                                                        'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                           'provenance': {'additional_upstream_erratum': 'This '
                                                                                                                                         'source '
                                                                                                                                         'query '
                                                                                                                                         'also '
                                                                                                                                         'inspects '
                                                                                                                                         'read-only-port '
                                                                                                                                         'rather '
                                                                                                                                         'than '
                                                                                                                                         'its '
                                                                                                                                         'named '
                                                                                                                                         'terminated-pod-gc-threshold '
                                                                                                                                         'setting.',
                                                                                                          'current_component': 'kube-controller-manager',
                                                                                                          'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                          'historical_source_status': 'historical_invalid_component_binding',
                                                                                                          'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                          'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/daemonset.pp',
                                                                                                          'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                          'prior_component': 'kubelet',
                                                                                                          'prior_description_sha256': '5d5b8748ef56ff665e6d42f7e2d655e6ca77b1e9710bca056e93db183d13e1d0',
                                                                                                          'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                          'prior_remediation_sha256': 'be239666924e3383ef4a8cb58f0a6145569bc2aba373f0db99f42c3da2512e20',
                                                                                                          'reason': 'The '
                                                                                                                    'pinned '
                                                                                                                    'upstream '
                                                                                                                    'query '
                                                                                                                    'incorrectly '
                                                                                                                    'tests '
                                                                                                                    'a '
                                                                                                                    'kubelet '
                                                                                                                    'command '
                                                                                                                    'for '
                                                                                                                    'a '
                                                                                                                    'kube-controller-manager '
                                                                                                                    'flag. '
                                                                                                                    'Retain '
                                                                                                                    'historical '
                                                                                                                    'IDs '
                                                                                                                    'and '
                                                                                                                    'source '
                                                                                                                    'evidence; '
                                                                                                                    'correct '
                                                                                                                    'the '
                                                                                                                    'native '
                                                                                                                    'component '
                                                                                                                    'binding.',
                                                                                                          'source_relationship': 'Corrected '
                                                                                                                                 'native '
                                                                                                                                 'criterion '
                                                                                                                                 'derived '
                                                                                                                                 'from '
                                                                                                                                 'documented '
                                                                                                                                 'controller-manager '
                                                                                                                                 'behavior; '
                                                                                                                                 'not '
                                                                                                                                 'literal '
                                                                                                                                 'upstream '
                                                                                                                                 'SQL '
                                                                                                                                 'parity.',
                                                                                                          'status': 'source_erratum_successor',
                                                                                                          'upstream_document_sha256': '7f6e297898a3e56985f1381e7e62435b55cd03c1cd18d30c05bde15b29d72710',
                                                                                                          'upstream_inspected_flag': 'read-only-port',
                                                                                                          'upstream_query_block_sha256': '16b6d5f552256a2af8d1045faf7e0eed90786faa7572b576d533c4deb5ebe2f9',
                                                                                                          'upstream_query_source': 'query/daemonset.pp:2341',
                                                                                                          'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/daemonset.pp#L631',
                                                                                                          'upstream_sql_sha256': '05980664e2d7e0121fbcb31c908d01f664e8932202a6bad9f7d12fb9863f277a',
                                                                                                          'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                           'remediation_fields': {'caveats': ['The '
                                                                                                                              'default '
                                                                                                                              '12500 '
                                                                                                                              'already '
                                                                                                                              'enables '
                                                                                                                              'garbage '
                                                                                                                              'collection; '
                                                                                                                              'this '
                                                                                                                              'check '
                                                                                                                              'needs '
                                                                                                                              'an '
                                                                                                                              'explicit '
                                                                                                                              'captured '
                                                                                                                              'value '
                                                                                                                              'and '
                                                                                                                              'does '
                                                                                                                              'not '
                                                                                                                              'read '
                                                                                                                              'the '
                                                                                                                              'running '
                                                                                                                              'controller '
                                                                                                                              'configuration.'],
                                                                                                                  'cli': [],
                                                                                                                  'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                    'expected': 0,
                                                                                                                                    'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                    'kind': 'daemonset',
                                                                                                                                    'operation': 'gt',
                                                                                                                                    'target': 'resource'},
                                                                                                                  'references': [{'title': 'Kubernetes '
                                                                                                                                           'controller-manager '
                                                                                                                                           'GC '
                                                                                                                                           'threshold',
                                                                                                                                  'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                  'review_status': 'approved',
                                                                                                                  'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                       'source '
                                                                                                                                                                       'query '
                                                                                                                                                                       'also '
                                                                                                                                                                       'inspects '
                                                                                                                                                                       'read-only-port '
                                                                                                                                                                       'rather '
                                                                                                                                                                       'than '
                                                                                                                                                                       'its '
                                                                                                                                                                       'named '
                                                                                                                                                                       'terminated-pod-gc-threshold '
                                                                                                                                                                       'setting.',
                                                                                                                                        'current_component': 'kube-controller-manager',
                                                                                                                                        'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                        'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                        'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                        'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/daemonset.pp',
                                                                                                                                        'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                        'prior_component': 'kubelet',
                                                                                                                                        'prior_description_sha256': '5d5b8748ef56ff665e6d42f7e2d655e6ca77b1e9710bca056e93db183d13e1d0',
                                                                                                                                        'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                        'prior_remediation_sha256': 'be239666924e3383ef4a8cb58f0a6145569bc2aba373f0db99f42c3da2512e20',
                                                                                                                                        'reason': 'The '
                                                                                                                                                  'pinned '
                                                                                                                                                  'upstream '
                                                                                                                                                  'query '
                                                                                                                                                  'incorrectly '
                                                                                                                                                  'tests '
                                                                                                                                                  'a '
                                                                                                                                                  'kubelet '
                                                                                                                                                  'command '
                                                                                                                                                  'for '
                                                                                                                                                  'a '
                                                                                                                                                  'kube-controller-manager '
                                                                                                                                                  'flag. '
                                                                                                                                                  'Retain '
                                                                                                                                                  'historical '
                                                                                                                                                  'IDs '
                                                                                                                                                  'and '
                                                                                                                                                  'source '
                                                                                                                                                  'evidence; '
                                                                                                                                                  'correct '
                                                                                                                                                  'the '
                                                                                                                                                  'native '
                                                                                                                                                  'component '
                                                                                                                                                  'binding.',
                                                                                                                                        'source_relationship': 'Corrected '
                                                                                                                                                               'native '
                                                                                                                                                               'criterion '
                                                                                                                                                               'derived '
                                                                                                                                                               'from '
                                                                                                                                                               'documented '
                                                                                                                                                               'controller-manager '
                                                                                                                                                               'behavior; '
                                                                                                                                                               'not '
                                                                                                                                                               'literal '
                                                                                                                                                               'upstream '
                                                                                                                                                               'SQL '
                                                                                                                                                               'parity.',
                                                                                                                                        'status': 'source_erratum_successor',
                                                                                                                                        'upstream_document_sha256': '7f6e297898a3e56985f1381e7e62435b55cd03c1cd18d30c05bde15b29d72710',
                                                                                                                                        'upstream_inspected_flag': 'read-only-port',
                                                                                                                                        'upstream_query_block_sha256': '16b6d5f552256a2af8d1045faf7e0eed90786faa7572b576d533c4deb5ebe2f9',
                                                                                                                                        'upstream_query_source': 'query/daemonset.pp:2341',
                                                                                                                                        'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/daemonset.pp#L631',
                                                                                                                                        'upstream_sql_sha256': '05980664e2d7e0121fbcb31c908d01f664e8932202a6bad9f7d12fb9863f277a',
                                                                                                                                        'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                  'steps': ['Set '
                                                                                                                            'a '
                                                                                                                            'positive '
                                                                                                                            'controller-manager '
                                                                                                                            'garbage-collection '
                                                                                                                            'threshold '
                                                                                                                            'suitable '
                                                                                                                            'for '
                                                                                                                            'the '
                                                                                                                            'cluster.'],
                                                                                                                  'summary': 'Set '
                                                                                                                             'a '
                                                                                                                             'positive '
                                                                                                                             'controller-manager '
                                                                                                                             'garbage-collection '
                                                                                                                             'threshold '
                                                                                                                             'suitable '
                                                                                                                             'for '
                                                                                                                             'the '
                                                                                                                             'cluster.'}},
 'k8s.ports.deployment.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                  'captured '
                                                                                                                                  'kube-controller-manager '
                                                                                                                                  'terminated-pod-gc-threshold '
                                                                                                                                  'declarations '
                                                                                                                                  'for '
                                                                                                                                  'a '
                                                                                                                                  'positive '
                                                                                                                                  'integer.',
                                                                                                                   'fail_when': 'An '
                                                                                                                                'applicable '
                                                                                                                                'complete '
                                                                                                                                'kube-controller-manager '
                                                                                                                                'declaration '
                                                                                                                                'explicitly '
                                                                                                                                'sets '
                                                                                                                                'terminated-pod-gc-threshold '
                                                                                                                                'to '
                                                                                                                                'zero; '
                                                                                                                                'malformed '
                                                                                                                                'or '
                                                                                                                                'missing '
                                                                                                                                'required '
                                                                                                                                'declarations '
                                                                                                                                'remain '
                                                                                                                                'UNKNOWN.',
                                                                                                                   'not_applicable_when': 'No '
                                                                                                                                          'applicable '
                                                                                                                                          'kube-controller-manager '
                                                                                                                                          'declaration '
                                                                                                                                          'is '
                                                                                                                                          'captured '
                                                                                                                                          'and '
                                                                                                                                          'component '
                                                                                                                                          'applicability '
                                                                                                                                          'is '
                                                                                                                                          'otherwise '
                                                                                                                                          'complete. '
                                                                                                                                          'A '
                                                                                                                                          'kubelet '
                                                                                                                                          'declaration '
                                                                                                                                          'alone '
                                                                                                                                          'is '
                                                                                                                                          'outside '
                                                                                                                                          'this '
                                                                                                                                          'corrected '
                                                                                                                                          'control.',
                                                                                                                   'pass_when': 'At '
                                                                                                                                'least '
                                                                                                                                'one '
                                                                                                                                'applicable '
                                                                                                                                'kube-controller-manager '
                                                                                                                                'declaration '
                                                                                                                                'is '
                                                                                                                                'captured; '
                                                                                                                                'every '
                                                                                                                                'applicable '
                                                                                                                                'declaration '
                                                                                                                                'has '
                                                                                                                                'complete '
                                                                                                                                'flags '
                                                                                                                                'and '
                                                                                                                                'an '
                                                                                                                                'explicitly '
                                                                                                                                'declared '
                                                                                                                                'positive '
                                                                                                                                'integer '
                                                                                                                                'threshold.',
                                                                                                                   'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                         'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                         'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                         'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                         'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/deployment.pp',
                                                                                                                                         'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                         'prior_component': 'kubelet',
                                                                                                                                         'prior_description_sha256': '4230a771e1594417f624dceb14cffac13d02bfdc2573655f28bdcb431a58a239',
                                                                                                                                         'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                         'prior_remediation_sha256': '8e848f84ba4904e43d458a56a98d48e427b3a1e48855e291864acf6058f27d40',
                                                                                                                                         'reason': 'The '
                                                                                                                                                   'pinned '
                                                                                                                                                   'upstream '
                                                                                                                                                   'query '
                                                                                                                                                   'incorrectly '
                                                                                                                                                   'tests '
                                                                                                                                                   'a '
                                                                                                                                                   'kubelet '
                                                                                                                                                   'command '
                                                                                                                                                   'for '
                                                                                                                                                   'a '
                                                                                                                                                   'kube-controller-manager '
                                                                                                                                                   'flag. '
                                                                                                                                                   'Retain '
                                                                                                                                                   'historical '
                                                                                                                                                   'IDs '
                                                                                                                                                   'and '
                                                                                                                                                   'source '
                                                                                                                                                   'evidence; '
                                                                                                                                                   'correct '
                                                                                                                                                   'the '
                                                                                                                                                   'native '
                                                                                                                                                   'component '
                                                                                                                                                   'binding.',
                                                                                                                                         'source_relationship': 'Corrected '
                                                                                                                                                                'native '
                                                                                                                                                                'criterion '
                                                                                                                                                                'derived '
                                                                                                                                                                'from '
                                                                                                                                                                'documented '
                                                                                                                                                                'controller-manager '
                                                                                                                                                                'behavior; '
                                                                                                                                                                'not '
                                                                                                                                                                'literal '
                                                                                                                                                                'upstream '
                                                                                                                                                                'SQL '
                                                                                                                                                                'parity.',
                                                                                                                                         'status': 'source_erratum_successor',
                                                                                                                                         'upstream_document_sha256': '935d43b62528b25536540fa4fed46cea03d7c04c5f99c172ffd4b9be063f1976',
                                                                                                                                         'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                         'upstream_query_block_sha256': 'e5ee0102598a0c8af4485d84874d9b4427c240eeb7a05cbf32f778ad7a6d2f94',
                                                                                                                                         'upstream_query_source': 'query/deployment.pp:2359',
                                                                                                                                         'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/deployment.pp#L639',
                                                                                                                                         'upstream_sql_sha256': '6f23a8a7ded0b8bd004df76e050f37b5230d44a2b7ecd620556cc88a4c84cfd5',
                                                                                                                                         'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                            'provenance': {'current_component': 'kube-controller-manager',
                                                                                                           'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                           'historical_source_status': 'historical_invalid_component_binding',
                                                                                                           'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                           'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/deployment.pp',
                                                                                                           'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                           'prior_component': 'kubelet',
                                                                                                           'prior_description_sha256': '4230a771e1594417f624dceb14cffac13d02bfdc2573655f28bdcb431a58a239',
                                                                                                           'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                           'prior_remediation_sha256': '8e848f84ba4904e43d458a56a98d48e427b3a1e48855e291864acf6058f27d40',
                                                                                                           'reason': 'The '
                                                                                                                     'pinned '
                                                                                                                     'upstream '
                                                                                                                     'query '
                                                                                                                     'incorrectly '
                                                                                                                     'tests '
                                                                                                                     'a '
                                                                                                                     'kubelet '
                                                                                                                     'command '
                                                                                                                     'for '
                                                                                                                     'a '
                                                                                                                     'kube-controller-manager '
                                                                                                                     'flag. '
                                                                                                                     'Retain '
                                                                                                                     'historical '
                                                                                                                     'IDs '
                                                                                                                     'and '
                                                                                                                     'source '
                                                                                                                     'evidence; '
                                                                                                                     'correct '
                                                                                                                     'the '
                                                                                                                     'native '
                                                                                                                     'component '
                                                                                                                     'binding.',
                                                                                                           'source_relationship': 'Corrected '
                                                                                                                                  'native '
                                                                                                                                  'criterion '
                                                                                                                                  'derived '
                                                                                                                                  'from '
                                                                                                                                  'documented '
                                                                                                                                  'controller-manager '
                                                                                                                                  'behavior; '
                                                                                                                                  'not '
                                                                                                                                  'literal '
                                                                                                                                  'upstream '
                                                                                                                                  'SQL '
                                                                                                                                  'parity.',
                                                                                                           'status': 'source_erratum_successor',
                                                                                                           'upstream_document_sha256': '935d43b62528b25536540fa4fed46cea03d7c04c5f99c172ffd4b9be063f1976',
                                                                                                           'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                           'upstream_query_block_sha256': 'e5ee0102598a0c8af4485d84874d9b4427c240eeb7a05cbf32f778ad7a6d2f94',
                                                                                                           'upstream_query_source': 'query/deployment.pp:2359',
                                                                                                           'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/deployment.pp#L639',
                                                                                                           'upstream_sql_sha256': '6f23a8a7ded0b8bd004df76e050f37b5230d44a2b7ecd620556cc88a4c84cfd5',
                                                                                                           'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                            'remediation_fields': {'caveats': ['The '
                                                                                                                               'default '
                                                                                                                               '12500 '
                                                                                                                               'already '
                                                                                                                               'enables '
                                                                                                                               'garbage '
                                                                                                                               'collection; '
                                                                                                                               'this '
                                                                                                                               'check '
                                                                                                                               'needs '
                                                                                                                               'an '
                                                                                                                               'explicit '
                                                                                                                               'captured '
                                                                                                                               'value '
                                                                                                                               'and '
                                                                                                                               'does '
                                                                                                                               'not '
                                                                                                                               'read '
                                                                                                                               'the '
                                                                                                                               'running '
                                                                                                                               'controller '
                                                                                                                               'configuration.'],
                                                                                                                   'cli': [],
                                                                                                                   'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                     'expected': 0,
                                                                                                                                     'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                     'kind': 'deployment',
                                                                                                                                     'operation': 'gt',
                                                                                                                                     'target': 'resource'},
                                                                                                                   'references': [{'title': 'Kubernetes '
                                                                                                                                            'controller-manager '
                                                                                                                                            'GC '
                                                                                                                                            'threshold',
                                                                                                                                   'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                   'review_status': 'approved',
                                                                                                                   'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                         'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                         'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                         'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                         'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/deployment.pp',
                                                                                                                                         'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                         'prior_component': 'kubelet',
                                                                                                                                         'prior_description_sha256': '4230a771e1594417f624dceb14cffac13d02bfdc2573655f28bdcb431a58a239',
                                                                                                                                         'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                         'prior_remediation_sha256': '8e848f84ba4904e43d458a56a98d48e427b3a1e48855e291864acf6058f27d40',
                                                                                                                                         'reason': 'The '
                                                                                                                                                   'pinned '
                                                                                                                                                   'upstream '
                                                                                                                                                   'query '
                                                                                                                                                   'incorrectly '
                                                                                                                                                   'tests '
                                                                                                                                                   'a '
                                                                                                                                                   'kubelet '
                                                                                                                                                   'command '
                                                                                                                                                   'for '
                                                                                                                                                   'a '
                                                                                                                                                   'kube-controller-manager '
                                                                                                                                                   'flag. '
                                                                                                                                                   'Retain '
                                                                                                                                                   'historical '
                                                                                                                                                   'IDs '
                                                                                                                                                   'and '
                                                                                                                                                   'source '
                                                                                                                                                   'evidence; '
                                                                                                                                                   'correct '
                                                                                                                                                   'the '
                                                                                                                                                   'native '
                                                                                                                                                   'component '
                                                                                                                                                   'binding.',
                                                                                                                                         'source_relationship': 'Corrected '
                                                                                                                                                                'native '
                                                                                                                                                                'criterion '
                                                                                                                                                                'derived '
                                                                                                                                                                'from '
                                                                                                                                                                'documented '
                                                                                                                                                                'controller-manager '
                                                                                                                                                                'behavior; '
                                                                                                                                                                'not '
                                                                                                                                                                'literal '
                                                                                                                                                                'upstream '
                                                                                                                                                                'SQL '
                                                                                                                                                                'parity.',
                                                                                                                                         'status': 'source_erratum_successor',
                                                                                                                                         'upstream_document_sha256': '935d43b62528b25536540fa4fed46cea03d7c04c5f99c172ffd4b9be063f1976',
                                                                                                                                         'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                         'upstream_query_block_sha256': 'e5ee0102598a0c8af4485d84874d9b4427c240eeb7a05cbf32f778ad7a6d2f94',
                                                                                                                                         'upstream_query_source': 'query/deployment.pp:2359',
                                                                                                                                         'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/deployment.pp#L639',
                                                                                                                                         'upstream_sql_sha256': '6f23a8a7ded0b8bd004df76e050f37b5230d44a2b7ecd620556cc88a4c84cfd5',
                                                                                                                                         'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                   'steps': ['Set '
                                                                                                                             'a '
                                                                                                                             'positive '
                                                                                                                             'controller-manager '
                                                                                                                             'garbage-collection '
                                                                                                                             'threshold '
                                                                                                                             'suitable '
                                                                                                                             'for '
                                                                                                                             'the '
                                                                                                                             'cluster.'],
                                                                                                                   'summary': 'Set '
                                                                                                                              'a '
                                                                                                                              'positive '
                                                                                                                              'controller-manager '
                                                                                                                              'garbage-collection '
                                                                                                                              'threshold '
                                                                                                                              'suitable '
                                                                                                                              'for '
                                                                                                                              'the '
                                                                                                                              'cluster.'}},
 'k8s.ports.job.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                           'captured '
                                                                                                                           'kube-controller-manager '
                                                                                                                           'terminated-pod-gc-threshold '
                                                                                                                           'declarations '
                                                                                                                           'for '
                                                                                                                           'a '
                                                                                                                           'positive '
                                                                                                                           'integer.',
                                                                                                            'fail_when': 'An '
                                                                                                                         'applicable '
                                                                                                                         'complete '
                                                                                                                         'kube-controller-manager '
                                                                                                                         'declaration '
                                                                                                                         'explicitly '
                                                                                                                         'sets '
                                                                                                                         'terminated-pod-gc-threshold '
                                                                                                                         'to '
                                                                                                                         'zero; '
                                                                                                                         'malformed '
                                                                                                                         'or '
                                                                                                                         'missing '
                                                                                                                         'required '
                                                                                                                         'declarations '
                                                                                                                         'remain '
                                                                                                                         'UNKNOWN.',
                                                                                                            'not_applicable_when': 'No '
                                                                                                                                   'applicable '
                                                                                                                                   'kube-controller-manager '
                                                                                                                                   'declaration '
                                                                                                                                   'is '
                                                                                                                                   'captured '
                                                                                                                                   'and '
                                                                                                                                   'component '
                                                                                                                                   'applicability '
                                                                                                                                   'is '
                                                                                                                                   'otherwise '
                                                                                                                                   'complete. '
                                                                                                                                   'A '
                                                                                                                                   'kubelet '
                                                                                                                                   'declaration '
                                                                                                                                   'alone '
                                                                                                                                   'is '
                                                                                                                                   'outside '
                                                                                                                                   'this '
                                                                                                                                   'corrected '
                                                                                                                                   'control.',
                                                                                                            'pass_when': 'At '
                                                                                                                         'least '
                                                                                                                         'one '
                                                                                                                         'applicable '
                                                                                                                         'kube-controller-manager '
                                                                                                                         'declaration '
                                                                                                                         'is '
                                                                                                                         'captured; '
                                                                                                                         'every '
                                                                                                                         'applicable '
                                                                                                                         'declaration '
                                                                                                                         'has '
                                                                                                                         'complete '
                                                                                                                         'flags '
                                                                                                                         'and '
                                                                                                                         'an '
                                                                                                                         'explicitly '
                                                                                                                         'declared '
                                                                                                                         'positive '
                                                                                                                         'integer '
                                                                                                                         'threshold.',
                                                                                                            'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                  'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                  'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                  'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                  'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/job.pp',
                                                                                                                                  'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                  'prior_component': 'kubelet',
                                                                                                                                  'prior_description_sha256': '62d827e497baf0bfaca413441b78d5386ba6c21a29b60f2c9e2b1f3c9e10f06d',
                                                                                                                                  'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                  'prior_remediation_sha256': '3b6c99c662b3111c24657e4c6a93742084921d3edc8acb2bbe33494608396acb',
                                                                                                                                  'reason': 'The '
                                                                                                                                            'pinned '
                                                                                                                                            'upstream '
                                                                                                                                            'query '
                                                                                                                                            'incorrectly '
                                                                                                                                            'tests '
                                                                                                                                            'a '
                                                                                                                                            'kubelet '
                                                                                                                                            'command '
                                                                                                                                            'for '
                                                                                                                                            'a '
                                                                                                                                            'kube-controller-manager '
                                                                                                                                            'flag. '
                                                                                                                                            'Retain '
                                                                                                                                            'historical '
                                                                                                                                            'IDs '
                                                                                                                                            'and '
                                                                                                                                            'source '
                                                                                                                                            'evidence; '
                                                                                                                                            'correct '
                                                                                                                                            'the '
                                                                                                                                            'native '
                                                                                                                                            'component '
                                                                                                                                            'binding.',
                                                                                                                                  'source_relationship': 'Corrected '
                                                                                                                                                         'native '
                                                                                                                                                         'criterion '
                                                                                                                                                         'derived '
                                                                                                                                                         'from '
                                                                                                                                                         'documented '
                                                                                                                                                         'controller-manager '
                                                                                                                                                         'behavior; '
                                                                                                                                                         'not '
                                                                                                                                                         'literal '
                                                                                                                                                         'upstream '
                                                                                                                                                         'SQL '
                                                                                                                                                         'parity.',
                                                                                                                                  'status': 'source_erratum_successor',
                                                                                                                                  'upstream_document_sha256': '3870a2d1fd7d973d330f6dd65c127794eb3b438be812e59950c8dcc56040e907',
                                                                                                                                  'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                  'upstream_query_block_sha256': '68a2479489af401bb4c8d23c135e269ed3b2e36bc2cc8ce034bbb594e57a3bdf',
                                                                                                                                  'upstream_query_source': 'query/job.pp:2344',
                                                                                                                                  'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/job.pp#L631',
                                                                                                                                  'upstream_sql_sha256': '6eb6d29bfe5132bd41df8785b63e51ebdade2cfb57fad5c098fbfa20f2f52362',
                                                                                                                                  'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                     'provenance': {'current_component': 'kube-controller-manager',
                                                                                                    'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                    'historical_source_status': 'historical_invalid_component_binding',
                                                                                                    'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                    'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/job.pp',
                                                                                                    'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                    'prior_component': 'kubelet',
                                                                                                    'prior_description_sha256': '62d827e497baf0bfaca413441b78d5386ba6c21a29b60f2c9e2b1f3c9e10f06d',
                                                                                                    'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                    'prior_remediation_sha256': '3b6c99c662b3111c24657e4c6a93742084921d3edc8acb2bbe33494608396acb',
                                                                                                    'reason': 'The '
                                                                                                              'pinned '
                                                                                                              'upstream '
                                                                                                              'query '
                                                                                                              'incorrectly '
                                                                                                              'tests '
                                                                                                              'a '
                                                                                                              'kubelet '
                                                                                                              'command '
                                                                                                              'for '
                                                                                                              'a '
                                                                                                              'kube-controller-manager '
                                                                                                              'flag. '
                                                                                                              'Retain '
                                                                                                              'historical '
                                                                                                              'IDs '
                                                                                                              'and '
                                                                                                              'source '
                                                                                                              'evidence; '
                                                                                                              'correct '
                                                                                                              'the '
                                                                                                              'native '
                                                                                                              'component '
                                                                                                              'binding.',
                                                                                                    'source_relationship': 'Corrected '
                                                                                                                           'native '
                                                                                                                           'criterion '
                                                                                                                           'derived '
                                                                                                                           'from '
                                                                                                                           'documented '
                                                                                                                           'controller-manager '
                                                                                                                           'behavior; '
                                                                                                                           'not '
                                                                                                                           'literal '
                                                                                                                           'upstream '
                                                                                                                           'SQL '
                                                                                                                           'parity.',
                                                                                                    'status': 'source_erratum_successor',
                                                                                                    'upstream_document_sha256': '3870a2d1fd7d973d330f6dd65c127794eb3b438be812e59950c8dcc56040e907',
                                                                                                    'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                    'upstream_query_block_sha256': '68a2479489af401bb4c8d23c135e269ed3b2e36bc2cc8ce034bbb594e57a3bdf',
                                                                                                    'upstream_query_source': 'query/job.pp:2344',
                                                                                                    'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/job.pp#L631',
                                                                                                    'upstream_sql_sha256': '6eb6d29bfe5132bd41df8785b63e51ebdade2cfb57fad5c098fbfa20f2f52362',
                                                                                                    'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                     'remediation_fields': {'caveats': ['The '
                                                                                                                        'default '
                                                                                                                        '12500 '
                                                                                                                        'already '
                                                                                                                        'enables '
                                                                                                                        'garbage '
                                                                                                                        'collection; '
                                                                                                                        'this '
                                                                                                                        'check '
                                                                                                                        'needs '
                                                                                                                        'an '
                                                                                                                        'explicit '
                                                                                                                        'captured '
                                                                                                                        'value '
                                                                                                                        'and '
                                                                                                                        'does '
                                                                                                                        'not '
                                                                                                                        'read '
                                                                                                                        'the '
                                                                                                                        'running '
                                                                                                                        'controller '
                                                                                                                        'configuration.'],
                                                                                                            'cli': [],
                                                                                                            'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                              'expected': 0,
                                                                                                                              'fields': ['terminated-pod-gc-threshold'],
                                                                                                                              'kind': 'job',
                                                                                                                              'operation': 'gt',
                                                                                                                              'target': 'resource'},
                                                                                                            'references': [{'title': 'Kubernetes '
                                                                                                                                     'controller-manager '
                                                                                                                                     'GC '
                                                                                                                                     'threshold',
                                                                                                                            'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                            'review_status': 'approved',
                                                                                                            'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                  'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                  'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                  'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                  'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/job.pp',
                                                                                                                                  'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                  'prior_component': 'kubelet',
                                                                                                                                  'prior_description_sha256': '62d827e497baf0bfaca413441b78d5386ba6c21a29b60f2c9e2b1f3c9e10f06d',
                                                                                                                                  'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                  'prior_remediation_sha256': '3b6c99c662b3111c24657e4c6a93742084921d3edc8acb2bbe33494608396acb',
                                                                                                                                  'reason': 'The '
                                                                                                                                            'pinned '
                                                                                                                                            'upstream '
                                                                                                                                            'query '
                                                                                                                                            'incorrectly '
                                                                                                                                            'tests '
                                                                                                                                            'a '
                                                                                                                                            'kubelet '
                                                                                                                                            'command '
                                                                                                                                            'for '
                                                                                                                                            'a '
                                                                                                                                            'kube-controller-manager '
                                                                                                                                            'flag. '
                                                                                                                                            'Retain '
                                                                                                                                            'historical '
                                                                                                                                            'IDs '
                                                                                                                                            'and '
                                                                                                                                            'source '
                                                                                                                                            'evidence; '
                                                                                                                                            'correct '
                                                                                                                                            'the '
                                                                                                                                            'native '
                                                                                                                                            'component '
                                                                                                                                            'binding.',
                                                                                                                                  'source_relationship': 'Corrected '
                                                                                                                                                         'native '
                                                                                                                                                         'criterion '
                                                                                                                                                         'derived '
                                                                                                                                                         'from '
                                                                                                                                                         'documented '
                                                                                                                                                         'controller-manager '
                                                                                                                                                         'behavior; '
                                                                                                                                                         'not '
                                                                                                                                                         'literal '
                                                                                                                                                         'upstream '
                                                                                                                                                         'SQL '
                                                                                                                                                         'parity.',
                                                                                                                                  'status': 'source_erratum_successor',
                                                                                                                                  'upstream_document_sha256': '3870a2d1fd7d973d330f6dd65c127794eb3b438be812e59950c8dcc56040e907',
                                                                                                                                  'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                  'upstream_query_block_sha256': '68a2479489af401bb4c8d23c135e269ed3b2e36bc2cc8ce034bbb594e57a3bdf',
                                                                                                                                  'upstream_query_source': 'query/job.pp:2344',
                                                                                                                                  'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/job.pp#L631',
                                                                                                                                  'upstream_sql_sha256': '6eb6d29bfe5132bd41df8785b63e51ebdade2cfb57fad5c098fbfa20f2f52362',
                                                                                                                                  'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                            'steps': ['Set '
                                                                                                                      'a '
                                                                                                                      'positive '
                                                                                                                      'controller-manager '
                                                                                                                      'garbage-collection '
                                                                                                                      'threshold '
                                                                                                                      'suitable '
                                                                                                                      'for '
                                                                                                                      'the '
                                                                                                                      'cluster.'],
                                                                                                            'summary': 'Set '
                                                                                                                       'a '
                                                                                                                       'positive '
                                                                                                                       'controller-manager '
                                                                                                                       'garbage-collection '
                                                                                                                       'threshold '
                                                                                                                       'suitable '
                                                                                                                       'for '
                                                                                                                       'the '
                                                                                                                       'cluster.'}},
 'k8s.ports.pod.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                           'captured '
                                                                                                                           'kube-controller-manager '
                                                                                                                           'terminated-pod-gc-threshold '
                                                                                                                           'declarations '
                                                                                                                           'for '
                                                                                                                           'a '
                                                                                                                           'positive '
                                                                                                                           'integer.',
                                                                                                            'fail_when': 'An '
                                                                                                                         'applicable '
                                                                                                                         'complete '
                                                                                                                         'kube-controller-manager '
                                                                                                                         'declaration '
                                                                                                                         'explicitly '
                                                                                                                         'sets '
                                                                                                                         'terminated-pod-gc-threshold '
                                                                                                                         'to '
                                                                                                                         'zero; '
                                                                                                                         'malformed '
                                                                                                                         'or '
                                                                                                                         'missing '
                                                                                                                         'required '
                                                                                                                         'declarations '
                                                                                                                         'remain '
                                                                                                                         'UNKNOWN.',
                                                                                                            'not_applicable_when': 'No '
                                                                                                                                   'applicable '
                                                                                                                                   'kube-controller-manager '
                                                                                                                                   'declaration '
                                                                                                                                   'is '
                                                                                                                                   'captured '
                                                                                                                                   'and '
                                                                                                                                   'component '
                                                                                                                                   'applicability '
                                                                                                                                   'is '
                                                                                                                                   'otherwise '
                                                                                                                                   'complete. '
                                                                                                                                   'A '
                                                                                                                                   'kubelet '
                                                                                                                                   'declaration '
                                                                                                                                   'alone '
                                                                                                                                   'is '
                                                                                                                                   'outside '
                                                                                                                                   'this '
                                                                                                                                   'corrected '
                                                                                                                                   'control.',
                                                                                                            'pass_when': 'At '
                                                                                                                         'least '
                                                                                                                         'one '
                                                                                                                         'applicable '
                                                                                                                         'kube-controller-manager '
                                                                                                                         'declaration '
                                                                                                                         'is '
                                                                                                                         'captured; '
                                                                                                                         'every '
                                                                                                                         'applicable '
                                                                                                                         'declaration '
                                                                                                                         'has '
                                                                                                                         'complete '
                                                                                                                         'flags '
                                                                                                                         'and '
                                                                                                                         'an '
                                                                                                                         'explicitly '
                                                                                                                         'declared '
                                                                                                                         'positive '
                                                                                                                         'integer '
                                                                                                                         'threshold.',
                                                                                                            'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                  'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                  'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                  'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                  'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod.pp',
                                                                                                                                  'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                  'prior_component': 'kubelet',
                                                                                                                                  'prior_description_sha256': 'b9aa37d892b6265d25cfb379346f52c79585ad389669b7fce4e4c190483c1b7c',
                                                                                                                                  'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                  'prior_remediation_sha256': '3b560ddfe7a5938531099eecccc4ba12c6f17f229fa7a5a5fa1b35d647c7facf',
                                                                                                                                  'reason': 'The '
                                                                                                                                            'pinned '
                                                                                                                                            'upstream '
                                                                                                                                            'query '
                                                                                                                                            'incorrectly '
                                                                                                                                            'tests '
                                                                                                                                            'a '
                                                                                                                                            'kubelet '
                                                                                                                                            'command '
                                                                                                                                            'for '
                                                                                                                                            'a '
                                                                                                                                            'kube-controller-manager '
                                                                                                                                            'flag. '
                                                                                                                                            'Retain '
                                                                                                                                            'historical '
                                                                                                                                            'IDs '
                                                                                                                                            'and '
                                                                                                                                            'source '
                                                                                                                                            'evidence; '
                                                                                                                                            'correct '
                                                                                                                                            'the '
                                                                                                                                            'native '
                                                                                                                                            'component '
                                                                                                                                            'binding.',
                                                                                                                                  'source_relationship': 'Corrected '
                                                                                                                                                         'native '
                                                                                                                                                         'criterion '
                                                                                                                                                         'derived '
                                                                                                                                                         'from '
                                                                                                                                                         'documented '
                                                                                                                                                         'controller-manager '
                                                                                                                                                         'behavior; '
                                                                                                                                                         'not '
                                                                                                                                                         'literal '
                                                                                                                                                         'upstream '
                                                                                                                                                         'SQL '
                                                                                                                                                         'parity.',
                                                                                                                                  'status': 'source_erratum_successor',
                                                                                                                                  'upstream_document_sha256': '5891be377b137bf9c0496163064050627dfd77854eed29c55cbd5c7fb346c478',
                                                                                                                                  'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                  'upstream_query_block_sha256': '359dcd5b006066daaa6a2748c9314e278499b0e38a0b3cd7a1b2d2b74845e563',
                                                                                                                                  'upstream_query_source': 'query/pod.pp:2365',
                                                                                                                                  'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod.pp#L634',
                                                                                                                                  'upstream_sql_sha256': '7c140f9223ab9a38d0da396ae6d7a3f4596cc250077b7fa492ce41117ede7b0b',
                                                                                                                                  'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                     'provenance': {'current_component': 'kube-controller-manager',
                                                                                                    'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                    'historical_source_status': 'historical_invalid_component_binding',
                                                                                                    'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                    'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod.pp',
                                                                                                    'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                    'prior_component': 'kubelet',
                                                                                                    'prior_description_sha256': 'b9aa37d892b6265d25cfb379346f52c79585ad389669b7fce4e4c190483c1b7c',
                                                                                                    'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                    'prior_remediation_sha256': '3b560ddfe7a5938531099eecccc4ba12c6f17f229fa7a5a5fa1b35d647c7facf',
                                                                                                    'reason': 'The '
                                                                                                              'pinned '
                                                                                                              'upstream '
                                                                                                              'query '
                                                                                                              'incorrectly '
                                                                                                              'tests '
                                                                                                              'a '
                                                                                                              'kubelet '
                                                                                                              'command '
                                                                                                              'for '
                                                                                                              'a '
                                                                                                              'kube-controller-manager '
                                                                                                              'flag. '
                                                                                                              'Retain '
                                                                                                              'historical '
                                                                                                              'IDs '
                                                                                                              'and '
                                                                                                              'source '
                                                                                                              'evidence; '
                                                                                                              'correct '
                                                                                                              'the '
                                                                                                              'native '
                                                                                                              'component '
                                                                                                              'binding.',
                                                                                                    'source_relationship': 'Corrected '
                                                                                                                           'native '
                                                                                                                           'criterion '
                                                                                                                           'derived '
                                                                                                                           'from '
                                                                                                                           'documented '
                                                                                                                           'controller-manager '
                                                                                                                           'behavior; '
                                                                                                                           'not '
                                                                                                                           'literal '
                                                                                                                           'upstream '
                                                                                                                           'SQL '
                                                                                                                           'parity.',
                                                                                                    'status': 'source_erratum_successor',
                                                                                                    'upstream_document_sha256': '5891be377b137bf9c0496163064050627dfd77854eed29c55cbd5c7fb346c478',
                                                                                                    'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                    'upstream_query_block_sha256': '359dcd5b006066daaa6a2748c9314e278499b0e38a0b3cd7a1b2d2b74845e563',
                                                                                                    'upstream_query_source': 'query/pod.pp:2365',
                                                                                                    'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod.pp#L634',
                                                                                                    'upstream_sql_sha256': '7c140f9223ab9a38d0da396ae6d7a3f4596cc250077b7fa492ce41117ede7b0b',
                                                                                                    'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                     'remediation_fields': {'caveats': ['The '
                                                                                                                        'default '
                                                                                                                        '12500 '
                                                                                                                        'already '
                                                                                                                        'enables '
                                                                                                                        'garbage '
                                                                                                                        'collection; '
                                                                                                                        'this '
                                                                                                                        'check '
                                                                                                                        'needs '
                                                                                                                        'an '
                                                                                                                        'explicit '
                                                                                                                        'captured '
                                                                                                                        'value '
                                                                                                                        'and '
                                                                                                                        'does '
                                                                                                                        'not '
                                                                                                                        'read '
                                                                                                                        'the '
                                                                                                                        'running '
                                                                                                                        'controller '
                                                                                                                        'configuration.'],
                                                                                                            'cli': [],
                                                                                                            'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                              'expected': 0,
                                                                                                                              'fields': ['terminated-pod-gc-threshold'],
                                                                                                                              'kind': 'pod',
                                                                                                                              'operation': 'gt',
                                                                                                                              'target': 'resource'},
                                                                                                            'references': [{'title': 'Kubernetes '
                                                                                                                                     'controller-manager '
                                                                                                                                     'GC '
                                                                                                                                     'threshold',
                                                                                                                            'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                            'review_status': 'approved',
                                                                                                            'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                  'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                  'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                  'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                  'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod.pp',
                                                                                                                                  'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                  'prior_component': 'kubelet',
                                                                                                                                  'prior_description_sha256': 'b9aa37d892b6265d25cfb379346f52c79585ad389669b7fce4e4c190483c1b7c',
                                                                                                                                  'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                  'prior_remediation_sha256': '3b560ddfe7a5938531099eecccc4ba12c6f17f229fa7a5a5fa1b35d647c7facf',
                                                                                                                                  'reason': 'The '
                                                                                                                                            'pinned '
                                                                                                                                            'upstream '
                                                                                                                                            'query '
                                                                                                                                            'incorrectly '
                                                                                                                                            'tests '
                                                                                                                                            'a '
                                                                                                                                            'kubelet '
                                                                                                                                            'command '
                                                                                                                                            'for '
                                                                                                                                            'a '
                                                                                                                                            'kube-controller-manager '
                                                                                                                                            'flag. '
                                                                                                                                            'Retain '
                                                                                                                                            'historical '
                                                                                                                                            'IDs '
                                                                                                                                            'and '
                                                                                                                                            'source '
                                                                                                                                            'evidence; '
                                                                                                                                            'correct '
                                                                                                                                            'the '
                                                                                                                                            'native '
                                                                                                                                            'component '
                                                                                                                                            'binding.',
                                                                                                                                  'source_relationship': 'Corrected '
                                                                                                                                                         'native '
                                                                                                                                                         'criterion '
                                                                                                                                                         'derived '
                                                                                                                                                         'from '
                                                                                                                                                         'documented '
                                                                                                                                                         'controller-manager '
                                                                                                                                                         'behavior; '
                                                                                                                                                         'not '
                                                                                                                                                         'literal '
                                                                                                                                                         'upstream '
                                                                                                                                                         'SQL '
                                                                                                                                                         'parity.',
                                                                                                                                  'status': 'source_erratum_successor',
                                                                                                                                  'upstream_document_sha256': '5891be377b137bf9c0496163064050627dfd77854eed29c55cbd5c7fb346c478',
                                                                                                                                  'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                  'upstream_query_block_sha256': '359dcd5b006066daaa6a2748c9314e278499b0e38a0b3cd7a1b2d2b74845e563',
                                                                                                                                  'upstream_query_source': 'query/pod.pp:2365',
                                                                                                                                  'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod.pp#L634',
                                                                                                                                  'upstream_sql_sha256': '7c140f9223ab9a38d0da396ae6d7a3f4596cc250077b7fa492ce41117ede7b0b',
                                                                                                                                  'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                            'steps': ['Set '
                                                                                                                      'a '
                                                                                                                      'positive '
                                                                                                                      'controller-manager '
                                                                                                                      'garbage-collection '
                                                                                                                      'threshold '
                                                                                                                      'suitable '
                                                                                                                      'for '
                                                                                                                      'the '
                                                                                                                      'cluster.'],
                                                                                                            'summary': 'Set '
                                                                                                                       'a '
                                                                                                                       'positive '
                                                                                                                       'controller-manager '
                                                                                                                       'garbage-collection '
                                                                                                                       'threshold '
                                                                                                                       'suitable '
                                                                                                                       'for '
                                                                                                                       'the '
                                                                                                                       'cluster.'}},
 'k8s.ports.podtemplate.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                   'captured '
                                                                                                                                   'kube-controller-manager '
                                                                                                                                   'terminated-pod-gc-threshold '
                                                                                                                                   'declarations '
                                                                                                                                   'for '
                                                                                                                                   'a '
                                                                                                                                   'positive '
                                                                                                                                   'integer.',
                                                                                                                    'fail_when': 'An '
                                                                                                                                 'applicable '
                                                                                                                                 'complete '
                                                                                                                                 'kube-controller-manager '
                                                                                                                                 'declaration '
                                                                                                                                 'explicitly '
                                                                                                                                 'sets '
                                                                                                                                 'terminated-pod-gc-threshold '
                                                                                                                                 'to '
                                                                                                                                 'zero; '
                                                                                                                                 'malformed '
                                                                                                                                 'or '
                                                                                                                                 'missing '
                                                                                                                                 'required '
                                                                                                                                 'declarations '
                                                                                                                                 'remain '
                                                                                                                                 'UNKNOWN.',
                                                                                                                    'not_applicable_when': 'No '
                                                                                                                                           'applicable '
                                                                                                                                           'kube-controller-manager '
                                                                                                                                           'declaration '
                                                                                                                                           'is '
                                                                                                                                           'captured '
                                                                                                                                           'and '
                                                                                                                                           'component '
                                                                                                                                           'applicability '
                                                                                                                                           'is '
                                                                                                                                           'otherwise '
                                                                                                                                           'complete. '
                                                                                                                                           'A '
                                                                                                                                           'kubelet '
                                                                                                                                           'declaration '
                                                                                                                                           'alone '
                                                                                                                                           'is '
                                                                                                                                           'outside '
                                                                                                                                           'this '
                                                                                                                                           'corrected '
                                                                                                                                           'control.',
                                                                                                                    'pass_when': 'At '
                                                                                                                                 'least '
                                                                                                                                 'one '
                                                                                                                                 'applicable '
                                                                                                                                 'kube-controller-manager '
                                                                                                                                 'declaration '
                                                                                                                                 'is '
                                                                                                                                 'captured; '
                                                                                                                                 'every '
                                                                                                                                 'applicable '
                                                                                                                                 'declaration '
                                                                                                                                 'has '
                                                                                                                                 'complete '
                                                                                                                                 'flags '
                                                                                                                                 'and '
                                                                                                                                 'an '
                                                                                                                                 'explicitly '
                                                                                                                                 'declared '
                                                                                                                                 'positive '
                                                                                                                                 'integer '
                                                                                                                                 'threshold.',
                                                                                                                    'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                         'source '
                                                                                                                                                                         'query '
                                                                                                                                                                         'also '
                                                                                                                                                                         'inspects '
                                                                                                                                                                         'read-only-port '
                                                                                                                                                                         'rather '
                                                                                                                                                                         'than '
                                                                                                                                                                         'its '
                                                                                                                                                                         'named '
                                                                                                                                                                         'terminated-pod-gc-threshold '
                                                                                                                                                                         'setting.',
                                                                                                                                          'current_component': 'kube-controller-manager',
                                                                                                                                          'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                          'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                          'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                          'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod_template.pp',
                                                                                                                                          'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                          'prior_component': 'kubelet',
                                                                                                                                          'prior_description_sha256': 'b00db983cd3b8320b15e77dd9fb9b22f956f9dd40bd782ffd0fd064969aac803',
                                                                                                                                          'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                          'prior_remediation_sha256': '7f72965744c137ba84d95f2edfc4fe6e5101b6c4dc629d32f42cb92aefc8a467',
                                                                                                                                          'reason': 'The '
                                                                                                                                                    'pinned '
                                                                                                                                                    'upstream '
                                                                                                                                                    'query '
                                                                                                                                                    'incorrectly '
                                                                                                                                                    'tests '
                                                                                                                                                    'a '
                                                                                                                                                    'kubelet '
                                                                                                                                                    'command '
                                                                                                                                                    'for '
                                                                                                                                                    'a '
                                                                                                                                                    'kube-controller-manager '
                                                                                                                                                    'flag. '
                                                                                                                                                    'Retain '
                                                                                                                                                    'historical '
                                                                                                                                                    'IDs '
                                                                                                                                                    'and '
                                                                                                                                                    'source '
                                                                                                                                                    'evidence; '
                                                                                                                                                    'correct '
                                                                                                                                                    'the '
                                                                                                                                                    'native '
                                                                                                                                                    'component '
                                                                                                                                                    'binding.',
                                                                                                                                          'source_relationship': 'Corrected '
                                                                                                                                                                 'native '
                                                                                                                                                                 'criterion '
                                                                                                                                                                 'derived '
                                                                                                                                                                 'from '
                                                                                                                                                                 'documented '
                                                                                                                                                                 'controller-manager '
                                                                                                                                                                 'behavior; '
                                                                                                                                                                 'not '
                                                                                                                                                                 'literal '
                                                                                                                                                                 'upstream '
                                                                                                                                                                 'SQL '
                                                                                                                                                                 'parity.',
                                                                                                                                          'status': 'source_erratum_successor',
                                                                                                                                          'upstream_document_sha256': 'bc0c68233ecbaa2c97f51bfa5e9a933ec04da53d353dd022942926ee3fb240a7',
                                                                                                                                          'upstream_inspected_flag': 'read-only-port',
                                                                                                                                          'upstream_query_block_sha256': '5f539f7781fec16913c7017a90e1eaa8358af073545bf661c005401234fbb611',
                                                                                                                                          'upstream_query_source': 'query/pod_template.pp:2351',
                                                                                                                                          'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod_template.pp#L583',
                                                                                                                                          'upstream_sql_sha256': '95ff05a80926900acd6a4f120b408236999a910f4f9a59ee5786243ea231a931',
                                                                                                                                          'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                             'provenance': {'additional_upstream_erratum': 'This '
                                                                                                                                           'source '
                                                                                                                                           'query '
                                                                                                                                           'also '
                                                                                                                                           'inspects '
                                                                                                                                           'read-only-port '
                                                                                                                                           'rather '
                                                                                                                                           'than '
                                                                                                                                           'its '
                                                                                                                                           'named '
                                                                                                                                           'terminated-pod-gc-threshold '
                                                                                                                                           'setting.',
                                                                                                            'current_component': 'kube-controller-manager',
                                                                                                            'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                            'historical_source_status': 'historical_invalid_component_binding',
                                                                                                            'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                            'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod_template.pp',
                                                                                                            'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                            'prior_component': 'kubelet',
                                                                                                            'prior_description_sha256': 'b00db983cd3b8320b15e77dd9fb9b22f956f9dd40bd782ffd0fd064969aac803',
                                                                                                            'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                            'prior_remediation_sha256': '7f72965744c137ba84d95f2edfc4fe6e5101b6c4dc629d32f42cb92aefc8a467',
                                                                                                            'reason': 'The '
                                                                                                                      'pinned '
                                                                                                                      'upstream '
                                                                                                                      'query '
                                                                                                                      'incorrectly '
                                                                                                                      'tests '
                                                                                                                      'a '
                                                                                                                      'kubelet '
                                                                                                                      'command '
                                                                                                                      'for '
                                                                                                                      'a '
                                                                                                                      'kube-controller-manager '
                                                                                                                      'flag. '
                                                                                                                      'Retain '
                                                                                                                      'historical '
                                                                                                                      'IDs '
                                                                                                                      'and '
                                                                                                                      'source '
                                                                                                                      'evidence; '
                                                                                                                      'correct '
                                                                                                                      'the '
                                                                                                                      'native '
                                                                                                                      'component '
                                                                                                                      'binding.',
                                                                                                            'source_relationship': 'Corrected '
                                                                                                                                   'native '
                                                                                                                                   'criterion '
                                                                                                                                   'derived '
                                                                                                                                   'from '
                                                                                                                                   'documented '
                                                                                                                                   'controller-manager '
                                                                                                                                   'behavior; '
                                                                                                                                   'not '
                                                                                                                                   'literal '
                                                                                                                                   'upstream '
                                                                                                                                   'SQL '
                                                                                                                                   'parity.',
                                                                                                            'status': 'source_erratum_successor',
                                                                                                            'upstream_document_sha256': 'bc0c68233ecbaa2c97f51bfa5e9a933ec04da53d353dd022942926ee3fb240a7',
                                                                                                            'upstream_inspected_flag': 'read-only-port',
                                                                                                            'upstream_query_block_sha256': '5f539f7781fec16913c7017a90e1eaa8358af073545bf661c005401234fbb611',
                                                                                                            'upstream_query_source': 'query/pod_template.pp:2351',
                                                                                                            'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod_template.pp#L583',
                                                                                                            'upstream_sql_sha256': '95ff05a80926900acd6a4f120b408236999a910f4f9a59ee5786243ea231a931',
                                                                                                            'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                             'remediation_fields': {'caveats': ['The '
                                                                                                                                'default '
                                                                                                                                '12500 '
                                                                                                                                'already '
                                                                                                                                'enables '
                                                                                                                                'garbage '
                                                                                                                                'collection; '
                                                                                                                                'this '
                                                                                                                                'check '
                                                                                                                                'needs '
                                                                                                                                'an '
                                                                                                                                'explicit '
                                                                                                                                'captured '
                                                                                                                                'value '
                                                                                                                                'and '
                                                                                                                                'does '
                                                                                                                                'not '
                                                                                                                                'read '
                                                                                                                                'the '
                                                                                                                                'running '
                                                                                                                                'controller '
                                                                                                                                'configuration.'],
                                                                                                                    'cli': [],
                                                                                                                    'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                      'expected': 0,
                                                                                                                                      'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                      'kind': 'podtemplate',
                                                                                                                                      'operation': 'gt',
                                                                                                                                      'target': 'resource'},
                                                                                                                    'references': [{'title': 'Kubernetes '
                                                                                                                                             'controller-manager '
                                                                                                                                             'GC '
                                                                                                                                             'threshold',
                                                                                                                                    'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                    'review_status': 'approved',
                                                                                                                    'source_correction': {'additional_upstream_erratum': 'This '
                                                                                                                                                                         'source '
                                                                                                                                                                         'query '
                                                                                                                                                                         'also '
                                                                                                                                                                         'inspects '
                                                                                                                                                                         'read-only-port '
                                                                                                                                                                         'rather '
                                                                                                                                                                         'than '
                                                                                                                                                                         'its '
                                                                                                                                                                         'named '
                                                                                                                                                                         'terminated-pod-gc-threshold '
                                                                                                                                                                         'setting.',
                                                                                                                                          'current_component': 'kube-controller-manager',
                                                                                                                                          'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                          'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                          'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                          'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/pod_template.pp',
                                                                                                                                          'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                          'prior_component': 'kubelet',
                                                                                                                                          'prior_description_sha256': 'b00db983cd3b8320b15e77dd9fb9b22f956f9dd40bd782ffd0fd064969aac803',
                                                                                                                                          'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                          'prior_remediation_sha256': '7f72965744c137ba84d95f2edfc4fe6e5101b6c4dc629d32f42cb92aefc8a467',
                                                                                                                                          'reason': 'The '
                                                                                                                                                    'pinned '
                                                                                                                                                    'upstream '
                                                                                                                                                    'query '
                                                                                                                                                    'incorrectly '
                                                                                                                                                    'tests '
                                                                                                                                                    'a '
                                                                                                                                                    'kubelet '
                                                                                                                                                    'command '
                                                                                                                                                    'for '
                                                                                                                                                    'a '
                                                                                                                                                    'kube-controller-manager '
                                                                                                                                                    'flag. '
                                                                                                                                                    'Retain '
                                                                                                                                                    'historical '
                                                                                                                                                    'IDs '
                                                                                                                                                    'and '
                                                                                                                                                    'source '
                                                                                                                                                    'evidence; '
                                                                                                                                                    'correct '
                                                                                                                                                    'the '
                                                                                                                                                    'native '
                                                                                                                                                    'component '
                                                                                                                                                    'binding.',
                                                                                                                                          'source_relationship': 'Corrected '
                                                                                                                                                                 'native '
                                                                                                                                                                 'criterion '
                                                                                                                                                                 'derived '
                                                                                                                                                                 'from '
                                                                                                                                                                 'documented '
                                                                                                                                                                 'controller-manager '
                                                                                                                                                                 'behavior; '
                                                                                                                                                                 'not '
                                                                                                                                                                 'literal '
                                                                                                                                                                 'upstream '
                                                                                                                                                                 'SQL '
                                                                                                                                                                 'parity.',
                                                                                                                                          'status': 'source_erratum_successor',
                                                                                                                                          'upstream_document_sha256': 'bc0c68233ecbaa2c97f51bfa5e9a933ec04da53d353dd022942926ee3fb240a7',
                                                                                                                                          'upstream_inspected_flag': 'read-only-port',
                                                                                                                                          'upstream_query_block_sha256': '5f539f7781fec16913c7017a90e1eaa8358af073545bf661c005401234fbb611',
                                                                                                                                          'upstream_query_source': 'query/pod_template.pp:2351',
                                                                                                                                          'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/pod_template.pp#L583',
                                                                                                                                          'upstream_sql_sha256': '95ff05a80926900acd6a4f120b408236999a910f4f9a59ee5786243ea231a931',
                                                                                                                                          'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                    'steps': ['Set '
                                                                                                                              'a '
                                                                                                                              'positive '
                                                                                                                              'controller-manager '
                                                                                                                              'garbage-collection '
                                                                                                                              'threshold '
                                                                                                                              'suitable '
                                                                                                                              'for '
                                                                                                                              'the '
                                                                                                                              'cluster.'],
                                                                                                                    'summary': 'Set '
                                                                                                                               'a '
                                                                                                                               'positive '
                                                                                                                               'controller-manager '
                                                                                                                               'garbage-collection '
                                                                                                                               'threshold '
                                                                                                                               'suitable '
                                                                                                                               'for '
                                                                                                                               'the '
                                                                                                                               'cluster.'}},
 'k8s.ports.replicaset.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                  'captured '
                                                                                                                                  'kube-controller-manager '
                                                                                                                                  'terminated-pod-gc-threshold '
                                                                                                                                  'declarations '
                                                                                                                                  'for '
                                                                                                                                  'a '
                                                                                                                                  'positive '
                                                                                                                                  'integer.',
                                                                                                                   'fail_when': 'An '
                                                                                                                                'applicable '
                                                                                                                                'complete '
                                                                                                                                'kube-controller-manager '
                                                                                                                                'declaration '
                                                                                                                                'explicitly '
                                                                                                                                'sets '
                                                                                                                                'terminated-pod-gc-threshold '
                                                                                                                                'to '
                                                                                                                                'zero; '
                                                                                                                                'malformed '
                                                                                                                                'or '
                                                                                                                                'missing '
                                                                                                                                'required '
                                                                                                                                'declarations '
                                                                                                                                'remain '
                                                                                                                                'UNKNOWN.',
                                                                                                                   'not_applicable_when': 'No '
                                                                                                                                          'applicable '
                                                                                                                                          'kube-controller-manager '
                                                                                                                                          'declaration '
                                                                                                                                          'is '
                                                                                                                                          'captured '
                                                                                                                                          'and '
                                                                                                                                          'component '
                                                                                                                                          'applicability '
                                                                                                                                          'is '
                                                                                                                                          'otherwise '
                                                                                                                                          'complete. '
                                                                                                                                          'A '
                                                                                                                                          'kubelet '
                                                                                                                                          'declaration '
                                                                                                                                          'alone '
                                                                                                                                          'is '
                                                                                                                                          'outside '
                                                                                                                                          'this '
                                                                                                                                          'corrected '
                                                                                                                                          'control.',
                                                                                                                   'pass_when': 'At '
                                                                                                                                'least '
                                                                                                                                'one '
                                                                                                                                'applicable '
                                                                                                                                'kube-controller-manager '
                                                                                                                                'declaration '
                                                                                                                                'is '
                                                                                                                                'captured; '
                                                                                                                                'every '
                                                                                                                                'applicable '
                                                                                                                                'declaration '
                                                                                                                                'has '
                                                                                                                                'complete '
                                                                                                                                'flags '
                                                                                                                                'and '
                                                                                                                                'an '
                                                                                                                                'explicitly '
                                                                                                                                'declared '
                                                                                                                                'positive '
                                                                                                                                'integer '
                                                                                                                                'threshold.',
                                                                                                                   'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                         'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                         'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                         'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                         'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replicaset.pp',
                                                                                                                                         'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                         'prior_component': 'kubelet',
                                                                                                                                         'prior_description_sha256': 'eaeb2f255d49110cbcf2c4c2ddc1378ce8472745b052bbb65354931477190e15',
                                                                                                                                         'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                         'prior_remediation_sha256': '09cddc1842a780ecac67a6d0ede6d17de699c1f176b2cd8c3f22ed1a7880fd31',
                                                                                                                                         'reason': 'The '
                                                                                                                                                   'pinned '
                                                                                                                                                   'upstream '
                                                                                                                                                   'query '
                                                                                                                                                   'incorrectly '
                                                                                                                                                   'tests '
                                                                                                                                                   'a '
                                                                                                                                                   'kubelet '
                                                                                                                                                   'command '
                                                                                                                                                   'for '
                                                                                                                                                   'a '
                                                                                                                                                   'kube-controller-manager '
                                                                                                                                                   'flag. '
                                                                                                                                                   'Retain '
                                                                                                                                                   'historical '
                                                                                                                                                   'IDs '
                                                                                                                                                   'and '
                                                                                                                                                   'source '
                                                                                                                                                   'evidence; '
                                                                                                                                                   'correct '
                                                                                                                                                   'the '
                                                                                                                                                   'native '
                                                                                                                                                   'component '
                                                                                                                                                   'binding.',
                                                                                                                                         'source_relationship': 'Corrected '
                                                                                                                                                                'native '
                                                                                                                                                                'criterion '
                                                                                                                                                                'derived '
                                                                                                                                                                'from '
                                                                                                                                                                'documented '
                                                                                                                                                                'controller-manager '
                                                                                                                                                                'behavior; '
                                                                                                                                                                'not '
                                                                                                                                                                'literal '
                                                                                                                                                                'upstream '
                                                                                                                                                                'SQL '
                                                                                                                                                                'parity.',
                                                                                                                                         'status': 'source_erratum_successor',
                                                                                                                                         'upstream_document_sha256': '646fee068fb9452474e5eb4fe1e66aa8ef56e934d76398a4dfc6fbb18695fbe5',
                                                                                                                                         'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                         'upstream_query_block_sha256': '4e123cfe842c56c8993dd0a0591af57f19de59f89a5ff8651ed3d80b0d13514c',
                                                                                                                                         'upstream_query_source': 'query/replicaset.pp:2343',
                                                                                                                                         'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replicaset.pp#L632',
                                                                                                                                         'upstream_sql_sha256': 'f671738ce732fe43cb23c7b801c16eabf870a38979c8c3fed8141df86c214c08',
                                                                                                                                         'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                            'provenance': {'current_component': 'kube-controller-manager',
                                                                                                           'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                           'historical_source_status': 'historical_invalid_component_binding',
                                                                                                           'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                           'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replicaset.pp',
                                                                                                           'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                           'prior_component': 'kubelet',
                                                                                                           'prior_description_sha256': 'eaeb2f255d49110cbcf2c4c2ddc1378ce8472745b052bbb65354931477190e15',
                                                                                                           'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                           'prior_remediation_sha256': '09cddc1842a780ecac67a6d0ede6d17de699c1f176b2cd8c3f22ed1a7880fd31',
                                                                                                           'reason': 'The '
                                                                                                                     'pinned '
                                                                                                                     'upstream '
                                                                                                                     'query '
                                                                                                                     'incorrectly '
                                                                                                                     'tests '
                                                                                                                     'a '
                                                                                                                     'kubelet '
                                                                                                                     'command '
                                                                                                                     'for '
                                                                                                                     'a '
                                                                                                                     'kube-controller-manager '
                                                                                                                     'flag. '
                                                                                                                     'Retain '
                                                                                                                     'historical '
                                                                                                                     'IDs '
                                                                                                                     'and '
                                                                                                                     'source '
                                                                                                                     'evidence; '
                                                                                                                     'correct '
                                                                                                                     'the '
                                                                                                                     'native '
                                                                                                                     'component '
                                                                                                                     'binding.',
                                                                                                           'source_relationship': 'Corrected '
                                                                                                                                  'native '
                                                                                                                                  'criterion '
                                                                                                                                  'derived '
                                                                                                                                  'from '
                                                                                                                                  'documented '
                                                                                                                                  'controller-manager '
                                                                                                                                  'behavior; '
                                                                                                                                  'not '
                                                                                                                                  'literal '
                                                                                                                                  'upstream '
                                                                                                                                  'SQL '
                                                                                                                                  'parity.',
                                                                                                           'status': 'source_erratum_successor',
                                                                                                           'upstream_document_sha256': '646fee068fb9452474e5eb4fe1e66aa8ef56e934d76398a4dfc6fbb18695fbe5',
                                                                                                           'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                           'upstream_query_block_sha256': '4e123cfe842c56c8993dd0a0591af57f19de59f89a5ff8651ed3d80b0d13514c',
                                                                                                           'upstream_query_source': 'query/replicaset.pp:2343',
                                                                                                           'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replicaset.pp#L632',
                                                                                                           'upstream_sql_sha256': 'f671738ce732fe43cb23c7b801c16eabf870a38979c8c3fed8141df86c214c08',
                                                                                                           'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                            'remediation_fields': {'caveats': ['The '
                                                                                                                               'default '
                                                                                                                               '12500 '
                                                                                                                               'already '
                                                                                                                               'enables '
                                                                                                                               'garbage '
                                                                                                                               'collection; '
                                                                                                                               'this '
                                                                                                                               'check '
                                                                                                                               'needs '
                                                                                                                               'an '
                                                                                                                               'explicit '
                                                                                                                               'captured '
                                                                                                                               'value '
                                                                                                                               'and '
                                                                                                                               'does '
                                                                                                                               'not '
                                                                                                                               'read '
                                                                                                                               'the '
                                                                                                                               'running '
                                                                                                                               'controller '
                                                                                                                               'configuration.'],
                                                                                                                   'cli': [],
                                                                                                                   'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                     'expected': 0,
                                                                                                                                     'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                     'kind': 'replicaset',
                                                                                                                                     'operation': 'gt',
                                                                                                                                     'target': 'resource'},
                                                                                                                   'references': [{'title': 'Kubernetes '
                                                                                                                                            'controller-manager '
                                                                                                                                            'GC '
                                                                                                                                            'threshold',
                                                                                                                                   'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                   'review_status': 'approved',
                                                                                                                   'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                         'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                         'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                         'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                         'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replicaset.pp',
                                                                                                                                         'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                         'prior_component': 'kubelet',
                                                                                                                                         'prior_description_sha256': 'eaeb2f255d49110cbcf2c4c2ddc1378ce8472745b052bbb65354931477190e15',
                                                                                                                                         'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                         'prior_remediation_sha256': '09cddc1842a780ecac67a6d0ede6d17de699c1f176b2cd8c3f22ed1a7880fd31',
                                                                                                                                         'reason': 'The '
                                                                                                                                                   'pinned '
                                                                                                                                                   'upstream '
                                                                                                                                                   'query '
                                                                                                                                                   'incorrectly '
                                                                                                                                                   'tests '
                                                                                                                                                   'a '
                                                                                                                                                   'kubelet '
                                                                                                                                                   'command '
                                                                                                                                                   'for '
                                                                                                                                                   'a '
                                                                                                                                                   'kube-controller-manager '
                                                                                                                                                   'flag. '
                                                                                                                                                   'Retain '
                                                                                                                                                   'historical '
                                                                                                                                                   'IDs '
                                                                                                                                                   'and '
                                                                                                                                                   'source '
                                                                                                                                                   'evidence; '
                                                                                                                                                   'correct '
                                                                                                                                                   'the '
                                                                                                                                                   'native '
                                                                                                                                                   'component '
                                                                                                                                                   'binding.',
                                                                                                                                         'source_relationship': 'Corrected '
                                                                                                                                                                'native '
                                                                                                                                                                'criterion '
                                                                                                                                                                'derived '
                                                                                                                                                                'from '
                                                                                                                                                                'documented '
                                                                                                                                                                'controller-manager '
                                                                                                                                                                'behavior; '
                                                                                                                                                                'not '
                                                                                                                                                                'literal '
                                                                                                                                                                'upstream '
                                                                                                                                                                'SQL '
                                                                                                                                                                'parity.',
                                                                                                                                         'status': 'source_erratum_successor',
                                                                                                                                         'upstream_document_sha256': '646fee068fb9452474e5eb4fe1e66aa8ef56e934d76398a4dfc6fbb18695fbe5',
                                                                                                                                         'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                         'upstream_query_block_sha256': '4e123cfe842c56c8993dd0a0591af57f19de59f89a5ff8651ed3d80b0d13514c',
                                                                                                                                         'upstream_query_source': 'query/replicaset.pp:2343',
                                                                                                                                         'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replicaset.pp#L632',
                                                                                                                                         'upstream_sql_sha256': 'f671738ce732fe43cb23c7b801c16eabf870a38979c8c3fed8141df86c214c08',
                                                                                                                                         'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                   'steps': ['Set '
                                                                                                                             'a '
                                                                                                                             'positive '
                                                                                                                             'controller-manager '
                                                                                                                             'garbage-collection '
                                                                                                                             'threshold '
                                                                                                                             'suitable '
                                                                                                                             'for '
                                                                                                                             'the '
                                                                                                                             'cluster.'],
                                                                                                                   'summary': 'Set '
                                                                                                                              'a '
                                                                                                                              'positive '
                                                                                                                              'controller-manager '
                                                                                                                              'garbage-collection '
                                                                                                                              'threshold '
                                                                                                                              'suitable '
                                                                                                                              'for '
                                                                                                                              'the '
                                                                                                                              'cluster.'}},
 'k8s.ports.replicationcontroller.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                             'captured '
                                                                                                                                             'kube-controller-manager '
                                                                                                                                             'terminated-pod-gc-threshold '
                                                                                                                                             'declarations '
                                                                                                                                             'for '
                                                                                                                                             'a '
                                                                                                                                             'positive '
                                                                                                                                             'integer.',
                                                                                                                              'fail_when': 'An '
                                                                                                                                           'applicable '
                                                                                                                                           'complete '
                                                                                                                                           'kube-controller-manager '
                                                                                                                                           'declaration '
                                                                                                                                           'explicitly '
                                                                                                                                           'sets '
                                                                                                                                           'terminated-pod-gc-threshold '
                                                                                                                                           'to '
                                                                                                                                           'zero; '
                                                                                                                                           'malformed '
                                                                                                                                           'or '
                                                                                                                                           'missing '
                                                                                                                                           'required '
                                                                                                                                           'declarations '
                                                                                                                                           'remain '
                                                                                                                                           'UNKNOWN.',
                                                                                                                              'not_applicable_when': 'No '
                                                                                                                                                     'applicable '
                                                                                                                                                     'kube-controller-manager '
                                                                                                                                                     'declaration '
                                                                                                                                                     'is '
                                                                                                                                                     'captured '
                                                                                                                                                     'and '
                                                                                                                                                     'component '
                                                                                                                                                     'applicability '
                                                                                                                                                     'is '
                                                                                                                                                     'otherwise '
                                                                                                                                                     'complete. '
                                                                                                                                                     'A '
                                                                                                                                                     'kubelet '
                                                                                                                                                     'declaration '
                                                                                                                                                     'alone '
                                                                                                                                                     'is '
                                                                                                                                                     'outside '
                                                                                                                                                     'this '
                                                                                                                                                     'corrected '
                                                                                                                                                     'control.',
                                                                                                                              'pass_when': 'At '
                                                                                                                                           'least '
                                                                                                                                           'one '
                                                                                                                                           'applicable '
                                                                                                                                           'kube-controller-manager '
                                                                                                                                           'declaration '
                                                                                                                                           'is '
                                                                                                                                           'captured; '
                                                                                                                                           'every '
                                                                                                                                           'applicable '
                                                                                                                                           'declaration '
                                                                                                                                           'has '
                                                                                                                                           'complete '
                                                                                                                                           'flags '
                                                                                                                                           'and '
                                                                                                                                           'an '
                                                                                                                                           'explicitly '
                                                                                                                                           'declared '
                                                                                                                                           'positive '
                                                                                                                                           'integer '
                                                                                                                                           'threshold.',
                                                                                                                              'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                                    'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                                    'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                                    'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                                    'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replication_controller.pp',
                                                                                                                                                    'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                                    'prior_component': 'kubelet',
                                                                                                                                                    'prior_description_sha256': '659d551a22d68e66304dc881299a5be533e3d9e70eeecb54fdeb74c0e7ca590a',
                                                                                                                                                    'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                                    'prior_remediation_sha256': 'b88e4c2665c2b4140a40a2576043fdb5cb04334bae8a1b201c617e10de1e720c',
                                                                                                                                                    'reason': 'The '
                                                                                                                                                              'pinned '
                                                                                                                                                              'upstream '
                                                                                                                                                              'query '
                                                                                                                                                              'incorrectly '
                                                                                                                                                              'tests '
                                                                                                                                                              'a '
                                                                                                                                                              'kubelet '
                                                                                                                                                              'command '
                                                                                                                                                              'for '
                                                                                                                                                              'a '
                                                                                                                                                              'kube-controller-manager '
                                                                                                                                                              'flag. '
                                                                                                                                                              'Retain '
                                                                                                                                                              'historical '
                                                                                                                                                              'IDs '
                                                                                                                                                              'and '
                                                                                                                                                              'source '
                                                                                                                                                              'evidence; '
                                                                                                                                                              'correct '
                                                                                                                                                              'the '
                                                                                                                                                              'native '
                                                                                                                                                              'component '
                                                                                                                                                              'binding.',
                                                                                                                                                    'source_relationship': 'Corrected '
                                                                                                                                                                           'native '
                                                                                                                                                                           'criterion '
                                                                                                                                                                           'derived '
                                                                                                                                                                           'from '
                                                                                                                                                                           'documented '
                                                                                                                                                                           'controller-manager '
                                                                                                                                                                           'behavior; '
                                                                                                                                                                           'not '
                                                                                                                                                                           'literal '
                                                                                                                                                                           'upstream '
                                                                                                                                                                           'SQL '
                                                                                                                                                                           'parity.',
                                                                                                                                                    'status': 'source_erratum_successor',
                                                                                                                                                    'upstream_document_sha256': '8730c1e22bd7e526e60542ba74cccf54cd7dbdd2aa244e52b568c5221d4939c1',
                                                                                                                                                    'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                                    'upstream_query_block_sha256': 'e3d9c1a8e1cd4749039adb1644c8ffcbbd862e89bd687ae386f5ee1a9427adfb',
                                                                                                                                                    'upstream_query_source': 'query/replication_controller.pp:2342',
                                                                                                                                                    'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replication_controller.pp#L631',
                                                                                                                                                    'upstream_sql_sha256': 'bada9933bcb5b6123007f79c4d11ecbe8f05c60623f574c6165f3e63301d30b7',
                                                                                                                                                    'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                                       'provenance': {'current_component': 'kube-controller-manager',
                                                                                                                      'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                      'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                      'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                      'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replication_controller.pp',
                                                                                                                      'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                      'prior_component': 'kubelet',
                                                                                                                      'prior_description_sha256': '659d551a22d68e66304dc881299a5be533e3d9e70eeecb54fdeb74c0e7ca590a',
                                                                                                                      'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                      'prior_remediation_sha256': 'b88e4c2665c2b4140a40a2576043fdb5cb04334bae8a1b201c617e10de1e720c',
                                                                                                                      'reason': 'The '
                                                                                                                                'pinned '
                                                                                                                                'upstream '
                                                                                                                                'query '
                                                                                                                                'incorrectly '
                                                                                                                                'tests '
                                                                                                                                'a '
                                                                                                                                'kubelet '
                                                                                                                                'command '
                                                                                                                                'for '
                                                                                                                                'a '
                                                                                                                                'kube-controller-manager '
                                                                                                                                'flag. '
                                                                                                                                'Retain '
                                                                                                                                'historical '
                                                                                                                                'IDs '
                                                                                                                                'and '
                                                                                                                                'source '
                                                                                                                                'evidence; '
                                                                                                                                'correct '
                                                                                                                                'the '
                                                                                                                                'native '
                                                                                                                                'component '
                                                                                                                                'binding.',
                                                                                                                      'source_relationship': 'Corrected '
                                                                                                                                             'native '
                                                                                                                                             'criterion '
                                                                                                                                             'derived '
                                                                                                                                             'from '
                                                                                                                                             'documented '
                                                                                                                                             'controller-manager '
                                                                                                                                             'behavior; '
                                                                                                                                             'not '
                                                                                                                                             'literal '
                                                                                                                                             'upstream '
                                                                                                                                             'SQL '
                                                                                                                                             'parity.',
                                                                                                                      'status': 'source_erratum_successor',
                                                                                                                      'upstream_document_sha256': '8730c1e22bd7e526e60542ba74cccf54cd7dbdd2aa244e52b568c5221d4939c1',
                                                                                                                      'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                      'upstream_query_block_sha256': 'e3d9c1a8e1cd4749039adb1644c8ffcbbd862e89bd687ae386f5ee1a9427adfb',
                                                                                                                      'upstream_query_source': 'query/replication_controller.pp:2342',
                                                                                                                      'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replication_controller.pp#L631',
                                                                                                                      'upstream_sql_sha256': 'bada9933bcb5b6123007f79c4d11ecbe8f05c60623f574c6165f3e63301d30b7',
                                                                                                                      'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                       'remediation_fields': {'caveats': ['The '
                                                                                                                                          'default '
                                                                                                                                          '12500 '
                                                                                                                                          'already '
                                                                                                                                          'enables '
                                                                                                                                          'garbage '
                                                                                                                                          'collection; '
                                                                                                                                          'this '
                                                                                                                                          'check '
                                                                                                                                          'needs '
                                                                                                                                          'an '
                                                                                                                                          'explicit '
                                                                                                                                          'captured '
                                                                                                                                          'value '
                                                                                                                                          'and '
                                                                                                                                          'does '
                                                                                                                                          'not '
                                                                                                                                          'read '
                                                                                                                                          'the '
                                                                                                                                          'running '
                                                                                                                                          'controller '
                                                                                                                                          'configuration.'],
                                                                                                                              'cli': [],
                                                                                                                              'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                                'expected': 0,
                                                                                                                                                'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                                'kind': 'replicationcontroller',
                                                                                                                                                'operation': 'gt',
                                                                                                                                                'target': 'resource'},
                                                                                                                              'references': [{'title': 'Kubernetes '
                                                                                                                                                       'controller-manager '
                                                                                                                                                       'GC '
                                                                                                                                                       'threshold',
                                                                                                                                              'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                              'review_status': 'approved',
                                                                                                                              'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                                    'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                                    'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                                    'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                                    'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/replication_controller.pp',
                                                                                                                                                    'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                                    'prior_component': 'kubelet',
                                                                                                                                                    'prior_description_sha256': '659d551a22d68e66304dc881299a5be533e3d9e70eeecb54fdeb74c0e7ca590a',
                                                                                                                                                    'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                                    'prior_remediation_sha256': 'b88e4c2665c2b4140a40a2576043fdb5cb04334bae8a1b201c617e10de1e720c',
                                                                                                                                                    'reason': 'The '
                                                                                                                                                              'pinned '
                                                                                                                                                              'upstream '
                                                                                                                                                              'query '
                                                                                                                                                              'incorrectly '
                                                                                                                                                              'tests '
                                                                                                                                                              'a '
                                                                                                                                                              'kubelet '
                                                                                                                                                              'command '
                                                                                                                                                              'for '
                                                                                                                                                              'a '
                                                                                                                                                              'kube-controller-manager '
                                                                                                                                                              'flag. '
                                                                                                                                                              'Retain '
                                                                                                                                                              'historical '
                                                                                                                                                              'IDs '
                                                                                                                                                              'and '
                                                                                                                                                              'source '
                                                                                                                                                              'evidence; '
                                                                                                                                                              'correct '
                                                                                                                                                              'the '
                                                                                                                                                              'native '
                                                                                                                                                              'component '
                                                                                                                                                              'binding.',
                                                                                                                                                    'source_relationship': 'Corrected '
                                                                                                                                                                           'native '
                                                                                                                                                                           'criterion '
                                                                                                                                                                           'derived '
                                                                                                                                                                           'from '
                                                                                                                                                                           'documented '
                                                                                                                                                                           'controller-manager '
                                                                                                                                                                           'behavior; '
                                                                                                                                                                           'not '
                                                                                                                                                                           'literal '
                                                                                                                                                                           'upstream '
                                                                                                                                                                           'SQL '
                                                                                                                                                                           'parity.',
                                                                                                                                                    'status': 'source_erratum_successor',
                                                                                                                                                    'upstream_document_sha256': '8730c1e22bd7e526e60542ba74cccf54cd7dbdd2aa244e52b568c5221d4939c1',
                                                                                                                                                    'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                                    'upstream_query_block_sha256': 'e3d9c1a8e1cd4749039adb1644c8ffcbbd862e89bd687ae386f5ee1a9427adfb',
                                                                                                                                                    'upstream_query_source': 'query/replication_controller.pp:2342',
                                                                                                                                                    'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/replication_controller.pp#L631',
                                                                                                                                                    'upstream_sql_sha256': 'bada9933bcb5b6123007f79c4d11ecbe8f05c60623f574c6165f3e63301d30b7',
                                                                                                                                                    'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                              'steps': ['Set '
                                                                                                                                        'a '
                                                                                                                                        'positive '
                                                                                                                                        'controller-manager '
                                                                                                                                        'garbage-collection '
                                                                                                                                        'threshold '
                                                                                                                                        'suitable '
                                                                                                                                        'for '
                                                                                                                                        'the '
                                                                                                                                        'cluster.'],
                                                                                                                              'summary': 'Set '
                                                                                                                                         'a '
                                                                                                                                         'positive '
                                                                                                                                         'controller-manager '
                                                                                                                                         'garbage-collection '
                                                                                                                                         'threshold '
                                                                                                                                         'suitable '
                                                                                                                                         'for '
                                                                                                                                         'the '
                                                                                                                                         'cluster.'}},
 'k8s.ports.statefulset.container_argument_kubelet_terminated_pod_gc_threshold_configured': {'description_fields': {'description': 'Checks '
                                                                                                                                   'captured '
                                                                                                                                   'kube-controller-manager '
                                                                                                                                   'terminated-pod-gc-threshold '
                                                                                                                                   'declarations '
                                                                                                                                   'for '
                                                                                                                                   'a '
                                                                                                                                   'positive '
                                                                                                                                   'integer.',
                                                                                                                    'fail_when': 'An '
                                                                                                                                 'applicable '
                                                                                                                                 'complete '
                                                                                                                                 'kube-controller-manager '
                                                                                                                                 'declaration '
                                                                                                                                 'explicitly '
                                                                                                                                 'sets '
                                                                                                                                 'terminated-pod-gc-threshold '
                                                                                                                                 'to '
                                                                                                                                 'zero; '
                                                                                                                                 'malformed '
                                                                                                                                 'or '
                                                                                                                                 'missing '
                                                                                                                                 'required '
                                                                                                                                 'declarations '
                                                                                                                                 'remain '
                                                                                                                                 'UNKNOWN.',
                                                                                                                    'not_applicable_when': 'No '
                                                                                                                                           'applicable '
                                                                                                                                           'kube-controller-manager '
                                                                                                                                           'declaration '
                                                                                                                                           'is '
                                                                                                                                           'captured '
                                                                                                                                           'and '
                                                                                                                                           'component '
                                                                                                                                           'applicability '
                                                                                                                                           'is '
                                                                                                                                           'otherwise '
                                                                                                                                           'complete. '
                                                                                                                                           'A '
                                                                                                                                           'kubelet '
                                                                                                                                           'declaration '
                                                                                                                                           'alone '
                                                                                                                                           'is '
                                                                                                                                           'outside '
                                                                                                                                           'this '
                                                                                                                                           'corrected '
                                                                                                                                           'control.',
                                                                                                                    'pass_when': 'At '
                                                                                                                                 'least '
                                                                                                                                 'one '
                                                                                                                                 'applicable '
                                                                                                                                 'kube-controller-manager '
                                                                                                                                 'declaration '
                                                                                                                                 'is '
                                                                                                                                 'captured; '
                                                                                                                                 'every '
                                                                                                                                 'applicable '
                                                                                                                                 'declaration '
                                                                                                                                 'has '
                                                                                                                                 'complete '
                                                                                                                                 'flags '
                                                                                                                                 'and '
                                                                                                                                 'an '
                                                                                                                                 'explicitly '
                                                                                                                                 'declared '
                                                                                                                                 'positive '
                                                                                                                                 'integer '
                                                                                                                                 'threshold.',
                                                                                                                    'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                          'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                          'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                          'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                          'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/statefulset.pp',
                                                                                                                                          'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                          'prior_component': 'kubelet',
                                                                                                                                          'prior_description_sha256': 'cde9b78c41187e43e618ad76f9935c19e0ad9ae3b328a2041e31ac76b71eeeef',
                                                                                                                                          'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                          'prior_remediation_sha256': 'de8711b3b3a656d2392694b51969d157c4c1b89b525d3fd5b755847a6b59ad70',
                                                                                                                                          'reason': 'The '
                                                                                                                                                    'pinned '
                                                                                                                                                    'upstream '
                                                                                                                                                    'query '
                                                                                                                                                    'incorrectly '
                                                                                                                                                    'tests '
                                                                                                                                                    'a '
                                                                                                                                                    'kubelet '
                                                                                                                                                    'command '
                                                                                                                                                    'for '
                                                                                                                                                    'a '
                                                                                                                                                    'kube-controller-manager '
                                                                                                                                                    'flag. '
                                                                                                                                                    'Retain '
                                                                                                                                                    'historical '
                                                                                                                                                    'IDs '
                                                                                                                                                    'and '
                                                                                                                                                    'source '
                                                                                                                                                    'evidence; '
                                                                                                                                                    'correct '
                                                                                                                                                    'the '
                                                                                                                                                    'native '
                                                                                                                                                    'component '
                                                                                                                                                    'binding.',
                                                                                                                                          'source_relationship': 'Corrected '
                                                                                                                                                                 'native '
                                                                                                                                                                 'criterion '
                                                                                                                                                                 'derived '
                                                                                                                                                                 'from '
                                                                                                                                                                 'documented '
                                                                                                                                                                 'controller-manager '
                                                                                                                                                                 'behavior; '
                                                                                                                                                                 'not '
                                                                                                                                                                 'literal '
                                                                                                                                                                 'upstream '
                                                                                                                                                                 'SQL '
                                                                                                                                                                 'parity.',
                                                                                                                                          'status': 'source_erratum_successor',
                                                                                                                                          'upstream_document_sha256': 'ca0586699a50349cd33ebcd9851ad53ab7134bd33140c8d2a390fedbaf65c850',
                                                                                                                                          'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                          'upstream_query_block_sha256': '5c019d1102922ed8aeeec390db26b9515ac54bd0b7fae82136962f66ead5532d',
                                                                                                                                          'upstream_query_source': 'query/statefulset.pp:2393',
                                                                                                                                          'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/statefulset.pp#L631',
                                                                                                                                          'upstream_sql_sha256': '1f127079e8f5d7a319601b46c0b6bafe5a1f6414f776b6599b5f32d639f30425',
                                                                                                                                          'version': 'k8s-gc-threshold-component-erratum-v1'}},
                                                                                             'provenance': {'current_component': 'kube-controller-manager',
                                                                                                            'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                            'historical_source_status': 'historical_invalid_component_binding',
                                                                                                            'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                            'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/statefulset.pp',
                                                                                                            'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                            'prior_component': 'kubelet',
                                                                                                            'prior_description_sha256': 'cde9b78c41187e43e618ad76f9935c19e0ad9ae3b328a2041e31ac76b71eeeef',
                                                                                                            'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                            'prior_remediation_sha256': 'de8711b3b3a656d2392694b51969d157c4c1b89b525d3fd5b755847a6b59ad70',
                                                                                                            'reason': 'The '
                                                                                                                      'pinned '
                                                                                                                      'upstream '
                                                                                                                      'query '
                                                                                                                      'incorrectly '
                                                                                                                      'tests '
                                                                                                                      'a '
                                                                                                                      'kubelet '
                                                                                                                      'command '
                                                                                                                      'for '
                                                                                                                      'a '
                                                                                                                      'kube-controller-manager '
                                                                                                                      'flag. '
                                                                                                                      'Retain '
                                                                                                                      'historical '
                                                                                                                      'IDs '
                                                                                                                      'and '
                                                                                                                      'source '
                                                                                                                      'evidence; '
                                                                                                                      'correct '
                                                                                                                      'the '
                                                                                                                      'native '
                                                                                                                      'component '
                                                                                                                      'binding.',
                                                                                                            'source_relationship': 'Corrected '
                                                                                                                                   'native '
                                                                                                                                   'criterion '
                                                                                                                                   'derived '
                                                                                                                                   'from '
                                                                                                                                   'documented '
                                                                                                                                   'controller-manager '
                                                                                                                                   'behavior; '
                                                                                                                                   'not '
                                                                                                                                   'literal '
                                                                                                                                   'upstream '
                                                                                                                                   'SQL '
                                                                                                                                   'parity.',
                                                                                                            'status': 'source_erratum_successor',
                                                                                                            'upstream_document_sha256': 'ca0586699a50349cd33ebcd9851ad53ab7134bd33140c8d2a390fedbaf65c850',
                                                                                                            'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                            'upstream_query_block_sha256': '5c019d1102922ed8aeeec390db26b9515ac54bd0b7fae82136962f66ead5532d',
                                                                                                            'upstream_query_source': 'query/statefulset.pp:2393',
                                                                                                            'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/statefulset.pp#L631',
                                                                                                            'upstream_sql_sha256': '1f127079e8f5d7a319601b46c0b6bafe5a1f6414f776b6599b5f32d639f30425',
                                                                                                            'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                             'remediation_fields': {'caveats': ['The '
                                                                                                                                'default '
                                                                                                                                '12500 '
                                                                                                                                'already '
                                                                                                                                'enables '
                                                                                                                                'garbage '
                                                                                                                                'collection; '
                                                                                                                                'this '
                                                                                                                                'check '
                                                                                                                                'needs '
                                                                                                                                'an '
                                                                                                                                'explicit '
                                                                                                                                'captured '
                                                                                                                                'value '
                                                                                                                                'and '
                                                                                                                                'does '
                                                                                                                                'not '
                                                                                                                                'read '
                                                                                                                                'the '
                                                                                                                                'running '
                                                                                                                                'controller '
                                                                                                                                'configuration.'],
                                                                                                                    'cli': [],
                                                                                                                    'field_binding': {'component': ['kube-controller-manager'],
                                                                                                                                      'expected': 0,
                                                                                                                                      'fields': ['terminated-pod-gc-threshold'],
                                                                                                                                      'kind': 'statefulset',
                                                                                                                                      'operation': 'gt',
                                                                                                                                      'target': 'resource'},
                                                                                                                    'references': [{'title': 'Kubernetes '
                                                                                                                                             'controller-manager '
                                                                                                                                             'GC '
                                                                                                                                             'threshold',
                                                                                                                                    'url': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/'}],
                                                                                                                    'review_status': 'approved',
                                                                                                                    'source_correction': {'current_component': 'kube-controller-manager',
                                                                                                                                          'current_predicate_sha256': '0950a5d3c0cbcf6b6042f0c18f3a7d7aff039641119e0c3aa389874083c657e0',
                                                                                                                                          'historical_source_status': 'historical_invalid_component_binding',
                                                                                                                                          'immutable_upstream_commit': '0c3811217525256c41d97ea0d67312f420bd814a',
                                                                                                                                          'immutable_upstream_query_url': 'https://raw.githubusercontent.com/turbot/steampipe-mod-kubernetes-compliance/0c3811217525256c41d97ea0d67312f420bd814a/query/statefulset.pp',
                                                                                                                                          'official_reference': 'https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/',
                                                                                                                                          'prior_component': 'kubelet',
                                                                                                                                          'prior_description_sha256': 'cde9b78c41187e43e618ad76f9935c19e0ad9ae3b328a2041e31ac76b71eeeef',
                                                                                                                                          'prior_predicate_sha256': 'dc4d5231bed17e92fefa6c0a07216920ac165ac22793f9ffaf9d63d02e395b74',
                                                                                                                                          'prior_remediation_sha256': 'de8711b3b3a656d2392694b51969d157c4c1b89b525d3fd5b755847a6b59ad70',
                                                                                                                                          'reason': 'The '
                                                                                                                                                    'pinned '
                                                                                                                                                    'upstream '
                                                                                                                                                    'query '
                                                                                                                                                    'incorrectly '
                                                                                                                                                    'tests '
                                                                                                                                                    'a '
                                                                                                                                                    'kubelet '
                                                                                                                                                    'command '
                                                                                                                                                    'for '
                                                                                                                                                    'a '
                                                                                                                                                    'kube-controller-manager '
                                                                                                                                                    'flag. '
                                                                                                                                                    'Retain '
                                                                                                                                                    'historical '
                                                                                                                                                    'IDs '
                                                                                                                                                    'and '
                                                                                                                                                    'source '
                                                                                                                                                    'evidence; '
                                                                                                                                                    'correct '
                                                                                                                                                    'the '
                                                                                                                                                    'native '
                                                                                                                                                    'component '
                                                                                                                                                    'binding.',
                                                                                                                                          'source_relationship': 'Corrected '
                                                                                                                                                                 'native '
                                                                                                                                                                 'criterion '
                                                                                                                                                                 'derived '
                                                                                                                                                                 'from '
                                                                                                                                                                 'documented '
                                                                                                                                                                 'controller-manager '
                                                                                                                                                                 'behavior; '
                                                                                                                                                                 'not '
                                                                                                                                                                 'literal '
                                                                                                                                                                 'upstream '
                                                                                                                                                                 'SQL '
                                                                                                                                                                 'parity.',
                                                                                                                                          'status': 'source_erratum_successor',
                                                                                                                                          'upstream_document_sha256': 'ca0586699a50349cd33ebcd9851ad53ab7134bd33140c8d2a390fedbaf65c850',
                                                                                                                                          'upstream_inspected_flag': 'terminated-pod-gc-threshold',
                                                                                                                                          'upstream_query_block_sha256': '5c019d1102922ed8aeeec390db26b9515ac54bd0b7fae82136962f66ead5532d',
                                                                                                                                          'upstream_query_source': 'query/statefulset.pp:2393',
                                                                                                                                          'upstream_source_url': 'https://github.com/turbot/steampipe-mod-kubernetes-compliance/blob/v1.1.0/controls/statefulset.pp#L631',
                                                                                                                                          'upstream_sql_sha256': '1f127079e8f5d7a319601b46c0b6bafe5a1f6414f776b6599b5f32d639f30425',
                                                                                                                                          'version': 'k8s-gc-threshold-component-erratum-v1'},
                                                                                                                    'steps': ['Set '
                                                                                                                              'a '
                                                                                                                              'positive '
                                                                                                                              'controller-manager '
                                                                                                                              'garbage-collection '
                                                                                                                              'threshold '
                                                                                                                              'suitable '
                                                                                                                              'for '
                                                                                                                              'the '
                                                                                                                              'cluster.'],
                                                                                                                    'summary': 'Set '
                                                                                                                               'a '
                                                                                                                               'positive '
                                                                                                                               'controller-manager '
                                                                                                                               'garbage-collection '
                                                                                                                               'threshold '
                                                                                                                               'suitable '
                                                                                                                               'for '
                                                                                                                               'the '
                                                                                                                               'cluster.'}}}


def _apply(check_id, original, kind):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    updated = deepcopy(original) if isinstance(original, dict) else {}
    updated.update(deepcopy(row[kind + "_fields"]))
    if kind == "remediation":
        updated.pop("iac", None)
    return updated


def description(check_id, original):
    return _apply(check_id, original, "description")


def remediation(check_id, original):
    return _apply(check_id, original, "remediation")


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'k8s' or finding.get('status') != 'FAIL':
        return None
    cid = finding.get('check_id')
    if not isinstance(cid,str) or cid not in ROWS or not isinstance(finding.get('evidence'),dict):
        return None
    evidence = finding['evidence']
    observations, flagged = evidence.get('observations'),evidence.get('containers_needing_review')
    if not isinstance(observations,list) or not isinstance(flagged,list):
        return None
    for row in observations[:100]:
        if not isinstance(row,dict) or row.get('component')!='kube-controller-manager':
            continue
        name = row.get('container')
        settings = row.get('settings')
        if isinstance(name,str) and name in flagged and len(name)<=100 and all(ord(c)>=32 for c in name) and isinstance(settings,dict) and settings.get('terminated-pod-gc-threshold')=='0':
            return 'Container “'+name+'” declares controller-manager terminated-Pod garbage collection disabled (threshold 0).'
    return None


REVIEWED_RISKS = {cid: ('medium','medium') for cid in ROWS}


def severity_review(check_id,source_severity):
    value = REVIEWED_RISKS.get(check_id)
    if value is None:
        return None
    return value[1]

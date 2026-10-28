"""Finite test-only native successors; immutable historical proofs stay intact."""
from copy import deepcopy
import gzip
import hashlib
import importlib
import inspect
import json
from pathlib import Path

import pytest
from peaso.checks.facts import MemoIndex
from tests.gcp_clarity_combined_successor_20261020 import cases_fingerprint

ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def checked(path):
    raw = (ROOT / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PINNED[path], path
    return json.loads(gzip.decompress(raw) if path.endswith('.gz') else raw)


@pytest.fixture(scope='module', autouse=True)
def immutable_inputs():
    def verify():
        for path, expected in PINNED.items():
            assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected, path
    verify()
    yield
    verify()


def gcp_case(cid, branch, historical):
    """Use only16 explicitly enumerated native producer families and branches."""
    reference = GCP_REFS.get(cid, {}).get(branch)
    if reference is None:
        return None
    if reference['historical_case_sha256'] is not None:
        assert cases_fingerprint(historical) == reference['historical_case_sha256']
    from peaso.checks import CHECKS
    check, = [c for c in CHECKS if c.id == cid]
    f = inspect.unwrap(check.evaluate)
    source = GCP_SOURCE[cid]
    assert f.__qualname__ == source['qualname']
    assert hashlib.sha256(inspect.getsource(f).encode()).hexdigest() == source['body_sha256']
    assert hashlib.sha256(Path(inspect.getsourcefile(f)).read_bytes()).hexdigest() == PINNED[source['path']]
    row = checked(reference['path'])['cases'][reference['position']]
    assert digest(row) == reference['row_sha256']
    assert row['check_id'] == cid and row['expected_status'] == branch.upper()
    return deepcopy(row['item']), MemoIndex(deepcopy(row['index']))


def _authenticated_empty(row):
    """Independent empty PodList variant with unchanged full native joins.

    The historical empty podInventory asserted no applicability without an
    authenticated capture. This variant retains the admitted ARM/TLS/UID and
    Namespace bindings and gives the real projector a complete zero-Pod page.
    """
    def visit(value):
        if isinstance(value, dict):
            if 'pods' in value and 'native_list_pages' in value:
                value['pods'] = []
                pages = value['native_list_pages']['/api/v1/pods']
                assert len(pages) == 1
                pages[0]['items'] = 0
                pages[0]['bytes'] = len(json.dumps({'apiVersion': 'v1', 'kind': 'PodList',
                    'metadata': {'resourceVersion': pages[0]['resourceVersion']}, 'items': []}).encode())
            if value.get('type') == 'pod' and 'items' in value:
                value['items'], value['status'] = [], 'empty'
            for part in value.values():
                visit(part)
        elif isinstance(value, list):
            for part in value:
                visit(part)
    visit(row)
    row['index']['pod'] = []
    return row


def azure_case(cid, status, historical):
    """Preserve each historical status and exact case hash; bind new evidence."""
    if cid not in AZURE_REFS:
        return deepcopy(historical), None
    reference = AZURE_REFS[cid][status]
    assert digest(historical) == reference['historical_case_sha256']
    name = reference['reference']
    if name.startswith('aks-native/'):
        branch = name.split('/', 1)[1]
        cases = checked('peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json')[cid]
        empty = branch == 'authenticated-empty'
        if empty:
            assert cid == 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524' and status == 'NOT_APPLICABLE'
            branch = 'pass'
        row = deepcopy({'item': cases[branch], 'index': cases.get(branch + '_index', cases.get('index', {}))})
        if empty:
            _authenticated_empty(row)
    elif name.startswith('retained-'):
        assert status in ('UNKNOWN', 'NOT_APPLICABLE') and name == 'retained-' + status.lower()
        row = deepcopy(historical)
    else:
        from tests.azure_native_successor_inputs_20261020 import _native_rows
        row = deepcopy(_native_rows()[cid][name])
        assert row['status'] == status
    assert digest({'item': row['item'], 'index': row['index']}) == reference['input_sha256']
    return row, reference['evidence_sha256']


def azure_binding(cid, historical):
    if cid not in AZURE_BINDINGS:
        return historical
    reference = AZURE_BINDINGS[cid]
    assert historical == reference['historical_binding']
    # Keep the original reviewed predicate code, including old closures,
    # rather than repinning an old review to the new callable.
    original = importlib.import_module(historical['module'])
    predicate = inspect.unwrap(getattr(original, historical['predicate_qualname']))
    closure = inspect.getclosurevars(predicate).nonlocals
    predicate = closure.get('function', closure.get('fn', closure.get('evaluator', predicate)))
    assert hashlib.sha256(inspect.getsource(predicate).encode()).hexdigest() == historical['predicate_source_sha256']
    audit = checked('docs/check-review/azure-k8s-current-predicate-bindings-20261020.json')
    record, = [row for row in audit['checks'] if row['id'] == cid]
    assert record['matches_reviewed_predicate'] is True
    assert record['expected_body_sha256'] == record['current_body_sha256'] == reference['predicate_source_sha256']
    assert record['current_source'] == reference['path']
    assert record['source_file_sha256_at_review'] == PINNED[reference['path']]
    return {k: deepcopy(v) for k, v in reference.items() if k not in ('historical_binding', 'path')}


GCP_REFS = json.loads(r'''
{
  "gcp.gap.iam_user_managed_sa_no_admin_roles": {
    "fail": {
      "historical_case_sha256": "9fcd822c844310fb2a448a76079ad7fb18a9a1f84aed21a55ddc6288e0ea6369",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 1,
      "row_sha256": "5d641412cfe9b55a08c0b49231dd0e9557273a5c50ee08e92ef8aff79cb873be"
    },
    "pass": {
      "historical_case_sha256": "9fcd822c844310fb2a448a76079ad7fb18a9a1f84aed21a55ddc6288e0ea6369",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 0,
      "row_sha256": "2f3e17c8c46261f6f43a775085c256206bb5674e7c90646d63c88747424239c9"
    }
  },
  "gcp.identity.non_service_account_mfa": {
    "fail": {
      "historical_case_sha256": "091bb1b3814ef168bcb700981e428d9fd6c3dbd787ee491143aa08ad202d84d5",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 1,
      "row_sha256": "893e1899d3fa0535bda05429ab4a32fe7da1c20fb9966ed2eec3a95cc2743087"
    },
    "pass": {
      "historical_case_sha256": "091bb1b3814ef168bcb700981e428d9fd6c3dbd787ee491143aa08ad202d84d5",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 0,
      "row_sha256": "10fa5a3fa7eb3ae9c810b0d49a4f78e8936860310e792868a1efd954c7f200bc"
    }
  },
  "gcp.identity.super_admin_recovery_group": {
    "fail": {
      "historical_case_sha256": "a4ae066e9a337fc9c270c676bf54246c57b49a60cf073c9b4be0020a6aa86731",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 4,
      "row_sha256": "656040b9dae418b924540842671d6f4d275b45a6d90c8d3aa08a74aed40336fb"
    },
    "pass": {
      "historical_case_sha256": "a4ae066e9a337fc9c270c676bf54246c57b49a60cf073c9b4be0020a6aa86731",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 3,
      "row_sha256": "3291d3daf18f787f1f29d4e54b5977ecea5d2e41da033509a3b839e88879104f"
    }
  },
  "gcp.ports.function_basic_role_declarations": {
    "fail": {
      "historical_case_sha256": "d4aa4056e4533976f82a1047efc9596c43281b2a7e2e606f8f7e5fc07720181c",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 7,
      "row_sha256": "89913acbf5135ff9479552c2d775f267180336ffe16fa40a38b0b5185b0311ae"
    },
    "pass": {
      "historical_case_sha256": "d4aa4056e4533976f82a1047efc9596c43281b2a7e2e606f8f7e5fc07720181c",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 6,
      "row_sha256": "bd5dccca40adad1cf2e66225ef7088862d84c452294d3ab57deec6e9459388f5"
    }
  },
  "gcp.ports.function_legacy_deployment_role_declarations": {
    "fail": {
      "historical_case_sha256": "cf4126d41460df27cd52934f888adfe98fa1f8f42c8b20d67b18e0c6e207edaf",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 13,
      "row_sha256": "4eafd3eaafa74882c86e248616247259feeac472876dc47f141b188fb9c1ac15"
    },
    "pass": {
      "historical_case_sha256": "cf4126d41460df27cd52934f888adfe98fa1f8f42c8b20d67b18e0c6e207edaf",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 12,
      "row_sha256": "fa3894e67df657fb81b81ae7c321b426893187749a7c93a221e36385134338b2"
    }
  },
  "gcp.ports.function_logging_mutation_declarations": {
    "fail": {
      "historical_case_sha256": "f85f1ae86ee4ce3348de18e1c99d1ba24e83733346fbec5f776fd8cb9f904b80",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 10,
      "row_sha256": "d6da605242004a043b395673f2f44c9181c07f419fa8595a35f4f32f3ccdca30"
    },
    "pass": {
      "historical_case_sha256": "f85f1ae86ee4ce3348de18e1c99d1ba24e83733346fbec5f776fd8cb9f904b80",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 9,
      "row_sha256": "c8bab38dc084ca293b2302b4ee1729e1c048bfa0a038be0d88036227e48a201a"
    }
  },
  "gcp.ports.service_account_mutating_role_declarations": {
    "fail": {
      "historical_case_sha256": "998b85dee0cec7cb0337ccc17fd2d2c448924f9ea47a938b21ca9e83f202ac2f",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 4,
      "row_sha256": "c1fdbf1af1633e42730f82d09446d58759d5008f535e409b3c38503b35305b3c"
    },
    "pass": {
      "historical_case_sha256": "998b85dee0cec7cb0337ccc17fd2d2c448924f9ea47a938b21ca9e83f202ac2f",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 3,
      "row_sha256": "b86ffd74c096ab53850ed57b4eb29c224223147aaa50b3120f06af6579fbd4d8"
    }
  },
  "gcp.ports.sql_instance_mysql_binary_log_enabled": {
    "fail": {
      "historical_case_sha256": "cf4d40f993bf6e06fb072224ad775e2098fc54caee67639d87cba684ff84ba84",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 16,
      "row_sha256": "421c2d2b0ca22f238067f5ce890ed503654f301cb4551b06b3a5bf850e4e49af"
    },
    "pass": {
      "historical_case_sha256": "cf4d40f993bf6e06fb072224ad775e2098fc54caee67639d87cba684ff84ba84",
      "path": "tests/fixtures/gcp-native57-native-successor-20261020.json",
      "position": 15,
      "row_sha256": "dc096961dd19b18f936ee313b30d45ea4e613805af8448ac04ce869f0e0ca559"
    }
  },
  "gcp_c5_log_event_fields": {
    "fail": {
      "historical_case_sha256": null,
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 10,
      "row_sha256": "6bb98aaae1c0cfff3cb3f88eed8b4adf107a5df45c07114014d3632c2a406eb2"
    },
    "pass": {
      "historical_case_sha256": null,
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 9,
      "row_sha256": "ca9197b01bae46a25a386d315f78fa5a4f284787ad8a7e7c18a24f40928ee4b1"
    }
  },
  "gcp_cloud_armor_waf_enabled": {
    "fail": {
      "historical_case_sha256": "d9f21786d5445abf758e2a3dc743dd2529041527ad1d74fd8ccf579fea9344b6",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 16,
      "row_sha256": "0e096d72f8c6c8c4785bc182bd41a3fefc72e0ee723dcc0bd58486645514f8ea"
    },
    "pass": {
      "historical_case_sha256": "d9f21786d5445abf758e2a3dc743dd2529041527ad1d74fd8ccf579fea9344b6",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 15,
      "row_sha256": "9a286404fb7ac726b7ca140d8299530d61a30721b3c65475e8a287c8e699ad6b"
    }
  },
  "gcp_gke_small_cluster_auto_upgrade": {
    "fail": {
      "historical_case_sha256": "bf8c00a16a88d6da9904952e098fa4f28b153745d5999358b728693286a50527",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 1,
      "row_sha256": "5f8255666b07584665adefd355571d90819764d922c58824c92f5854c37402ff"
    },
    "pass": {
      "historical_case_sha256": "bf8c00a16a88d6da9904952e098fa4f28b153745d5999358b728693286a50527",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 0,
      "row_sha256": "ca04799b1e9422188defd40d3efc1f181692b95c052e3c84b6112cf73da093e0"
    }
  },
  "gcp_kms_key_destroy_alert": {
    "fail": {
      "historical_case_sha256": "254a19289e55ec42b32dc2e484363b1cce191720ab8d1fbda3a8a796235911c7",
      "path": "tests/fixtures/gcp-alert-native-successor-20261020.json",
      "position": 1,
      "row_sha256": "655cc050a2c7006089eb14bc2bff5c7dff71a9f9fe3996a405b8c8f88f1de48d"
    },
    "pass": {
      "historical_case_sha256": "254a19289e55ec42b32dc2e484363b1cce191720ab8d1fbda3a8a796235911c7",
      "path": "tests/fixtures/gcp-alert-native-successor-20261020.json",
      "position": 0,
      "row_sha256": "e1d7470242815c33f364994d84978eb1dbce00554874d724ed1de4a2f9d072fa"
    }
  },
  "gcp_logging_enumeration_alert": {
    "fail": {
      "historical_case_sha256": "f01cedfbe9691ba958598197487997ec9a05d4753d615190240a3a2f5a197af2",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 13,
      "row_sha256": "9ca4a4b33580f89c78eba1dfecea81fc67fd5079cbc51da878833f9f6f6e4ce9"
    },
    "pass": {
      "historical_case_sha256": "f01cedfbe9691ba958598197487997ec9a05d4753d615190240a3a2f5a197af2",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 12,
      "row_sha256": "bfe89304daee7e515870805ffb588aa1c58b83bb68f04c502471453fa0b7a15c"
    }
  },
  "gcp_pci_backend_service_2ce96d36d0bf": {
    "fail": {
      "historical_case_sha256": "945add150419ed3cdb007cc6cc2807daa326ea0933593fe9aca0cdcf19e70ee3",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 4,
      "row_sha256": "d09b2664b03458cf2bc5fef83e1b1dafd28fdf1fdf41dcdf3b5f9d3fd70b5087"
    },
    "pass": {
      "historical_case_sha256": "945add150419ed3cdb007cc6cc2807daa326ea0933593fe9aca0cdcf19e70ee3",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 3,
      "row_sha256": "c3ed4333ede84dd1a5c98d7509b6698bb846c58214f22812476ebc7032da52de"
    }
  },
  "gcp_pci_bucket_157fb0c69361": {
    "fail": {
      "historical_case_sha256": "b40e3e666f3a8467b90a4de935388db789aff16eccd5c952469a405189dbb666",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 7,
      "row_sha256": "8887825beee6ae04293a6057f7aef35b635f46bdd1cf897eaaf3e13ebf353321"
    },
    "pass": {
      "historical_case_sha256": "b40e3e666f3a8467b90a4de935388db789aff16eccd5c952469a405189dbb666",
      "path": "tests/fixtures/gcp-native-review-behavior.json",
      "position": 6,
      "row_sha256": "ec0e4a46dd651eae2bfef931344b749475f8dbf45b176bb1e4f5069261568c51"
    }
  },
  "gcp_pci_url_map_9ed56c323a05": {
    "fail": {
      "historical_case_sha256": "2e41d31848c33ed1c7c67c1ec4bed0ca09682c6409e3d613cc2669cbf4cf1fde",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 7,
      "row_sha256": "9f8700c5147151e2c59a0c3c881c9f2b98aece2130ee415f029066cd681b6604"
    },
    "pass": {
      "historical_case_sha256": "2e41d31848c33ed1c7c67c1ec4bed0ca09682c6409e3d613cc2669cbf4cf1fde",
      "path": "tests/fixtures/gcp-final-services-native-successor-20261020.json",
      "position": 6,
      "row_sha256": "67b84f972b0c0cff8722f5e661b14eb4e9791eb33b8cf9a0b12de5714bbf2abf"
    }
  }
}
''')


GCP_SOURCE = json.loads(r'''
{
  "gcp.gap.iam_user_managed_sa_no_admin_roles": {
    "body_sha256": "103e14d28539db12d9606fecaf0b270fd6e2bcb24853665b90fb95c1e71c953e",
    "path": "peaso/checks/gcp_gap_cis.py",
    "qualname": "user_managed_sa_admin_roles"
  },
  "gcp.identity.non_service_account_mfa": {
    "body_sha256": "50cbbdc399eee40571270f10471855db37bfa5127b30028faefaa73f4c635b99",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_52.<locals>.non_service_account_mfa"
  },
  "gcp.identity.super_admin_recovery_group": {
    "body_sha256": "bb844feb23d638990eb1739079019b9fc6375e3dba700e40baf1654c1f5a6415",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_52.<locals>.super_admin_recovery_group"
  },
  "gcp.ports.function_basic_role_declarations": {
    "body_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
    "path": "peaso/checks/gcp_ports_iam.py",
    "qualname": "function_roles.<locals>.evaluate"
  },
  "gcp.ports.function_legacy_deployment_role_declarations": {
    "body_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
    "path": "peaso/checks/gcp_ports_iam.py",
    "qualname": "function_roles.<locals>.evaluate"
  },
  "gcp.ports.function_logging_mutation_declarations": {
    "body_sha256": "770536c864c0b576048e7b2b73975556548634a6968ec5bdf54e1c33c934936f",
    "path": "peaso/checks/gcp_ports_iam.py",
    "qualname": "function_roles.<locals>.evaluate"
  },
  "gcp.ports.service_account_mutating_role_declarations": {
    "body_sha256": "dcc9cb3c58e32796e36053c8037398af7541c8e740849312097b1664107b427b",
    "path": "peaso/checks/gcp_ports_iam.py",
    "qualname": "account_mutations"
  },
  "gcp.ports.sql_instance_mysql_binary_log_enabled": {
    "body_sha256": "2e8960e6893c6b472450c3a2fbf53c01961aa86d8850e8286f5191445cd33970",
    "path": "peaso/checks/gcp_ports_services.py",
    "qualname": "scalar.<locals>.evaluate"
  },
  "gcp_c5_log_event_fields": {
    "body_sha256": "fa20939444bd51cc9204b23101d06258fac4a90696020ef1a8184d5c5854337e",
    "path": "peaso/checks/compliance_new_sw52.py",
    "qualname": "c5_log_event_fields"
  },
  "gcp_cloud_armor_waf_enabled": {
    "body_sha256": "4762601e9fc9b3f392906a24b8c94af7006ee4c4a38704111b664b692cc42eac",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_52.<locals>.cloud_armor_waf_enabled"
  },
  "gcp_gke_small_cluster_auto_upgrade": {
    "body_sha256": "9637b15211535769a296105b0540945cb31a0611d4489d7f0b37e6755575f343",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_54.<locals>.gke_small_cluster_auto_upgrade"
  },
  "gcp_kms_key_destroy_alert": {
    "body_sha256": "0e62c8072e708efdcd225d177c0b93ae4e72d476c448bc6126f7c7ecf064018a",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_54.<locals>.kms_key_destroy_alert"
  },
  "gcp_logging_enumeration_alert": {
    "body_sha256": "5e710f318d9f13dda47f72fb3abb2cb00d67bb50184024c6ac3dc98fce09b51c",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_54.<locals>.logging_enumeration_alert"
  },
  "gcp_pci_backend_service_2ce96d36d0bf": {
    "body_sha256": "0e7e1b72fa6a98f54cb9dd3077c37bc211924188bd8fb3ffa9b8ae182f2ab33c",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_51.<locals>.cdn_viewer_tls"
  },
  "gcp_pci_bucket_157fb0c69361": {
    "body_sha256": "ff2714b828f6dd342979aa93113d4bec73029533a33d26462e121b48cf6e4d1a",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_50.<locals>._evaluate"
  },
  "gcp_pci_url_map_9ed56c323a05": {
    "body_sha256": "cf1d92b8deca9faebf9f7dd2db6652aa7384fbc8cad4cf64540d9de0afd3d1f6",
    "path": "peaso/checks/batch_remaining_gcp.py",
    "qualname": "_load_52.<locals>.pci_url_map_redirect"
  }
}
''')


AZURE_REFS = json.loads(r'''
{
  "azure_aks_cluster_7_2_1_6_93c4fab": {
    "FAIL": {
      "evidence_sha256": "f834968abf72921abe74c10a0a66e7b3d8525d30b0708e404b2dd01e1e43bcaf",
      "historical_case_sha256": "d7a2a713f9bcabb41556f3da7c8acfcbd0ce7740fbfa252a342b57831cbec386",
      "input_sha256": "2f7ee013caa929373a49bb80bb0fa1deb28a71b2456f65ff425ba8e062f2741f",
      "reference": "aks-native/fail"
    },
    "PASS": {
      "evidence_sha256": "a904bc5fbc1b346127506391226c0a542d1498dae43954164051b6a144a64cc8",
      "historical_case_sha256": "05de766baf31789f53ca4f2d5c714c22f79842e66ac4eb39d8f804d00a81e4dc",
      "input_sha256": "3d743c887f06b4d225e6772b3c3b614e61fa3728c68079ac36023ab72a346317",
      "reference": "aks-native/pass"
    },
    "UNKNOWN": {
      "evidence_sha256": "d1100d4ca97ef092cff5e00cdfaa71be05d84bb09c0e5fe351577010f63e4c21",
      "historical_case_sha256": "8d224b3d18dd48490e306378d1a820937fb6c2ac860acd91a9592808af45fbae",
      "input_sha256": "e75bc7bdf86b414a2a1f361903476ea6370a63d7fef7d6e365793ca51c18ff6c",
      "reference": "aks-native/unknown"
    }
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524": {
    "FAIL": {
      "evidence_sha256": "45d84a7a0adbd967b3b7917365f6754f147d2546fb38daa18919ecb716c15c54",
      "historical_case_sha256": "0350046ca0d25f0e88cbd8bcff599bdf2a850e8629b82595e593fa0dca6084c4",
      "input_sha256": "ce233658465f6af4a1c7076481f21a4b5481906878180861ca03565eec2fa729",
      "reference": "aks-native/fail"
    },
    "NOT_APPLICABLE": {
      "evidence_sha256": "2bdec7e4752d393d18a05a62a1a9538f89dd4f5736ff7e6f9113d1caa936f155",
      "historical_case_sha256": "0d8177ba4126d25cb7968749eb332bf074174c4cca0eb29805881a4fc0ca1a7d",
      "input_sha256": "36422dabac7819224e85de317e442acd3c0c8c694af6bfa26cb39431ebccb8be",
      "reference": "aks-native/authenticated-empty"
    },
    "PASS": {
      "evidence_sha256": "daf312aef92391e977b7fed4afda138d87ed3a3f30bff3a31297a50a03d0ac42",
      "historical_case_sha256": "f643a8558508383f5d228e12cac176100688510e0866897d615f7e9757e9fffe",
      "input_sha256": "eb820829f7a1938c34520d24c844732f6dd997a4f0504a1caa2734743930aa88",
      "reference": "aks-native/pass"
    },
    "UNKNOWN": {
      "evidence_sha256": "77f4fdca9448c10f4eaecb7bcc34261fb6819006b5f15affc0731cacb20d709b",
      "historical_case_sha256": "8d224b3d18dd48490e306378d1a820937fb6c2ac860acd91a9592808af45fbae",
      "input_sha256": "17c516dba6e2003403fd952ce8362238562e8cb54786efb2ed3c18ba6eec852b",
      "reference": "aks-native/unknown"
    }
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2": {
    "FAIL": {
      "evidence_sha256": "d743fde6c7689dd1592a4cd223aa3560978b68594232cc18acf0c3b31d516716",
      "historical_case_sha256": "b02df18f23850b69f68826e1077b1c03a34199157339a5002e92265a461b9753",
      "input_sha256": "bdc0003d3811626df47dfe9f05c4c164f85157f796e643ee840631c86343fcbc",
      "reference": "edge-successor/53/0/inline_candidate_detection"
    },
    "NOT_APPLICABLE": {
      "evidence_sha256": "0be0062513a7e52a55ffb759b0673d082e522d90570fad7f5e9ed6ea1a73f437",
      "historical_case_sha256": "49412c68c36b9a3ca1f9d8a811d948054f1d2fa96718e87541e7b243daf08098",
      "input_sha256": "fadcb0c3de6fda158db1a36cd7a102206bbfcee87a92aab6579ab0f17001e189",
      "reference": "retained-not_applicable"
    },
    "PASS": {
      "evidence_sha256": "1f4cf94621fc6695a2b2cff3f1482058352ce1d00ebe1a5606f48184775c6d6a",
      "historical_case_sha256": "31e47af8594e883b250cc83a22a615d2dfda5415002048720d0c1cf5f65547ae",
      "input_sha256": "4bce8c34e9571fd29cae5607fb7a82a4c5441cf59cbe8030744de118229f2f91",
      "reference": "edge-successor/51/0/inline_candidate_prevention"
    },
    "UNKNOWN": {
      "evidence_sha256": "01fcb216953a3852a23f9178e083c98d517afcc81bbabb1b83c67793c50a755a",
      "historical_case_sha256": "bf97477a4255f193029f5177506b58ef44a40859a04b8f07af99dd1edaffcf7b",
      "input_sha256": "bae2b4871f2105c3395f65fe621fb01b46b9f372caa8f3c1349aac9db3e6bd55",
      "reference": "edge-successor/55/0/inline_candidate_missing_enabled"
    }
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361": {
    "FAIL": {
      "evidence_sha256": "0b126f9338b13aa85ddb61d10644f1fa290fd469e9fb64120c655d65d2caf36a",
      "historical_case_sha256": "e6ea50dfdc63f4d4dfee721eb82eb5bc438376f0caa49e102a5bc0ca0b124b2d",
      "input_sha256": "404187a5589724edd8e5b27fc9354d8f90e429e78e2f33794a5d85dac34e7333",
      "reference": "edge-successor/43/0/gateway_logging_candidate_empty_diagnostics"
    },
    "PASS": {
      "evidence_sha256": "2877336bcedc68f3c79a54afed3820dff55b67c7bf11ee751502d21f0807c419",
      "historical_case_sha256": "573db75119a5aa672829c1605e196c6a81da67a2dc66c845a0163e69b4bd5fc5",
      "input_sha256": "67ff5e660ab6d58b24e51f23135d58387cca0f939f3428e67a2f720163d7c6af",
      "reference": "edge-successor/41/0/gateway_logging_candidate_positive"
    },
    "UNKNOWN": {
      "evidence_sha256": "48c25a45967d97efcdb6f804141a692e44eb30aecc3eb0d42fe788b124e0ba46",
      "historical_case_sha256": "dc3da649aa48f0b9da17ac582fef8356987fbf343aab602a2a84f9e3a3e9fcdd",
      "input_sha256": "2c8236cbc6cc5671308ae178f31f3d45e15689e81f45088bdff15750a9f7d860",
      "reference": "retained-unknown"
    }
  }
}
''')


AZURE_BINDINGS = json.loads(r'''
{
  "azure_aks_cluster_7_2_1_6_93c4fab": {
    "closure": {},
    "delegates": {},
    "historical_binding": {
      "closure": {},
      "delegates": {},
      "kind": "aks_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "privileged",
      "predicate_source_sha256": "ef7b992d7276bf5ba86ff0e337b9cb92f1fc938187ac89796a1fa2979f603719",
      "source_qualname": "privileged"
    },
    "kind": "aks_cluster",
    "module": "peaso.checks.azure_aks_legacy_projection_review_20261020",
    "path": "peaso/checks/azure_aks_legacy_projection_review_20261020.py",
    "predicate_qualname": "privileged",
    "predicate_source_sha256": "90f1e43816a146dde1c4f0f6ea63e52db552195e6283587811e99c8b643197c5",
    "source_qualname": "privileged"
  },
  "azure_aks_cluster_aks_cluster_rbac_enabled_db12524": {
    "closure": {},
    "delegates": {},
    "historical_binding": {
      "closure": {},
      "delegates": {},
      "kind": "aks_cluster",
      "module": "peaso.checks._bulk_pending_compliance_new_sw30",
      "predicate_qualname": "nonroot",
      "predicate_source_sha256": "145cd00154f8a701c093147ffa74fd90b8198bb44d5718906c0af28f1ae4bb22",
      "source_qualname": "nonroot"
    },
    "kind": "aks_cluster",
    "module": "peaso.checks.azure_aks_legacy_projection_review_20261020",
    "path": "peaso/checks/azure_aks_legacy_projection_review_20261020.py",
    "predicate_qualname": "nonroot",
    "predicate_source_sha256": "eececf75a0dd6ff06b650959de4d7ab22f4fb4732378492015a4175f697bf80a",
    "source_qualname": "nonroot"
  },
  "azure_application_gateway_11_5_1_1_1_f56bdc2": {
    "closure": {},
    "delegates": {},
    "historical_binding": {
      "closure": {
        "evaluator": {
          "callable": "_network"
        },
        "target": "scope"
      },
      "delegates": {},
      "kind": "application_gateway_frontdoor_load_balancer_public_ip",
      "module": "peaso.checks._bulk_pending_compliance_new_sw22",
      "predicate_qualname": "_network",
      "predicate_source_sha256": "237723d0f6042e9bc1fbecd0ea96d918be0e6a9bac3b5314f511ccf65a78fa25",
      "source_qualname": "_install.<locals>.evaluate"
    },
    "kind": "application_gateway_frontdoor_load_balancer_public_ip",
    "module": "peaso.checks.azure_public_edge_config_review_20261020",
    "path": "peaso/checks/azure_public_edge_config_review_20261020.py",
    "predicate_qualname": "evaluate",
    "predicate_source_sha256": "e0a1b976e2b1bd5340512534e881562a391e7a4030c56780b78ba25908249d48",
    "source_qualname": "evaluate"
  },
  "azure_application_gateway_app_http_logs_enabled_2de0361": {
    "closure": {},
    "delegates": {},
    "historical_binding": {
      "closure": {
        "function": {
          "callable": "gateway_and_balancer_logs"
        }
      },
      "delegates": {},
      "kind": "application_gateway_and_load_balancer",
      "module": "peaso.checks._bulk_pending_compliance_new_sw33",
      "predicate_qualname": "gateway_and_balancer_logs",
      "predicate_source_sha256": "a4927de5baf9dcd0574ec2970095c00ae0cd67511787c1ef8f7cc08e03a4b84e",
      "source_qualname": "_signed.<locals>.decorate.<locals>.evaluate"
    },
    "kind": "application_gateway",
    "module": "peaso.checks.azure_gateway_logging_review_20261020",
    "path": "peaso/checks/azure_gateway_logging_review_20261020.py",
    "predicate_qualname": "evaluate",
    "predicate_source_sha256": "8c3d71c83ebbc8dd3154f310a6023491f54114a7e3882d4f6e3c3850daefb92c",
    "source_qualname": "evaluate"
  }
}
''')


PINNED = json.loads(r'''
{
  "docs/check-review/azure-function-settings-production-integration-20261020.json": "e17a9cc2dd49606c69bb92f485947e8a6593418c4319639a58a9397ccc4b44bf",
  "docs/check-review/azure-k8s-current-predicate-bindings-20261020.json": "23ab6679ae1f7a4a35a86da7477c7427126bc668b3067ddc678d442d58bb8799",
  "docs/check-review/azure-rejected-source-recheck-20261020.json": "f8acfb410ac0f060bae1c77829e840cc4fb05e67faba0d93a4aec61cfabeb21a",
  "peaso/checks/azure_aks_legacy_projection_review_20261020.py": "d2aac095ecf0da4019853fb86c4be7129e5f2f75578c1484414bb8b17cfac633",
  "peaso/checks/azure_aks_legacy_projection_review_20261020_fixtures.json": "7e4233f962bc14aa19ddeb4cf9f9c0d3d26a78ca0f600dde3600fa372e06e3a6",
  "peaso/checks/azure_bulk_clarity_reviewed.py": "6c36caa185c2b483eb94185110aa8b514ddebefe56188e2d9e0dc1f921967d22",
  "peaso/checks/azure_final_native_admission_20261020.json": "208520e936e2f692d2bb03ac93d49915134ed84e0fd2e3ae2c9dc409675a6431",
  "peaso/checks/azure_final_native_admission_20261020.py": "30dfd6f2bee166ece1cce8d322693d72e42f7351650cc71d1b22c10fae050518",
  "peaso/checks/azure_function_monitoring_declaration_proposal_20261020.py": "69a85e993fca6a514afdfa4b43df692cd37eb241daa41df5e025298ca75578c1",
  "peaso/checks/azure_function_settings_runtime_admission_20261020.json": "239d2ad906d06d515eb39496a9d16cc0b4f6ac6740f7ecbfd87faf11dc0f60ba",
  "peaso/checks/azure_function_settings_runtime_admission_20261020.py": "a9823cb9bdbc5391ab278ee220ad1c26bb64720ff2ef6576bf29342d2acda5b1",
  "peaso/checks/azure_function_settings_runtime_consumer_20261020.py": "411689c7e89c3f70baa29eb3a235b1ee0ecffbdb6d8fbc6b2543be269c23451c",
  "peaso/checks/azure_gateway_logging_review_20261020.py": "c6898ab3ad1145494615329dcc2d12d938a2a75f7d0332ce9ce413ac248c0c4b",
  "peaso/checks/azure_native_review_copy_20261020.py": "89a6fc92ac9861a088960e7736dfe05aa69ee778289b5b8c3e005a6f4b218393",
  "peaso/checks/azure_public_edge_config_review_20261020.py": "1e5f8ca3e560adbece0529428e945888789f729a6b71e99188053b92b5305263",
  "peaso/checks/batch_remaining_gcp.py": "5f2b783c85e0fe80a8cda82619a562ead5118f9450797f5c629532c8437e1502",
  "peaso/checks/compliance_new_sw52.py": "28e4e029e4f1b0c2ca7c4dabef08f6e136767a74e1240157457f88a1f855ea9d",
  "peaso/checks/gcp_gap_cis.py": "c14625656c45cc735158d77bc0946de4ebb87446b14e3e09b11c33d5856a94e7",
  "peaso/checks/gcp_ports_iam.py": "f9e561c71df457a14f14c659a9fd1ca977e45800bacc99c27b6653ec973a761d",
  "peaso/checks/gcp_ports_services.py": "4d0572d9f8dc88212772031afdb125725f1f7fca37b87cb790e647d494802ab2",
  "tests/azure_native_successor_inputs_20261020.py": "88e8f03a54b829fc88cf34a1d3b03fafc17d6bced2c598e1e55e1cee44135445",
  "tests/fixtures/azure_application_compute_2_native_successors_20261020.json": "6987925bd50161b345e4af9147ae371c62795a2db8e62394f6f33d79af676fd3",
  "tests/fixtures/azure_application_compute_native_successors_20261020.json": "734b729df1232d6588080dbb72894b982970a61e7a4d8f1eebe9ebb9c912929d",
  "tests/fixtures/azure_bulk_clarity_reviewed.json.gz": "9fe102d51a371d3da5724ce9c2dd937c7a467f8ab922ef31588fd701955e064b",
  "tests/fixtures/azure_database_crypto_backup_2_evaluator_inputs_20261020.json": "1c29a99df697adb2ae09ab46a62ac3627be0786fcad926d41cd9dd3300a15f27",
  "tests/fixtures/azure_database_native_evaluator_inputs_20261020.json": "fffe69c4a4c7bfd5b155783f82e908e590a92af13c621e47ccc78da1d51b2eb8",
  "tests/fixtures/azure_edge_native_current_inputs_20261020.json.gz": "8fd363d85f247f9586e544808088c6652b0b142bfc3513a63c0820ac785d0ebd",
  "tests/fixtures/azure_function_role_native_successors_20261020.json": "fffbb2d1d0b74dcac8a03cb9a12fd4d809a3eff9dbf5d9690d0744a879a1df0b",
  "tests/fixtures/azure_identity_enforcement_native_successors_20261020.json": "83c17c059b9f7fcfabf9810c277c657f051e198a993ccfe892cc63a9fadd99ae",
  "tests/fixtures/azure_identity_native_successors_20261020.json": "aa0ff70196a8c4ca5316535ba241742a5160e554d7d62bc0b6f60799ce6da3a8",
  "tests/fixtures/azure_lock_native_successors_20261020.json.gz": "1d6c40d1a1b705b209c3ab0477564686f0de6d15492bf8715e4f2418858a8bfa",
  "tests/fixtures/azure_network_native_evaluator_inputs_20261020.json": "84d1e943bdc7280f98a539b58a55fff19b194c98233a1ef655198adf64762830",
  "tests/fixtures/azure_services1_native_evaluator_inputs_20261020.json.gz": "dd8f5099b70b5042af97e0dcd5c8b79217ca3bd8ed9c45791e0f1ae2f62d73ef",
  "tests/fixtures/azure_services2_native_evaluator_inputs_20261020.json.gz": "b014bfcae225cb6921963107cd1d534d455037887c3715c343915560ea1cac1c",
  "tests/fixtures/azure_services3_native_evaluator_inputs_20261020.json.gz": "a972e55d611340f8e343e64828628b05e011fc56f43bbc6aac75e924ed7d19a8",
  "tests/fixtures/gcp-alert-native-successor-20261020.json": "d96b5cc131dad48afbf37fb71cf5f3e51d6d3ec650539269f6d782b8f37f7aad",
  "tests/fixtures/gcp-compute-native-successor-20261020.json": "5d4a2038ed11af3a4ef4a9a1dff0fa38c74d5dde657f37308869528c6b359c5d",
  "tests/fixtures/gcp-final-services-native-successor-20261020.json": "09a0560846d444fc217f7f2b30f96b8cac709e72d1abb1fd19a5e21bfd22dbdb",
  "tests/fixtures/gcp-native-review-behavior.json": "491de9e6bd9587721d67732baf22425f6b920af1ab01366a9863fcd3a1170e4f",
  "tests/fixtures/gcp-native57-native-successor-20261020.json": "561872fb0ad465c851a53cff31cbc0e3b2ccaf72ac9da50bea84c66e0e8face9",
  "tests/fixtures/gcp-prior-bounded-native-successor-20261020.json": "0ca12fc2736547034ccf66a275c865c7793517f8c1a416edb9b75a3f5dcd15d4",
  "tests/gcp_clarity_combined_successor_20261020.py": "57f88b167964348b2dcdbf99ce3dc1a08c35f9cabdd4138f9fcc49d05cf1624f"
}
''')

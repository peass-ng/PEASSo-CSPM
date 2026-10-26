"""Finite accepted late AWS source/copy contracts; historical fixtures stay intact."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = {'aws.review.lambda.selected_environment_secret_indicators': {'predicate': '7774d944ed4e78740b753e66e387e1a2d806ec4f453dfe8dbc2762c9a41a1456', 'description': '735b4d662ab365928cdf8ad11e1cba4b3bdae0f44b4162801f64dab3558e759c', 'copy': '747895214fcd9d5c316d7b8b0817f0da4578c895008ea9418de1bfac72ca8aaa', 'ledger': '9e29d9fbc95676abb00f36087baf5f54aecde77e1d0b4500572026b5f41facc9', 'files': {'docs/check-review/aws-lambda-environment-secret-implementation-20261020.json': '1fb5f88fb027783f0bd49f4aaffb0b554da91ab892590d065de6e5b05cbdebc5', 'peaso/checks/aws_lambda_environment_secret_review_20261020.py': 'd179108bd8146e8d0055d39ecd0d5f9db31e4b912987cb94cb71fc51de66daaf', 'peaso/checks/aws_lambda_environment_secret_review_20261020_fixtures.json': '6613ff2f298f0dd84cb966cb9e718f09508fd671d6835582db0d25b12f34fa0c'}}, 'aws.review.configuration.selected_content_secret_indicators': {'predicate': '124565e4295df00ba05a6643476e98e0e55b9cce0be9280e26f5f626946184f9', 'description': 'c470d4c5a9093159a06973eda875e93d5c07ebdc36ed08ecf510272a8a369e5c', 'copy': 'd3e2fdec0f3011090518f4ed19fb518b87d87f354b957ad71b5a3b9ef26ca19a', 'ledger': 'e9a2b01045e798b4e687a5caf45ebe78a109368962699161a5a995d4d3672b4d', 'files': {'peaso/checks/aws_selected_configuration_secret_review_20261020.py': '819cb82c47a3eefca9e4e7c6a3d14a6624f4e0e836e2b50638384533cb9d6b65', 'peaso/checks/aws_selected_configuration_secret_review_20261020_fixtures.json': '1e32b62f97e82baff43c5f3732255d42e9f9135c808a839ab99357eb93555306'}}, 'aws.review.s3.selected_source_secret_indicators': {'predicate': '11c5eb88d78d7535ce59ac4aad701ee9e2f02dfe67c18d9ee883888992e422ec', 'description': '6b46cdd639a01efbcbc224511d61237e075d1e326a345a5e1d666e57f1bc906b', 'copy': '77b0a57e8e6117ce3b75c4d19844f9dfcd1a34f63e2a917b35cae9524cdff1e1', 'ledger': '680f7e67deee64d8c93f897c2839751776b4eb283a75218123beaf9c23b5f169', 'files': {'peaso/checks/aws_s3_selected_source_native_cases_20261020.json': '4e975cf83c54b2c53f44cd21aee86c8f4c516a1b4ecc22d39cc4ec33333508a0', 'peaso/checks/aws_s3_selected_source_secret_review_20261020.py': 'c70abcb816d1071cd5c7a3c1ec6ded177b6bf1c96b03b30105ff98594733cb6d'}}, 'aws.review.codebuild.selected_inline_buildspec_secret_indicators': {'predicate': 'f719d77edb555fe1728631ae5129c3baf223d1bb279f0adf818f941a048a59a5', 'description': '2f3ebf6a4c92d6182f6eb1a42e3783c3907d6738324bfb7acfa0248f1b5f1c35', 'copy': '351ec65f0e6be313875e4b58c043ef508bdb6172681e265c33778fa46a9cf681', 'ledger': 'cb1269975fd2be62fc353d9ebb35d096455b55a1ddaf45e1257cfcf8414973bb', 'files': {'docs/check-review/aws-codebuild-current-acceptance-20261020.json': '17a4d8ea9e4371b65367769a87206841b4b988c4bc70ca2979d1169984a6cdb1', 'peaso/checks/aws_codebuild_buildspec_runtime_cases_20261020.json': 'cfd12423e126de3a52f0eedfb5f88c378b68e05e3ebb18fa96a97f188cbfc035', 'peaso/checks/aws_codebuild_buildspec_runtime_consumer_20261020.py': '463330f572896ffb3919cdd0b88e0bb678bafd740c5df71135ae3994fcb7338e'}}, 'aws.review.workload.selected_command_literal_secret_indicators': {'predicate': '27fc0706ac46884d952ade177104a024c7c531883dec4ac58ad450ae420cfdb2', 'description': '2795c923a521ce5cde7d1eaec3af08e10945ab505b3ce6b7e2180fc9d6592e85', 'copy': '912bafb29cc62c9412f3f3e668473decb1f18bc9a3cba6cc6ef2acebe0cf429e', 'ledger': '57b9b075640132b08937172aa0b00d2a0c16f2179bed2bf2401cae834ff3e89c', 'files': {'docs/check-review/aws-workload-command-runtime-20261020.json': '51c78497fb81e2c9d988753cb3ff7e44820cbe708cc59842c868db9eee5b3409', 'docs/check-review/aws-workload-commands-current-acceptance-20261020.json': 'f5b04024d242eab0697817a3b8d9d3f8e76aeba73eed4928e989fb926283580a', 'docs/check-review/aws-workload-commands-current-native-witnesses-20261020.json.gz': 'b7e7e7d00d2aec8dfd2ffe386fa29a2918436de0aac572866a140fc5bc791a10', 'peaso/checks/aws_workload_command_runtime_consumer_20261020.py': '26fda08fe5718108901af36aa404a6e4807d21a5f5628c977f6397144ae8f1ed', 'tests/test_aws_workload_command_runtime_20261020.py': 'db1cef420bb43fc4cdc24317c7bc347bfd98571e04f317da20ce21a6b57a4ad5'}}}
IDS = frozenset(CONTRACTS)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def assert_contract(cid, check, ledger, copy_row, description):
    expected = CONTRACTS[cid]
    assert hashlib.sha256(inspect.getsource(inspect.unwrap(check.evaluate)).encode()).hexdigest() == expected['predicate']
    assert digest(ledger) == expected['ledger']
    assert digest(copy_row) == expected['copy']
    assert digest(description) == expected['description']
    for relative, sha in expected['files'].items():
        current_sha = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if relative == 'docs/check-review/aws-codebuild-current-acceptance-20261020.json':
            # Keep the contract's earlier digest. The sealed master admission
            # records the subsequently accepted receipt bytes.
            assert sha == '17a4d8ea9e4371b65367769a87206841b4b988c4bc70ca2979d1169984a6cdb1'
            admission = ROOT / 'docs/check-review/aws-codebuild-master-admission-20261020.json'
            assert hashlib.sha256(admission.read_bytes()).hexdigest() == (
                'de0e435621a3970dbba9327ecb4e4ef37a0bae6350f5f49dfc36d0b2f26f5971')
            successor = json.loads(admission.read_bytes())['acceptance_receipt']
            assert successor['path'] == relative and current_sha == successor['sha256']
        else:
            assert current_sha == sha, relative
    if 'fixture_source' in ledger:
        cases = json.loads((ROOT / ledger['fixture_source']).read_text())[cid]
        for branch, status in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
            item = deepcopy(cases[branch])
            index = deepcopy(cases.get(branch + '_index', cases.get('index', {})))
            before = deepcopy((item, index))
            assert check.evaluate(item, index)[0] == status, (cid, branch)
            assert (item, index) == before
    else:
        # This check deliberately has no fabricated JSON fixture. Its accepted
        # SDK+two-detector runtime tests prove clean and exposed cases; this
        # immutable archive contains the actual replayed exposed findings.
        assert cid == 'aws.review.workload.selected_command_literal_secret_indicators'
        assert set(ledger['status_coverage']) == {'PASS', 'FAIL', 'UNKNOWN'}
        assert set(ledger['branch_coverage']) == {'PASS', 'FAIL', 'UNKNOWN'}
        witness = json.loads(gzip.decompress((ROOT / ledger['native_replay_witnesses']['path']).read_bytes()))
        assert witness['check_id'] == cid and witness['witnesses']
        from peaso.engine import evaluate_snapshot
        for captured in witness['witnesses']:
            snapshot = deepcopy(captured['snapshot'])
            before = deepcopy(snapshot)
            actual = evaluate_snapshot(snapshot, checks=[cid])['findings']
            assert actual and all(row['status'] == captured['status'] == 'FAIL' for row in actual)
            assert len(actual) == len(captured['findings'])
            assert [row['evidence'] for row in actual] == [row['evidence'] for row in captured['findings']]
            assert snapshot == before
        assert check.evaluate({}, {})[0] == 'UNKNOWN'


def workload_witness_case():
    cid = 'aws.review.workload.selected_command_literal_secret_indicators'
    ledger = json.loads((ROOT / 'docs/evidence-reviews/aws.json').read_text())['checks'][cid]
    raw = (ROOT / ledger['native_replay_witnesses']['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CONTRACTS[cid]['files'][ledger['native_replay_witnesses']['path']]
    snapshot = json.loads(gzip.decompress(raw))['witnesses'][0]['snapshot']
    kind = 'aws_selected_workload_command_literals'
    envelope, = [row for row in snapshot['collections'] if row['type'] == kind]
    scope = envelope['scope']
    index = {'context': {'provider': 'aws', 'scope': scope, 'metadata': snapshot['metadata']},
             'collections': {kind: [deepcopy(envelope)]}}
    return deepcopy(envelope['items'][0]), index


def assert_workload_producer(check, producer):
    # The static old audit recognizes literal kind branches, whereas this
    # admitted producer is a typed collect/publish hook with a constant kind.
    import ast
    from peaso.collectors import aws, aws_workload_command_runtime_20261020 as runtime
    from peaso.checks import aws_workload_command_runtime_admission_20261020 as admission
    admission.reviewed_inputs()
    assert check.id == runtime.CHECK == 'aws.review.workload.selected_command_literal_secret_indicators'
    assert check.kind == runtime.KIND == 'aws_selected_workload_command_literals'
    assert check.dependencies == [runtime.KIND]
    assert producer['supported'] and producer['native_type'] == runtime.KIND
    import importlib
    assert importlib.import_module('peaso.collectors.aws_workload_command_runtime_20261020') is runtime
    tree = ast.parse(inspect.getsource(aws.collect))
    imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level == 1]
    assert sum(alias.name == 'aws_workload_command_runtime_20261020' and alias.asname == 'workload_commands'
               for node in imports for alias in node.names) == 1
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
             and node.func.value.id == 'workload_commands']
    assert sum(node.func.attr == 'collect_selected' for node in calls) == 1
    assert sum(node.func.attr == 'publish' for node in calls) == 1
    assert callable(runtime.collect_selected) and callable(runtime.publish)

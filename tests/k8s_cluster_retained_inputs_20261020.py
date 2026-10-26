"""Lossless portable old native input retention, not a current producer proof."""
from copy import deepcopy
from functools import lru_cache
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = 'tests/fixtures/k8s_cluster_native_inputs_20261020.tar.gz'
ARCHIVE_SHA256 = '60812356285354c3d0ed08742ccb8ba2cea225abc0199cf527b8d04393d419e2'
REPORT = 'docs/check-review/k8s-cluster-native-review-20261020.json'
REPORT_SHA256 = '214034ee33aec42c30e525cfcd7932e3060904c8884b39f372c2f33d0231dffc'
INDEX_SHA256 = '1763b44258e42562dbe7956298a57351c58f4ff461aa427a8acb513601ed1929'


@lru_cache(maxsize=1)
def _inputs():
    raw = (ROOT / ARCHIVE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA256, 'Unreviewed retained archive'
    assert hashlib.sha256((ROOT / REPORT).read_bytes()).hexdigest() == REPORT_SHA256, 'Original cluster report changed'
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
        members = tar.getmembers()
        assert len({m.name for m in members}) == len(members) == 438
        assert all(m.isfile() and m.size <= 5_000_000 for m in members)
        assert sum(m.size for m in members) <= 8_000_000
        manifest = json.loads(tar.extractfile('manifest.json').read())
        index = tar.extractfile('native-cases.json').read()
        assert hashlib.sha256(index).hexdigest() == INDEX_SHA256
        assert manifest['source_report_sha256'] == REPORT_SHA256
        assert manifest['index_sha256'] == INDEX_SHA256
        rows = manifest['captures']; expected = {'manifest.json', 'native-cases.json'}
        result = {}
        for row in rows:
            assert row['branch'] in ('positive', 'negative')
            name = 'captures/' + Path(row['path']).name
            assert name not in expected; expected.add(name)
            data = tar.extractfile(name).read()
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            document = json.loads(gzip.decompress(data))
            assert set(document) == {'snapshot', 'evaluator_arguments'}
            assert len(document['evaluator_arguments']) in (0, 1)
            key = row['id'], row['branch']
            assert key not in result
            result[key] = {**row, 'retained_member': name, 'document': document}
        assert expected == {m.name for m in members}
        assert len(result) == 436 and len({key[0] for key in result}) == 218
        return result


def capture(check_id, branch):
    """Fresh independent object; source changes still require separate adjudication."""
    return deepcopy(_inputs()[(check_id, branch)])


def ids():
    return tuple(sorted({cid for cid, branch in _inputs()}))

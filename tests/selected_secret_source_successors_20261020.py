"""Explicit current source successors; immutable admissions are never repinned."""
import gzip,hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SUCCESSORS={
 ('peaso/collectors/azure_app_settings_secret_indicators.py', 'cfa3a355e56183d283e6bdcd43aef57a5d4e0723be00f98746e8891bc1971a68'):
 ('docs/check-review/azure-selected-secret-union-source-successor-20261020.json', 'a18d8d25df01ff65f4dbc0cd493d18d6f381f89a73347d79c4607040a8db68bc'),
 ('peaso/collectors/azure_acr_image_secret_indicators.py', '59f9a87a07a6216a1cc940e68f973352a4b50f32f581507422b1733eeac368af'):
 ('docs/check-review/azure-selected-secret-union-source-successor-20261020.json', 'a18d8d25df01ff65f4dbc0cd493d18d6f381f89a73347d79c4607040a8db68bc'),
 ('peaso/collectors/k8s_literal_secret_indicators.py', '18b8e421f7e0c9b72f605c76ee5aab9955ca334a366e0ebce82f8bfdd9f53dd5'):
 ('docs/check-review/k8s-controller-literal-source-successor-20261020.json', '10a4ac4f4c35fe0c56f50b63df7f35983b708eabbb1b9f5cc00333a7f63be4f2'),
 ('peaso/checks/k8s_literal_secret_review_20261020.py', '9dc7cc4989fae8754808710f7d9fb55d2070886e938b4434c78621aa74dd5886'):
 ('docs/check-review/k8s-controller-literal-source-successor-20261020.json', '10a4ac4f4c35fe0c56f50b63df7f35983b708eabbb1b9f5cc00333a7f63be4f2'),
 ('peaso/secret_findings.py','7de03e95c2ddf07ecffc4634e9f5a07fe1d8563439dab844651c92bc382c7784'):
 ('docs/check-review/secret-grouping-incomplete-source-successor-20261020.json','5ce78ce7549a6c28e643a11505917140a9a5fb89ac8f1cecc0dc72379e8df49f'),
}
PRIVATE_NATIVE_SOURCE = (
 'peaso/collectors/aws_lambda_environment_secret_indicators.py',
 '2fce27977e83ba4f9abc6baa6ac78d4ff5e0e4a2b8b27d52d333a0458e67f289',
)
RAWV2_SCANNER_SOURCE = (
 'peaso/secret_scanning.py',
 '72aaf391e3b168d9b8f7a10603a5763c04137b5e7807fef320b4fc22fa1a9d19',
)

def _successor(path,expected,root):
    proof_path,proof_sha=SUCCESSORS[(path,expected)]
    raw=(root/proof_path).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==proof_sha,'Source successor proof changed'
    document=json.loads(raw)
    candidates=document.get('sources',[document])
    row,=[r for r in candidates if r['source_path']==path and r['prior_sha256']==expected]
    retained=row['retained_predecessor'];target=(root/retained['path']).resolve()
    assert target.is_relative_to(root.resolve()),'Retained source escaped repository'
    raw=target.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==retained['sha256'],'Retained source archive changed'
    before=gzip.decompress(raw)
    assert hashlib.sha256(before).hexdigest()==expected,'Historical source is not the admitted predecessor'
    current=(root/path).read_bytes()
    if hashlib.sha256(current).hexdigest()!=row['current_sha256']:
        from peaso import private_secret_source_epoch_20261021 as epoch
        current=epoch.predecessor_bytes(path,current,row['current_sha256'],root)
    assert hashlib.sha256(current).hexdigest()==row['current_sha256'],'Unreviewed current source changed'
    return before


def assert_source_receipt(path,expected,root=ROOT):
    root=Path(root);path=str(path)
    if hashlib.sha256((root/path).read_bytes()).hexdigest()==expected:return
    if (path,expected)==PRIVATE_NATIVE_SOURCE:
        from peaso.private_secret_source_epoch_20261021 import predecessor_bytes
        before=predecessor_bytes(path,(root/path).read_bytes(),expected,root)
        assert hashlib.sha256(before).hexdigest()==expected,'Historical native source changed'
        return
    if (path,expected)==RAWV2_SCANNER_SOURCE:
        from peaso.rawv2_private_source_successor_20261021 import source_bytes
        before=source_bytes(path,(root/path).read_bytes(),expected,root)
        assert hashlib.sha256(before).hexdigest()==expected,'Historical scanner source changed'
        return
    from peaso import private_secret_source_epoch_20261021 as epoch
    row=epoch.source_rows().get(path)
    reviewed=epoch._receipt()[0]['current_reviewed_files'].get(path)
    if ((row is not None and row['before_sha256']==expected)
            or (reviewed is not None and reviewed['predecessor_sha256']==expected)):
        before=epoch.predecessor_bytes(path,(root/path).read_bytes(),expected,root)
        assert hashlib.sha256(before).hexdigest()==expected,'Historical native source changed'
        return
    if (path,expected)==('peaso/collectors/gcp_image_secret_indicators.py',
            '7891365e7a5ecd82734dd385d1ed64b56b11e1283e07dc2f3b9e16cbee2e104e'):
        from peaso import gcp_private_source_successor_20261021 as current
        rows=current._source_delta(root)
        current._source_hash(path,(root/path).read_bytes(),expected,rows,root)
        return
    assert (path,expected)in SUCCESSORS,'No reviewed source successor: '+path
    _successor(path,expected,root)


def assert_callable_receipt(path,name,expected,source_sha,root=ROOT):
    """Validate the historical function against retained, source-bound bytes."""
    import ast
    root=Path(root)
    assert_source_receipt(path,source_sha,root)
    if hashlib.sha256((root/path).read_bytes()).hexdigest()==source_sha:
        raw=(root/path).read_bytes()
    else:
        raw=_successor(path,source_sha,root)
    text=raw.decode();node,=[n for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name]
    lines=text.splitlines(keepends=True)
    body=''.join(lines[node.lineno-1:node.end_lineno])
    assert hashlib.sha256(body.encode()).hexdigest()==expected,'Historical predicate body changed'

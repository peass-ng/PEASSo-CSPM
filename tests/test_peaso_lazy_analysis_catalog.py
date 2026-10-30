"""Pure projections stay offline; explicit metadata requests retain all guards."""
import subprocess
import sys
import textwrap


def run(code):
    subprocess.run([sys.executable, '-c', textwrap.dedent(code)], capture_output=True, text=True, check=True)


def test_real_principal_projection_and_report_expansion_do_not_initialize_registries():
    run('''
        import sys
        from peaso.principal_exposure import project
        from peaso.snapshot import make_snapshot, resources
        from peaso.engine import REPORT_SCHEMA_VERSION, expand_report
        snap=make_snapshot('gcp',['projects/one'],[{'type':'service_account','scope':'projects/one',
            'status':'collected','items':[{'email':'one@fixture.invalid','name':'one'}]}])
        rows=resources(snap)
        assert 'serviceAccount:one@fixture.invalid' in project(snap,rows)
        report={'schema_version':REPORT_SCHEMA_VERSION,'snapshot_id':snap['snapshot_id'],
            'provider':'gcp','resources':[{k:v for k,v in row.items() if k!='data'} for row in rows],
            'findings':[],'graphs':{}}
        assert expand_report(report,snap)['resources'][0]['data']==rows[0]['data']
        assert not any(name in sys.modules for name in ('peaso.collectors','peaso.checks','peaso.analysis.catalog'))
    ''')


def test_metadata_is_lazy_cached_and_preserves_public_imports_and_explicit_overrides():
    run('''
        import sys,types
        import peaso.analysis as analysis
        assert 'REQUIRED_TYPES' in dir(analysis) and 'ANALYSIS_CHECKS' in dir(analysis)
        assert 'peaso.analysis.catalog' not in sys.modules
        metadata=types.ModuleType('peaso.analysis.catalog')
        metadata.REQUIRED_TYPES={'fixture':{'exposure':['exact-type']}}
        metadata.ANALYSIS_CHECKS=[{'id':'fixture'}]
        sys.modules['peaso.analysis.catalog']=metadata
        override=[{'id':'explicit-override'}]
        analysis.ANALYSIS_CHECKS=override
        from peaso.analysis import REQUIRED_TYPES,ANALYSIS_CHECKS
        assert REQUIRED_TYPES is metadata.REQUIRED_TYPES
        assert ANALYSIS_CHECKS is override
        assert analysis.REQUIRED_TYPES is REQUIRED_TYPES
        try: analysis.unknown_export
        except AttributeError: pass
        else: raise AssertionError('unknown export must fail')
        assert 'peaso.collectors' not in sys.modules
    ''')


def test_provider_registration_failure_is_still_propagated_when_metadata_is_requested():
    run('''
        import sys,types
        import peaso.analysis as analysis
        calls=[]
        provider=types.ModuleType('peaso.collectors')
        def supported_types(name):
            calls.append(name)
            raise RuntimeError('provider_registration_guard')
        provider.supported_types=supported_types
        sys.modules['peaso.collectors']=provider
        for name in ('REQUIRED_TYPES','ANALYSIS_CHECKS'):
            try: getattr(analysis,name)
            except RuntimeError as error: assert str(error)=='provider_registration_guard'
            else: raise AssertionError('registration errors cannot be suppressed')
            assert name not in analysis.__dict__
            assert 'peaso.analysis.catalog' not in sys.modules
        assert len(calls)==2
    ''')


def test_moved_catalog_initialization_matches_reviewed_predecessor_ast():
    # Metadata construction remains the same program; moving it must not change
    # the requested inventory floor or the public analysis check descriptions.
    import ast
    import hashlib
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'peaso/analysis/catalog.py').read_text()
    import sys
    body = ast.parse(source[source.index('REQUIRED_TYPES = {'):])
    # Python 3.13 omits empty AST fields by default; keep one dump format across versions.
    options = {'show_empty': True} if sys.version_info >= (3, 13) else {}
    assert hashlib.sha256(ast.dump(body, **options).encode()).hexdigest() == 'f59be80226e8274ca35c8c93250f52612ce593a7c0b4ba014cd19ffd771f8446'


def test_analysis_findings_use_reviewed_presentation_without_native_import():
    run('''
        import json,sys
        from pathlib import Path
        from peaso.analysis.common import finding
        registry=json.loads(Path('peaso/checks/finding_types.json').read_text())['checks']
        snapshot={'provider':'aws','snapshot_id':'fixture','collections':[]}
        resource={'provider':'aws','scope':'account/region','type':'instance','id':'fixture','data':{}}
        for cid in registry:
            if cid.startswith('analysis.'):
                result=finding(snapshot,resource,'exposure',cid,'Recorded condition','info',{},status='UNKNOWN')
                assert result['finding_type']==registry[cid]
        assert not any(name in sys.modules for name in ('peaso.checks','peaso.collectors','peaso.analysis.catalog'))
    ''')


def test_nonanalysis_finding_lookup_preserves_native_resolution_and_failure():
    run('''
        import sys,types
        from peaso.analysis.common import finding
        import peaso.finding_types as taxonomy
        calls=[]
        def lookup(cid):
            calls.append(cid)
            raise RuntimeError('native taxonomy registration rejected')
        taxonomy.type_for=lookup
        snapshot={'provider':'aws','snapshot_id':'fixture','collections':[]}
        resource={'provider':'aws','scope':'account/region','type':'instance','id':'fixture','data':{}}
        try: finding(snapshot,resource,'hardening','native.fixture','Recorded condition','info',{})
        except RuntimeError as error: assert str(error)=='native taxonomy registration rejected'
        else: raise AssertionError('native failure was suppressed')
        assert calls==['native.fixture']
    ''')


def test_exposure_only_projection_does_not_initialize_inventory_catalog():
    run('''
        import sys
        from peaso.analysis import analyze_findings
        from peaso.snapshot import make_snapshot,resources
        snap=make_snapshot('aws',['111122223333/global'],[{'type':'iam_role',
            'scope':'111122223333/global','status':'collected','items':[{
                'Arn':'arn:aws:iam::111122223333:role/runtime','RoleName':'runtime',
                'AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow',
                    'Principal':{'AWS':'*'},'Action':'sts:AssumeRole'}]}}]}])
        output=analyze_findings(snap,resources(snap),categories={'exposure'},include_manual_only=False)
        assert output and all(row['category']=='exposure' for row in output)
        assert not any(name in sys.modules for name in ('peaso.checks','peaso.collectors','peaso.analysis.catalog'))
    ''')

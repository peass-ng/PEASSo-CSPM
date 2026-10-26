"""Exact readable Markdown JSON parity and conservative native-encoder fallbacks."""
import copy,datetime,importlib.util,json,os,random,re
from pathlib import Path
import pytest
from peaso.snapshot import freeze,FrozenDict,FrozenList
candidate=os.environ.get('PEASO_REPORTS_CANDIDATE')
if candidate:
 spec=importlib.util.spec_from_file_location('peaso.markdown_candidate',candidate);subject=importlib.util.module_from_spec(spec);spec.loader.exec_module(subject)
else:
 from peaso import reports as subject

def original(value):
 text=json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)
 longest=max((len(m.group()) for m in re.finditer(r'`+',text)),default=0);fence='`'*max(3,longest+1)
 return [fence+'json',text,fence,'']

def outcome(call,value):
 try:return ('value',call(value))
 except Exception as exc:return ('error',type(exc),exc.args)

@pytest.mark.parametrize('value',[None,True,False,0,-12,2**63-1,2**100,2**4096,'',[],{},[{},[],None],{'z':{'b':[2,1],'a':None},'a':True},{'z':'é 😀 \u2028 \u2029','a':'"\\/\b\f\n\r\t\x00\x1f'},{'````':'triple``` and five`````'},{'日本語':'مرحبا','𝌆':'é'},{'data':FrozenDict({'z':FrozenList([1,False,None]),'a':'native'})}])
def test_strict_json_preserves_exact_fences_spacing_unicode_and_key_order(value):
 before=copy.deepcopy(value);assert subject._json_block(value)==original(value);assert value==before

def test_seeded_generated_and_frozen_trees_match_exact_stdlib():
 rng=random.Random(77119)
 def tree(depth):
  if depth<=0 or rng.random()<.4:return rng.choice([None,True,False,0,-7,2**100,'é😀','````','quote"\n\\',''])
  if rng.random()<.5:return [tree(depth-1) for _ in range(rng.randrange(5))]
  return {str(rng.randrange(30))+rng.choice(['','é','😀']):tree(depth-1) for _ in range(rng.randrange(5))}
 for _ in range(600):
  value=tree(5);assert subject._json_block(value)==original(value)
  sealed=freeze(value);assert subject._json_block(sealed)==original(sealed)

@pytest.mark.parametrize('value',[0.0,-0.0,1.3,1e-6,1e30,float('inf'),float('-inf'),float('nan'),{'x':[1,3.2]},'\ud800',{'\udfff':'x'},b'bytes',{1:'key'}, {None:'key'}, {True:'key'}, {1:'x','a':'y'}, {'x':datetime.datetime(2026,1,1)}, {'x':{1,2}}, (1,2)])
def test_unsupported_values_preserve_stdlib_output_and_exception(monkeypatch,value):
 def forbidden(*args,**kwargs):raise AssertionError('Unsupported value reached native encoder')
 monkeypatch.setattr(subject,'_core_pretty_json',forbidden)
 assert outcome(subject._json_block,value)==outcome(original,value)

@pytest.mark.parametrize('factory',[lambda:type('String',(str,),{})('x'),lambda:type('Integer',(int,),{})(3),lambda:type('Float',(float,),{})(1.25),lambda:type('List',(list,),{})([1]),lambda:type('Dict',(dict,),{})({'a':1}),lambda:type('Frozen',(FrozenDict,),{})({'a':1})])
def test_arbitrary_subclasses_retain_original_path(monkeypatch,factory):
 def forbidden(*args,**kwargs):raise AssertionError('Subclass reached native encoder')
 monkeypatch.setattr(subject,'_core_pretty_json',forbidden);value=factory();assert outcome(subject._json_block,value)==outcome(original,value)

def test_cycles_and_deep_supported_trees_keep_original_behavior(monkeypatch):
 def forbidden(*args,**kwargs):raise AssertionError('Unsupported depth reached native encoder')
 monkeypatch.setattr(subject,'_core_pretty_json',forbidden)
 cycle=[];cycle.append(cycle);assert outcome(subject._json_block,cycle)==outcome(original,cycle)
 value='leaf'
 for _ in range(80):value=[value]
 assert subject._json_block(value)==original(value)

def test_native_failure_and_absent_optional_backend_fall_back(monkeypatch):
 value={'z':[1,2],'a':'é'}
 def unavailable(*args,**kwargs):raise ValueError('native unavailable')
 monkeypatch.setattr(subject,'_core_pretty_json',unavailable);assert subject._json_block(value)==original(value)
 monkeypatch.setattr(subject,'_core_pretty_json',None);assert subject._json_block(value)==original(value)

def test_supported_native_path_actually_executes(monkeypatch):
 real=subject._core_pretty_json
 if real is None:pytest.skip('Optional native encoder not installed or unsupported')
 calls=[]
 def record(value,**kwargs):calls.append(value);return real(value,**kwargs)
 monkeypatch.setattr(subject,'_core_pretty_json',record)
 value={'z':{'b':1,'a':'é'},'a':FrozenList([True,None])};assert subject._json_block(value)==original(value)
 assert len(calls)==1 and list(calls[0])==['a','z'] and type(calls[0]['a']) is list


def test_large_integer_keeps_stdlib_digit_limit_and_output(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Large integer reached native encoder')
    monkeypatch.setattr(subject, '_core_pretty_json', forbidden)
    for value in [2**100, -(2**100), 2**20000]:
        assert outcome(subject._json_block, value) == outcome(original, value)

def test_exhaustive_bmp_scalar_escaping_matches_stdlib():
    value = ''.join(chr(i) for i in range(65536) if not 0xD800 <= i <= 0xDFFF)
    assert subject._json_block({'text': value}) == original({'text': value})

@pytest.mark.parametrize('mode',['missing_keyword','wrong_format','unavailable'])
def test_older_or_incompatible_backend_is_disabled_once(monkeypatch,mode):
    import sys,types
    fake=types.ModuleType('pydantic_core')
    if mode=='missing_keyword':
        fake.to_json=lambda value,indent=None:b'{}'
    elif mode=='wrong_format':
        fake.to_json=lambda value,**kwargs:b'{}'
    else:
        def unavailable(*args,**kwargs):raise ValueError('unsupported')
        fake.to_json=unavailable
    monkeypatch.setitem(sys.modules,'pydantic_core',fake)
    spec=importlib.util.spec_from_file_location('peaso.markdown_compatibility',subject.__file__)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    assert module._core_pretty_json is None
    assert module._json_block({'z':[1,2],'a':'é'})==original({'z':[1,2],'a':'é'})

def test_backtick_free_blocks_skip_the_fence_scan_with_identical_output(monkeypatch):
 values=[{'a':[1,'plain',None]},{'tick':'one ` and ``` three'}]
 expected=[original(value) for value in values]
 scans=[]
 real=subject.re.finditer
 monkeypatch.setattr(subject.re,'finditer',lambda *a,**k:scans.append(a[1]) or real(*a,**k))
 assert [subject._json_block(value) for value in values]==expected
 assert len(scans)==1 and '```' in scans[0]

"""Request-bound runtime bridge for the immutable selected metadata reader."""
import json
from . import k8s_selected_metadata_secret_indicators_20261020 as source

KIND=source.KIND
CHECK=source.CHECK
OPTION=source.OPTION
GRANT='_k8s_selected_metadata_grant'
_TOKEN=object()


class _Grant:
    __slots__=('token','scopes','selection')
    def __init__(self,scopes,selection):
        self.token=_TOKEN
        self.scopes=tuple(scopes)
        self.selection=selection
    def __repr__(self):
        return '<selected Kubernetes metadata authorization>'


def _selection(options):
    return json.dumps(options.get(OPTION),sort_keys=True,separators=(',',':'),allow_nan=False)


def preflight(options,scopes,named=()):
    """Validate explicit selectors before credentials, without authorizing reads."""
    if not isinstance(options,dict):raise ValueError('Kubernetes options must be an object')
    probe={**options,'_content_secret_scan_kinds':[KIND]if CHECK in named else[]}
    return source.selected_targets(probe,scopes)


def authorize(options,scopes,named=()):
    """Called by public engine after request validation; untrusted grants replaced."""
    options.pop(GRANT,None)
    targets=preflight(options,scopes,named)
    if options.get('content_secret_scans')is True and CHECK in named:
        options[GRANT]=_Grant(scopes,_selection(options))
    return targets


def enabled(options,scopes=None):
    grant=options.get(GRANT)
    try:
        return (type(grant)is _Grant and grant.token is _TOKEN
            and options.get('content_secret_scans')is True and grant.selection==_selection(options)
            and (scopes is None or tuple(scopes)==grant.scopes[:len(scopes)]))
    except(TypeError,ValueError):return False


def assert_private_transport(api):
    client=getattr(getattr(api,'api',api),'api_client',None)
    pool=getattr(getattr(client,'rest_client',None),'pool_manager',None)
    if source._wire_debug_enabled(getattr(pool,'pool',None)):
        raise source.Incomplete('native_wire_debug_enabled')


def collect(reader,api,options,scopes,cluster):
    authorized=enabled(options,scopes)
    selected=source.selected_targets({**options,'_content_secret_scan_kinds':[]},list(options[GRANT].scopes)if authorized else scopes)
    selected=[target for target in selected if scopes==['*']or target['namespace']in scopes]
    safe={**options,'_content_secret_scan_kinds':[KIND]if authorized and selected else[]}
    if selected:safe[OPTION]=selected
    else:safe.pop(OPTION,None)
    if authorized:
        assert_private_transport(api)
    return source.collect(reader,api,safe,scopes,cluster)


def finalize(scopes,collections,metadata,*ledgers):
    """Scrub the full union once, before clearing any constituent match set."""
    union=set().union(*ledgers)
    try:return source.redact_output(scopes,collections,metadata,union)
    finally:
        for ledger in ledgers:ledger.clear()

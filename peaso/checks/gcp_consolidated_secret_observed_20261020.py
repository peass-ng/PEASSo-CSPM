"""Brief positive observations of canonical, deduplicated GCP source leaks."""
import json
import re
from functools import lru_cache
from pathlib import Path
from peaso.secret_scanning import merge_leaks
from peaso.secret_findings import _observed as _grouped_observed


@lru_cache(maxsize=1)
def profiles():
    return json.loads(Path(__file__).with_name('gcp_consolidated_secret_profiles_20261020.json').read_text())


def observation(finding):
    try:
        allowed=profiles();cid=finding['check_id'];linked=finding['linked_check_ids'];e=finding['evidence']
        partial=e.get('complete')is False and e.get('coverage')=='incomplete'
        if (finding['provider']!='gcp'or finding['status']!='FAIL'or cid not in allowed['checks']
                or not isinstance(linked,list)or not linked or len(set(linked))!=len(linked)
                or cid not in linked or not set(linked)<=set(allowed['checks'])
                or e.get('credential_validation')!='not_attempted'
                or set(e)!={'secret_leaks','credential_validation','observed'}|({'complete','coverage'}if partial else set())):return None
        leaks=e['secret_leaks']
        if (not isinstance(leaks,list)or len(leaks)!=1 or merge_leaks(leaks)!=leaks
                or finding['secret_fingerprint']!=leaks[0]['fingerprint']):return None
        if (not re.fullmatch(r'[0-9a-f]{64}',leaks[0]['fingerprint'])or not leaks[0]['detectors']
                or any(d.get('engine')not in ('kingfisher','trufflehog')for d in leaks[0]['detectors'])):return None
        count=len(leaks[0]['locations'])
        if count<1:return None
        # Reports stored before found values were shown say "Its value is hidden.".
        legacy=(f'The same secret was detected in {count} scanned location(s). Its value is hidden.'
                +(' Coverage is incomplete.'if partial else''))
        if e['observed']!=_grouped_observed(e) and ('value' in leaks[0] or e['observed']!=legacy):return None
        if set(linked)<=set(allowed['locators']):
            seen=set()
            for loc in leaks[0]['locations']:
                scope=loc.get('scope')
                if not isinstance(scope,str)or not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]',scope):return None
                matches=[]
                for key in linked:
                    profile=allowed['locators'][key]
                    suffix=r'\.part-(?:[1-9][0-9]?|100)'if profile['part']else r'\.source'
                    match=re.fullmatch('('+re.escape(profile['prefix'])+r':[0-9a-f]{64})'+suffix,loc.get('path',''))
                    if match and loc.get('resource_id')=='//gcp/'+scope+'/global/'+profile['kind']+'/'+match[1]:matches.append(key)
                if len(matches)!=1:return None
                seen.update(matches)
            if seen!=set(linked):return None
        subjects=allowed['subjects']
        if len(linked)==1 and linked[0]in subjects:subject=subjects[linked[0]]
        elif set(linked)<=set(subjects):
            services=sorted({subjects[key].split()[2]for key in linked})
            subject='selected '+' and '.join(services)+' sources'
        else:subject=f'{count} selected source '+('location'if count==1 else'locations')
        return f'A likely secret was detected in {subject}. Its value is hidden and was not validated'+('; inspection is incomplete.'if partial else'.')
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):return None

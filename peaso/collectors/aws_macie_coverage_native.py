"""Complete native account/Region Macie configuration, never classification results."""
import copy
import re

KIND='s3_macie_region_coverage'
SPECS={KIND:('macie2','get_macie_session',None)}
GLOBAL_TYPES={KIND}
NATIVE_IDS={KIND:'id'}
_OK={'collected','empty'}


def _result(rows=(),status='collected',code=None):
    from .aws import ReadResult
    return ReadResult(list(rows),status,{'code':code}if code else None)


def _require(read,reason):
    from .aws import ReadFailure
    if read.status not in _OK:
        raise ReadFailure((read.error or{}).get('cause_status',read.status),(read.error or{}).get('code',reason))
    return read.items


def _detail(value,reason):
    from .aws import ReadFailure
    if not isinstance(value,dict)or value.get('collection_status')!='collected':
        raise ReadFailure(value.get('collection_status','malformed')if isinstance(value,dict)else'malformed',(value.get('error')or{}).get('code',reason)if isinstance(value,dict)else reason)
    return value


def collect(requests,session,region,account):
    from .aws import ReadFailure
    try:
        identity=_detail(requests.detail(session,'sts',region,'get_caller_identity'),'macie_account_identity_incomplete')
        arn=identity.get('Arn','')
        match=re.fullmatch(r'arn:(aws(?:-[a-z0-9-]+)?):(?:iam|sts)::'+re.escape(account)+r':.+',arn)
        if identity.get('Account')!=account or not match:raise ValueError('Macie account/partition identity mismatch')
        partition=match.group(1)
        discovery=requests.pages(session,'ec2',region,'describe_regions','Regions',AllRegions=True)
        native_regions=_require(discovery,'macie_region_universe_incomplete');seen=set();enabled=[]
        for row in native_regions:
            name,state=row.get('RegionName'),row.get('OptInStatus')
            if (not isinstance(name,str)or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+',name)or name in seen
                    or state not in {'opt-in-not-required','opted-in','not-opted-in'}):raise ValueError('Macie enabled Region identity unresolved')
            if session.get_partition_for_region(name)!=partition:raise ValueError('Macie Region partition mismatch')
            seen.add(name)
            if state!='not-opted-in':enabled.append(name)
        excluded = getattr(requests, 'scp_denied_regions_by_account', {}).get(account, [])
        if (not isinstance(excluded, list) or len(set(excluded)) != len(excluded)
                or any(name not in enabled for name in excluded)):
            raise ValueError('Macie SCP Region exclusion evidence invalid')
        enabled = [name for name in enabled if name not in excluded]
        audited=getattr(requests,'audited_regions_by_account',{}).get(account)
        if not enabled or not isinstance(audited,list)or len(audited)!=len(set(audited))or set(audited)!=set(enabled):
            return _result([], 'not_collected','macie_full_account_region_selection_incomplete')
        regions=[]
        operations={'sts:GetCallerIdentity','ec2:DescribeRegions','macie2:GetMacieSession','macie2:ListClassificationJobs'}
        for observed in sorted(enabled):
            native_session=requests.detail(session,'macie2',observed,'get_macie_session')
            service_off=(native_session.get('collection_status')=='empty'and native_session.get('absent')is True
                         and(native_session.get('error')or{}).get('code')=='service_not_enabled')
            session_fact={'status':'DISABLED'}if service_off else _detail(native_session,'macie_session_incomplete')
            state=session_fact.get('status')
            if state not in {'ENABLED','PAUSED'}and not(service_off and state=='DISABLED'):raise ValueError('Macie session state unknown')
            service_role=session_fact.get('serviceRole')
            if service_role is not None and (not isinstance(service_role,str)or not service_role.startswith('arn:'+partition+':iam::'+account+':role/')):
                raise ValueError('Macie session service role belongs to another account')
            regional={'Region':observed,'Session':{'status':state,'collection_status':'collected'}}
            if service_off:
                regional['Session']['_provenance']={'service_state':'service_not_enabled','original_collection_status':'empty'}
            if state=='ENABLED':
                operations.add('macie2:GetAutomatedDiscoveryConfiguration')
                automated=_detail(requests.detail(session,'macie2',observed,'get_automated_discovery_configuration'),'macie_automated_discovery_incomplete')
                if automated.get('status')not in {'ENABLED','DISABLED'}:raise ValueError('Macie automated discovery state unknown')
                # ENABLED alone does not prove this bucket is in the actual
                # classification scope (including organization administrator
                # exclusions). GetClassificationScope is intentionally outside
                # the current permission set; retain unavailable, never DISABLED.
                if automated['status'] == 'ENABLED':
                    return _result([], 'not_collected', 'macie_automated_scope_unresolved')
                regional['AutomatedDiscovery']={'status':automated['status'],'collection_status':'collected'}
            listing=requests.pages(session,'macie2',observed,'list_classification_jobs','items')
            if listing.status=='empty'and(listing.error or{}).get('code')not in {None,'service_not_enabled'}:
                raise ReadFailure('unknown','macie_classification_jobs_state_unresolved')
            if service_off and listing.items:
                raise ReadFailure('unknown','macie_session_jobs_state_conflict')
            jobs=[];job_ids=set()
            for summary in _require(listing,'macie_classification_jobs_incomplete'):
                job_id=summary.get('jobId')
                if not isinstance(job_id,str)or not re.fullmatch(r'[a-fA-F0-9]{32}',job_id)or job_id in job_ids:raise ValueError('Macie classification job identity unresolved')
                job_ids.add(job_id)
                operations.add('macie2:DescribeClassificationJob')
                job=_detail(requests.detail(session,'macie2',observed,'describe_classification_job',jobId=job_id),'macie_job_detail_incomplete')
                if job.get('jobId')!=job_id or job.get('jobArn')!='arn:'+partition+':macie2:'+observed+':'+account+':classification-job/'+job_id:
                    raise ValueError('Macie classification job account/Region mismatch')
                if job.get('jobStatus')not in {'RUNNING','COMPLETE','CANCELLED','PAUSED','IDLE','USER_PAUSED'}:raise ValueError('Macie classification job state unknown')
                definition=job.get('s3JobDefinition')
                if not isinstance(definition,dict):raise ValueError('Macie job bucket selection missing')
                selection={key:copy.deepcopy(definition[key])for key in ('bucketDefinitions','bucketCriteria')if key in definition}
                unresolved_reason=None
                if definition.get('scoping') not in (None, {}):
                    selection={};unresolved_reason='object_scope_unresolved'
                sampling=job.get('samplingPercentage')
                # No native GET omission is promoted into a sampling default.
                if type(sampling) is not int or sampling != 100:
                    selection={};unresolved_reason='full_sampling_unproven'
                criteria = selection.get('bucketCriteria')
                if isinstance(criteria, dict):
                    # Unknown/tag criteria stay unresolved without retaining
                    # free-form tag values or custom classifier text.
                    supported = set(criteria) <= {'includes', 'excludes'}
                    for block in criteria.values():
                        rules = block.get('and') if isinstance(block, dict) else None
                        if not isinstance(rules, list) or set(block) != {'and'}: supported = False; continue
                        for rule in rules:
                            simple = rule.get('simpleCriterion') if isinstance(rule, dict) else None
                            if not isinstance(simple, dict) or set(rule) != {'simpleCriterion'} or simple.get('key') not in {'ACCOUNT_ID', 'S3_BUCKET_NAME'} or simple.get('comparator') not in {'EQ', 'NE'}:
                                supported = False
                            elif set(simple) != {'key', 'comparator', 'values'} or not isinstance(simple['values'], list) or not 1 <= len(simple['values']) <= 1000:
                                supported = False
                            elif any(not isinstance(value, str) or not re.fullmatch(r'[0-9]{12}' if simple['key'] == 'ACCOUNT_ID' else r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value) for value in simple['values']):
                                supported = False
                    if not supported: selection = {};unresolved_reason='bucket_criteria_unresolved'
                definitions = selection.get('bucketDefinitions')
                if definitions is not None:
                    if not isinstance(definitions, list) or len(definitions) > 1000: raise ValueError('Macie bucket definitions malformed')
                    for group in definitions:
                        if not isinstance(group, dict) or set(group) != {'accountId', 'buckets'} or not isinstance(group['accountId'], str) or not re.fullmatch(r'[0-9]{12}', group['accountId']) or not isinstance(group['buckets'], list) or len(group['buckets']) > 1000:
                            raise ValueError('Macie bucket ownership malformed')
                        if any(not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', name) for name in group['buckets']): raise ValueError('Macie bucket name malformed')
                # Preserve actual selection semantics; no findings, sample values,
                # free-form job descriptions, names or custom classifier payload.
                jobs.append({'jobId':job_id,'jobArn':job['jobArn'],'jobStatus':job['jobStatus'],'s3JobDefinition':selection,**({'_provenance':{'selection_status':'unresolved','reason':unresolved_reason}}if unresolved_reason else{})})
            regional['Jobs']={'collection_status':'collected'if jobs else'empty','items':jobs}
            regions.append(regional)
        return _result([{'id':'macie-coverage/'+account,'AccountId':account,'AllEnabledRegionsCollected':True,'Regions':regions,
            '_provenance':{'read_only':True,'native_region_universe_complete':True,'observed_at':requests.observed_at.isoformat(),
                           'scp_denied_regions':sorted(excluded),'operations':sorted(operations)}}])
    except ReadFailure as exc:
        return _result([],exc.status,exc.code)
    except (ValueError,TypeError,KeyError,AttributeError):
        return _result([],'malformed','macie_native_evidence_malformed')


FETCHERS={KIND:collect}

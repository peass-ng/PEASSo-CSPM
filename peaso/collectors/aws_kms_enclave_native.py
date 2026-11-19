"""Opt-in KMS Nitro enclave PCR metadata from CloudTrail management event history.

The raw event, identity, access keys, requests and responses never enter a cache
or snapshot. This does not decrypt data or attest that an enclave is running.
"""
from datetime import datetime,timedelta,timezone
import json,re
SPECS={'cloudtrail_event':('cloudtrail','lookup_events','Events')}
NATIVE_IDS={'cloudtrail_event':'EventId'}
READ_ACTIONS={('ec2', 'describe_instances')}  # Existing exact inventory grant; history uses shared pacing.
OPERATIONS={'Decrypt','DeriveSharedSecret','GenerateDataKey','GenerateDataKeyPair','GenerateRandom'}
REFERENCE='https://docs.aws.amazon.com/kms/latest/developerguide/ct-nitro-enclave.html'

def _time(value):
 if not isinstance(value,str):raise ValueError('event time missing')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None or parsed.utcoffset()is None:raise ValueError('event time timezone missing')
 return parsed.astimezone(timezone.utc)
def _object(pairs):
 out={}
 for key,value in pairs:
  if key in out:raise ValueError('ambiguous duplicate event key')
  out[key]=value
 return out

def is_enclave_query(attributes):
 return (isinstance(attributes,list)and len(attributes)==1 and isinstance(attributes[0],dict)and set(attributes[0])=={'AttributeKey','AttributeValue'}and attributes[0].get('AttributeKey')=='EventName'and attributes[0].get('AttributeValue')in OPERATIONS)

def project(response, expected_operation):
 """Called at the SDK boundary, before Request's single-flight Future is set."""
 from .aws import ReadFailure
 try:
  if expected_operation not in OPERATIONS:raise ValueError('undeclared enclave query')
  if not isinstance(response,dict)or not isinstance(response.get('Events'),list):raise ValueError('event page unavailable')
  rows=[]
  for event in response['Events']:
   if not isinstance(event,dict)or not isinstance(event.get('CloudTrailEvent'),str):raise ValueError('event body missing')
   payload=json.loads(event['CloudTrailEvent'],object_pairs_hook=_object)
   if not isinstance(payload,dict):raise ValueError('event body malformed')
   ident=event.get('EventId');name=event.get('EventName');when=event.get('EventTime');account=payload.get('recipientAccountId');region=payload.get('awsRegion')
   if not isinstance(ident,str)or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',ident)or payload.get('eventID')!=ident or payload.get('eventName')!=name or payload.get('eventSource')!='kms.amazonaws.com'or event.get('EventSource','kms.amazonaws.com')!='kms.amazonaws.com'or payload.get('eventType')!='AwsApiCall'or not isinstance(account,str)or not re.fullmatch(r'[0-9]{12}',account)or not isinstance(region,str)or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+',region)or not isinstance(when,datetime)or when.tzinfo is None or _time(payload.get('eventTime'))!=when.astimezone(timezone.utc):raise ValueError('event identity mismatch')
   if name!=expected_operation:raise ValueError('event query mismatch')
   additional=payload.get('additionalEventData',{})
   if not isinstance(additional,dict):raise ValueError('additional event data malformed')
   if 'recipient'not in additional:continue
   recipient=additional['recipient']
   if not isinstance(recipient,dict):raise ValueError('recipient metadata malformed')
   module=recipient.get('attestationDocumentModuleId')
   if isinstance(module,str)and re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})-tpm[0-9a-f]{8,32}',module)and any(k.startswith('attestationDocumentNitroTPMPCR')for k in recipient):continue
   if not isinstance(module,str)or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})-enc[0-9a-f]{8,32}',module):raise ValueError('enclave module metadata unavailable')
   pcrs={'PCR0':recipient.get('attestationDocumentEnclaveImageDigest')}
   for key,value in recipient.items():
    if key.startswith('attestationDocumentEnclavePCR'):
     index=key.removeprefix('attestationDocumentEnclavePCR')
     if index not in('0','1','2','3','4','8'):raise ValueError('unrecognized enclave PCR')
     if index=='0'and value!=pcrs['PCR0']:raise ValueError('conflicting PCR0 metadata')
     pcrs['PCR'+index]=value
   if any(not isinstance(v,str)or not re.fullmatch(r'[0-9a-fA-F]{96}',v)for v in pcrs.values()):raise ValueError('PCR SHA384 metadata malformed')
   rows.append({'EventId':ident,'EventName':name,'EventSource':'kms.amazonaws.com','EventTime':when.isoformat(),'AccountId':account,'Region':region,'IsEnclaveAttestation':True,'AttestationPcrs':pcrs})
  result={'Events':rows}
  if 'NextToken'in response:
   if not isinstance(response['NextToken'],str)or not response['NextToken']:raise ValueError('event cursor malformed')
   result['NextToken']=response['NextToken']
  return result
 except (ValueError,TypeError,AttributeError):raise ReadFailure('malformed','kms_enclave_metadata_invalid')from None

def _history_jobs(requests, start, end):
 # Explicit inventory caps retain their serial admission and pagination budget.
 parallel = (getattr(requests, 'workers', 1) > 1 and all(
  getattr(requests, name, None) is None for name in ('max_calls', 'max_pages', 'max_items')))
 count = min(24, max(1, (requests.activity_minutes + 59) // 60)) if parallel else 1
 edges = [start + (end - start) * index / count for index in range(count)] + [end]
 # Overlap internal edges so an event on a boundary is covered even when
 # the provider treats a query endpoint as exclusive. Never widen the user's
 # requested outer window.
 overlap = timedelta(seconds=1) if count > 1 else timedelta(0)
 return [(name, max(start, edges[index] - overlap), min(end, edges[index + 1] + overlap))
         for name in sorted(OPERATIONS) for index in range(count)], parallel

def events(requests,session,region,account):
 from .aws import ReadResult
 from .aws_request_pool import ordered_reads
 end=requests.observed_at;start=end-timedelta(minutes=requests.activity_minutes);rows=[];seen={}
 jobs, parallel = _history_jobs(requests, start, end)
 readers = min(8, getattr(requests, 'workers', 1))
 def read_job(job):
  name, lower, upper = job
  return requests.pages(session,'cloudtrail',region,'lookup_events','Events',LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':name}],StartTime=lower,EndTime=upper)
 # Probe one page per operation: sparse/empty histories keep their original
 # one-query cost, while a continuation proves that partitioning is useful.
 completed = []
 if parallel:
  names = sorted(OPERATIONS)
  probes = ordered_reads(requests, names, lambda name: requests.pages(session,'cloudtrail',region,'lookup_events','Events',_page_limit=1,LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':name}],StartTime=start,EndTime=end), workers=readers)
  pending = set()
  for name, read in zip(names, probes):
   if (read.error or {}).get('code') == 'page_limit':
    pending.add(name)
   elif read.status in ('collected', 'empty'):
    completed.append(((name, start, end), read))
   else:
    return ReadResult([],read.status,(read.error or {'code':'enclave_history_incomplete'}))
  jobs = [job for job in jobs if job[0] in pending]
 # Independent slices overlap at internal query boundaries. Up to eight
 # latency-bound readers share Requests.call's existing account/Region 2 TPS
 # limiter; the requested history window and projected evidence stay unchanged.
 reads = completed + list(zip(jobs, ordered_reads(requests, jobs, read_job, workers=readers))) if parallel else ((job, read_job(job)) for job in jobs)
 for (name, lower, upper), read in reads:
  if read.status not in('collected','empty'):return ReadResult([],read.status,(read.error or{'code':'enclave_history_incomplete'}))
  local_seen = set()
  for row in read.items:
   try:
    when = _time(row.get('EventTime'))
    valid=(isinstance(row,dict)and row.get('AccountId')==account and row.get('Region')==region and row.get('EventName')==name and lower<=when<=upper)
   except (TypeError,ValueError,AttributeError):valid=False
   if not valid:return ReadResult([],'malformed',{'code':'kms_enclave_scope_or_window_mismatch'})
   ident = row.get('EventId')
   if ident in local_seen:return ReadResult([],'malformed',{'code':'kms_enclave_scope_or_window_mismatch'})
   local_seen.add(ident)
   previous = seen.get(ident)
   if previous is not None:
    # The exact same native event can occur in adjacent overlapping queries.
    # Conflicting identities or duplicates within one page/read are
    # still malformed, rather than silently hidden by deduplication.
    old_row, old_name, old_lower, old_upper = previous
    if parallel and row == old_row and name == old_name and old_lower < lower <= when <= old_upper < upper:
     continue
    return ReadResult([],'malformed',{'code':'kms_enclave_scope_or_window_mismatch'})
   seen[row['EventId']] = (row, name, lower, upper)
   rows.append({**row,'_provenance':{'source_operation':'cloudtrail:LookupEvents','read_only':True,'reference':REFERENCE,'window_start':start.isoformat(),'window_end':end.isoformat(),'boundary':'Observed Nitro enclave PCR metadata only; no attestation verification, secret read or complete historical-delivery assurance'}})
 return ReadResult(rows,'collected'if rows else'empty')
def discover_region(requests, session, region, account):
 """Current local enclave-capable parents, not proof of historical/global non-use."""
 from .aws import ReadResult
 read = requests.pages(session, 'ec2', region, 'describe_instances', 'Reservations',
                       Filters=[{'Name':'enclave-options.enabled','Values':['true']}])
 if read.status not in ('collected', 'empty'):
  return ReadResult([], read.status, {**(read.error or {}), 'phase':'enclave_discovery',
                                      'iam_action':'ec2:DescribeInstances'})
 ids = set()
 for reservation in read.items:
  if (not isinstance(reservation, dict) or reservation.get('OwnerId') != account
      or not isinstance(reservation.get('Instances'), list) or not reservation['Instances']):
   return ReadResult([], 'malformed', {'code':'enclave_parent_identity_invalid'})
  for instance in reservation['Instances']:
   ident = instance.get('InstanceId') if isinstance(instance, dict) else None
   if (not isinstance(ident, str) or not re.fullmatch(r'i-(?:[0-9a-f]{8}|[0-9a-f]{17})', ident)
       or ident in ids or not isinstance(instance.get('EnclaveOptions'), dict)
       or instance['EnclaveOptions'].get('Enabled') is not True):
    return ReadResult([], 'malformed', {'code':'enclave_parent_identity_invalid'})
   ids.add(ident)
 proof = {'code':'enclave_parents_discovered' if ids else 'no_current_enclave_enabled_instances',
          'source_operation':'ec2:DescribeInstances', 'scope':account+'/'+region,
          'complete':True, 'instance_ids':sorted(ids), 'observed_at':requests.observed_at.isoformat(),
          'boundary':'Current local EC2 configuration only; historical and cross-account enclave use is not excluded.'}
 return ReadResult([{'InstanceId':ident} for ident in sorted(ids)], 'collected' if ids else 'empty', proof)


def discover_accounts(requests, contexts, regions_by_account):
 """Finish cheap discovery across the selected Regions before history is scheduled."""
 from .aws_request_pool import ordered_reads
 pairs = [(session, identity['Account'], region) for session, identity in contexts
          for region in regions_by_account.get(identity['Account'], [])]
 def discover(pair):
  session, account, region = pair
  return discover_region(requests, session, region, account)
 reads = ordered_reads(requests, pairs, discover, workers=min(8, max(1, len(pairs))))
 requests.enclave_region_discovery = {(account, region):read
     for (_, account, region), read in zip(pairs, reads)}
 return [{'account':account, 'region':region, 'status':read.status,
          'candidate':bool(read.items), 'evidence':read.error}
         for (_, account, region), read in zip(pairs, reads)]


def applicable_events(requests, session, region, account):
 from .aws import ReadResult
 if getattr(requests, 'enclave_history_mode', 'auto') == 'all':
  return events(requests, session, region, account)
 discovery = getattr(requests, 'enclave_region_discovery', {}).get((account, region))
 if discovery is None:
  discovery = discover_region(requests, session, region, account)
 if discovery.status not in ('collected', 'empty'):
  return discovery
 if not discovery.items:
  return ReadResult([], 'empty', discovery.error)
 return events(requests, session, region, account)


FETCHERS={'cloudtrail_event':applicable_events}

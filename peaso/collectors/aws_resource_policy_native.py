"""Scoped resource-policy documents, with explicit AWS policy-family discovery.

The original four collectors retain their exact SDK contracts; the extended
recipes add service and nested-resource coverage. Unread policies remain gaps.
"""
from __future__ import annotations
import json,re
from urllib.parse import urlsplit
SPECS={'aws_resource_policy':('sns','list_topics','Topics')}
NATIVE_IDS={'aws_resource_policy':'ResourceArn'}
READ_ACTIONS={(s,o)for s,ops in {'sns':('list_topics','get_topic_attributes'),'sqs':('list_queues','get_queue_attributes'),'lambda':('list_functions','get_policy'),'ecr':('describe_repositories','get_repository_policy')}.items()for o in ops}
OK=('collected','empty')

def base_policies(requests,session,region,account):
 from .aws import ReadResult
 partition=session.get_partition_for_region(region);rows=[];failures=[];seen=set()
 def fail(status='malformed',code='resource_policy_identity_or_document_invalid'):
  failures.append((status,code))
 def detail(service,operation,**args):
  response=requests.detail(session,service,region,operation,**args)
  if response.get('collection_status')!='collected':
   fail(response.get('collection_status','not_collected'),(response.get('error')or{}).get('code','resource_policy_detail_incomplete'));return None
  return response
 def own(arn,service,tail):
  return isinstance(arn,str)and bool(re.fullmatch('arn:'+re.escape(partition)+':'+service+':'+re.escape(region)+':'+re.escape(account)+':'+tail,arn))
 def emit(arn,document,service,operation):
  try:
   if isinstance(document,str):document=json.loads(document)
   if not isinstance(document,dict)or not isinstance(document.get('Statement'),(dict,list)):raise ValueError()
   statements=document['Statement'];statements=[statements]if isinstance(statements,dict)else statements
   if not statements or any(not isinstance(s,dict)for s in statements)or arn in seen:raise ValueError()
   json.dumps(document,allow_nan=False)
  except (ValueError,TypeError):fail();return
  seen.add(arn);rows.append({'ResourceArn':arn,'Policy':document,'_provenance':{'read_only':True,'owner_account':account,'source_region':region,'collection_region':region,'families':[service+'-base'],'source_operation':service+':'+operation,'covered_services':['sns','sqs','lambda','ecr'],'coverage_boundary':'Four regional service families only; Lambda unqualified functions only, not version or alias policies; other AWS resource-policy families are not assessed'}})
 for service,operation,expression in [('sns','list_topics','Topics'),('sqs','list_queues','QueueUrls || `[]`'),('lambda','list_functions','Functions'),('ecr','describe_repositories','repositories')]:
  read=requests.pages(session,service,region,operation,expression,**({'MaxResults':1000}if service=='sqs'else{}))
  if read.status not in OK:fail(read.status,(read.error or{}).get('code','resource_policy_listing_incomplete'))
  source_seen=set()
  for item in read.items:
   if service=='sqs':
    if not isinstance(item,str):fail();continue
    parsed=urlsplit(item);suffix='amazonaws.com.cn'if partition=='aws-cn'else'amazonaws.com'
    if parsed.scheme!='https'or parsed.netloc!=f'sqs.{region}.{suffix}'or parsed.query or parsed.fragment or not re.fullmatch('/'+account+r'/[A-Za-z0-9_-]{1,80}(?:\.fifo)?',parsed.path)or item in source_seen:fail();continue
    source_seen.add(item)
    response=detail(service,'get_queue_attributes',QueueUrl=item,AttributeNames=['All'])
    if response is None:continue
    attrs=response.get('Attributes');name=parsed.path.rsplit('/',1)[1];arn=f'arn:{partition}:sqs:{region}:{account}:{name}'
    if not isinstance(attrs,dict)or attrs.get('QueueArn')!=arn:fail();continue
    if 'Policy'in attrs:emit(arn,attrs['Policy'],service,'GetQueueAttributes')
    continue
   if not isinstance(item,dict):fail();continue
   field,tail={'sns':('TopicArn',r'[A-Za-z0-9_-]{1,256}(?:\.fifo)?'),'lambda':('FunctionArn',r'function:[A-Za-z0-9_-]{1,64}'),'ecr':('repositoryArn',r'repository/[a-z0-9][a-z0-9._/-]{0,255}')}[service]
   arn=item.get(field)
   if not own(arn,service,tail)or arn in source_seen:fail();continue
   source_seen.add(arn)
   if service=='sns':
    response=detail(service,'get_topic_attributes',TopicArn=arn)
    if response is None:continue
    attrs=response.get('Attributes')
    if not isinstance(attrs,dict)or attrs.get('TopicArn')!=arn or attrs.get('Owner')!=account or 'Policy'not in attrs:fail();continue
    emit(arn,attrs['Policy'],service,'GetTopicAttributes')
   elif service=='lambda':
    # Only this typed GetPolicy response means no attached function policy.
    name=item.get('FunctionName')
    if name!=arn.rsplit(':',1)[-1]:fail();continue
    response=requests.detail(session,service,region,'get_policy',FunctionName=name,absent=('ResourceNotFoundException',))
    if response.get('collection_status')=='empty'and response.get('absent')is True and(response.get('error')or{}).get('code')==('ResourceNotFoundException'if service=='lambda'else'RepositoryPolicyNotFoundException'):continue
    if response.get('collection_status')!='collected':fail(response.get('collection_status','not_collected'),(response.get('error')or{}).get('code','lambda_policy_incomplete'));continue
    emit(arn,response.get('Policy'),service,'GetPolicy')
   else:
    name=item.get('repositoryName')
    if item.get('registryId')!=account or not isinstance(name,str)or arn.rsplit(':',1)[-1]!='repository/'+name:fail();continue
    response=requests.detail(session,service,region,'get_repository_policy',repositoryName=name,absent=('RepositoryPolicyNotFoundException',))
    if response.get('collection_status')=='empty'and response.get('absent')is True and(response.get('error')or{}).get('code')==('ResourceNotFoundException'if service=='lambda'else'RepositoryPolicyNotFoundException'):continue
    if response.get('collection_status')!='collected':fail(response.get('collection_status','not_collected'),(response.get('error')or{}).get('code','ecr_policy_incomplete'));continue
    if response.get('registryId')!=account or response.get('repositoryName')!=name:fail();continue
    emit(arn,response.get('policyText'),service,'GetRepositoryPolicy')
 if failures:
  status,code=failures[0];return ReadResult(rows,'partial'if rows else status,{'code':code})
 return ReadResult(rows,'collected'if rows else'empty')
from .aws_resource_policy_families import READ_ACTIONS as EXTENDED_ACTIONS, collect as extended_policies
READ_ACTIONS.update(EXTENDED_ACTIONS)


def policies(requests, session, region, account):
 from .aws import ReadResult
 base = base_policies(requests, session, region, account)
 extra = extended_policies(requests, session, region, account)
 rows = base.items + extra.items
 failures = [read for read in (base, extra) if read.status not in OK]
 if failures:
  return ReadResult(rows, 'partial' if rows else failures[0].status,
      {'code': 'resource_policy_coverage_incomplete', 'details': [read.error for read in failures]})
 return ReadResult(rows, 'collected' if rows else 'empty')

FETCHERS={'aws_resource_policy':policies}

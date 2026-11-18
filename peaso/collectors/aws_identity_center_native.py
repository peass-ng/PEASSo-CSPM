"""Identity Center account assignments joined to current native user status.

Every user/group membership and permission set must be complete and bound to
its exact instance, store and audited account. Empty regional instance lists do
not prove account-wide absence: the home region may be elsewhere.
"""
from __future__ import annotations

import re

SPECS = {'identity_center': ('sso-admin', 'list_instances', 'Instances')}
NATIVE_IDS = {'identity_center': 'id'}
READ_ACTIONS = {('sso-admin','list_instances'), ('sso-admin','list_permission_sets'),
                ('sso-admin','list_account_assignments'), ('identitystore','describe_user'),
                ('identitystore','list_group_memberships')}
_OK = ('collected','empty')
_UUID = r'(?:[0-9a-f]{10}-)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
_STORE = r'(?:d-[0-9a-f]{10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'


def _result(rows=(), status=None, code=None):
    from .aws import ReadResult
    rows=list(rows)
    return ReadResult(rows,status or ('collected' if rows else 'empty'),{'code':code} if code else None)


def _failure(read, code):
    return _result([], read.status if read.status not in _OK else 'malformed',
                   (read.error or {}).get('code',code))


def _match(pattern,value):
    return isinstance(value,str) and re.fullmatch(pattern,value) is not None


def identity_center(requests, session, region, account):
    if not _match(r'[0-9]{12}',account):
        return _result([], 'malformed', 'identity_center_audited_account_invalid')
    partition=session.get_partition_for_region(region)
    read=requests.pages(session,'sso-admin',region,'list_instances','Instances')
    if read.status not in _OK:return _failure(read,'identity_center_instances_incomplete')
    if not read.items:
        return _result([], 'not_collected', 'identity_center_home_region_unresolved')
    instances=[];seen_instances=set();user_cache={};group_cache={};expanded_count=0
    for native in read.items:
        if not isinstance(native,dict):return _result([], 'malformed', 'identity_center_instance_invalid')
        arn,store,owner=native.get('InstanceArn'),native.get('IdentityStoreId'),native.get('OwnerAccountId')
        prefix=f'arn:{partition}:sso:::instance/'
        if (not _match(re.escape(prefix)+r'(?:sso)?ins-[a-zA-Z0-9.-]{16}',arn)
                or not _match(_STORE,store) or not _match(r'[0-9]{12}',owner)
                or arn in seen_instances):
            return _result([], 'malformed', 'identity_center_instance_binding_invalid')
        if native.get('Status')!='ACTIVE':
            return _result([], 'not_collected', 'identity_center_instance_active_status_unresolved')
        expected_store_arn=f'arn:{partition}:identitystore::{owner}:identitystore/{store}'
        if native.get('IdentityStoreArn',expected_store_arn)!=expected_store_arn:
            return _result([], 'malformed', 'identity_center_store_owner_mismatch')
        from .aws_identity_center_regions import remember
        remember(requests, account, region)
        seen_instances.add(arn);instance_id=arn.rsplit('/',1)[-1]
        sets=requests.pages(session,'sso-admin',region,'list_permission_sets','PermissionSets',InstanceArn=arn)
        if sets.status not in _OK:return _failure(sets,'identity_center_permission_sets_incomplete')
        seen_sets=set();seen_assignments=set();assignments=[]
        for permission in sets.items:
            if (not _match(re.escape(f'arn:{partition}:sso:::permissionSet/{instance_id}/')+r'ps-[a-zA-Z0-9./-]{16}',permission)
                    or permission in seen_sets):
                return _result([], 'malformed', 'identity_center_permission_set_binding_invalid')
            seen_sets.add(permission)
            assigned=requests.pages(session,'sso-admin',region,'list_account_assignments','AccountAssignments',
                                    InstanceArn=arn,AccountId=account,PermissionSetArn=permission)
            if assigned.status not in _OK:return _failure(assigned,'identity_center_assignments_incomplete')
            for assignment in assigned.items:
                if not isinstance(assignment,dict):return _result([], 'malformed', 'identity_center_assignment_invalid')
                kind,principal=assignment.get('PrincipalType'),assignment.get('PrincipalId')
                key=(permission,kind,principal)
                if (assignment.get('AccountId')!=account or assignment.get('PermissionSetArn')!=permission
                        or kind not in ('USER','GROUP') or not _match(_UUID,principal) or key in seen_assignments):
                    return _result([], 'malformed', 'identity_center_assignment_binding_invalid')
                seen_assignments.add(key)
                members=[(principal,None)]
                if kind=='GROUP':
                    gkey=(store,principal)
                    if gkey not in group_cache:
                        members_read=requests.pages(session,'identitystore',region,'list_group_memberships','GroupMemberships',
                                                    IdentityStoreId=store,GroupId=principal)
                        if members_read.status not in _OK:return _failure(members_read,'identity_center_group_members_incomplete')
                        seen_users=set();seen_memberships=set();expanded=[]
                        for member in members_read.items:
                            if not isinstance(member,dict):return _result([], 'malformed', 'identity_center_group_member_invalid')
                            mid,member_id=member.get('MembershipId'),member.get('MemberId')
                            uid=member_id.get('UserId') if isinstance(member_id,dict) else None
                            if (member.get('IdentityStoreId')!=store or member.get('GroupId')!=principal
                                    or not _match(_UUID,mid) or not _match(_UUID,uid)
                                    or mid in seen_memberships or uid in seen_users):
                                return _result([], 'malformed', 'identity_center_group_membership_binding_invalid')
                            if member.get('MembershipArn',f'arn:{partition}:identitystore:::membership/{mid}')!=f'arn:{partition}:identitystore:::membership/{mid}':
                                return _result([], 'malformed', 'identity_center_membership_arn_invalid')
                            seen_memberships.add(mid);seen_users.add(uid);expanded.append((uid,mid))
                        group_cache[gkey]=expanded
                    members=group_cache[gkey]
                for uid,membership in members:
                    ukey=(store,uid)
                    if ukey not in user_cache:
                        user=requests.detail(session,'identitystore',region,'describe_user',IdentityStoreId=store,UserId=uid)
                        if user.get('collection_status')!='collected':
                            return _result([],user.get('collection_status','unknown'),
                                           user.get('error',{}).get('code','identity_center_user_incomplete'))
                        user_arn=f'arn:{partition}:identitystore:::user/{uid}'
                        if (user.get('IdentityStoreId')!=store or user.get('UserId')!=uid
                                or user.get('UserArn',user_arn)!=user_arn or user.get('UserStatus') not in ('ENABLED','DISABLED')):
                            return _result([], 'malformed', 'identity_center_user_status_binding_invalid')
                        # Never persist user name, email, photo, phone or profile.
                        user_cache[ukey]=user['UserStatus']
                    expanded_count+=1
                    if requests.max_items is not None and expanded_count>requests.max_items:
                        return _result([], 'not_collected', 'identity_center_expanded_assignment_limit')
                    assignments.append({'AccountId':account,'PermissionSetArn':permission,'PrincipalId':uid,
                        'UserStatus':user_cache[ukey],'AssignedPrincipalId':principal,'AssignedPrincipalType':kind,
                        **({'GroupMembershipId':membership} if membership is not None else {}),
                        '_provenance':{'source_operation':'ListAccountAssignments+DescribeUser',
                          'group_membership_operation':'ListGroupMemberships' if kind=='GROUP' else None,
                          'read_only':True,'identity_store_id':store,'exact_instance_and_account_join':True}})
        instances.append({'InstanceArn':arn,'IdentityStoreId':store,'OwnerAccountId':owner,'Status':'ACTIVE',
                          'AccountAssignments':assignments})
    return _result([{'id':f'{account}/{region}/identity-center-assignment-coverage','AccountId':account,'Region':region,
                     'AuditedAccountId':account,'Instances':instances,
                     '_provenance':{'source_operation':'ListInstances+ListPermissionSets+ListAccountAssignments',
                       'read_only':True,'regional_instance_enumeration_complete':True,'audited_account_only':True,
                       'account_wide_absence_proven':False}}])


FETCHERS = {'identity_center': identity_center}

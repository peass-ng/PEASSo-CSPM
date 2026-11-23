"""Account evidence required before reporting an IAM console password-policy gap."""


def applies_to(check):
    return check.kind == 'iam_password_policy' or 'iam_password_policy' in check.dependencies


def console_user_status(collections, account):
    """Use an account-bound ListUsers inventory and GetLoginProfile results."""
    scoped = [row for row in collections if row.get('scope') == account + '/global'
              or (row.get('global') is True and row.get('account_id') == account
                  and row.get('scope', '').split('/', 1)[0] == account)]
    if len(scoped) != 1:
        return 'UNKNOWN', {'reason': 'No unique account IAM user inventory'}
    envelope, = scoped
    if envelope.get('account_id') not in (None, account):
        return 'UNKNOWN', {'reason': 'IAM user inventory account identity conflicts'}
    if envelope.get('status') == 'empty' and envelope['items']:
        return 'UNKNOWN', {'reason': 'IAM user inventory is inconsistent'}
    missing = False
    for user in envelope['items']:
        if not isinstance(user, dict) or user.get('AccountId') not in (None, account):
            return 'UNKNOWN', {'reason': 'IAM user inventory account identity conflicts'}
        profile = user.get('LoginProfile')
        if not isinstance(profile, dict):
            missing = True
            continue
        details = profile.get('LoginProfile')
        if (envelope.get('status') in ('collected', 'partial')
                and profile.get('collection_status') == 'collected' and isinstance(details, dict)
                and user.get('UserName') and details.get('UserName') == user['UserName']):
            return None
        if not (profile.get('collection_status') == 'empty' and profile.get('absent') is True):
            missing = True
    if envelope.get('status') not in ('collected', 'empty') or missing:
        return 'UNKNOWN', {'reason': 'IAM user console login inventory is incomplete'}
    return 'NOT_APPLICABLE', {'reason': 'No IAM user has a console login profile in this account'}

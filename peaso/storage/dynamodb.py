"""Optional hosted tenant repository with transactionally reserved weekly quotas.

Uses only PK/SK, paginated strongly consistent tenant queries and fenced writes.
No live deployment is implied by this adapter; cloud validation is documented.
"""
from decimal import Decimal
import hashlib
import json
import os
import time
import uuid
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from botocore.exceptions import ClientError
from .sqlite import SQLiteStore, StoreError, TERMINAL, SCAN_CAPACITY, QUEUE_WAIT_SECONDS, failure_error, curated_failure_reasons, INVALID_CREDENTIALS_FAILURE, utc, week

SERIALIZER, DESERIALIZER = TypeSerializer(), TypeDeserializer()


def attrs(value):
    value = json.loads(json.dumps(value), parse_float=Decimal)
    return {k: SERIALIZER.serialize(v) for k, v in value.items()}


def plain(value):
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def row(item):
    return plain({k: DESERIALIZER.deserialize(v) for k, v in item.items()})


class DynamoStore:
    public_job = staticmethod(SQLiteStore.public_job)
    public_schedule = staticmethod(SQLiteStore.public_schedule)

    def __init__(self, table, client=None, *, work_state_index=None, schedule_time_index=None):
        if client is None:
            import boto3
            client = boto3.client("dynamodb")
        self.table, self.client = table, client
        self.claims = {}
        self.claim_attempts = {}
        self.clock = time.time
        self.work_state_index = os.getenv('PEASO_WORK_STATE_INDEX', '') if work_state_index is None else work_state_index
        self.schedule_time_index = os.getenv('PEASO_SCHEDULE_TIME_INDEX', '') if schedule_time_index is None else schedule_time_index
        self._batch_reads_available = True

    def key(self, tenant, kind, ident):
        return {"PK": "tenant/" + tenant, "SK": kind + "/" + ident}

    @staticmethod
    def _workspace_key(workspace_id, kind, ident):
        return {"PK": "workspace/" + workspace_id, "SK": kind + "/" + ident}

    @staticmethod
    def _workspace_user_key(user_id, kind, ident):
        return {"PK": "user/" + user_id, "SK": kind + "/" + ident}

    def _workspace_get(self, key):
        item = self.client.get_item(TableName=self.table, Key=attrs(key), ConsistentRead=True).get("Item")
        return row(item) if item else None

    def _get_many(self, keys):
        keys = list({(key['PK'], key['SK']): key for key in keys}.values())
        found = {}
        for offset in range(0, len(keys), 100):
            if not self._batch_reads_available:
                for key in keys[offset:]:
                    value = self._workspace_get(key)
                    if value:
                        found[key['PK'], key['SK']] = value
                return found
            pending = [attrs(key) for key in keys[offset:offset + 100]]
            for attempt in range(8):
                try:
                    page = self.client.batch_get_item(RequestItems={self.table: {
                        'Keys': pending, 'ConsistentRead': True}})
                except ClientError as exc:
                    if exc.response['Error']['Code'] != 'AccessDeniedException':
                        raise
                    # Existing deployments may roll code before the additional
                    # batch permission. Preserve the original strong reads.
                    self._batch_reads_available = False
                    for key in keys[offset:]:
                        value = self._workspace_get(key)
                        if value:
                            found[key['PK'], key['SK']] = value
                    return found
                for item in page.get('Responses', {}).get(self.table, []):
                    value = row(item)
                    found[value['PK'], value['SK']] = value
                pending = page.get('UnprocessedKeys', {}).get(self.table, {}).get('Keys', [])
                if not pending:
                    break
                if attempt < 7:
                    time.sleep(min(0.025 * 2**attempt, 0.5))
            else:
                raise StoreError(503, 'Metadata reads temporarily unavailable')
        return found

    def _workspace_query(self, partition, prefix):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:pk AND begins_with(SK,:prefix)",
                     "ExpressionAttributeValues": attrs({":pk": partition, ":prefix": prefix})}
        result = []
        while True:
            page = self.client.query(**arguments)
            result.extend(row(item) for item in page.get("Items", []))
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def workspace(self, workspace_id):
        return self._workspace_get(self._workspace_key(workspace_id, "meta", "current"))

    def workspace_role(self, workspace_id, user_id):
        member = self._workspace_get(self._workspace_key(workspace_id, "member", user_id))
        return member.get("role") if member else None

    def workspaces(self, user_id):
        refs = self._workspace_query("user/" + user_id, "workspace/")
        values = self._get_many(
            self._workspace_key(ref['workspace_id'], kind, ident)
            for ref in refs for kind, ident in (('meta', 'current'), ('member', user_id)))
        result = []
        for ref in refs:
            workspace = values.get(('workspace/' + ref['workspace_id'], 'meta/current'))
            member = values.get(('workspace/' + ref['workspace_id'], 'member/' + user_id))
            role = member.get('role') if workspace and member else None
            if role:
                result.append({"id": workspace["id"], "name": workspace["name"], "owner": workspace["owner"], "role": role})
        return sorted(result, key=lambda item: item["name"].casefold())

    def create_workspace(self, owner, name, name_key, email):
        ident, now = "ws_" + uuid.uuid4().hex, time.time()
        meta = dict(self._workspace_key(ident, "meta", "current"), id=ident, owner=owner, name=name, name_key=name_key, created=now, occupied=0)
        member = dict(self._workspace_key(ident, "member", owner), workspace_id=ident, user_id=owner, email=email, role="admin", joined=now)
        ref = dict(self._workspace_user_key(owner, "workspace", ident), workspace_id=ident)
        name_lock = {"PK": "workspace-name/" + name_key, "SK": "current", "workspace_id": ident}
        capacity = self._workspace_user_key(owner, "workspace_capacity", "current")
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(meta), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(member), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(ref), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(name_lock), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(capacity), "UpdateExpression": "ADD workspace_count :one",
                            "ConditionExpression": "attribute_not_exists(workspace_count) OR workspace_count<:limit",
                            "ExpressionAttributeValues": attrs({":one": 1, ":limit": 5})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                if self._workspace_get({"PK": "workspace-name/" + name_key, "SK": "current"}):
                    raise StoreError(409, "Workspace name is already in use") from None
                raise StoreError(403, "You can create up to five workspaces") from None
            raise
        return {"id": ident, "owner": owner, "name": name, "role": "admin"}

    def workspace_people(self, workspace_id):
        members = self._workspace_query("workspace/" + workspace_id, "member/")
        invites = self._workspace_query("workspace/" + workspace_id, "invite/")
        return ([{k: item[k] for k in ("user_id", "email", "role", "joined")} for item in members],
                [{k: item[k] for k in ("user_id", "email", "role", "invited_by", "created")} for item in invites])

    def workspace_invitations(self, user_id):
        refs = self._workspace_query("user/" + user_id, "invite/")
        values = self._get_many(self._workspace_key(ref['workspace_id'], 'meta', 'current') for ref in refs)
        result = []
        for ref in refs:
            workspace = values.get(('workspace/' + ref['workspace_id'], 'meta/current'))
            if workspace:
                result.append({k: ref[k] for k in ("workspace_id", "email", "role", "invited_by", "created")} | {"name": workspace["name"]})
        return sorted(result, key=lambda item: item["created"], reverse=True)

    def invite_workspace(self, workspace_id, user_id, email, role, invited_by):
        if self.workspace_role(workspace_id, user_id):
            raise StoreError(409, "This person is already a workspace member")
        now = time.time()
        payload = {"workspace_id": workspace_id, "user_id": user_id, "email": email, "role": role, "invited_by": invited_by, "created": now}
        invite = dict(self._workspace_key(workspace_id, "invite", user_id), **payload)
        pointer = dict(self._workspace_user_key(user_id, "invite", workspace_id), **payload)
        try:
            self.client.transact_write_items(TransactItems=[
                self._workspace_admin_condition(workspace_id, invited_by),
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "member", user_id)),
                                    "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(invite), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(pointer), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :one", "ConditionExpression": "attribute_exists(PK) AND occupied<:limit",
                            "ExpressionAttributeValues": attrs({":one": 1, ":limit": 100})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                if self.workspace_role(workspace_id, invited_by) != "admin":
                    raise StoreError(403, "Workspace admin access required") from None
                if self.workspace_role(workspace_id, user_id):
                    raise StoreError(409, "This person is already a workspace member") from None
                if self._workspace_get(self._workspace_key(workspace_id, "invite", user_id)):
                    raise StoreError(409, "An invitation is already pending") from None
                raise StoreError(403, "Workspace invitation limit reached") from None
            raise

    def respond_workspace_invitation(self, workspace_id, user_id, accept):
        invite_key = self._workspace_key(workspace_id, "invite", user_id)
        invite = self._workspace_get(invite_key)
        if not invite:
            raise StoreError(404, "Invitation not found")
        actions = [
            {"Delete": {"TableName": self.table, "Key": attrs(invite_key),
                        "ConditionExpression": "attribute_exists(PK) AND #role=:role AND #email=:email AND #created=:created AND #invited_by=:invited_by",
                        "ExpressionAttributeNames": {'#' + key: key for key in ('role', 'email', 'created', 'invited_by')},
                        "ExpressionAttributeValues": attrs({':' + key: invite[key] for key in ('role', 'email', 'created', 'invited_by')})}},
            {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "invite", workspace_id))}},
        ]
        if accept:
            member = dict(self._workspace_key(workspace_id, "member", user_id), workspace_id=workspace_id,
                          user_id=user_id, email=invite["email"], role=invite["role"], joined=time.time())
            ref = dict(self._workspace_user_key(user_id, "workspace", workspace_id), workspace_id=workspace_id)
            actions.extend([
                {"Put": {"TableName": self.table, "Item": attrs(member), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(ref), "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        else:
            actions.append({"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                                      "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}})
        try:
            self.client.transact_write_items(TransactItems=actions)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Invitation changed; refresh and try again") from None
            raise

    def _workspace_admin_condition(self, workspace_id, actor):
        return {"ConditionCheck": {"TableName": self.table,
            "Key": attrs(self._workspace_key(workspace_id, "member", actor)),
            "ConditionExpression": "#actor_role=:actor_admin",
            "ExpressionAttributeNames": {"#actor_role": "role"},
            "ExpressionAttributeValues": attrs({":actor_admin": "admin"})}}

    def _workspace_admin_transaction(self, actions, workspace_id, actor):
        if actor is not None:
            guard = self._workspace_admin_condition(workspace_id, actor)["ConditionCheck"]
            # DynamoDB forbids checking and writing one item twice in a transaction.
            # A self-demotion/removal carries its guard on the write itself.
            own = next((value for action in actions for value in action.values()
                        if value.get("Key") == guard["Key"]), None)
            if own is None:
                actions.append({"ConditionCheck": guard})
            else:
                own["ConditionExpression"] = "(" + own.get("ConditionExpression", "attribute_exists(PK)") + ") AND " + guard["ConditionExpression"]
                for key in ("ExpressionAttributeNames", "ExpressionAttributeValues"):
                    own.setdefault(key, {}).update(guard[key])
        try:
            self.client.transact_write_items(TransactItems=actions)
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "TransactionCanceledException" and actor is not None
                    and self.workspace_role(workspace_id, actor) != "admin"):
                raise StoreError(403, "Workspace admin access required") from None
            raise

    def revoke_workspace_invitation(self, workspace_id, user_id, *, actor=None):
        try:
            self._workspace_admin_transaction([
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "invite", user_id)),
                            "ConditionExpression": "attribute_exists(PK)"}},
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "invite", workspace_id))}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}},
            ], workspace_id, actor)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "Invitation not found") from None
            raise

    def set_workspace_role(self, workspace_id, user_id, role, *, actor=None):
        workspace = self.workspace(workspace_id)
        if not workspace or workspace["owner"] == user_id:
            raise StoreError(403, "The workspace owner's role cannot be changed")
        try:
            self._workspace_admin_transaction([{"Update": dict(TableName=self.table, Key=attrs(self._workspace_key(workspace_id, "member", user_id)),
                                    UpdateExpression="SET #role=:role", ConditionExpression="attribute_exists(PK)",
                                    ExpressionAttributeNames={"#role": "role"}, ExpressionAttributeValues=attrs({":role": role}))}], workspace_id, actor)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in {"ConditionalCheckFailedException", "TransactionCanceledException"}:
                raise StoreError(404, "Workspace member not found") from None
            raise

    def remove_workspace_member(self, workspace_id, user_id, *, actor=None):
        workspace = self.workspace(workspace_id)
        if not workspace or workspace["owner"] == user_id:
            raise StoreError(403, "The workspace owner cannot be removed")
        try:
            self._workspace_admin_transaction([
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "member", user_id)), "ConditionExpression": "attribute_exists(PK)"}},
                {"Delete": {"TableName": self.table, "Key": attrs(self._workspace_user_key(user_id, "workspace", workspace_id))}},
                {"Update": {"TableName": self.table, "Key": attrs(self._workspace_key(workspace_id, "meta", "current")),
                            "UpdateExpression": "ADD occupied :minus", "ExpressionAttributeValues": attrs({":minus": -1})}},
            ], workspace_id, actor)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "Workspace member not found") from None
            raise

    def _get(self, tenant, kind, ident):
        item = self.client.get_item(TableName=self.table, Key=attrs(self.key(tenant, kind, ident)), ConsistentRead=True).get("Item")
        return row(item) if item else None

    def _put(self, tenant, kind, ident, value, old=None):
        value = dict(value, **self.key(tenant, kind, ident), kind=kind, rev=0 if old is None else old["rev"] + 1)
        item = attrs(value)
        if len(json.dumps(item)) > 380000:
            raise StoreError(413, "Hosted connector input is too large; use a smaller snapshot")
        arguments = {"TableName": self.table, "Item": item, "ConditionExpression": "attribute_not_exists(PK)"}
        if old is not None:
            arguments.update(ConditionExpression="#rev=:rev", ExpressionAttributeNames={"#rev": "rev"}, ExpressionAttributeValues=attrs({":rev": old["rev"]}))
        self.client.put_item(**arguments)

    def _query(self, tenant, kind):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:kind)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":kind": kind + "/"})}
        result = []
        while True:
            page = self.client.query(**arguments)
            result += [row(item) for item in page.get("Items", [])]
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _scan(self, kind):
        arguments = {"TableName": self.table, "ConsistentRead": True, "FilterExpression": "#kind=:kind",
                     "ExpressionAttributeNames": {"#kind": "kind"}, "ExpressionAttributeValues": attrs({":kind": kind})}
        result = []
        while True:
            page = self.client.scan(**arguments)
            result += [row(item) for item in page.get("Items", [])]
            if not page.get("LastEvaluatedKey"):
                return result
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _index_candidates(self, index, expression, names, values, kind):
        """Indexes nominate keys; strongly consistent base reads grant authority."""
        arguments = dict(TableName=self.table, IndexName=index,
                         KeyConditionExpression=expression,
                         ExpressionAttributeNames=names,
                         ExpressionAttributeValues=attrs(values))
        result = []
        while True:
            page = self.client.query(**arguments)
            keys = [row(item) for item in page.get('Items', [])]
            keys = [{'PK': item['PK'], 'SK': item['SK']} for item in keys
                    if item['PK'].startswith('tenant/') and item['SK'].startswith(kind + '/')]
            result.extend(self._get_many(keys).values())
            if not page.get('LastEvaluatedKey'):
                return result
            arguments['ExclusiveStartKey'] = page['LastEvaluatedKey']

    def _work_jobs(self, statuses):
        if not self.work_state_index:
            return [item for item in self._scan('job') if item['status'] in statuses]
        found = {}
        try:
            for status in statuses:
                for item in self._index_candidates(self.work_state_index, '#status=:status',
                                                  {'#status': 'status'}, {':status': status}, 'job'):
                    if item.get('kind') == 'job' and item['status'] in statuses:
                        found[item['PK'], item['SK']] = item
        except ClientError as exc:
            if exc.response['Error']['Code'] not in ('AccessDeniedException', 'ResourceNotFoundException', 'ValidationException'):
                raise
            return [item for item in self._scan('job') if item['status'] in statuses]
        return list(found.values())

    def create_api_key(self, tenant, record):
        """Store the hash under the tenant and a hash-free random-ID lookup pointer."""
        from peaso.auth.api_keys import MAX_UNREVOKED_KEYS
        value = {key: item for key, item in record.items() if item is not None}
        value.update(self.key(tenant, "api_key", record["id"]), kind="api_key", tenant=tenant)
        pointer = {"PK": "api-key/" + record["id"], "SK": "lookup", "kind": "api_key_lookup", "tenant": tenant}
        capacity = self.key(tenant, "api_key_capacity", "current")
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(value), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Put": {"TableName": self.table, "Item": attrs(pointer), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(capacity),
                            "UpdateExpression": "SET #kind=:kind ADD active_count :one",
                            "ConditionExpression": "attribute_not_exists(active_count) OR active_count<:limit",
                            "ExpressionAttributeNames": {"#kind": "kind"},
                            "ExpressionAttributeValues": attrs({":kind": "api_key_capacity", ":one": 1, ":limit": MAX_UNREVOKED_KEYS})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(429, "Revoke an unused API key before creating another") from None
            raise
        return dict(value)

    def api_key(self, key_id):
        pointer = self.client.get_item(TableName=self.table,
                                       Key=attrs({"PK": "api-key/" + key_id, "SK": "lookup"}),
                                       ConsistentRead=True).get("Item")
        if not pointer:
            return None
        tenant = row(pointer).get("tenant")
        if not isinstance(tenant, str):
            return None
        value = self._get(tenant, "api_key", key_id)
        return value if value and value.get("tenant") == tenant and value.get("id") == key_id else None

    def api_keys(self, tenant, after=None, limit=50):
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:kind)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":kind": "api_key/"}),
                     "Limit": limit + 1}
        if after:
            arguments["ExclusiveStartKey"] = attrs(self.key(tenant, "api_key", after))
        values = []
        while len(values) <= limit:
            page = self.client.query(**arguments)
            values.extend(row(item) for item in page.get("Items", ()))
            if not page.get("LastEvaluatedKey") or len(values) > limit:
                break
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]
            arguments["Limit"] = limit + 1 - len(values)
        return values[:limit], values[limit - 1]["id"] if len(values) > limit else None

    def revoke_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        try:
            self.client.transact_write_items(TransactItems=[
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "api_key", key_id)),
                            "UpdateExpression": "SET revoked_at=:now",
                            "ConditionExpression": "attribute_exists(PK) AND attribute_not_exists(revoked_at)",
                            "ExpressionAttributeValues": attrs({":now": now})}},
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "api_key_capacity", "current")),
                            "UpdateExpression": "ADD active_count :minus",
                            "ConditionExpression": "attribute_exists(active_count) AND active_count>:zero",
                            "ExpressionAttributeValues": attrs({":minus": -1, ":zero": 0})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(404, "API key not found") from None
            raise

    def touch_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "api_key", key_id)),
                                    UpdateExpression="SET last_used_at=:now",
                                    ConditionExpression="attribute_exists(PK) AND attribute_not_exists(revoked_at) AND (attribute_not_exists(expires_at) OR expires_at>:now)",
                                    ExpressionAttributeValues=attrs({":now": now}))
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def workspace_external_id(self, tenant):
        import secrets
        existing = self._get(tenant, "aws_external_id", "workspace")
        if existing:
            return existing["external_id"]
        value = "hacktricks-cspm-ws-" + secrets.token_urlsafe(48)
        try:
            self._put(tenant, "aws_external_id", "workspace", {"external_id": value})
            return value
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            existing = self._get(tenant, "aws_external_id", "workspace")
            if not existing:
                raise
            return existing["external_id"]

    def ai_state(self, user, name):
        item = self.client.get_item(TableName=self.table, Key=attrs(self.key(user, "ai", name)), ConsistentRead=True).get("Item")
        return row(item)["value"] if item else None

    def set_ai_state(self, user, name, value, expected=None):
        arguments = dict(TableName=self.table, ConditionExpression="attribute_not_exists(PK)" if expected is None else "#v=:old")
        if expected is not None:
            arguments.update(ExpressionAttributeNames={"#v": "value"}, ExpressionAttributeValues=attrs({":old": expected}))
        try:
            if value is None:
                self.client.delete_item(Key=attrs(self.key(user, "ai", name)), **arguments)
            else:
                self.client.put_item(Item=attrs(dict(self.key(user, "ai", name), value=value)), **arguments)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def add_connector(self, tenant, data, encrypted_auth):
        value = dict(data, id=uuid.uuid4().hex, created_at=utc())
        self._put(tenant, "connector", value["id"], {"id": value["id"], "tenant": tenant, "data": json.dumps(value), "auth": encrypted_auth})
        return value

    def connector(self, tenant, ident):
        value = self._get(tenant, "connector", ident)
        if not value:
            raise StoreError(404, "Connector not found")
        return value

    def connectors(self, tenant):
        return self._query(tenant, "connector")

    def update_connector(self, tenant, ident, patch, encrypted_auth=None):
        for _ in range(8):
            old = self.connector(tenant, ident)
            new = dict(old, data=json.dumps(dict(json.loads(old["data"]), **patch)), auth=encrypted_auth or old["auth"])
            try:
                self._put(tenant, "connector", ident, new, old)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        raise StoreError(409, "Connector changed concurrently; retry")

    def delete_connector(self, tenant, ident):
        self.connector(tenant, ident)
        self.client.delete_item(TableName=self.table, Key=attrs(self.key(tenant, "connector", ident)))
        for schedule in self.schedules(tenant):
            if schedule["connector_id"] == ident:
                try:
                    self.delete_schedule(tenant, schedule["id"])
                except StoreError:
                    pass

    def usage(self, tenant, now=None):
        current = self._get(tenant, "quota", week(time.time() if now is None else now))
        return current.get("used", 0) if current else 0

    def _unlimited_scans_grant(self, tenant):
        """Read the operator-owned row consistently; malformed rows confer no access."""
        if not isinstance(tenant, str) or not tenant:
            return None
        key = {"PK": "tenant/" + tenant, "SK": "operator_scan_quota"}
        item = self.client.get_item(TableName=self.table, Key=attrs(key), ConsistentRead=True).get("Item")
        if not item:
            return None
        grant = row(item)
        strings = ("verified_email", "cognito_pool_id", "actor", "reason", "audit_id")
        if (grant.get("PK") != key["PK"] or grant.get("SK") != key["SK"] or
                grant.get("kind") != "operator_scan_quota" or
                grant.get("tenant") != tenant or grant.get("cognito_subject") != tenant or
                grant.get("unlimited") is not True or
                any(not isinstance(grant.get(field), str) or not grant[field].strip() for field in strings) or
                "@" not in grant["verified_email"] or
                not grant["actor"].startswith("arn:aws:sts::") or
                type(grant.get("created")) not in (int, float) or grant["created"] <= 0):
            return None
        return grant

    def unlimited_scans(self, tenant):
        return self._unlimited_scans_grant(tenant) is not None

    def get_admin_qa_grant(self, tenant):
        value = self._get(tenant, "entitlement", "admin_qa")
        return value if value and value.get("tenant") == tenant and value.get("kind") == "admin_qa_grant" else None

    def issue_admin_qa_grant(self, tenant, record, now=None, expected_predecessor=None):
        from peaso.auth.admin_qa import valid_issue
        now = self.clock() if now is None else now
        if not valid_issue(record, tenant=tenant, now=now):
            raise StoreError(400, "Invalid administrator QA grant")
        if expected_predecessor is not None and (
                not isinstance(expected_predecessor, dict) or
                set(expected_predecessor) != {"audit_id", "rev"} or
                not isinstance(expected_predecessor["audit_id"], str) or
                type(expected_predecessor["rev"]) is not int or expected_predecessor["rev"] < 0):
            raise StoreError(400, "Invalid reviewed predecessor")
        prior = self.get_admin_qa_grant(tenant)
        if expected_predecessor is None:
            if prior is not None:
                raise StoreError(409, "Prior administrator QA grant requires explicit review")
            revision = 0
            condition = "attribute_not_exists(PK)"
            values = None
        else:
            if (not prior or prior.get("audit_id") != expected_predecessor["audit_id"] or
                    prior.get("rev") != expected_predecessor["rev"]):
                raise StoreError(409, "Reviewed predecessor is absent or changed")
            revoked = type(prior.get("revoked_at")) in (int, float) and prior["revoked_at"] > 0
            expired = type(prior.get("hard_expires_at")) in (int, float) and prior["hard_expires_at"] <= now
            if not (revoked or expired):
                raise StoreError(409, "Reviewed predecessor remains active")
            revision = prior["rev"] + 1
            condition = ("audit_id=:old_audit AND #rev=:old_rev AND "
                         "((attribute_type(revoked_at,:number_type) AND revoked_at>:zero) "
                         "OR hard_expires_at<=:now)")
            values = attrs({":old_audit": expected_predecessor["audit_id"],
                            ":old_rev": expected_predecessor["rev"],
                            ":number_type": "N", ":zero": 0, ":now": now})
        current = dict(self.key(tenant, "entitlement", "admin_qa"), **record,
                       kind="admin_qa_grant", rev=revision)
        event = dict(self.key(tenant, "admin_qa_grant_event", record["audit_id"] + "/issue"),
                     kind="admin_qa_grant_event", tenant=tenant, audit_id=record["audit_id"],
                     event="issue", record=record)
        put = {"TableName": self.table, "Item": attrs(current), "ConditionExpression": condition}
        if values is not None:
            put.update(ExpressionAttributeNames={"#rev": "rev"}, ExpressionAttributeValues=values)
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": put},
                {"Put": {"TableName": self.table, "Item": attrs(event),
                         "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Administrator QA predecessor or audit ID changed") from None
            raise
        return dict(current)

    def revoke_admin_qa_grant(self, tenant, audit_id, actor, reason, now=None):
        now = self.clock() if now is None else now
        from peaso.auth.admin_qa import valid_actor
        if not valid_actor(actor) or not isinstance(reason, str) or not reason.strip():
            raise StoreError(400, "Valid revocation actor and reason required")
        old = self.get_admin_qa_grant(tenant)
        if not old or old.get("audit_id") != audit_id or old.get("revoked_at") is not None:
            raise StoreError(409, "Administrator QA grant changed or expired")
        updated = dict(old, revoked_at=now, revoked_by=actor, revoke_reason=reason.strip(), rev=old["rev"] + 1)
        event = dict(self.key(tenant, "admin_qa_grant_event", audit_id + "/revoke"),
                     kind="admin_qa_grant_event", tenant=tenant, audit_id=audit_id,
                     event="revoke", record=updated)
        try:
            self.client.transact_write_items(TransactItems=[
                {"Put": {"TableName": self.table, "Item": attrs(updated),
                         "ConditionExpression": "#rev=:rev AND audit_id=:audit AND attribute_not_exists(revoked_at)",
                         "ExpressionAttributeNames": {"#rev": "rev"},
                         "ExpressionAttributeValues": attrs({":rev": old["rev"], ":audit": audit_id})}},
                {"Put": {"TableName": self.table, "Item": attrs(event),
                         "ConditionExpression": "attribute_not_exists(PK)"}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Administrator QA grant changed or expired") from None
            raise
        return updated

    def get_entitlement(self, tenant):
        value = self._get(tenant, "entitlement", "stripe")
        return value["paid"] if value and value["expires_at"] > time.time() else None

    def set_entitlement(self, tenant, paid, seconds=3600):
        self.client.put_item(TableName=self.table, Item=attrs(dict(self.key(tenant, "entitlement", "stripe"), kind="entitlement", paid=bool(paid), verified_at=int(time.time()), expires_at=int(time.time() + seconds))))

    def _replay(self, tenant, idem, digest):
        if idem is None:
            return None
        current = self._get(tenant, "idem", hashlib.sha256(idem.encode()).hexdigest())
        if not current or current.get("expires_at", float("inf")) <= self.clock():
            return None
        if current["digest"] != digest:
            raise StoreError(409, "Idempotency key already used for a different request")
        return self.public_job(self.job(tenant, current["id"]))

    def enqueue(self, tenant, request, limit=1, timeout=900, idem=None, now=None, extra=None):
        now = time.time() if now is None else now
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        replay = self._replay(tenant, idem, digest)
        if replay:
            return replay
        for attempt in range(8):
            grant = self._unlimited_scans_grant(tenant)
            connector = self.connector(tenant, request["connector_id"])
            ident = uuid.uuid4().hex
            value = dict(self.key(tenant, "job", ident), kind="job", rev=0, id=ident, tenant=tenant,
                         connector_id=request["connector_id"], data=json.dumps(request), connector=json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]}),
                         status="queued", created=now, queued_at=now, deadline=now + QUEUE_WAIT_SECONDS, execution_timeout=timeout, expires_at=int(now + max(30 * 86400, timeout + 86400)), owner=None, lease=None, snapshot=None, report=None, error=None, error_code=None, error_stage=None, resume_attempt=0, history=[{"status": "queued", "at": utc(now)}], idem=idem, digest=digest)
            quota_values = {":kind": "quota", ":one": 1, ":expires": int(now + 14 * 86400)}
            quota_update = {"TableName": self.table, "Key": attrs(self.key(tenant, "quota", week(now))),
                            "UpdateExpression": "SET #kind=:kind, expires_at=:expires ADD used :one",
                            "ExpressionAttributeNames": {"#kind": "kind"}}
            if not grant:
                quota_update["ConditionExpression"] = "attribute_not_exists(used) OR used<:limit"
                quota_values[":limit"] = limit
            quota_update["ExpressionAttributeValues"] = attrs(quota_values)
            transactions = [
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self.key(tenant, "connector", connector["id"])), "ConditionExpression": "#rev=:rev", "ExpressionAttributeNames": {"#rev": "rev"}, "ExpressionAttributeValues": attrs({":rev": connector["rev"]})}},
                {"Update": quota_update},
                {"Put": {"TableName": self.table, "Item": attrs(value), "ConditionExpression": "attribute_not_exists(PK)"}},
            ]
            if grant:
                fields = ("kind", "tenant", "cognito_subject", "unlimited", "verified_email",
                          "cognito_pool_id", "actor", "reason", "created", "audit_id")
                transactions.append({"ConditionCheck": {"TableName": self.table,
                    "Key": attrs({"PK": grant["PK"], "SK": grant["SK"]}),
                    "ConditionExpression": " AND ".join(f"#{field}=:{field}" for field in fields),
                    "ExpressionAttributeNames": {f"#{field}": field for field in fields},
                    "ExpressionAttributeValues": attrs({f":{field}": grant[field] for field in fields})}})
            if idem is not None:
                transactions.append({"Put": {"TableName": self.table, "Item": attrs(dict(self.key(tenant, "idem", hashlib.sha256(idem.encode()).hexdigest()), kind="idem", id=ident, digest=digest, expires_at=value["expires_at"])), "ConditionExpression": "attribute_not_exists(PK) OR expires_at<=:now", "ExpressionAttributeValues": attrs({":now": now})}})
            if extra:
                transactions.append(extra)
            try:
                self.client.transact_write_items(TransactItems=transactions)
                return self.public_job(value)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "TransactionCanceledException":
                    raise
                replay = self._replay(tenant, idem, digest)
                if replay:
                    return replay
                reasons = exc.response.get("CancellationReasons", [])
                if extra and reasons and reasons[-1].get("Code") == "ConditionalCheckFailed":
                    raise StoreError(409, "Schedule changed concurrently")
                if not self.unlimited_scans(tenant) and self.usage(tenant, now) >= limit:
                    raise StoreError(429, "Weekly scan quota exhausted")
                time.sleep(0.01 * (attempt + 1))
        raise StoreError(409, "Concurrent reservation; retry")

    def resume_job(self, tenant, ident, expected_connector, now=None, *, refresh=None):
        """Conditionally reset the same item and bind one connector revision."""
        from peaso.server.scan_resume import resume_stage
        now = self.clock() if now is None else now
        job = self.job(tenant, ident)
        from peaso.server.scan_resume import consume_section_refresh
        refresh_plan = consume_section_refresh(refresh, job) if refresh is not None else None
        stage = 'collector' if refresh_plan is not None else resume_stage(job)
        if stage is None:
            raise StoreError(409, "This scan has no recoverable work")
        connector = self.connector(tenant, job["connector_id"])
        if (connector["rev"] != expected_connector["rev"]
                or connector["data"] != expected_connector["data"]
                or connector["auth"] != expected_connector["auth"]):
            raise StoreError(409, "Connector changed; check access and retry")
        status = "queued"
        events = list(job.get("history") or [])
        events.append({"status": status, "at": utc(now)})
        values = {":status": status, ":old_status": job["status"], ":now": now,
                  ":deadline": now + QUEUE_WAIT_SECONDS,
                  ":connector": json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]}),
                  ":null": None, ":history": events, ":phase": stage,
                  ":attempt": int(job.get("resume_attempt") or 0) + 1,
                  ":old_attempt": int(job.get("resume_attempt") or 0), ":refresh": refresh_plan}
        refresh_condition = ''
        refresh_names = {}
        if refresh_plan is not None:
            values.update({':source_snapshot': job['snapshot'], ':source_report': job['report'],
                           ':source_sequence': job.get('checkpoint_sequence', 0), ':source_frozen': job['connector']})
            refresh_condition = ' AND #source_snapshot=:source_snapshot AND #source_report=:source_report AND #source_sequence=:source_sequence AND #source_frozen=:source_frozen'
            refresh_names = {'#source_snapshot':'snapshot','#source_report':'report','#source_sequence':'checkpoint_sequence','#source_frozen':'connector'}
        try:
            self.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": self.table,
                    "Key": attrs(self.key(tenant, "connector", connector["id"])),
                    "ConditionExpression": "#rev=:revision",
                    "ExpressionAttributeNames": {"#rev": "rev"},
                    "ExpressionAttributeValues": attrs({":revision": connector["rev"]})}},
                {"Update": {"TableName": self.table,
                    "Key": attrs(self.key(tenant, "job", ident)),
                    "UpdateExpression": "SET #status=:status,connector=:connector,deadline=:deadline,queued_at=:now,"
                        "#owner=:null,lease=:null,#error=:null,error_code=:null,error_stage=:null,"
                        "progress_details=:null,#history=:history,resume_attempt=:attempt,"
                        "resume_phase=:phase,native_refresh=:refresh REMOVE admitted_at",
                    "ConditionExpression": "#status=:old_status AND connector_id=:connector_id "
                        "AND (attribute_not_exists(resume_attempt) OR resume_attempt=:old_attempt) "
                        "AND (attribute_not_exists(expires_at) OR expires_at>:now)" + refresh_condition,
                    "ExpressionAttributeNames": {"#status": "status", "#owner": "owner",
                                                 "#error": "error", "#history": "history", **refresh_names},
                    "ExpressionAttributeValues": attrs({**values, ":connector_id": connector["id"]})}},
            ])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                raise StoreError(409, "Scan or connector changed; retry") from None
            raise
        # A terminal write can precede its previous attempt's release if that
        # worker was interrupted. This key is fenced from the new attempt.
        self.release_admission(tenant, ident, int(job.get("resume_attempt") or 0))
        return self.public_job(self.job(tenant, ident))

    def job(self, tenant, ident):
        value = self._get(tenant, "job", ident)
        if not value or value.get("expires_at", float("inf")) <= self.clock():
            raise StoreError(404, "Scan not found")
        return value

    def job_control(self, tenant, ident):
        """Strongly consistent cancellation/TTL state, without the full job body."""
        item = self.client.get_item(TableName=self.table, Key=attrs(self.key(tenant, "job", ident)),
            ConsistentRead=True, ProjectionExpression="#status, #expires",
            ExpressionAttributeNames={"#status": "status", "#expires": "expires_at"}).get("Item")
        value = row(item) if item else None
        if not value or value.get("expires_at", float("inf")) <= self.clock():
            raise StoreError(404, "Scan not found")
        return value

    def replace_completed_report(self, tenant, ident, expected_report, report):
        """Operator-only compare-and-swap; keep original runtime and job history."""
        values = {":report": report, ":expected": expected_report, ":completed": "completed", ":now": self.clock()}
        if not self._update_job(tenant, ident, "SET #report=:report", {"#report": "report", "#status": "status"}, values,
                                "#status=:completed AND #report=:expected AND (attribute_not_exists(expires_at) OR expires_at>:now)"):
            raise StoreError(409, "Completed scan report changed")

    def record_checkpoint(self, tenant, ident, owner, sequence, reference, *, kind=None, scope=None,
                          report_ref=None, stage="collector", now=None):
        """Tenant, lease, owner and monotonic sequence fenced checkpoint write."""
        from .artifacts import job_prefix
        now = self.clock() if now is None else now
        if (type(sequence) is not int or sequence < 1 or not isinstance(reference, str)
                or not reference.startswith(job_prefix(tenant, ident))
                or report_ref is not None and (not isinstance(report_ref, str) or not report_ref.startswith(job_prefix(tenant, ident)))):
            raise ValueError("Invalid checkpoint reference or sequence")
        if stage not in {"collector", "analyzer_native"}:
            raise ValueError("Invalid checkpoint stage")
        if report_ref is None:
            if not isinstance(kind, str) or not isinstance(scope, str) or stage != "collector":
                raise ValueError("Collection checkpoint needs native type and scope")
            checkpoint_id = ident + "/" + hashlib.sha256((kind + "\0" + scope).encode()).hexdigest()
            item = dict(self.key(tenant, "scan_checkpoint", checkpoint_id), kind="scan_checkpoint",
                        scan_id=ident, native_kind=kind, scope=scope, sequence=sequence,
                        reference=reference, expires_at=int(now + 30 * 86400))
            update = {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                         "UpdateExpression": "SET checkpoint_sequence=:seq",
                         "ConditionExpression": "#status=:collecting AND #owner=:owner AND lease>:now AND deadline>:now AND (attribute_not_exists(checkpoint_sequence) OR checkpoint_sequence<:seq)",
                         "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                         "ExpressionAttributeValues": attrs({":seq": sequence, ":collecting": "collecting", ":owner": owner, ":now": now})}}
            actions = [update, {"Put": {"TableName": self.table, "Item": attrs(item)}}]
        else:
            phase = "analyzing" if stage == "analyzer_native" else "collecting"
            expression = "SET partial_snapshot=:snapshot,partial_report=:report,partial_report_sequence=:seq"
            condition = ("#status=:phase AND #owner=:owner AND lease>:now AND deadline>:now "
                         "AND (attribute_not_exists(partial_report_sequence) OR partial_report_sequence<:seq) "
                         "AND " + ("(attribute_not_exists(checkpoint_sequence) OR checkpoint_sequence<:seq)"
                                    if stage == "analyzer_native" else "checkpoint_sequence>=:seq"))
            if stage == "analyzer_native":
                expression += ",checkpoint_sequence=:seq"
            actions = [{"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                        "UpdateExpression": expression,
                        "ConditionExpression": condition,
                        "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                        "ExpressionAttributeValues": attrs({":snapshot": reference, ":report": report_ref,
                                                            ":phase": phase, ":owner": owner,
                                                            ":now": now, ":seq": sequence})}}]
        try:
            self.client.transact_write_items(TransactItems=actions)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise

    def checkpoint_collections(self, tenant, ident):
        self.job(tenant, ident)
        prefix = "scan_checkpoint/" + ident + "/"
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:prefix)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":prefix": prefix})}
        out = []
        while True:
            page = self.client.query(**arguments)
            out.extend({"kind": value["native_kind"], "scope": value["scope"],
                        "sequence": value["sequence"], "reference": value["reference"]}
                       for value in (row(item) for item in page.get("Items", [])))
            if not page.get("LastEvaluatedKey"):
                return sorted(out, key=lambda value: value["sequence"])
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    @staticmethod
    def _stage_key(tenant, ident, stage):
        return {"PK": "tenant/" + tenant, "SK": "scan_stage/" + ident + "/" + stage}

    def claim_stage(self, tenant, ident, stage, data_revision, owner, lease_seconds, now=None):
        SQLiteStore._stage_args(stage, data_revision, owner)
        if lease_seconds <= 0:
            raise ValueError("Invalid progressive lease")
        now = self.clock() if now is None else now
        try:
            self.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                    "ConditionExpression": "#status IN (:collecting,:collected,:analyzing) AND deadline>:now AND (attribute_not_exists(#owner) OR #owner<>:owner)",
                    "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                    "ExpressionAttributeValues": attrs({":collecting": "collecting", ":collected": "collected",
                        ":analyzing": "analyzing", ":now": now, ":owner": owner})}},
                {"Update": {"TableName": self.table, "Key": attrs(self._stage_key(tenant, ident, stage)),
                    "UpdateExpression": "SET data_revision=:revision,#status=:running,#owner=:owner,lease=:lease,result_ref=:null,expires_at=:expires",
                    "ConditionExpression": "attribute_not_exists(PK) OR data_revision<:revision OR (data_revision=:revision AND #status=:running AND lease<=:now)",
                    "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                    "ExpressionAttributeValues": attrs({":revision": data_revision, ":running": "running",
                        ":owner": owner, ":lease": now + lease_seconds, ":now": now,
                        ":null": None, ":expires": int(now + 30 * 86400)})}},
            ])
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise

    def heartbeat_stage(self, tenant, ident, stage, data_revision, owner, lease_seconds, now=None):
        SQLiteStore._stage_args(stage, data_revision, owner)
        if lease_seconds <= 0:
            raise ValueError("Invalid progressive lease")
        now = self.clock() if now is None else now
        try:
            self.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                    "ConditionExpression": "#status IN (:collecting,:collected,:analyzing) AND deadline>:now",
                    "ExpressionAttributeNames": {"#status": "status"},
                    "ExpressionAttributeValues": attrs({":collecting": "collecting", ":collected": "collected",
                        ":analyzing": "analyzing", ":now": now})}},
                {"Update": {"TableName": self.table, "Key": attrs(self._stage_key(tenant, ident, stage)),
                    "UpdateExpression": "SET lease=:lease",
                    "ConditionExpression": "data_revision=:revision AND #status=:running AND #owner=:owner AND lease>:now",
                    "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                    "ExpressionAttributeValues": attrs({":revision": data_revision, ":running": "running",
                        ":owner": owner, ":lease": now + lease_seconds, ":now": now})}},
            ])
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise

    def abandon_stage(self, tenant, ident, stage, data_revision, owner):
        """Release only our drained obsolete claim; newer/foreign claims survive."""
        SQLiteStore._stage_args(stage, data_revision, owner)
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self._stage_key(tenant, ident, stage)),
                UpdateExpression="SET #status=:cancelled,#owner=:null,lease=:null,result_ref=:null",
                ConditionExpression="data_revision=:revision AND #status=:running AND #owner=:owner",
                ExpressionAttributeNames={"#status": "status", "#owner": "owner"},
                ExpressionAttributeValues=attrs({":revision": data_revision, ":running": "running",
                    ":cancelled": "cancelled", ":owner": owner, ":null": None}))
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def finish_stage(self, tenant, ident, stage, data_revision, owner, result_ref, now=None):
        from .artifacts import job_prefix
        SQLiteStore._stage_args(stage, data_revision, owner)
        if not isinstance(result_ref, str) or not result_ref.startswith(job_prefix(tenant, ident)):
            raise ValueError("Invalid progressive result reference")
        now = self.clock() if now is None else now
        try:
            self.client.transact_write_items(TransactItems=[
                {"ConditionCheck": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                    "ConditionExpression": "#status IN (:collecting,:collected,:analyzing) AND deadline>:now",
                    "ExpressionAttributeNames": {"#status": "status"},
                    "ExpressionAttributeValues": attrs({":collecting": "collecting", ":collected": "collected",
                        ":analyzing": "analyzing", ":now": now})}},
                {"Update": {"TableName": self.table, "Key": attrs(self._stage_key(tenant, ident, stage)),
                    "UpdateExpression": "SET #status=:completed,#owner=:null,lease=:null,result_ref=:result",
                    "ConditionExpression": "data_revision=:revision AND #status=:running AND #owner=:owner AND lease>:now",
                    "ExpressionAttributeNames": {"#status": "status", "#owner": "owner"},
                    "ExpressionAttributeValues": attrs({":revision": data_revision, ":running": "running",
                        ":completed": "completed", ":owner": owner, ":null": None,
                        ":result": result_ref, ":now": now})}},
            ])
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                return False
            raise

    def _stage_rows(self, tenant, ident):
        prefix = "scan_stage/" + ident + "/"
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:prefix)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":prefix": prefix})}
        out = []
        while True:
            page = self.client.query(**arguments)
            out.extend(row(item) for item in page.get("Items", []))
            if not page.get("LastEvaluatedKey"):
                return out
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def stage_results(self, tenant, ident):
        self.job(tenant, ident)
        return {entry["SK"].split("/")[-1]: {"data_revision": entry["data_revision"],
                "result_ref": entry["result_ref"]} for entry in self._stage_rows(tenant, ident)
                if entry.get("status") == "completed" and entry.get("result_ref")}

    def jobs(self, tenant, transform=None):
        return [(transform or self.public_job)(value) for value in sorted(self._query(tenant, "job"), key=lambda x: x["created"], reverse=True) if value.get("expires_at", float("inf")) > self.clock()]

    def deletion_job(self, tenant, ident):
        # TTL expiry hides scans from normal reads, but their objects still need deletion.
        value = self._get(tenant, "job", ident)
        if not value:
            raise StoreError(404, "Scan not found")
        return value

    def deletion_jobs(self, tenant):
        return self._query(tenant, "job")

    def delete_job(self, tenant, ident):
        self.deletion_job(tenant, ident)
        try:
            self.client.delete_item(TableName=self.table, Key=attrs(self.key(tenant, "job", ident)),
                ConditionExpression="attribute_exists(PK) AND (#status IN (:done,:failed,:cancelled,:timed,:queue_exhausted) OR deadline<=:now)",
                ExpressionAttributeNames={"#status": "status"}, ExpressionAttributeValues=attrs({
                    ":done": "completed", ":failed": "failed", ":cancelled": "cancelled", ":timed": "timed_out", ":queue_exhausted": "queue_exhausted", ":now": time.time()}))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise StoreError(409, "Scan changed; refresh and retry") from None
            raise
        # Keep the separately keyed native deltas bounded to the deleted scan.
        for checkpoint in self.checkpoint_collections_for_deleted(tenant, ident):
            digest_id = hashlib.sha256((checkpoint["kind"] + "\0" + checkpoint["scope"]).encode()).hexdigest()
            self.client.delete_item(TableName=self.table,
                                    Key=attrs(self.key(tenant, "scan_checkpoint", ident + "/" + digest_id)))
        for stage in self._stage_rows(tenant, ident):
            self.client.delete_item(TableName=self.table, Key=attrs({"PK": stage["PK"], "SK": stage["SK"]}))

    def checkpoint_collections_for_deleted(self, tenant, ident):
        prefix = "scan_checkpoint/" + ident + "/"
        arguments = {"TableName": self.table, "ConsistentRead": True,
                     "KeyConditionExpression": "PK=:tenant AND begins_with(SK,:prefix)",
                     "ExpressionAttributeValues": attrs({":tenant": "tenant/" + tenant, ":prefix": prefix})}
        out = []
        while True:
            page = self.client.query(**arguments)
            out.extend({"kind": value["native_kind"], "scope": value["scope"]}
                       for value in (row(item) for item in page.get("Items", [])))
            if not page.get("LastEvaluatedKey"):
                return out
            arguments["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def queued_jobs(self, *, authoritative=False):
        candidates = ([item for item in self._scan('job') if item['status'] == 'queued']
                      if authoritative else self._work_jobs(('queued',)))
        return sorted(candidates, key=lambda item: (item.get("queued_at", item["created"]), item["id"]))

    @staticmethod
    def _reservation_key(tenant, ident, attempt=0):
        suffix = "" if not attempt else "/" + str(attempt)
        return {"PK": "GLOBAL", "SK": "SCAN_RESERVATION/" + tenant + "/" + ident + suffix}

    def release_admission(self, tenant, ident, attempt=0):
        """Release exactly once; a terminal write may precede this if a process dies."""
        try:
            self.client.transact_write_items(TransactItems=[
                {"Delete": {"TableName": self.table, "Key": attrs(self._reservation_key(tenant, ident, attempt)),
                            "ConditionExpression": "attribute_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}),
                            "UpdateExpression": "ADD active_count :minus",
                            "ConditionExpression": "active_count>:zero",
                            "ExpressionAttributeValues": attrs({":minus": -1, ":zero": 0})}},
            ])
            return True
        except ClientError:
            return False

    def reconcile_admissions(self, now=None):
        now = time.time() if now is None else now
        for reservation in self._scan("scan_reservation"):
            try:
                job = self.job(reservation["tenant"], reservation["id"])
            except StoreError as exc:
                if exc.status != 404:
                    raise
                self.release_admission(reservation["tenant"], reservation["id"], reservation.get("attempt", 0))
                continue
            if reservation.get("attempt", 0) != int(job.get("resume_attempt") or 0) or job["status"] in TERMINAL:
                self.release_admission(job["tenant"], job["id"], reservation.get("attempt", 0))
            elif job["deadline"] <= now:
                self._expire_job(job, now)

    def admit(self, tenant, ident, now=None):
        """Atomically reserve global capacity and start this job's execution budget."""
        now = time.time() if now is None else now
        job = self.job(tenant, ident)
        if job["status"] != "queued":
            return False
        if job.get("admitted_at") is not None:
            return True
        if job["deadline"] <= now:
            self._expire_job(job, now)
            return False
        # Scheduler walks this list in order; this check also prevents a new API
        # request from jumping ahead of an older waiting scan.
        # GSI visibility can lag an older waiter. Admission fairness still
        # requires the existing strong scan; indexes only nominate dispatches.
        waiting = [item for item in self.queued_jobs(authoritative=True) if item.get("admitted_at") is None and item["deadline"] > now]
        if waiting and (waiting[0]["tenant"], waiting[0]["id"]) != (tenant, ident):
            return False
        attempt = int(job.get("resume_attempt") or 0)
        reservation = dict(self._reservation_key(tenant, ident, attempt), kind="scan_reservation", id=ident, tenant=tenant, attempt=attempt)
        try:
            self.client.transact_write_items(TransactItems=[
                {"Update": {"TableName": self.table, "Key": attrs({"PK": "GLOBAL", "SK": "SCAN_CAPACITY"}),
                            "UpdateExpression": "ADD active_count :one",
                            "ConditionExpression": "attribute_not_exists(active_count) OR active_count<:limit",
                            "ExpressionAttributeValues": attrs({":one": 1, ":limit": SCAN_CAPACITY})}},
                {"Put": {"TableName": self.table, "Item": attrs(reservation), "ConditionExpression": "attribute_not_exists(PK)"}},
                {"Update": {"TableName": self.table, "Key": attrs(self.key(tenant, "job", ident)),
                            "UpdateExpression": "SET admitted_at=:now, deadline=:execution_deadline",
                            "ConditionExpression": "#status=:queued AND attribute_not_exists(admitted_at) AND deadline>:now AND (attribute_not_exists(resume_attempt) OR resume_attempt=:attempt)",
                            "ExpressionAttributeNames": {"#status": "status"},
                            "ExpressionAttributeValues": attrs({":queued": "queued", ":now": now, ":execution_deadline": now + job.get("execution_timeout", 900), ":attempt": attempt})}},
            ])
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransactionCanceledException":
                fresh = self.job(tenant, ident)
                return bool(fresh["status"] == "queued" and fresh.get("admitted_at") is not None
                            and int(fresh.get("resume_attempt") or 0) == attempt)
            raise

    def _update_job(self, tenant, ident, expression, names, values, condition):
        new_status = values.get(":status") if "#status=:status" in expression else values.get(":active") if "#status=:active" in expression else values.get(":cancelled") if "#status=:cancelled" in expression else values.get(":timed") if "#status=:timed" in expression else None
        if new_status:
            expression += ", #history=list_append(if_not_exists(#history,:empty),:events)"
            names["#history"] = "history"
            values[":empty"] = []
            values[":events"] = [{"status": new_status, "at": utc(values.get(":now", time.time()))}]
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "job", ident)), UpdateExpression=expression, ExpressionAttributeNames=names, ExpressionAttributeValues=attrs(values), ConditionExpression="attribute_exists(PK) AND " + condition)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def cancel(self, tenant, ident):
        job = self.job(tenant, ident)
        attempt = int(job.get("resume_attempt") or 0)
        changed = self._update_job(tenant, ident, "SET #status=:cancelled, #owner=:null, lease=:null", {"#status": "status", "#owner": "owner"},
                         {":cancelled": "cancelled", ":null": None, ":done": "completed", ":failed": "failed", ":timed": "timed_out", ":queue_exhausted": "queue_exhausted", ":credentials_expired": "credentials_expired", ":attempt": attempt}, "NOT (#status IN (:done,:failed,:cancelled,:timed,:queue_exhausted,:credentials_expired)) AND (attribute_not_exists(resume_attempt) OR resume_attempt=:attempt)")
        if changed:
            self.release_admission(tenant, ident, attempt)
        return self.public_job(self.job(tenant, ident))

    def expire(self, now=None):
        now = time.time() if now is None else now
        candidates = (self._work_jobs(('queued', 'collecting', 'collected', 'analyzing'))
                      if self.work_state_index else self._scan('job'))
        for job in candidates:
            self._expire_job(job, now)

    def expire_job(self, tenant, ident, now=None):
        """Expire one tenant job without enumerating other jobs or tenants."""
        now = time.time() if now is None else now
        return self._expire_job(self.job(tenant, ident), now)

    def _expire_job(self, job, now):
        if job["status"] in TERMINAL or job["deadline"] > now:
            return False
        if job["status"] == "queued" and job.get("admitted_at") is None:
            return self._update_job(job["tenant"], job["id"],
                                    "SET #status=:queue_exhausted, #error=:error, #error_code=:code, #error_stage=:stage",
                                    {"#status": "status", "#error": "error", "#error_code": "error_code", "#error_stage": "error_stage"},
                                    {":queue_exhausted": "queue_exhausted", ":previous": "queued", ":now": now,
                                     ":attempt": int(job.get("resume_attempt") or 0),
                                     ":error": "Queue exhausted: no scan slot became available within one hour",
                                     ":code": "queue_exhausted", ":stage": "queue"},
                                    "deadline<=:now AND #status=:previous AND attribute_not_exists(admitted_at) AND (attribute_not_exists(resume_attempt) OR resume_attempt=:attempt)")
        stage = "collector" if job["status"] in {"queued", "collecting"} else "analyzer"
        changed = self._update_job(job["tenant"], job["id"],
                                "SET #status=:timed, #owner=:null, lease=:null, #error=:error, #error_code=:code, #error_stage=:stage",
                                {"#status": "status", "#owner": "owner", "#error": "error", "#error_code": "error_code", "#error_stage": "error_stage"},
                                {":timed": "timed_out", ":null": None, ":previous": job["status"], ":now": now, ":error": "Scan deadline exceeded", ":code": "deadline_exceeded", ":stage": stage, ":attempt": int(job.get("resume_attempt") or 0)},
                                "deadline<=:now AND #status=:previous AND (attribute_not_exists(resume_attempt) OR resume_attempt=:attempt)")
        if changed:
            self.release_admission(job["tenant"], job["id"], int(job.get("resume_attempt") or 0))
        return changed

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        if ident is not None and tenant is None:
            raise ValueError("Tenant required for targeted claim")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        candidates = ([self.job(tenant, ident)] if ident is not None else
                      self._work_jobs(('queued', 'collecting', 'collected', 'analyzing'))
                      if self.work_state_index else self._scan('job'))
        for job in sorted(candidates, key=lambda x: (x.get("queued_at", x["created"]), x["id"])):
            if job["deadline"] <= now:
                self._expire_job(job, now)
                continue
            if job["status"] != ready and not (job["status"] == active and (job["lease"] or 0) <= now):
                continue
            if role == "collector" and job.get("admitted_at") is None:
                continue
            owner = uuid.uuid4().hex
            success = self._update_job(job["tenant"], job["id"], "SET #status=:active, #owner=:owner, lease=:lease", {"#status": "status", "#owner": "owner"},
                                      {":active": active, ":ready": ready, ":owner": owner, ":lease": now + lease_seconds, ":now": now, ":attempt": int(job.get("resume_attempt") or 0)},
                                      "deadline>:now AND (#status=:ready OR (#status=:active AND lease<=:now)) AND (attribute_not_exists(resume_attempt) OR resume_attempt=:attempt)" + (" AND attribute_exists(admitted_at)" if role == "collector" else ""))
            if success:
                self.claims[(job["id"], owner)] = job["tenant"]
                self.claim_attempts[(job["id"], owner)] = int(job.get("resume_attempt") or 0)
                return dict(job, status=active, owner=owner, lease=now + lease_seconds)
        return None

    def heartbeat(self, ident, owner, lease_seconds=30, now=None):
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        if tenant is None:
            return False
        return self._update_job(tenant, ident, "SET lease=:lease", {"#owner": "owner", "#status": "status"},
                                {":owner": owner, ":lease": now + lease_seconds, ":now": now, ":collecting": "collecting", ":analyzing": "analyzing"},
                                "#owner=:owner AND lease>:now AND deadline>:now AND #status IN (:collecting,:analyzing)")

    def record_progress(self, ident, owner, event, now=None):
        from peaso.progress import sanitize_event
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        cleaned = sanitize_event(event)
        cleaned.pop("scope", None)
        if tenant is None or not cleaned:
            return False
        cleaned["at"] = utc(now)
        try:
            return self._update_job(tenant, ident, "SET progress_details=:progress",
                                    {"#owner": "owner", "#status": "status"},
                                    {":progress": cleaned, ":owner": owner, ":now": now,
                                     ":collecting": "collecting", ":analyzing": "analyzing"},
                                    "#owner=:owner AND lease>:now AND deadline>:now AND #status IN (:collecting,:analyzing)")
        except Exception:
            return False

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed", failure_reasons=None):
        if status not in {"collected", "completed", "failed", "credentials_expired"}:
            raise ValueError("Invalid worker transition")
        now = time.time() if now is None else now
        tenant = self.claims.get((ident, owner))
        if tenant is None:
            return False
        names = {"#owner": "owner", "#status": "status", "#artifact": "snapshot" if status in {"collected", "credentials_expired"} else "report", "#error": "error"}
        values = {":owner": owner, ":now": now, ":status": status, ":null": None, ":artifact": artifact,
                  ":error": ("Connector credentials expired during the scan. Update them, then resume this scan or start a new one."
                             if status == "credentials_expired" else
                             INVALID_CREDENTIALS_FAILURE if status == "failed" and error_code == "credentials_invalid" and not curated_failure_reasons(failure_reasons) else
                             failure_error(failure_reasons) if status == "failed" else None)}
        names.update({"#error_code": "error_code", "#error_stage": "error_stage"})
        allowed = {"processing_failed", "invalid_input", "credential_access_denied", "dependency_unavailable", "provider_error", "collector_timeout", "artifact_error", "worker_interrupted", "credentials_invalid"}
        values[":error_code"] = ("credentials_expired" if status == "credentials_expired" else
                                 error_code if status == "failed" and error_code in allowed else
                                 "processing_failed" if status == "failed" else None)
        values[":error_stage"] = (("collector" if self.job(tenant, ident)["status"] == "collecting" else "analyzer")
                                   if status in {"failed", "credentials_expired"} else None)
        if status in {"failed", "credentials_expired"}:
            values.update({":collecting": "collecting", ":analyzing": "analyzing"})
            previous = "#status IN (:collecting,:analyzing)"
        else:
            values[":previous"] = "collecting" if status == "collected" else "analyzing"
            previous = "#status=:previous"
        artifact_assignment = ", #artifact=:artifact" if status != "credentials_expired" or artifact is not None else ""
        if not artifact_assignment:
            names.pop("#artifact")
            values.pop(":artifact")
        changed = self._update_job(tenant, ident, "SET #status=:status, #owner=:null, lease=:null" + artifact_assignment + ", #error=:error, #error_code=:error_code, #error_stage=:error_stage", names, values,
                                   "#owner=:owner AND lease>:now AND deadline>:now AND " + previous)
        if changed and status in {"completed", "failed", "credentials_expired"}:
            self.release_admission(tenant, ident, self.claim_attempts.get((ident, owner), 0))
        return changed

    def schedules(self, tenant):
        return [self.public_schedule(value) for value in self._query(tenant, "schedule")]

    def add_schedule(self, tenant, data, next_run, enabled=True):
        self.connector(tenant, data["connector_id"])
        ident = uuid.uuid4().hex
        value = {"id": ident, "tenant": tenant, "data": json.dumps(data), "next_run": next_run, "enabled": bool(enabled), "last_error": None}
        self._put(tenant, "schedule", ident, value)
        return self.public_schedule(value)

    def update_schedule(self, tenant, ident, patch, next_run=None, enabled=None):
        for _ in range(8):
            old = self._get(tenant, "schedule", ident)
            if old is None:
                raise StoreError(404, "Schedule not found")
            data = dict(json.loads(old["data"]), **patch)
            self.connector(tenant, data["connector_id"])
            effective_next = next_run
            if effective_next is None and (set(patch) & {'rules', 'timezone', 'interval_hours'} or enabled is True and not old['enabled']):
                from peaso.scheduling import next_run as following_run
                effective_next = following_run(data, time.time())
            new = dict(old, data=json.dumps(data), next_run=old["next_run"] if effective_next is None else effective_next, enabled=old["enabled"] if enabled is None else enabled, last_error=None)
            try:
                self._put(tenant, "schedule", ident, new, old)
                return self.public_schedule(new)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        raise StoreError(409, "Schedule changed concurrently; retry")

    def delete_schedule(self, tenant, ident):
        try:
            self.client.delete_item(TableName=self.table, Key=attrs(self.key(tenant, "schedule", ident)), ConditionExpression="attribute_exists(PK)")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise StoreError(404, "Schedule not found") from None
            raise

    def due_schedules(self, now=None):
        now = time.time() if now is None else now
        try:
            candidates = (self._index_candidates(self.schedule_time_index, '#kind=:kind AND #next<=:now',
                          {'#kind': 'kind', '#next': 'next_run'}, {':kind': 'schedule', ':now': now}, 'schedule')
                          if self.schedule_time_index else self._scan('schedule'))
        except ClientError as exc:
            if exc.response['Error']['Code'] not in ('AccessDeniedException', 'ResourceNotFoundException', 'ValidationException'):
                raise
            candidates = self._scan('schedule')
        return [value for value in candidates if (not self.schedule_time_index or value.get('kind') == 'schedule')
                and value["enabled"] and value["next_run"] <= now]

    def pause_schedule(self, tenant, ident, *, reason="Schedule disabled: identity is no longer eligible"):
        try:
            self.client.update_item(TableName=self.table, Key=attrs(self.key(tenant, "schedule", ident)), UpdateExpression="SET #enabled=:false,last_error=:error ADD #rev :one", ConditionExpression="attribute_exists(PK)", ExpressionAttributeNames={"#enabled": "enabled", "#rev": "rev"}, ExpressionAttributeValues=attrs({":false": False, ":error": reason, ":one": 1}))
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # A concurrent deletion must not halt other tenants or resurrect a row.
                return False
            raise

    def trigger_schedule(self, current, limit=1, timeout=900, now=None):
        now = time.time() if now is None else now
        data = json.loads(current["data"])
        if not current['enabled'] or current['next_run'] > now:
            return None
        from peaso.scheduling import next_run as following_run
        upcoming = following_run(data, now)
        request = {k: data[k] for k in ("connector_id", "categories", "checks", "content_checks", "leaks_enabled", "images_enabled", "frameworks", "ai_enabled", "ai_priorities_enabled", "ai_network_enabled", "ai_user_id") if k in data}
        update = {"TableName": self.table, "Key": attrs(self.key(current["tenant"], "schedule", current["id"])),
                  "UpdateExpression": "SET next_run=:next, last_error=:null ADD #rev :one", "ConditionExpression": "#enabled=:true AND next_run=:old AND #rev=:rev",
                  "ExpressionAttributeNames": {"#enabled": "enabled", "#rev": "rev"},
                  "ExpressionAttributeValues": attrs({":next": upcoming, ":old": current["next_run"], ":rev": current["rev"], ":one": 1, ":true": True, ":null": None})}
        try:
            return self.enqueue(current["tenant"], request, limit, timeout, f"schedule:{current['id']}:{current['next_run']}", now, {"Update": update})
        except StoreError as exc:
            if exc.status == 409:
                return None
            update["ExpressionAttributeValues"] = attrs({":next": upcoming, ":old": current["next_run"], ":rev": current["rev"], ":one": 1, ":true": True, ":null": exc.message})
            try:
                self.client.update_item(**update)
            except ClientError as update_error:
                if update_error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
            return None

    def health(self):
        self.client.describe_table(TableName=self.table)

"""Durable tenant-scoped state, atomic quotas, fenced leases and schedules."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import time
import uuid
from .cost import runtime_estimate

SCAN_CAPACITY = 10
QUEUE_WAIT_SECONDS = 3600
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "queue_exhausted", "credentials_expired"}
GENERIC_FAILURE = "Scan processing failed; check connector access and coverage"
INVALID_CREDENTIALS_FAILURE = ("The provider rejected the connector credentials, so no data was read. "
                               "Update the connector credentials, then start a new scan.")
# Fifty maximum-length role ARNs with the longest fixed message serialize to <64 KiB.
_MAX_FAILURE_ERROR_BYTES = 128 * 1024
_ROLE_ARN = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_TARGET_MESSAGES = {
    "external_id_not_required_by_trust": "trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding.",
    "external_id_trust_unverified": "the role's External ID boundary could not be verified; require an exact workspace External ID and retry.",
    "platform_owned_account": "this platform account cannot be a customer scan target.",
    "role_target_limit": "the hosted scan limit of 50 role targets was reached.",
}


def curated_failure_reasons(reasons):
    """Accept only generated text derived from allowlisted codes and IAM role ARNs."""
    safe = []
    for item in reasons[:50] if isinstance(reasons, list) else []:
        if not isinstance(item, dict):
            continue
        code, arn = item.get("code"), item.get("role_arn")
        if not isinstance(code, str) or code not in _TARGET_MESSAGES or not isinstance(arn, str) or not _ROLE_ARN.fullmatch(arn):
            continue
        safe.append({"code": code, "role_arn": arn,
                     "message": f"Role {arn} was refused: {_TARGET_MESSAGES[code]}"})
    return safe


def failure_error(reasons):
    safe = curated_failure_reasons(reasons)
    return json.dumps({"failure_reasons": safe}, separators=(",", ":")) if safe else GENERIC_FAILURE


def public_failure(error):
    """Render the existing job error field without exposing arbitrary stored text."""
    if not isinstance(error, str) or not error.startswith('{"failure_reasons":'):
        return error, []
    # Generated envelopes are ASCII; this also bounds encoded bytes before parsing.
    if len(error) > _MAX_FAILURE_ERROR_BYTES or not error.isascii():
        return GENERIC_FAILURE, []
    try:
        decoded = json.loads(error)
    except (RecursionError, TypeError, ValueError):
        return GENERIC_FAILURE, []
    if not isinstance(decoded, dict) or set(decoded) != {"failure_reasons"}:
        return GENERIC_FAILURE, []
    entries = decoded["failure_reasons"]
    if not isinstance(entries, list) or len(entries) > 50:
        return GENERIC_FAILURE, []
    reasons = curated_failure_reasons(entries)
    if len(reasons) != len(entries):
        return GENERIC_FAILURE, []
    return reasons[0]["message"] if reasons else GENERIC_FAILURE, reasons


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def week(now):
    date = datetime.fromtimestamp(now, timezone.utc).date()
    return (date - timedelta(days=date.weekday())).isoformat()


def history(row, status, now):
    events = row.get("history", []) if isinstance(row, dict) else row["history"]
    events = json.loads(events) if isinstance(events, str) else list(events or [])
    events.append({"status": status, "at": utc(now)})
    return json.dumps(events)


class StoreError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class SQLiteStore:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = state_dir / "peaso.sqlite3"
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS workspace_external_ids (tenant TEXT PRIMARY KEY, external_id TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS connectors (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, auth TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS connectors_tenant ON connectors(tenant);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, connector_id TEXT NOT NULL, data TEXT NOT NULL, connector TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, deadline REAL NOT NULL, owner TEXT, lease REAL, snapshot TEXT, report TEXT, error TEXT, idem TEXT, digest TEXT);
            CREATE TABLE IF NOT EXISTS scan_checkpoint_collections (tenant TEXT NOT NULL, scan_id TEXT NOT NULL, kind TEXT NOT NULL, scope TEXT NOT NULL, sequence INTEGER NOT NULL, reference TEXT NOT NULL, PRIMARY KEY(tenant,scan_id,kind,scope));
            CREATE TABLE IF NOT EXISTS scan_stage_results (tenant TEXT NOT NULL, scan_id TEXT NOT NULL, stage TEXT NOT NULL, data_revision INTEGER NOT NULL, status TEXT NOT NULL, owner TEXT, lease REAL, result_ref TEXT, PRIMARY KEY(tenant,scan_id,stage));
            CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem ON jobs(tenant,idem) WHERE idem IS NOT NULL;
            CREATE INDEX IF NOT EXISTS jobs_tenant ON jobs(tenant,created);
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,lease);
            CREATE TABLE IF NOT EXISTS quota (tenant TEXT NOT NULL, week TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(tenant,week));
            CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, data TEXT NOT NULL, next_run REAL NOT NULL, enabled INTEGER NOT NULL, last_error TEXT);
            CREATE TABLE IF NOT EXISTS entitlements (tenant TEXT PRIMARY KEY, paid INTEGER NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_qa_grants (tenant TEXT PRIMARY KEY, record TEXT NOT NULL, rev INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS admin_qa_grant_events (audit_id TEXT NOT NULL, event TEXT NOT NULL, tenant TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(audit_id,event));
            CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, secret_sha256 TEXT NOT NULL, name TEXT NOT NULL, prefix TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL, revoked_at REAL, last_used_at REAL, cognito_username TEXT);
            CREATE INDEX IF NOT EXISTS api_keys_tenant ON api_keys(tenant,id);
            CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS workspaces_owner ON workspaces(owner);
            CREATE TABLE IF NOT EXISTS workspace_members (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, joined REAL NOT NULL, PRIMARY KEY(workspace_id,user_id));
            CREATE INDEX IF NOT EXISTS workspace_members_user ON workspace_members(user_id);
            CREATE TABLE IF NOT EXISTS workspace_invites (workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, email TEXT NOT NULL, role TEXT NOT NULL, invited_by TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(workspace_id,user_id));
            CREATE INDEX IF NOT EXISTS workspace_invites_user ON workspace_invites(user_id);
            """)
            db.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            for name, definition in (("history", "TEXT NOT NULL DEFAULT '[]'"), ("error_code", "TEXT"), ("error_stage", "TEXT"),
                                     ("admitted_at", "REAL"), ("execution_timeout", "REAL NOT NULL DEFAULT 900"),
                                     ("progress_details", "TEXT"), ("checkpoint_sequence", "INTEGER NOT NULL DEFAULT 0"),
                                     ("partial_snapshot", "TEXT"), ("partial_report", "TEXT"),
                                     ("partial_report_sequence", "INTEGER NOT NULL DEFAULT 0"),
                                     ("resume_attempt", "INTEGER NOT NULL DEFAULT 0"),
                                     ("resume_phase", "TEXT"), ("queued_at", "REAL"), ("native_refresh", "TEXT")):
                if name not in columns:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")
            db.execute("UPDATE jobs SET queued_at=created WHERE queued_at IS NULL")
            if "execution_timeout" not in columns:
                db.execute("UPDATE jobs SET execution_timeout=deadline-created,deadline=created+? WHERE status='queued'",
                           (QUEUE_WAIT_SECONDS,))
            if "admitted_at" not in columns:
                db.execute("UPDATE jobs SET admitted_at=created WHERE status IN ('collecting','collected','analyzing')")
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None, factory=ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def workspaces(self, user_id):
        with self.connect() as db:
            rows = db.execute("SELECT w.id,w.owner,w.name,m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id=w.id WHERE m.user_id=? ORDER BY w.name COLLATE NOCASE", (user_id,)).fetchall()
            return [dict(row) for row in rows]

    def workspace(self, workspace_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            return dict(row) if row else None

    def workspace_role(self, workspace_id, user_id):
        with self.connect() as db:
            row = db.execute("SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone()
            return row["role"] if row else None

    def create_workspace(self, owner, name, name_key, email):
        ident, now = "ws_" + uuid.uuid4().hex, time.time()
        with self.transaction() as db:
            if db.execute("SELECT COUNT(*) FROM workspaces WHERE owner=?", (owner,)).fetchone()[0] >= 5:
                raise StoreError(403, "You can create up to five workspaces")
            try:
                db.execute("INSERT INTO workspaces VALUES(?,?,?,?,?)", (ident, owner, name, name_key, now))
            except sqlite3.IntegrityError:
                raise StoreError(409, "Workspace name is already in use") from None
            db.execute("INSERT INTO workspace_members VALUES(?,?,?,?,?)", (ident, owner, email, "admin", now))
        return {"id": ident, "owner": owner, "name": name, "role": "admin"}

    def workspace_people(self, workspace_id):
        with self.connect() as db:
            members = [dict(row) for row in db.execute("SELECT user_id,email,role,joined FROM workspace_members WHERE workspace_id=? ORDER BY joined", (workspace_id,))]
            invites = [dict(row) for row in db.execute("SELECT user_id,email,role,invited_by,created FROM workspace_invites WHERE workspace_id=? ORDER BY created", (workspace_id,))]
        return members, invites

    def workspace_invitations(self, user_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT i.workspace_id,i.email,i.role,i.invited_by,i.created,w.name FROM workspace_invites i JOIN workspaces w ON w.id=i.workspace_id WHERE i.user_id=? ORDER BY i.created DESC", (user_id,))]

    def invite_workspace(self, workspace_id, user_id, email, role, invited_by):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, invited_by)
            if db.execute("SELECT 1 FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone():
                raise StoreError(409, "This person is already a workspace member")
            if db.execute("SELECT 1 FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone():
                raise StoreError(409, "An invitation is already pending")
            count = db.execute("SELECT COUNT(*) FROM workspace_members WHERE workspace_id=?", (workspace_id,)).fetchone()[0] - 1
            count += db.execute("SELECT COUNT(*) FROM workspace_invites WHERE workspace_id=?", (workspace_id,)).fetchone()[0]
            if count >= 100:
                raise StoreError(403, "Workspace invitation limit reached")
            db.execute("INSERT INTO workspace_invites VALUES(?,?,?,?,?,?)", (workspace_id, user_id, email, role, invited_by, time.time()))

    def respond_workspace_invitation(self, workspace_id, user_id, accept):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).fetchone()
            if not row:
                raise StoreError(404, "Invitation not found")
            if accept:
                db.execute("INSERT INTO workspace_members VALUES(?,?,?,?,?)", (workspace_id, user_id, row["email"], row["role"], time.time()))
            db.execute("DELETE FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id))

    @staticmethod
    def _require_workspace_admin(db, workspace_id, actor):
        if actor is not None:
            row = db.execute("SELECT role FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, actor)).fetchone()
            if not row or row["role"] != "admin":
                raise StoreError(403, "Workspace admin access required")

    def revoke_workspace_invitation(self, workspace_id, user_id, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            if db.execute("DELETE FROM workspace_invites WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Invitation not found")

    def set_workspace_role(self, workspace_id, user_id, role, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            row = db.execute("SELECT owner FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            if not row or row["owner"] == user_id:
                raise StoreError(403, "The workspace owner's role cannot be changed")
            if db.execute("UPDATE workspace_members SET role=? WHERE workspace_id=? AND user_id=?", (role, workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Workspace member not found")

    def remove_workspace_member(self, workspace_id, user_id, *, actor=None):
        with self.transaction() as db:
            self._require_workspace_admin(db, workspace_id, actor)
            row = db.execute("SELECT owner FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
            if not row or row["owner"] == user_id:
                raise StoreError(403, "The workspace owner cannot be removed")
            if db.execute("DELETE FROM workspace_members WHERE workspace_id=? AND user_id=?", (workspace_id, user_id)).rowcount != 1:
                raise StoreError(404, "Workspace member not found")

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def create_api_key(self, tenant, record):
        from peaso.auth.api_keys import MAX_UNREVOKED_KEYS
        with self.transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM api_keys WHERE tenant=? AND revoked_at IS NULL", (tenant,)).fetchone()[0]
            if count >= MAX_UNREVOKED_KEYS:
                raise StoreError(429, "Revoke an unused API key before creating another")
            db.execute("INSERT INTO api_keys(id,tenant,secret_sha256,name,prefix,created_at,expires_at,revoked_at,last_used_at,cognito_username) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (record["id"], tenant, record["secret_sha256"], record["name"], record["prefix"], record["created_at"], record.get("expires_at"), None, None, record.get("cognito_username")))
        return dict(record, tenant=tenant, revoked_at=None, last_used_at=None)

    def api_key(self, key_id):
        with self.connect() as db:
            value = db.execute("SELECT * FROM api_keys WHERE id=?", (key_id,)).fetchone()
            return dict(value) if value else None

    def api_keys(self, tenant, after=None, limit=50):
        with self.connect() as db:
            rows = [dict(value) for value in db.execute("SELECT * FROM api_keys WHERE tenant=? AND id>? ORDER BY id LIMIT ?", (tenant, after or "", limit + 1))]
        return rows[:limit], rows[limit - 1]["id"] if len(rows) > limit else None

    def revoke_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            changed = db.execute("UPDATE api_keys SET revoked_at=? WHERE tenant=? AND id=? AND revoked_at IS NULL", (now, tenant, key_id)).rowcount
        if changed != 1:
            raise StoreError(404, "API key not found")

    def touch_api_key(self, tenant, key_id, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE api_keys SET last_used_at=? WHERE tenant=? AND id=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
                              (now, tenant, key_id, now)).rowcount == 1

    def workspace_external_id(self, tenant):
        """Allocate once, atomically, without deriving the ID from public names."""
        import secrets
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO workspace_external_ids VALUES(?,?)",
                       (tenant, "hacktricks-cspm-ws-" + secrets.token_urlsafe(48)))
            return db.execute("SELECT external_id FROM workspace_external_ids WHERE tenant=?", (tenant,)).fetchone()["external_id"]

    def ai_state(self, user, name):
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS ai_state (user TEXT, name TEXT, value TEXT, PRIMARY KEY(user,name))")
            row = db.execute("SELECT value FROM ai_state WHERE user=? AND name=?", (user, name)).fetchone()
            return row[0] if row else None

    def set_ai_state(self, user, name, value, expected=None):
        # Compare-and-swap serializes device polling and refresh-token rotation.
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS ai_state (user TEXT, name TEXT, value TEXT, PRIMARY KEY(user,name))")
            row = db.execute("SELECT value FROM ai_state WHERE user=? AND name=?", (user, name)).fetchone()
            if (row[0] if row else None) != expected:
                return False
            if value is None:
                db.execute("DELETE FROM ai_state WHERE user=? AND name=?", (user, name))
            else:
                db.execute("INSERT INTO ai_state VALUES(?,?,?) ON CONFLICT(user,name) DO UPDATE SET value=excluded.value", (user, name, value))
            return True

    def add_connector(self, tenant, data, encrypted_auth):
        value = dict(data, id=uuid.uuid4().hex, created_at=utc())
        with self.transaction() as db:
            db.execute("INSERT INTO connectors VALUES(?,?,?,?)", (value["id"], tenant, json.dumps(value), encrypted_auth))
        return value

    def connector(self, tenant, ident, db=None):
        if db is None:
            with self.connect() as connection:
                return self.connector(tenant, ident, connection)
        row = db.execute("SELECT * FROM connectors WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
        if not row:
            raise StoreError(404, "Connector not found")
        return dict(row)

    def connectors(self, tenant):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM connectors WHERE tenant=? ORDER BY rowid", (tenant,))]

    def update_connector(self, tenant, ident, patch, encrypted_auth=None):
        with self.transaction() as db:
            row = self.connector(tenant, ident, db)
            data = json.loads(row["data"])
            data.update(patch)
            db.execute("UPDATE connectors SET data=?,auth=? WHERE tenant=? AND id=?", (json.dumps(data), encrypted_auth or row["auth"], tenant, ident))

    def delete_connector(self, tenant, ident):
        with self.transaction() as db:
            self.connector(tenant, ident, db)
            db.execute("DELETE FROM connectors WHERE tenant=? AND id=?", (tenant, ident))
            # Retire schedules at deletion, while existing jobs retain their encrypted input.
            for row in db.execute("SELECT * FROM schedules WHERE tenant=?", (tenant,)).fetchall():
                if json.loads(row["data"])["connector_id"] == ident:
                    db.execute("DELETE FROM schedules WHERE id=? AND tenant=?", (row["id"], tenant))

    def _enqueue(self, db, tenant, request, limit, timeout, idem, now):
        digest = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if idem is not None:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND idem=?", (tenant, idem)).fetchone()
            if row:
                if row["digest"] != digest:
                    raise StoreError(409, "Idempotency key already used for a different request")
                return self.public_job(row)
        connector = self.connector(tenant, request["connector_id"], db)
        current = week(now)
        db.execute("INSERT INTO quota VALUES(?,?,0) ON CONFLICT DO NOTHING", (tenant, current))
        if db.execute("UPDATE quota SET used=used+1 WHERE tenant=? AND week=? AND used<?", (tenant, current, limit)).rowcount != 1:
            raise StoreError(429, "Weekly scan quota exhausted")
        ident = uuid.uuid4().hex
        encrypted_input = json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]})
        db.execute("INSERT INTO jobs(id,tenant,connector_id,data,connector,status,created,deadline,idem,digest,history,execution_timeout,queued_at) VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?)",
                   (ident, tenant, request["connector_id"], json.dumps(request), encrypted_input, now, now + QUEUE_WAIT_SECONDS, idem, digest, history({}, "queued", now), timeout, now))
        return self.public_job(db.execute("SELECT * FROM jobs WHERE id=?", (ident,)).fetchone())

    def enqueue(self, tenant, request, limit=1, timeout=900, idem=None, now=None):
        with self.transaction() as db:
            return self._enqueue(db, tenant, request, limit, timeout, idem, time.time() if now is None else now)

    def resume_job(self, tenant, ident, expected_connector, now=None, *, refresh=None):
        """Reset one recoverable row atomically; keep selectors and all evidence refs."""
        from peaso.server.scan_resume import resume_stage
        now = time.time() if now is None else now
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            from peaso.server.scan_resume import consume_section_refresh
            refresh_plan = consume_section_refresh(refresh, dict(row)) if refresh is not None else None
            stage = 'collector' if refresh_plan is not None else resume_stage(dict(row))
            if stage is None:
                raise StoreError(409, "This scan has no recoverable work")
            connector = self.connector(tenant, row["connector_id"], db)
            if (connector["data"] != expected_connector["data"]
                    or connector["auth"] != expected_connector["auth"]):
                raise StoreError(409, "Connector changed; check access and retry")
            status = "queued"
            db.execute("UPDATE jobs SET status=?,connector=?,deadline=?,queued_at=?,admitted_at=NULL,owner=NULL,lease=NULL,"
                       "resume_attempt=resume_attempt+1,resume_phase=?,native_refresh=?,"
                       "error=NULL,error_code=NULL,error_stage=NULL,progress_details=NULL,history=? "
                       "WHERE tenant=? AND id=?",
                       (status, json.dumps({"data": json.loads(connector["data"]), "auth": connector["auth"]}),
                        now + QUEUE_WAIT_SECONDS, now,
                        stage, json.dumps(refresh_plan) if refresh_plan is not None else None,
                        history(row, status, now), tenant, ident))
            return self.public_job(db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone())

    @staticmethod
    def public_job(row):
        value = dict(row)
        events = value.get("history", [])
        events = json.loads(events) if isinstance(events, str) else events
        error, reasons = public_failure(row["error"])
        result = dict(json.loads(row["data"]), id=row["id"], status=row["status"], created_at=utc(row["created"]), deadline_at=utc(row["deadline"]), admitted_at=utc(value["admitted_at"]) if value.get("admitted_at") is not None else None, error=error, error_code=value.get("error_code"), error_stage=value.get("error_stage"), timeline=events, updated_at=events[-1]["at"] if events else utc(row["created"]), input_mode=json.loads(row["connector"])["data"].get("input_mode", "live"), runtime=runtime_estimate(events), result_available=bool(value.get("report") or value.get("partial_report")))
        from peaso.server.scan_resume import resume_stage
        result["resumable"] = bool(resume_stage(value))
        if reasons:
            result["failure_reasons"] = reasons
        if value.get("progress_details"):
            result["progress_details"] = json.loads(value["progress_details"]) if isinstance(value["progress_details"], str) else value["progress_details"]
        return result

    def job(self, tenant, ident):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            return dict(row)

    def job_control(self, tenant, ident):
        """Fresh cancellation state without loading connector or report metadata."""
        with self.connect() as db:
            value = db.execute("SELECT status FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if value is None:
                raise StoreError(404, "Scan not found")
            return dict(value)

    def replace_completed_report(self, tenant, ident, expected_report, report):
        """Operator-only compare-and-swap; keep original runtime and job history."""
        with self.transaction() as db:
            cursor = db.execute("UPDATE jobs SET report=? WHERE tenant=? AND id=? AND status='completed' AND report=?",
                                (report, tenant, ident, expected_report))
            if cursor.rowcount != 1:
                raise StoreError(409, "Completed scan report changed")

    def record_checkpoint(self, tenant, ident, owner, sequence, reference, *, kind=None, scope=None,
                          report_ref=None, stage="collector", now=None):
        """Lease-fenced CAS for one public envelope or one partial report manifest."""
        from .artifacts import job_prefix
        now = time.time() if now is None else now
        if (type(sequence) is not int or sequence < 1 or not isinstance(reference, str)
                or not reference.startswith(job_prefix(tenant, ident))
                or report_ref is not None and (not isinstance(report_ref, str) or not report_ref.startswith(job_prefix(tenant, ident)))):
            raise ValueError("Invalid checkpoint reference or sequence")
        if stage not in {"collector", "analyzer_native"}:
            raise ValueError("Invalid checkpoint stage")
        if report_ref is None and (not isinstance(kind, str) or not isinstance(scope, str) or stage != "collector"):
            raise ValueError("Collection checkpoint needs native type and scope")
        with self.transaction() as db:
            row = db.execute("SELECT status,owner,lease,deadline,checkpoint_sequence,partial_report_sequence FROM jobs WHERE tenant=? AND id=?",
                             (tenant, ident)).fetchone()
            expected_status = "analyzing" if stage == "analyzer_native" else "collecting"
            if (not row or row["status"] != expected_status or row["owner"] != owner
                    or row["lease"] is None or row["lease"] <= now or row["deadline"] <= now):
                return False
            current = row["checkpoint_sequence"] or 0
            published = row["partial_report_sequence"] or 0
            if report_ref is None:
                if sequence <= current:
                    return False
                db.execute("INSERT INTO scan_checkpoint_collections(tenant,scan_id,kind,scope,sequence,reference) VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,scan_id,kind,scope) DO UPDATE SET sequence=excluded.sequence,reference=excluded.reference WHERE excluded.sequence>scan_checkpoint_collections.sequence",
                           (tenant, ident, kind, scope, sequence, reference))
                db.execute("UPDATE jobs SET checkpoint_sequence=? WHERE tenant=? AND id=?", (sequence, tenant, ident))
            else:
                if sequence <= published or (sequence <= current if stage == "analyzer_native" else sequence > current):
                    return False
                if stage == "analyzer_native":
                    db.execute("UPDATE jobs SET partial_snapshot=?,partial_report=?,partial_report_sequence=?,checkpoint_sequence=? WHERE tenant=? AND id=?",
                               (reference, report_ref, sequence, sequence, tenant, ident))
                else:
                    db.execute("UPDATE jobs SET partial_snapshot=?,partial_report=?,partial_report_sequence=? WHERE tenant=? AND id=?",
                               (reference, report_ref, sequence, tenant, ident))
            return True

    def checkpoint_collections(self, tenant, ident):
        self.job(tenant, ident)
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT kind,scope,sequence,reference FROM scan_checkpoint_collections WHERE tenant=? AND scan_id=? ORDER BY sequence", (tenant, ident))]

    @staticmethod
    def _stage_args(stage, data_revision, owner=None):
        if (not isinstance(stage, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,47}", stage)
                or type(data_revision) is not int or data_revision < 0
                or owner is not None and (not isinstance(owner, str) or not re.fullmatch(r"[a-f0-9]{32}", owner))):
            raise ValueError("Invalid progressive stage")

    def claim_stage(self, tenant, ident, stage, data_revision, owner, lease_seconds, now=None):
        """Claim one AI/section revision without touching the collector lease."""
        self._stage_args(stage, data_revision, owner)
        if lease_seconds <= 0:
            raise ValueError("Invalid progressive lease")
        now = time.time() if now is None else now
        with self.transaction() as db:
            job = db.execute("SELECT status,deadline,owner FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if (not job or job["status"] not in {"collecting", "collected", "analyzing"}
                    or job["deadline"] <= now or job["owner"] == owner):
                return False
            row = db.execute("SELECT data_revision,status,lease FROM scan_stage_results WHERE tenant=? AND scan_id=? AND stage=?",
                             (tenant, ident, stage)).fetchone()
            if row and (row["data_revision"] > data_revision or
                        row["data_revision"] == data_revision and (row["status"] == "completed" or (row["lease"] or 0) > now)):
                return False
            db.execute("INSERT INTO scan_stage_results(tenant,scan_id,stage,data_revision,status,owner,lease,result_ref) VALUES(?,?,?,?,'running',?,?,NULL) ON CONFLICT(tenant,scan_id,stage) DO UPDATE SET data_revision=excluded.data_revision,status='running',owner=excluded.owner,lease=excluded.lease,result_ref=NULL",
                       (tenant, ident, stage, data_revision, owner, now + lease_seconds))
            return True

    def heartbeat_stage(self, tenant, ident, stage, data_revision, owner, lease_seconds, now=None):
        self._stage_args(stage, data_revision, owner)
        if lease_seconds <= 0:
            raise ValueError("Invalid progressive lease")
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE scan_stage_results SET lease=? WHERE tenant=? AND scan_id=? AND stage=? AND data_revision=? AND status='running' AND owner=? AND lease>? AND EXISTS (SELECT 1 FROM jobs WHERE tenant=? AND id=? AND status IN ('collecting','collected','analyzing') AND deadline>?)",
                              (now + lease_seconds, tenant, ident, stage, data_revision, owner, now,
                               tenant, ident, now)).rowcount == 1

    def finish_stage(self, tenant, ident, stage, data_revision, owner, result_ref, now=None):
        from .artifacts import job_prefix
        self._stage_args(stage, data_revision, owner)
        if not isinstance(result_ref, str) or not result_ref.startswith(job_prefix(tenant, ident)):
            raise ValueError("Invalid progressive result reference")
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE scan_stage_results SET status='completed',owner=NULL,lease=NULL,result_ref=? WHERE tenant=? AND scan_id=? AND stage=? AND data_revision=? AND status='running' AND owner=? AND lease>? AND EXISTS (SELECT 1 FROM jobs WHERE tenant=? AND id=? AND status IN ('collecting','collected','analyzing') AND deadline>?)",
                              (result_ref, tenant, ident, stage, data_revision, owner, now,
                               tenant, ident, now)).rowcount == 1

    def stage_results(self, tenant, ident):
        self.job(tenant, ident)
        with self.connect() as db:
            return {row["stage"]: {"data_revision": row["data_revision"], "result_ref": row["result_ref"]}
                    for row in db.execute("SELECT stage,data_revision,result_ref FROM scan_stage_results WHERE tenant=? AND scan_id=? AND status='completed'",
                                          (tenant, ident))}

    def jobs(self, tenant, transform=None):
        with self.connect() as db:
            return [(transform or self.public_job)(row) for row in db.execute("SELECT * FROM jobs WHERE tenant=? ORDER BY created DESC", (tenant,))]

    def deletion_job(self, tenant, ident):
        return self.job(tenant, ident)

    def deletion_jobs(self, tenant):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,status,deadline FROM jobs WHERE tenant=?", (tenant,))]

    def delete_job(self, tenant, ident):
        with self.transaction() as db:
            row = db.execute("SELECT status,deadline FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] not in TERMINAL and row["deadline"] > time.time():
                raise StoreError(409, "Cancel the scan or wait for it to finish before deleting it")
            db.execute("DELETE FROM jobs WHERE tenant=? AND id=?", (tenant, ident))
            db.execute("DELETE FROM scan_checkpoint_collections WHERE tenant=? AND scan_id=?", (tenant, ident))
            db.execute("DELETE FROM scan_stage_results WHERE tenant=? AND scan_id=?", (tenant, ident))

    def usage(self, tenant, now=None):
        with self.connect() as db:
            row = db.execute("SELECT used FROM quota WHERE tenant=? AND week=?", (tenant, week(time.time() if now is None else now))).fetchone()
            return row["used"] if row else 0

    def get_entitlement(self, tenant):
        with self.connect() as db:
            row = db.execute("SELECT * FROM entitlements WHERE tenant=? AND expires>?", (tenant, time.time())).fetchone()
            return bool(row["paid"]) if row else None

    def set_entitlement(self, tenant, paid, seconds=3600):
        with self.transaction() as db:
            db.execute("INSERT INTO entitlements VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET paid=excluded.paid,expires=excluded.expires", (tenant, bool(paid), time.time() + seconds))

    def get_admin_qa_grant(self, tenant):
        with self.connect() as db:
            row = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            return dict(json.loads(row["record"]), rev=row["rev"]) if row else None

    def issue_admin_qa_grant(self, tenant, record, now=None, expected_predecessor=None):
        from peaso.auth.admin_qa import valid_issue
        now = time.time() if now is None else now
        if not valid_issue(record, tenant=tenant, now=now):
            raise StoreError(400, "Invalid administrator QA grant")
        if expected_predecessor is not None and (
                not isinstance(expected_predecessor, dict) or
                set(expected_predecessor) != {"audit_id", "rev"} or
                not isinstance(expected_predecessor["audit_id"], str) or
                type(expected_predecessor["rev"]) is not int or expected_predecessor["rev"] < 0):
            raise StoreError(400, "Invalid reviewed predecessor")
        with self.transaction() as db:
            previous = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            if expected_predecessor is None:
                if previous:
                    raise StoreError(409, "Prior administrator QA grant requires explicit review")
                rev = 0
            else:
                if not previous:
                    raise StoreError(409, "Reviewed predecessor is absent")
                prior = json.loads(previous["record"])
                revoked = type(prior.get("revoked_at")) in (int, float) and prior["revoked_at"] > 0
                expired = type(prior.get("hard_expires_at")) in (int, float) and prior["hard_expires_at"] <= now
                if (prior.get("audit_id") != expected_predecessor["audit_id"] or
                        previous["rev"] != expected_predecessor["rev"] or not (revoked or expired)):
                    raise StoreError(409, "Reviewed predecessor changed or remains active")
                rev = previous["rev"] + 1
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
            db.execute("INSERT INTO admin_qa_grant_events(audit_id,event,tenant,record) VALUES(?,?,?,?)",
                       (record["audit_id"], "issue", tenant, serialized))
            if previous:
                db.execute("UPDATE admin_qa_grants SET record=?,rev=? WHERE tenant=? AND rev=?",
                           (serialized, rev, tenant, previous["rev"]))
            else:
                db.execute("INSERT INTO admin_qa_grants(tenant,record,rev) VALUES(?,?,?)", (tenant, serialized, rev))
        return dict(record, rev=rev)

    def revoke_admin_qa_grant(self, tenant, audit_id, actor, reason, now=None):
        from peaso.auth.admin_qa import valid_actor
        now = time.time() if now is None else now
        if not valid_actor(actor) or not isinstance(reason, str) or not reason.strip():
            raise StoreError(400, "Valid revocation actor and reason required")
        with self.transaction() as db:
            old = db.execute("SELECT record,rev FROM admin_qa_grants WHERE tenant=?", (tenant,)).fetchone()
            if not old:
                raise StoreError(404, "Administrator QA grant not found")
            value = json.loads(old["record"])
            if value.get("audit_id") != audit_id or value.get("revoked_at") is not None:
                raise StoreError(409, "Administrator QA grant changed")
            value.update(revoked_at=now, revoked_by=actor, revoke_reason=reason.strip())
            serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
            next_rev = old["rev"] + 1
            db.execute("UPDATE admin_qa_grants SET record=?,rev=? WHERE tenant=? AND rev=?",
                       (serialized, next_rev, tenant, old["rev"]))
            db.execute("INSERT INTO admin_qa_grant_events(audit_id,event,tenant,record) VALUES(?,?,?,?)",
                       (audit_id, "revoke", tenant, serialized))
        return dict(value, rev=next_rev)

    def cancel(self, tenant, ident):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] not in TERMINAL:
                db.execute("UPDATE jobs SET status='cancelled',owner=NULL,lease=NULL,history=? WHERE tenant=? AND id=?", (history(row, "cancelled", time.time()), tenant, ident))
        return self.public_job(self.job(tenant, ident))

    def queued_jobs(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY queued_at,id")]

    def admit(self, tenant, ident, now=None):
        """Reserve one of ten global scan slots under the SQLite write lock."""
        now = time.time() if now is None else now
        self.expire(now)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row or row["status"] != "queued":
                return False
            if row["admitted_at"] is not None:
                return True
            older = db.execute("SELECT 1 FROM jobs WHERE status='queued' AND admitted_at IS NULL AND (queued_at<? OR (queued_at=? AND id<?)) LIMIT 1", (row["queued_at"], row["queued_at"], ident)).fetchone()
            occupied = db.execute("SELECT COUNT(*) FROM jobs WHERE admitted_at IS NOT NULL AND status NOT IN ('completed','failed','cancelled','timed_out','queue_exhausted','credentials_expired')").fetchone()[0]
            if older or occupied >= SCAN_CAPACITY:
                return False
            db.execute("UPDATE jobs SET admitted_at=?,deadline=? WHERE tenant=? AND id=? AND status='queued'",
                       (now, now + row["execution_timeout"], tenant, ident))
            return True

    def expire(self, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            for row in db.execute("SELECT * FROM jobs WHERE deadline<=? AND status NOT IN ('completed','failed','cancelled','timed_out','queue_exhausted','credentials_expired')", (now,)).fetchall():
                if row["status"] == "queued" and row["admitted_at"] is None:
                    db.execute("UPDATE jobs SET status='queue_exhausted',error='Queue exhausted: no scan slot became available within one hour',error_code='queue_exhausted',error_stage='queue',history=? WHERE id=?", (history(row, "queue_exhausted", now), row["id"]))
                    continue
                stage = "collector" if row["status"] in {"queued", "collecting"} else "analyzer"
                db.execute("UPDATE jobs SET status='timed_out',owner=NULL,lease=NULL,error='Scan deadline exceeded',error_code='deadline_exceeded',error_stage=?,history=? WHERE id=?", (stage, history(row, "timed_out", now), row["id"]))

    def expire_job(self, tenant, ident, now=None):
        """Expire only the addressed job under the same lock as its status read."""
        now = time.time() if now is None else now
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Scan not found")
            if row["status"] in TERMINAL or row["deadline"] > now:
                return False
            if row["status"] == "queued" and row["admitted_at"] is None:
                return db.execute("UPDATE jobs SET status='queue_exhausted',error='Queue exhausted: no scan slot became available within one hour',error_code='queue_exhausted',error_stage='queue',history=? WHERE tenant=? AND id=? AND deadline<=? AND status='queued' AND admitted_at IS NULL",
                                  (history(row, "queue_exhausted", now), tenant, ident, now)).rowcount == 1
            stage = "collector" if row["status"] in {"queued", "collecting"} else "analyzer"
            return db.execute("UPDATE jobs SET status='timed_out',owner=NULL,lease=NULL,error='Scan deadline exceeded',error_code='deadline_exceeded',error_stage=?,history=? WHERE tenant=? AND id=? AND deadline<=? AND status=?",
                              (stage, history(row, "timed_out", now), tenant, ident, now, row["status"])).rowcount == 1

    def claim(self, role, lease_seconds=30, now=None, tenant=None, ident=None):
        if role not in {"collector", "analyzer"}:
            raise ValueError("Unknown worker role")
        if ident is not None and tenant is None:
            raise ValueError("Tenant required for targeted claim")
        now = time.time() if now is None else now
        ready, active = ("queued", "collecting") if role == "collector" else ("collected", "analyzing")
        if ident is not None:
            self.expire_job(tenant, ident, now)
        else:
            self.expire(now)
        with self.transaction() as db:
            query = "SELECT * FROM jobs WHERE deadline>? AND (status=? OR (status=? AND lease<=?))"
            args = [now, ready, active, now]
            if ident is not None:
                query += " AND tenant=? AND id=?"
                args += [tenant, ident]
            row = db.execute(query + " ORDER BY queued_at,id LIMIT 1", args).fetchone()
            if not row:
                return None
            if role == "collector" and row["admitted_at"] is None:
                occupied = db.execute("SELECT COUNT(*) FROM jobs WHERE admitted_at IS NOT NULL AND status NOT IN ('completed','failed','cancelled','timed_out','queue_exhausted','credentials_expired')").fetchone()[0]
                older = db.execute("SELECT 1 FROM jobs WHERE status='queued' AND admitted_at IS NULL AND (queued_at<? OR (queued_at=? AND id<?)) LIMIT 1", (row["queued_at"], row["queued_at"], row["id"])).fetchone()
                if occupied >= SCAN_CAPACITY or older:
                    return None
                db.execute("UPDATE jobs SET admitted_at=?,deadline=? WHERE id=?", (now, now + row["execution_timeout"], row["id"]))
            owner = uuid.uuid4().hex
            db.execute("UPDATE jobs SET status=?,owner=?,lease=?,history=? WHERE id=?", (active, owner, now + lease_seconds, history(row, active, now), row["id"]))
            return dict(db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def heartbeat(self, ident, owner, lease_seconds=30, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            return db.execute("UPDATE jobs SET lease=? WHERE id=? AND owner=? AND lease>? AND deadline>? AND status IN ('collecting','analyzing')", (now + lease_seconds, ident, owner, now, now)).rowcount == 1

    def record_progress(self, ident, owner, event, now=None):
        from peaso.progress import sanitize_event
        now = time.time() if now is None else now
        cleaned = sanitize_event(event)
        cleaned.pop("scope", None)
        if not cleaned:
            return False
        cleaned["at"] = utc(now)
        try:
            with self.transaction() as db:
                return db.execute("UPDATE jobs SET progress_details=? WHERE id=? AND owner=? AND lease>? AND deadline>? AND status IN ('collecting','analyzing')",
                                  (json.dumps(cleaned), ident, owner, now, now)).rowcount == 1
        except Exception:
            return False

    def finish(self, ident, owner, status, artifact=None, now=None, error_code="processing_failed", failure_reasons=None):
        now = time.time() if now is None else now
        if status not in {"collected", "completed", "failed", "credentials_expired"}:
            raise ValueError("Invalid worker transition")
        previous = "collecting" if status == "collected" else "analyzing" if status == "completed" else None
        field = "snapshot" if status in {"collected", "credentials_expired"} else "report"
        with self.transaction() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND owner=? AND lease>? AND deadline>?", (ident, owner, now, now)).fetchone()
            if not row or row["status"] not in {"collecting", "analyzing"} or (previous and row["status"] != previous):
                return False
            if status in {"failed", "credentials_expired"}:
                allowed = {"processing_failed", "invalid_input", "credential_access_denied", "dependency_unavailable", "provider_error", "collector_timeout", "artifact_error", "worker_interrupted", "credentials_invalid"}
                error_code = ("credentials_expired" if status == "credentials_expired" else
                              error_code if error_code in allowed else "processing_failed")
                stage = "collector" if row["status"] == "collecting" else "analyzer"
                error = ("Connector credentials expired during the scan. Update them, then resume this scan or start a new one."
                         if status == "credentials_expired" else
                         INVALID_CREDENTIALS_FAILURE if error_code == "credentials_invalid" and not curated_failure_reasons(failure_reasons) else
                         failure_error(failure_reasons))
                if status == "credentials_expired" and artifact is not None:
                    db.execute("UPDATE jobs SET status=?,snapshot=?,error=?,error_code=?,error_stage=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (status, artifact, error, error_code, stage, history(row, status, now), ident, owner))
                else:
                    db.execute("UPDATE jobs SET status=?,error=?,error_code=?,error_stage=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (status, error, error_code, stage, history(row, status, now), ident, owner))
            else:
                db.execute(f"UPDATE jobs SET status=?,{field}=?,history=?,owner=NULL,lease=NULL WHERE id=? AND owner=?", (status, artifact, history(row, status, now), ident, owner))
            return True

    @staticmethod
    def public_schedule(row):
        return dict(json.loads(row["data"]), id=row["id"], enabled=bool(row["enabled"]), next_run_at=utc(row["next_run"]), last_error=row["last_error"])

    def schedules(self, tenant):
        with self.connect() as db:
            return [self.public_schedule(row) for row in db.execute("SELECT * FROM schedules WHERE tenant=?", (tenant,))]

    def add_schedule(self, tenant, data, next_run, enabled=True):
        with self.transaction() as db:
            self.connector(tenant, data["connector_id"], db)
            ident = uuid.uuid4().hex
            db.execute("INSERT INTO schedules VALUES(?,?,?,?,?,NULL)", (ident, tenant, json.dumps(data), next_run, enabled))
            return self.public_schedule(db.execute("SELECT * FROM schedules WHERE id=?", (ident,)).fetchone())

    def update_schedule(self, tenant, ident, patch, next_run=None, enabled=None):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM schedules WHERE tenant=? AND id=?", (tenant, ident)).fetchone()
            if not row:
                raise StoreError(404, "Schedule not found")
            data = dict(json.loads(row["data"]), **patch)
            self.connector(tenant, data["connector_id"], db)
            if next_run is None and (set(patch) & {'rules', 'timezone', 'interval_hours'} or enabled is True and not row['enabled']):
                from peaso.scheduling import next_run as following_run
                next_run = following_run(data, time.time())
            db.execute("UPDATE schedules SET data=?,next_run=?,enabled=?,last_error=NULL WHERE tenant=? AND id=?", (json.dumps(data), row["next_run"] if next_run is None else next_run, row["enabled"] if enabled is None else enabled, tenant, ident))
            return self.public_schedule(db.execute("SELECT * FROM schedules WHERE id=?", (ident,)).fetchone())

    def delete_schedule(self, tenant, ident):
        with self.transaction() as db:
            if db.execute("DELETE FROM schedules WHERE tenant=? AND id=?", (tenant, ident)).rowcount != 1:
                raise StoreError(404, "Schedule not found")

    def pause_schedule(self, tenant, ident, *, reason="Schedule disabled: identity is no longer eligible"):
        with self.transaction() as db:
            db.execute("UPDATE schedules SET enabled=0,last_error=? WHERE tenant=? AND id=?", (reason, tenant, ident))

    def due_schedules(self, now=None):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (time.time() if now is None else now,))]

    def trigger_schedule(self, row, limit=1, timeout=900, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            current = db.execute("SELECT * FROM schedules WHERE tenant=? AND id=? AND enabled=1 AND next_run=? AND next_run<=?", (row["tenant"], row["id"], row["next_run"], now)).fetchone()
            if not current:
                return None
            data = json.loads(current["data"])
            request = {k: data[k] for k in ("connector_id", "categories", "checks", "content_checks", "leaks_enabled", "images_enabled", "frameworks", "ai_enabled", "ai_priorities_enabled", "ai_network_enabled", "ai_user_id") if k in data}
            error, result = None, None
            # Savepoint ensures a rejected enqueue never partially reserves quota.
            db.execute("SAVEPOINT scheduled_enqueue")
            try:
                result = self._enqueue(db, row["tenant"], request, limit, timeout, f"schedule:{row['id']}:{row['next_run']}", now)
            except StoreError as exc:
                db.execute("ROLLBACK TO scheduled_enqueue")
                error = exc.message
            db.execute("RELEASE scheduled_enqueue")
            from peaso.scheduling import next_run as following_run
            db.execute("UPDATE schedules SET next_run=?,last_error=? WHERE id=? AND tenant=?", (following_run(data, now), error, row["id"], row["tenant"]))
            return result

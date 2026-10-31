# Disposable QA resources

These helpers belong to the supervised integration dispatch recorded in
`docs/testing.md` ("Testing against real clouds"). They deliberately pin its authorized accounts,
subscription, task and existing Cognito pool. They are not general cloud cleanup
commands and contain no wildcard deletion or administrator grants.

Create a private 0700 working directory and a 0600 JSON ledger **before** any
creation. The cloud session ledger contains `schema_version: 1`,
`task_id: task_02a312b5ac1f`, `dispatch_id: ctx_e2284cf3ad99`, and
`resources: []`. Use separate ledger files for concurrent fixture sessions; a
cleanup command owns all active records in its own ledger.

- `session.py aws` creates a private empty encrypted bucket, an unattached VPC
  and a security group with no ingress. `session.py azure` creates a tagged
  dedicated group, NSG and VNet with a recorded private subnet. Both require an
  in-session command and remove exact ledger resources in `finally`.
- `session.py audit-role` creates a uniquely named AWS SecurityAudit role with
  an exact collector-principal condition and external ID. `hold_audit_role.py`
  provides the bounded release watchdog. No access keys are created.
- `session.py cleanup --ledger PATH` repeats exact ownership/tag/identity checks
  and verifies absence. It refuses buckets containing unexpected objects,
  groups with unledgered resources and roles with unexpected policies/profiles.
- `update_audit_trust.py` changes only the owned temporary role's external ID
  to the server-generated connector value, preserving its exact principal.
- `local_k8s_session.py` creates a unique tagged Docker network and localhost
  kind cluster with inert restricted workloads, performs a real CLI scan,
  and removes the exact cluster/network/private kubeconfig. It does not prove
  GKE coverage or actual NetworkPolicy enforcement.
- `cognito_probe.py` reads only existing pool/client prerequisite metadata.
  `cognito_session.py` must run inside the authorized `assume wiki --exec`
  session, verifies account before each write, creates only suppressed new free
  fixture users, authenticates them through the existing client, and finally
  globally signs out/deletes exact email/sub/native-username matches. Passwords
  and tokens are stored only in a private file and removed on release.
- `live_scan.py` records collection/evaluation/serialization wall time and
  exact snapshot reevaluation. `--raw-all` exercises every native collector type
  directly; default mode exercises the engine dependency plan.
- `cli_roundtrip.py` freezes one consistent code build, runs a fresh CLI scan,
  and compares its report with offline evaluation using absent cloud credential
  configuration files. JSON, Markdown and sanitized summaries stay private.
- `default_aws_gate.py` runs the exact unfiltered default AWS CLI command in a
  frozen defensive build, measures phases without altering inventory requests,
  and verifies the same-session account before the specifically authorized
  IAM credential-report metadata generation. Live helpers refuse the primary
  research checkout while supplied privilege-chain code/hooks remain there.
- `hosted_acceptance.py` uses the three real owned free subjects for AWS,
  large Azure and cancellation/isolation tests. It requires the real deployed
  CSPM, ledger-owned customer role and short-lived authorized Azure credentials.
  Its tenant-data ledger is written before HTTP writes. No paid entitlement is
  fabricated, and administrative user creation does not establish public
  Turnstile registration acceptance.
- `hosted_fixture_guard.py` runs hosted tests within an inert Azure fixture
  session, retains a bounded UI inspection window and cancels active owned jobs
  before invoking `hosted_data_cleanup.py` in `finally`. The cleanup helper
  records and removes only exact test-subject DynamoDB keys and exact owned-job
  S3 keys, verifies absence, and never deletes tables/buckets/infrastructure.
- `compose_cleanup_guard.py` owns only the unique QA Compose project and
  verifies containers, volumes and network disappear when released.
- `cancel_compose_session.py` creates a separate fresh free API-only Compose
  fixture for deterministic queued cancellation and schedule CRUD. It never
  changes the primary or hosted quota/entitlement and removes its own state,
  identity, containers and network in `finally`.

The private directory uses `release-audit-role`, `release-cognito` and
`release-compose` marker files to release the corresponding bounded guards.
Cloud resources, identities and hosted tenant records must be verified absent
before reporting final completion. Existing infrastructure, identities and
other tenants are outside these ledgers and must never be deleted.

# Privilege escalation analysis

The privilege escalation (privesc) analysis answers one question: **which identities could gain
more power than they have now, and how?** It combines a catalog of known techniques with the
permissions found in the snapshot and builds a graph of possible escalation steps.

Like all analysis, it runs offline on the snapshot. It never tries a technique and never calls
a provider.

## What counts as privilege escalation

The rules are in `peaso/privesc/catalog_policy.yaml`. A technique belongs in the catalog only if
a source principal's permissions (or a credential it controls) allow a concrete action that:

- gives it another known principal's usable credentials, tokens or execution context, or
- grants the source new effective permissions, with the exact newly authorized action named.

"Principal" includes cloud users, roles, service accounts, managed identities, application,
database and device identities. Reading a configuration or a secret is **exposure**, not
privilege escalation, unless the exact credential and the principal it belongs to are proven.

## The technique catalog

Techniques are YAML files under `peaso/privesc/catalog/<provider>/<service>.yaml` for AWS, GCP,
Azure and Kubernetes. Files whose names start with `_excluded` record techniques that were
reviewed and rejected, with the reason. The JSON Schema is
`peaso/privesc/privesc-technique.schema.json`.

A technique entry:

```yaml
- id: aws-iam-createpolicyversion-self
  provider: aws
  service: iam
  title: Create a new default version of a customer-managed policy attached to the source
  source: src/pentesting-cloud/aws-security/aws-privilege-escalation/aws-iam-privesc/README.md#iamcreatepolicyversion
  summary: The source can obtain administrator privileges by rewriting a customer-managed policy attached to itself.
  requires:
    all_of:
      - action: iam:CreatePolicyVersion
        resource: "{source.attached_policy_arn}"
  target:
    kind: aws_account_admin
    scope: same_account
    aggregate_as: "Administrator of {account} (self-escalation)"
  preconditions: [source_boundary_allows_account_admin]
  blockers: [scp_or_boundary_deny]
  severity: critical
  mitigation: ...
```

Required fields: `id`, `provider`, `service`, `title`, `source`, `summary`, `requires`,
`target`, `severity`, `mitigation`. Optional fields include `source_revision`, `source_kind`,
`preconditions`, `conditions` (documented caveats), `blockers` (what stops the path, such as an
SCP or permission boundary deny), `confidence`, `references` and `notes`.

`requires` is a tree of `all_of` / `any_of` permission requirements with placeholders bound to
the source and target. `target.kind` names what the source gains (another principal, an admin
of an account/project/subscription, a cluster admin, and so on).

## How the evaluator works

`peaso.privesc.analyze(snapshot, related_snapshots=...)` returns findings, a graph, coverage and
stats:

1. A provider **model** (`effective_permissions/aws.py`, `gcp.py`, `azure.py`, `k8s.py`) works
   out each principal's effective permissions from the snapshot: identity and resource
   policies, role bindings, inherited grants, conditions, boundaries and SCPs/deny policies.
2. Technique-specific modules in `effective_permissions/` add exact evidence for techniques that
   need more than a permission match (for example which identity a workload runs as).
3. The **evaluator** (`evaluator.py`) matches every technique against every principal and
   creates edges `source → target`. It repeats until nothing changes (a fixpoint), so gained
   permissions can unlock further edges.
4. Each edge carries a **confidence**: `derived` (all evidence present), `conditional`
   (depends on a documented condition) or `unknown` (some evidence missing). A chained path
   takes the weakest confidence of its edges.

`related_snapshots` lets one provider's analysis join with another's. For example, a Kubernetes
snapshot plus the snapshot of the cloud account that hosts the cluster can show paths from a
pod's service account into cloud identities. On the CLI use `--related-snapshot PATH`.

## Queries and views

`peaso/privesc/queries.py` answers the questions the UI and API need:

- `reach_admin`: principals that can reach an admin-equivalent target, up to 6 steps.
- `shortest_paths`: the shortest paths from one principal to a target.
- `broad_reach`: principals that can reach many other principals.
- `principal_card`: one principal's paths and findings.

The API exposes these under `/api/scans/{id}/privesc/admins`, `/paths`, `/broad`,
`/principals` and `/api/scans/{id}/graphs/privesc/subgraph`. The web app's
**Privilege Escalation Map** page draws them.

## Limits

- Paths are based on **declared** permissions in the snapshot. They show what the configuration
  could allow, not that anyone used it.
- Missing inventory (denied or partial reads) makes affected edges `unknown` instead of hiding them.
- Some conditions (for example runtime context or external systems) cannot be read from
  configuration; these appear as `conditional`.

## Keeping the catalog in sync with HackTricks Cloud

The catalog is shared with the HackTricks Cloud book under `src/privilege-escalation-paths/`.

```bash
# validate the local catalog (optionally verify source paths against a HackTricks checkout)
python scripts/peaso_validate_privesc_catalog.py --hacktricks-root ../hacktricks-cloud --permissions

# pull reviewed upstream changes (three-way merge against the last sync)
python scripts/sync_hacktricks_privesc.py --book-root ../hacktricks-cloud --check

# export the local catalog into the book layout
python scripts/export_privesc_catalog.py --book-root ../hacktricks-cloud --check
```

Use `--check` first to see what would change. `export_privesc_catalog.py` only removes upstream
files with `--prune`.

## Best practices

- Add a technique only when it meets the catalog policy; record rejected ideas in an `_excluded` file.
- Always list `blockers` so deny policies and boundaries remove false paths.
- Prefer exact evidence modules over broad permission matches for workload-identity techniques.
- Run the validator before every catalog change and keep a behaviour test with a realistic snapshot.
- Read `conditional` and `unknown` paths as leads to confirm, not as proven escalation.

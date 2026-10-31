# Collectors

Collectors are the only part of PEASO CSPM that talks to cloud providers. They turn
credentials, scopes and options into a snapshot. This page explains how they work and how to
extend them.

## Flow

1. `engine.plan_collection(request)` works out which resource **types** the selected checks,
   analysis and privesc models need. Only those types are read. Types that were not needed are
   recorded in the snapshot metadata as `omitted_inventories`.
2. `collectors.collect_live(connector, requirements)` loads `peaso.collectors.<provider>` and
   passes it to `bulk_evidence.collect`, which calls the provider module's
   `collect(connector, requirements)`.
3. The provider module reads each type in each scope and appends one **envelope** per
   (type, scope).
4. The collector builds the snapshot with `make_snapshot` and the metadata records
   `"collection": "read-only"`, call counts and any limits you set.

## Provider modules

| Module | Type registry | Notes |
| --- | --- | --- |
| `collectors/aws.py` | `SPECS` (type → service, operation, result path), `GLOBAL_TYPES`, `AWS_TYPES` | boto3; account-global types (IAM, S3 buckets, Organizations) are read once per account |
| `collectors/gcp.py` | `SUPPORTED_TYPES` | Google REST APIs with google-auth |
| `collectors/azure.py` | `TYPES` | ARM, Microsoft Graph and data-plane endpoints; injectable `transport` for tests |
| `collectors/k8s.py` | `TYPES` | Kubernetes API; injectable `api` for tests |

`collectors.supported_types(provider)` returns the full type list without credentials or
network calls.

## Envelopes and statuses

Each envelope has `type`, `scope`, `service`, `status`, `items` and, when relevant, `error`.

| Status | Meaning |
| --- | --- |
| `collected` | Read succeeded and returned items |
| `empty` | Read succeeded and there were no items |
| `partial` | Some items were read, then an error or a limit stopped the read |
| `denied` | The provider refused the read (for example AccessDenied, Forbidden) |
| `timeout` | The read timed out |
| `malformed` | The provider response could not be parsed |
| `unknown` | Any other failure |

Checks rely on this distinction. A missing or failed envelope makes dependent checks report
`UNKNOWN` (or `DENIED`), never `PASS`.

## Scopes

- **AWS**: account IDs or `account/region`. Regions can also come from the `regions` option.
  Cross-account collection needs explicit `assume_roles` in the auth object or the
  `organization_role_name` option.
- **GCP**: project IDs. Options such as `discover_projects`, `all_projects`,
  `allowed_projects` and `project_restrictions` control project discovery. Hosted connectors
  need exact project IDs.
- **Azure**: subscription IDs; tenant-level Entra ID data is read with Graph.
- **Kubernetes**: the cluster (from kubeconfig, context or inline server) and optional namespaces.

## Options and limits

Collection options come from `--options-file`, the request's `connector.options`, or the web
app connector form. Common ones:

| Option | Meaning |
| --- | --- |
| `regions` | AWS regions to read |
| `max_pages`, `max_resources`, `max_calls` | Hard limits; reaching one marks envelopes `partial` with a limit error code |
| `concurrency`, `service_concurrency`, `scope_concurrency`, `region_concurrency` | Parallelism |
| `retries`, `page_size` | Retry count and page size |
| `activity_days`, `log_entry_minutes` | How far back to read activity and log data |
| `inventories` | Explicit inventory selection |
| `trusted_scope_ids`, `trusted_domains` | Extra trusted scopes/domains for trust analysis (see [network-and-exposure.md](network-and-exposure.md)) |
| `content_secret_scans`, `image_vulnerability_scans`, `selected_*` | Optional content and image scans (see [secrets-and-images.md](secrets-and-images.md)) |

The server rejects unknown option keys (`peaso/server/validation.py`, `OPTIONS`). Hosted mode
caps parallelism and windows: `concurrency` ≤ 4, `service_concurrency` ≤ 32,
`scope_concurrency` ≤ 2, `region_concurrency` ≤ 2, `retries` ≤ 5, `page_size` ≤ 1000,
`activity_days` ≤ 90, `log_entry_minutes` ≤ 1440.

The AWS collector retries throttling errors with capped exponential backoff and uses a single
attempt for other errors so that denied reads fail fast.

## Per-scan caches

Several checks often need the same raw response. Collectors keep **scan-local** caches:

- AWS: a single-flight request cache in `aws.py`, so concurrent identical calls run once.
- GCP and Azure: bounded caches in `collectors/scan_cache.py`.
- Kubernetes: `collectors/k8s_response_cache.py`.

These caches live only for one scan, have memory budgets, and never store transient errors, so
a retry can still succeed.

## Cancellation and deadlines

Collection honours a cancel event and a deadline. The CLI exits with `130` on Ctrl-C. In the
server, `POST /api/scans/{id}/cancel` stops the scan. Workers checkpoint completed sections so a scan can be resumed
(`POST /api/scans/{id}/resume`).

## Adding a resource type

1. Add the type to the provider module. For simple AWS list/describe calls this is one `SPECS`
   entry: `"my_type": ("service", "describe_things", "Things")`.
2. Make sure items get a stable resource ID.
3. Add the needed read action to the customer role policy if it is not already covered by
   `ReadOnlyAccess` or `SecurityAudit`.
4. Declare the type in the `dependencies` of the checks that need it, so planning collects it.
5. Add a behaviour test that uses a stubbed client or transport, never live credentials.

## Best practices

- Only use read APIs in collectors; never call APIs that return secret values for the core scan.
- Always record a status for every planned (type, scope), including failures.
- Prefer explicit scopes and limits in automation so scan cost and duration are predictable.
- Do not catch and hide errors as `empty`; a denied read must stay `denied`.
- Keep caches scan-scoped; never share cloud responses across tenants or scans.

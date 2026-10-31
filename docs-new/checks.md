# Native checks

Native checks are small, deterministic functions that look at one resource (or one scope) in a
snapshot and return a status plus evidence. They never call a cloud provider. This page explains
how they work, what the statuses mean, how to write one, and how to write the observed evidence
shown to users.

## Where checks live

| Path | Content |
| --- | --- |
| `peaso/checks/__init__.py` | The `Check` dataclass, the `register` decorator, `result`/`unknown` helpers, the `CHECKS` list and check aliases. Provider modules are imported here so they register on import. |
| `peaso/checks/<provider>_*.py` | Provider check modules (AWS, GCP, Azure, Kubernetes) |
| `peaso/checks/facts.py` | Strict fact accessors: `get`, `optional`, `list_of_objects`, `guard`, `complete_items`, memoized indexes, and `field_check` |
| `peaso/checks/fixtures.py` | `CASES`: pass/fail/unknown/missing/malformed fixtures per check |
| `peaso/checks/k8s_managed.py` | Handling for provider- or control-plane-managed Kubernetes objects |
| `peaso/checks/*_evidence_explanations.*` | Per-provider observed-evidence text |
| `peaso/analysis/` | Cross-resource "analysis checks" (exposure, coverage, principal exposure, federated trust) |
| `peaso/rulepacks/` | Static metadata: native catalog, descriptions, remediation text, framework mappings |

To see every check with its metadata, run `peaso catalog` or call `GET /api/catalog` and
`GET /api/catalog/checks/{id}`.

## Check metadata

Each check is registered with:

| Field | Meaning |
| --- | --- |
| `id` | Stable dotted ID, for example `aws.iam.root_mfa` |
| `provider` | `aws`, `gcp`, `azure` or `k8s` |
| `category` | `hardening`, `exposure`, `least_privilege`, `iam_graph` or `network` |
| `kind` | The snapshot resource type the check evaluates |
| `title`, `severity`, `control`, `remediation` | Display data; severity is `critical`, `high`, `medium`, `low` or `info` |
| `target` | `resource` (one result per item) or `scope` (one result per account/project/subscription/cluster) |
| `dependencies` | Extra resource types the check needs; planning collects them |
| `allow_incomplete_failure` | Whether a FAIL is still valid when some inventory is incomplete |
| `empty_applicability_dependencies` | For scope checks: which dependencies being empty means "not applicable" |

Retired IDs that were exact duplicates stay resolvable through `alias_check(retired, survivor)`,
so stored scans, diffs and selections keep working.

## Statuses

| Status | Meaning |
| --- | --- |
| `PASS` | Recorded evidence shows the setting meets the check |
| `FAIL` | Recorded evidence shows the setting does not meet the check |
| `UNKNOWN` | Evidence needed to decide is missing, partial or malformed |
| `DENIED` | The read needed for the evidence was refused |
| `MANUAL` | The requirement needs human review; no automatic decision |
| `NOT_APPLICABLE` | The check does not apply to this resource |
| `EMPTY` | The resource type was read successfully and no resources exist |

Two safety rules are built into the registry:

- If a check raises `Unavailable` (missing fact, unavailable collection, malformed coverage) or
  a common parsing error, the result becomes `UNKNOWN`. An absent fact is never treated as safe.
- Checks can only return the statuses above with a dictionary of evidence; anything else is an error.

By default reports keep `NOT_APPLICABLE` and `EMPTY` as per-check counts in
`finding_aggregates`. Use `--include-not-applicable` to keep every row.

## Selecting checks

The CLI, the API and the scan form accept the same selectors:

- `--categories`: one or more categories from the catalog.
- `--checks`: native check IDs, `privesc` for all privilege-escalation techniques, or
  individual privesc technique IDs.
- `--frameworks`: `hacktricks` (HackTricks Cloud Best Practices), `nist_800_53`, or a full
  framework name from the catalog (see [compliance.md](compliance.md)).

Selectors are validated by `peaso/server/validation.validate_selectors`. Only the resource types
the selected checks need are collected.

## Writing a check

A minimal resource check:

```python
from peaso.checks import register, result
from peaso.checks.facts import get

@register(
    "aws.example.bucket_versioning",
    "aws", "hardening", "bucket",
    "S3 bucket versioning is enabled",
    "medium", "CP-9",
    "Enable versioning on the bucket.",
)
def bucket_versioning(item, index):
    status = get(item, "versioning.Status", str)
    return result(status != "Enabled", versioning_status=status)
```

Notes:

- Read every fact with `facts.get` (or `optional` when absence is a real, meaningful state).
  `get` raises `Unavailable` on missing facts and on coverage markers that are not `collected`
  or `empty`, so the check becomes `UNKNOWN` automatically.
- Put recorded values into the evidence (`result(failed, **evidence)`). These values feed the
  observed-evidence text.
- Use `unknown(reason, **evidence)` when the evidence exists but is not enough to decide.
- For one-field checks, `field_check(check_id, provider, kind, path, good, bad, title, ...)`
  registers the check and its fixture spec in one call.
- Use the `index` argument (and `MemoIndex` / `memoized` helpers) for joins across resources,
  so large snapshots stay fast.
- Add the module import to `peaso/checks/__init__.py` so it registers.
- Add fixture cases to `fixtures.CASES` and a behaviour test that proves PASS, FAIL and UNKNOWN
  for real inputs. Do not add tests that only pin names, hashes or strings.

## Observed evidence

Every finding shows a short **observed evidence** text that explains what was found on the
resource. The rules below come from the project's `AGENTS.md` and apply to every AWS, GCP,
Azure and Kubernetes check, for every status.

1. Write 3 to 5 short lines, with one plain sentence per line.
2. Start with the setting, value or condition actually found on the resource. Use recorded
   evidence; never invent a finding from the check result alone.
3. Explain what that finding may allow to happen, then why it matters to people or their data.
4. Use simple English. Keep technical terms only when they name the setting, resource or action
   needed to understand the finding.
5. Make the lines read as one connected explanation.
6. Use "may" or "could" for possible outcomes that were not observed. Never claim access,
   reachability, a breach or harm without evidence.
7. Talk about the resource, not about the check, scan, assessment, result or review process.
   Do not say what a check did not show, test, prove or assess. For an unknown result, name the
   missing recorded fact and explain why the setting is unclear.
8. Do not add fix instructions, generic control descriptions or a repeat of the check title.
9. Use the same structure for pass, fail, unknown and other results. For incomplete evidence,
   name the exact missing setting or the risk left unclear. Avoid stock lines such as "the
   current setting is unclear" without naming the setting.
10. Match the impact to the exact setting recorded. A declared path, rule, port, role or Secret
    reference does not by itself prove the file works, traffic reaches it, access is granted,
    or harm occurred.

Example for a FAIL:

```text
Bucket "billing-exports" has versioning set to Suspended.
Objects that are overwritten or deleted may not keep an earlier copy.
A mistake or a malicious delete could remove billing records for good.
```

Example for an UNKNOWN:

```text
The versioning status of bucket "billing-exports" was not recorded.
Without that value, it is unclear whether earlier copies of objects are kept.
Billing records could be lost after a delete if versioning is off.
```

The text is produced per provider by `peaso/checks/<provider>_evidence_explanations.py` and
selected in `peaso/finding_observation.evidence_summary`. Privilege-escalation findings have
their own explanation modules in `peaso/privesc/`.

## Best practices

- Never return `PASS` when a fact is missing; let `facts.get` raise and produce `UNKNOWN`.
- Keep checks pure: no network, no clock-dependent logic without recorded timestamps, no global state.
- Record the exact values you used to decide in the evidence dictionary.
- Declare all extra resource types in `dependencies` so planning collects them.
- Follow the observed-evidence rules for every status, not only for failures.
- Test behaviour with realistic pass, fail and unknown inputs; avoid change-detector tests.

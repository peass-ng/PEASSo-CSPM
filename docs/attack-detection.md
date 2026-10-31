# Attack detection

Attack detection reads a bounded window of cloud audit logs with a connector's read-only access
and runs detection rules over the events. It is separate from posture scanning: posture checks
look at configuration, attack detection looks at what happened.

The code lives in `peaso/attack_detection/` (normalizers and rules) and in the server modules
`attack_logs.py`, `gcp_attack_logs.py`, `azure_attack_logs.py` and `entra_attack_logs.py`.

## Supported log sources

| `kind` | Source | Extra fields |
| --- | --- | --- |
| `aws_event_history` | CloudTrail event history (`LookupEvents`) | `region`, optional `role_arn` |
| `aws_cloudtrail_s3` | CloudTrail log files delivered to S3 | `region`, `bucket`, `prefix`, `day` |
| `gcp_audit` | Cloud Audit Logs | `project_id` |
| `gke_audit` | GKE / Kubernetes audit logs | `project_id`, `cluster_id` |
| `azure_activity_log` | Azure Activity Log | `subscription_id` |
| `entra_directory_audit` | Entra ID directory audit log | `tenant_id` |

Reads are bounded (for example, at most 5 S3 objects, 10 MB compressed, 2,000 events and 40
lookup pages per AWS run) so a run is quick and cheap.

## Flow

1. `POST /api/attack-analysis/check-access` with the connector and source. The server confirms
   the logs can be read and returns a `check_token`.
2. `POST /api/attack-analysis/run` with the same source and the `check_token`. The server reads
   the events, normalizes them into a common shape, and runs the rules.
3. The response lists the coverage of what was read and the detections, each with the evidence
   events that matched.

The web app's **Attack Detection** page drives this flow.

## Rules

Rules use a small, portable subset of Sigma: `logsource`, `detection` with exact field
equality, OR lists, AND within one selection, and `condition: selection`. Anything else fails
when the rules are loaded, so a rule can never silently match too much. Some techniques also have
Python correlators that join several events (for example a change followed by its use).

Rule source:

- Rules come from the public GitHub repository `peass-ng/peasso-cspm-detections`.
- `catalog_mode: latest` (the API default) resolves the repository's `main` branch to a commit
  at access-check time; the run then reuses that exact commit and rule digest, so the rules
  cannot change between check and run.
- `catalog_mode: pinned` uses a commit and SHA-256 digest fixed in the code.
- For pinned mode, `HACKTRICKS_CSPM_RULES_GITHUB_REPO` and `HACKTRICKS_CSPM_RULES_GITHUB_REF`
  point at another repository and ref, and `HACKTRICKS_CSPM_RULES_PACK_SHA256` sets the expected
  digest. `HACKTRICKS_CSPM_RULES_DIR` loads `*.yml` rules from a local directory (local auth mode only).

## Reading results

A detection means events matched a rule pattern. It is a lead for investigation, not proof of
an attack: administrators often perform the same actions on purpose. No detection means no
rule matched in the window that was read; it does not mean nothing happened.

## Best practices

- Use a short, recent window first, then widen it if you need more history.
- Confirm every detection with the actor, time and change it describes before acting.
- Use `pinned` mode when you need repeatable results across runs; `latest` picks up new rules.
- Grant log-read access only to the identity that runs detection, and only for the sources you use.

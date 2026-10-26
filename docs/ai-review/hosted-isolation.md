# Hosted agent isolation

The supported hosted backend is `PEASO_AI_RUNTIME=fargate`. It runs each Hardening,
Exposure, Network or Priorities invocation in a separate Fargate task. Priorities
still starts after all reviewers finish. The AWS deployment admits up to six
concurrent tasks, subject to analyzer memory headroom. Each task uses 0.5 vCPU /
2 GiB. The 3,000-second AI phase budget includes task startup and is bounded by
the scan deadline less a final-publication reserve (at most 300 seconds); about
30% (at most 600 seconds) is reserved for priorities, which may use up to
1,500 seconds of what remains. The analyzer task shares the workflow’s one-hour ceiling; the
collector retains its 30-minute stage limit. Absolute task deadlines leave time for result upload and shutdown. The remaining
invocation budget also sets the inner agent wrapper’s runtime budget; the
parent process and relay enforce the absolute deadline. An ECS failure before
the agent starts can retry once within the remaining phase budget. Each attempt
cleans up its task and transport objects. Completed agent output is collected as
soon as its container stops successfully, with task cleanup requested before
returning. Each agent validates output against its original local references
and can make one corrective pass within the same invocation deadline. The
backend independently validates the final output. Manual/unknown network and
privilege-escalation evidence can support an explicitly qualified review action;
Hardening/Exposure recommendations still require confirmed FAIL reviews.

## Boundaries

- The task has **no task role**. Its dedicated execution role can pull the worker
  image from the selected ECR repository and write to the AI log group. ECS
  does not expose execution-role credentials to the containers. ECS Exec is disabled.
- AI tasks run in their own ECS cluster. The analyzer can run the pinned AI task
  definition and stop tasks in that cluster, without permission to stop the
  collector or analyzer tasks in the scan cluster.
- Agent and relay containers have separate default PID namespaces and distinct
  writable `/tmp` volumes. Root filesystems are read-only; both run as UID/GID
  10001 with all Linux capabilities dropped. No host/platform mounts or secrets.
- The analyzer checks the resolved task definition before staging inputs or
  launching it. A task role, shared PID namespace, secret/env injection, shared
  scratch, root user or mutable image causes failure before launch.
- Only the relay receives a short-lived presigned URL for its bootstrap object.
  That object contains the model token and exact input/result object URLs.
  **The agent never receives the real Codex token or any S3 transport URLs.**
- The relay exposes only its own bounded input, result upload, and fixed Codex
  response/model routes on task-local loopback. Arbitrary upstream URLs, OAuth,
  account APIs, cookies, redirects and raw upstream errors are not forwarded.
  The agent's Codex auth file holds a task-local relay capability in JWT shape.
- Codex 0.147.0 uses a named `cspm-relay` provider with Responses HTTP streaming
  and WebSockets disabled. Built-in `openai` provider overrides are rejected by
  that version. Chack's direct cache transport is disabled to prevent bypassing
  the relay; the real installed CLI and Chack have a local fake-SSE regression.
- The dedicated AI subnet/SG/NACL permits public HTTPS and Kubernetes 6443 and
  denies private/link-local/CGNAT egress. AWS-reserved metadata/DNS are not reliably
  controlled by NACLs; the metadata credential boundary relies on **no task role**,
  separate container PID/filesystems, and no platform credentials in the task.
- AWS credentials are not sent to agents, including for older scans. AWS review
  uses captured evidence. Other eligible customer cloud credentials for the
  assigned batch remain in `credentials.json`, so customers must grant the
  documented read permissions. Public cloud egress is permitted; network
  isolation does not restrict the actions granted by those credentials.
- Shared hosted GCP service-account tokens are withheld, including derived GKE
  tokens: selected projects do not constrain that identity's actual permissions.
  Those scans still run all agents using captured evidence. Customer-provided
  credentials retain live verification. Older GCP credential envelopes are not
  exported; rescan to capture customer-owned access under the current policy.

The analyzer deletes three transport objects and calls StopTask when an invocation
ends, fails or times out. The relay also exits at the absolute invocation deadline,
which stops the essential task if the parent dies. Bucket lifecycle deletes
abandoned objects after one day. Inputs use a bounded flat regular-file archive;
symlinks, traversal and model-auth/result injection are rejected. Results are
bounded to 8 MB, parsed, then checked by the existing stage schemas/contracts and
redacted before publication. Logs do not include prompts, credentials, signed
URLs or provider error bodies; model HTTP failures log only numeric status.

## Deployment wiring

`infra/aws/ai_runtime.tf` defines the dedicated AI cluster, execution role,
log group, task, private AES256 transport bucket, cleanup policy, analyzer
dispatch permissions and `local.ai_runtime_env`. The analyzer and API capability environments include that map. The S3 gateway
endpoint policy allows exact transport bucket object Get/Put/Delete. The runtime
uses its dedicated AI subnet and security group. The API needs no ECS task
launch privileges. `DescribeTaskDefinition` requires `Resource: "*"` because AWS
does not support resource-level authorization for that API; its region is limited.
RunTask is restricted to the exact task revision and cluster; PassRole permits only
the execution role. [AWS service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecs.html).

Before collection, the worker applies `ai_access.may_capture_live(connector)`.
It suppresses AWS sessions and shared hosted GCP identities, including Kubernetes
credentials derived from that GCP identity. Old AWS entries are also filtered
before agent dispatch. Live access for these identities requires a future
read-only, scope-bound broker or a customer-owned delegated identity.

No pass-through local launcher is used. Missing configuration, unsafe task
definition, failed transfer, unavailable capacity, model refusal or malformed
output still fails closed and preserves deterministic findings.

## Release verification

Mocked unit tests do not establish deployed compatibility. Before declaring hosted
AI ready, the release owner must run the isolated live smoke **after deployment**:

```sh
python -m peaso.worker analyzer --ai-smoke
```

Run it with the deployed analyzer's `local.ai_runtime_env`, its own AWS identity,
and the configured operator Codex secret ARN. This explicitly incurs a real model
call. It sends a tiny local fixture through the same role-free task/relay path and
requires the model to use its shell/file tool to recover a random marker, correct
the finding to PASS and include that marker. Only success metadata is printed.
It then runs an offline native snapshot through all four deployed agents and
requires completed reviewer results, Network and Priorities output. It does not
read customer clouds or write tenant scan artifacts. Authenticated hosted scans
should additionally be checked for the expected published AI sections.

Verify the actual task has no task role, private PID namespaces, separate scratch,
the pinned image digest and dedicated AI subnet/SG. Confirm task exit/StopTask and
transport cleanup, and review sanitized CloudWatch statuses if the smoke fails.
Do not substitute a successful mocked run for this deployment acceptance.

Local pinned CLI/Chack compatibility test (fake model, no paid API calls):

```sh
PEASO_TEST_CODEX_BIN=/path/to/pinned/codex \
  .venv/bin/python -m pytest tests/test_peaso_ai_fargate.py -q
```

The provider routing keys follow Codex's documented custom provider configuration;
compatibility is checked against the pinned binary, not assumed from newer docs.
[Codex configuration reference](https://developers.openai.com/codex/config-reference/).

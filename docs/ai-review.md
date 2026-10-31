# AI review

AI review is an **optional** layer on top of the deterministic results. It reads the finished
native evidence and adds two things:

- **Network Architecture**: a model-written review of the network layout and its risks.
- **Top 15 Actions**: a prioritized list of the most useful changes, ordered by what to do first.

Native results never wait for AI and are never changed by it. The code lives in `peaso/ai/`.

## Rules the AI layer follows

- **Native verdicts are final.** Hardening and exposure results come from native checks only;
  the model does not add, remove or change a `PASS`/`FAIL`.
- **AI errors never discard deterministic results.** If a stage fails or times out, the scan
  keeps all native results and the AI section shows its error.
- **Captured evidence first.** Agents read the captured report, snapshot metadata and inventory
  through a local context tool, and never receive found secret values.
- **Limited live access.** For AI-enabled GCP, Azure and Kubernetes scans, the collector can
  capture the already-resolved session tokens it used (never passwords, private keys or SDK
  credential chains), encrypt them, and hand them to the isolated agents so they can confirm
  details with the same read-only access. AWS scans and the shared GCP
  `platform-service-account` method never get live access; those agents use captured evidence only.
- **Progressive display.** The web app shows native results first; each AI section appears when
  its stage finishes.

## Stages

| Stage | Runs when | Output |
| --- | --- | --- |
| `network` | The scan includes the `network` category and `ai_network_enabled` is not false | Network architecture review (validated against `network.schema.json`) |
| `priorities` | `ai_priorities_enabled` is not false | Top actions (validated against `recommendations.schema.json`); also runs `network` first |

Agent definitions are YAML files in `peaso/ai/agents/` (`network.yaml`, `priorities.yaml`, plus
`hardening.yaml` and `exposure.yaml`, which are kept but not used for model calls because those
results are native-final). Each defines a system prompt, the model alias (`OPENAI_BEST_QUALITY`)
and the thinking effort (`high`). Model output is validated against a JSON schema before it is
stored.

Turn AI on or off per scan with `ai_enabled`, `ai_network_enabled` and `ai_priorities_enabled`
in `POST /api/scans`, or per user in **Settings** (`/api/ai/preferences`).

## Model providers and credentials

Supported providers: `codex`, `openai`, `anthropic`, `anthropic_token` and `openrouter`.
Thinking effort can be `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max`.

Ways to provide a credential:

- **Personal Codex sign-in** from Settings: a device login against `auth.openai.com`
  (`POST /api/ai/codex/login`, then `/api/ai/codex/login/poll`).
- **AI configuration** in Settings (`/api/ai/configuration`, `/api/ai/configuration/validate`):
  provider, model, effort and API key or token.
- **Environment** on the analyzer: `CODEX_ACCESS_TOKEN`, or `CODEX_TOKEN_SECRET_ARN` (a
  Secrets Manager secret holding a token or JSON with `access_token`).

AI credentials are encrypted with a key separate from connector credentials
(`PEASO_AI_ENCRYPTION_KEY` or `PEASO_AI_CREDENTIAL_SECRET_ARN`; otherwise a key file under the
identity directory's `ai/` folder).

## Isolation

Agents can run shell commands to explore the evidence, so they must run in an isolated
environment. Without isolation the AI stages refuse to run (`ai_isolation_unavailable`). There
are two options:

1. **Local launcher**: set `PEASO_AI_ISOLATION_LAUNCHER` to an absolute path of an executable
   owned by root or the worker user and not writable by others. It is called as
   `LAUNCHER --workspace DIR -- EXECUTABLE ARG...` and must provide a private PID namespace, no
   inherited descriptors or platform identity, the workspace as the only scan-specific mount,
   and a network policy that blocks platform metadata and internal services.
2. **Fargate runtime** (hosted): set `PEASO_AI_RUNTIME=fargate` and the
   `PEASO_AI_FARGATE_CLUSTER`, `_TASK_DEFINITION`, `_SUBNETS`, `_SECURITY_GROUPS` and `_BUCKET`
   variables. Each scan's AI stages run in a separate, role-free Fargate task in its own subnet,
   and evidence moves through a dedicated transport bucket.

## Limits

- `PEASO_AI_TIMEOUT_SECONDS`: per-scan AI time budget (default 300 seconds locally, 600 with the Fargate runtime).
- `PEASO_AI_MAX_CONCURRENCY`: how many AI reviews run at once on an analyzer (default 2; at most 6 locally, 12 with Fargate).

## Best practices

- Treat AI output as advice to review, not as findings; the native results are the record.
- Always run AI in a real isolation boundary; a temporary directory is not a sandbox.
- Use a dedicated model credential with spending limits for the scanner.
- Keep AI credentials and connector credentials under different encryption keys, as the code does by default.
- If a stage keeps timing out, raise `PEASO_AI_TIMEOUT_SECONDS` before narrowing the scan.

# Getting started

This page shows the shortest paths to a first result: a demo scan, a real CLI scan, and the
local web app.

## Requirements

- Python 3.10 or newer (the container images use Python 3.12).
- For live scans: the `cloud` extra, which installs the AWS, Google, Azure and Kubernetes SDKs.
- For secret scanning: the `secrets` extra (Kingfisher) and, for full coverage, the TruffleHog binary on `PATH`.
- For image CVE scanning: the Trivy binary.
- For the web app: Docker with Compose, or Node.js 22 if you build the frontend yourself.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[cloud]'          # live collection SDKs
pip install -e '.[cloud,secrets]'  # add secret scanning
pip install -e '.[test]'           # test dependencies
```

Other extras: `ai` (AI review runtime), `hosted` (AWS hosted mode), `analytics` (DuckDB).

The package installs two equivalent commands, `peaso` and `hacktricks-cspm`. You can also run
`python -m peaso`.

## First scan with the demo data

Demo mode uses a fixed, built-in sample. It makes no cloud calls and needs no credentials.

```bash
peaso scan --demo --provider aws --format markdown -o demo-report.md
peaso scan --demo --provider gcp -o demo-report.json
```

Open the Markdown report to see the summary, counts by status and category, findings and the
stated limitations.

## Real CLI scans

The CLI uses the provider's normal default credentials unless you pass an auth file.

```bash
# AWS: one account in two regions, using a named profile
peaso scan --provider aws --profile audit --scopes 123456789012/us-east-1 123456789012/eu-west-1 \
  --snapshot-output aws-snapshot.json -o aws-report.json

# GCP: one project, Application Default Credentials
peaso scan --provider gcp --scopes my-project-id -o gcp-report.json

# Azure: one subscription, Azure CLI / default credential chain
peaso scan --provider azure --scopes 00000000-0000-0000-0000-000000000000 -o azure-report.json

# Kubernetes: a kubeconfig context
peaso scan --provider k8s --context my-cluster -o k8s-report.json
```

Useful options:

| Option | Meaning |
| --- | --- |
| `--scopes` | Accounts (`account/region` for AWS), projects, subscriptions, or cluster namespaces to read |
| `--auth-file` | JSON/YAML auth object (for example `{"method": "assume_role", "role_arn": "...", "external_id": "..."}`); `-` reads JSON from stdin |
| `--options-file` | JSON/YAML collection options (regions, limits, content scans) |
| `--request` | Full scan request containing a `connector` object |
| `--categories`, `--checks`, `--frameworks` | Limit what is evaluated (see [checks.md](checks.md)) |
| `--snapshot-output` | Save the collected snapshot for later offline use |
| `--format json\|markdown`, `-o` | Output format and file |
| `--include-not-applicable` | Keep per-resource `NOT_APPLICABLE` and `EMPTY` rows |
| `--embed-native` | Emit report schema 1.0 with native items embedded (larger) |
| `--related-snapshot PATH` | Add another provider's snapshot for cross-provider privesc joins (repeatable) |
| `--quiet` | No progress messages on stderr |

Exit codes: `0` success, `2` error, `3` when nothing could be read with the given credentials,
`130` (or `128 + signal`) when cancelled.

### Work offline with snapshots

```bash
peaso collect --provider aws --profile audit --scopes 123456789012/us-east-1 --snapshot-output snap.json
peaso evaluate snap.json -o report.json              # evaluate again, no cloud calls
peaso scan --snapshot snap.json --checks privesc     # only privilege escalation
peaso report report.json -o report.md                # render a saved report as Markdown
peaso diff old-report.json new-report.json           # what changed between two reports
peaso catalog --format markdown -o catalog.md        # categories, checks and frameworks
```

## Local web app with Docker Compose

```bash
cp .env.example .env
chmod 600 .env
docker compose up --build -d --wait
docker compose exec api cat /var/lib/peaso/identity/local.token
```

Open <http://127.0.0.1:8000> and paste the token. The stack has three services:

- `api`: FastAPI server and the built frontend, bound to `127.0.0.1` only.
- `collector`: worker that reads from cloud providers.
- `analyzer`: worker that evaluates snapshots and runs optional AI stages.

All containers run read-only, drop Linux capabilities and run as an unprivileged user. Data
lives in the `state`, `identity` and `ai-identity` volumes. `docker compose down -v` deletes all
local data, including saved connectors and the local token.

In the UI, add a connector (provider, auth method, scopes), run its access check, then start a
scan. Native results appear as soon as each part finishes.

## Running the server without Docker

```bash
pip install -e '.[cloud,secrets]'
python -m peaso.server               # API on 127.0.0.1:8000 (PEASO_BIND, PEASO_PORT)
python -m peaso.worker collector     # in a second terminal
python -m peaso.worker analyzer      # in a third terminal
```

State goes to `.peaso/state` and identity files (local token, encryption keys) to
`.peaso/identity`. To serve the UI from the same origin, build the frontend and copy
`frontend/dist` to `peaso/frontend_dist`, or run the Vite dev server (see [frontend.md](frontend.md)).

## Best practices

- Learn the output with `--demo` first; it is fast and needs no credentials.
- Always save snapshots for real scans so you can re-evaluate, filter and diff without new reads.
- Scope scans explicitly with `--scopes`; do not rely on whatever the default credential can see.
- Keep `.env` at mode `600` and never commit it.
- Keep the local server on loopback; put it behind proper authentication before exposing it.

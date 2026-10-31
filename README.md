# PEASS'o CSPM

Open-source, read-only cloud security posture management for **AWS, Google Cloud, Azure and Kubernetes**, built by HackTricks.

Use the [hosted application](https://cspm.hacktricks.wiki/) or run the same engine locally with the `peaso` CLI or the local web app.

## What it does

- Collects provider configuration with read-only API calls and saves it as an immutable snapshot.
- Evaluates that snapshot offline: hardening, exposure, identity, least-privilege and network checks.
- Groups results under compliance frameworks (review aids, not certifications).
- Maps declared privilege-escalation paths and internet exposure.
- Optionally scans selected content for secrets and container images for CVEs, adds AI review, and runs audit-log detections.

`UNKNOWN`, `DENIED` and partial evidence are never treated as a pass. Relationship maps do not prove effective access or live reachability.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[cloud]'

# Offline demo: no credentials, no cloud calls
peaso scan --demo --provider aws --format markdown -o demo-report.md

# Live scan with an existing AWS profile
peaso scan --provider aws --profile audit --scopes 123456789012/us-east-1 \
  --snapshot-output snapshot.json -o report.json

# Re-evaluate a saved snapshot without cloud calls
peaso evaluate snapshot.json --format markdown -o report.md
```

Run the local web app with `docker compose up --build -d --wait` and open <http://127.0.0.1:8000>. See [Getting started](docs/getting-started.md) for all providers and options.

## Documentation

Start at [docs/README.md](docs/README.md). Main pages:

| Topic | Page |
| --- | --- |
| Install, first scan, local web app | [getting-started.md](docs/getting-started.md) |
| Read-only access each provider needs | [permissions.md](docs/permissions.md) |
| Code layout, data flow, snapshots | [architecture.md](docs/architecture.md) |
| Collectors, checks, compliance | [collectors.md](docs/collectors.md) · [checks.md](docs/checks.md) · [compliance.md](docs/compliance.md) |
| Privilege escalation, network exposure | [privesc.md](docs/privesc.md) · [network-and-exposure.md](docs/network-and-exposure.md) |
| Secrets, images, AI, detections | [secrets-and-images.md](docs/secrets-and-images.md) · [ai-review.md](docs/ai-review.md) · [attack-detection.md](docs/attack-detection.md) |
| Web app, API, configuration | [frontend.md](docs/frontend.md) · [api.md](docs/api.md) · [configuration.md](docs/configuration.md) |
| Hosted AWS deployment, testing | [hosted-deployment.md](docs/hosted-deployment.md) · [testing.md](docs/testing.md) |

The original Blue-CloudPEASS IAM/RBAC report scripts (`Blue-AWSPEAS.py`, `Blue-GCPPEAS.py`, `Blue-AzurePEAS.py`, `Blue-K8sPEAS.py`) are still included; run any of them with `--help`.

## License

PEASS'o CSPM is licensed under **GNU AGPL v3 or later**; see [LICENSE](LICENSE). Network operators of modified versions must offer the corresponding source of the running version as required by section 13. Third-party dependencies, reference data and assets retain their own licenses and notices.

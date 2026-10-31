# Secret scanning and image vulnerabilities

Besides configuration checks, PEASO CSPM can look **inside** selected content for leaked
secrets and can scan selected container images for known vulnerabilities (CVEs). Both are
optional and only run on targets you select.

## Secret scanning

### Engines

`peaso/secret_scanning.py` runs two detectors on the same content and merges the results:

- **Kingfisher** 1.4.0 (Python package from the `secrets` extra).
- **TruffleHog** 3.92.5 (binary; installed in the collector image).

Detection is offline: Kingfisher runs in-process through its SDK, and TruffleHog runs with
`--no-verification` and `--no-update`, so found secrets are not tested against live services.
Input size and finding counts are capped (64 MB of input and 5,000 findings per scan unit) to
keep scans bounded.

### What content can be scanned

Content scans cover places where secrets often leak, for example:

- Configuration: Lambda environment variables, ECS task definitions, Azure App Service and
  Function settings, App Configuration values, Kubernetes manifests and ConfigMaps.
- Code and build: function packages, build specs, Cloud Build and CodeBuild definitions,
  source repository files, Dataform and Databricks notebooks and files.
- Logs and outputs: sampled CloudWatch, Log Analytics, Application Insights and Kubernetes pod logs.
- Container images: layers of selected images in ECR, Artifact Registry, ACR and other registries.

Each surface is enabled by the `content_secret_scans` option and narrowed with a matching
`selected_*` option (for example `selected_aws_lambda_functions`,
`selected_k8s_log_samples`, `selected_artifact_images`). Image and registry selections require
exact, immutable references such as `sha256:` digests. The server rejects selections that are
not exact. Each surface also needs its own read permission (see [permissions.md](permissions.md)).

In the web app scan form, the **Leaks** switch (`leaks_enabled` in `POST /api/scans`) turns
content secret scanning off for one scan even if the connector enables it.

### How secret values are handled

Found secrets are shown in clear text to people who are allowed to see the scan. To make that
safe, the value takes a separate, protected path:

1. The collector finds a match and correlates repeated values with a random, process-local HMAC
   key. The key never leaves the collector process, so values cannot be linked across scans.
2. The matched value is stored as **private secret evidence**, encrypted with the same key that
   protects connector credentials (`peaso/secret_evidence.py`).
3. The public finding and the snapshot carry only redacted data. Secret values never enter
   native observations, reports' public fields, AI input or logs.
4. The analyzer worker never has the decryption key.
5. `GET /api/scans/{id}/findings/{finding_id}` returns the decrypted value as
   `secret_evidence` to an authorized workspace user, with `Cache-Control: private, no-store`.

On the CLI, outputs never contain secret values unless you pass `--include-secret-values`,
which only works for fresh live scans written to a JSON `--output` file you own.

Worker child processes run with their output suppressed, and API failure logs record only the
exception class and location, so secret material does not end up in logs.

## Image vulnerability scanning

`image_vulnerability_scans` plus a selection option (for example
`selected_aws_image_vulnerabilities`, `selected_azure_acr_image_vulnerabilities`,
`selected_gcp_registry_image_vulnerabilities`, `selected_gke_pod_images`,
`selected_azure_aks_pod_images`, `selected_k8s_registry_images`) scans the listed images with
**Trivy** in the collector. Images are identified by immutable digest. Registry credentials,
when needed, are given separately in the connector auth (`registry_auth`) and bound to the
allowed registry hosts (`selected_registry_hosts`).

Results are presented by `peaso/image_findings.py` and served by:

- `GET /api/scans/{id}/image-findings`
- `GET /api/scans/{id}/image-findings/{finding_id}/assets`

The web app shows them on the **Images CVEs** page. The **Images** switch (`images_enabled`)
turns image scanning off for one scan.

Trivy's database and binary location are runtime settings of the collector, not scan options;
requests that try to set them are rejected.

## Best practices

- Select only the content you need to scan; every selected surface is an extra read permission.
- Use immutable image digests, never tags, so results match exactly what runs.
- Limit who can open finding details, because they show secret values in clear text.
- Rotate any credential found by a scan, even if the resource looks unused.
- Do not use `--include-secret-values` in shared pipelines; store such files with strict permissions and delete them after use.

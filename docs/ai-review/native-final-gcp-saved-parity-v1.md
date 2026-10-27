# GCP native-final saved review parity v1

The [numeric receipt](native-final-gcp-saved-parity-v1.json) binds four
completed production GCP scans to SHA-256 hashes of their private pre-AI and
final reports. The report bytes remain outside the repository under
`~/peaso-work/native-final-gcp-private/` (mode 0600). No finding evidence or
resource names are included in the receipt.

Read-only discovery used `AWS_PROFILE=wiki`, with AWS credential environment
variables unset, against DynamoDB table `hacktricks-cspm` in `us-east-1`.
The consistent query was `PK = tenant/d48824c8-5021-7029-7c47-9c55bf99e58f`
and `begins_with(SK, job/)`, projected to status, connector, snapshot, report,
and partial report references. It returned 50 jobs, four completed GCP jobs.
S3 listings used bucket `hacktricks-cspm-artifacts-202533532952` and each
scan prefix under `artifacts/0ea2296509f9ccab54e6ba279fb10f73fe1e2e8513ef846ee2421357930b255a/`.
The final and partial report manifests supplied their respective `report_json`
references. Each downloaded report pair has provider `gcp` and one matching
snapshot ID; the final report's AI status is `completed`.

The four scans yielded 23 eligible native FAIL observations in the 12 source
reviewed scalar checks. Four IDs had observations: `gcp.compute.secure_boot`
(6), `gcp.gke.secrets_encryption` (5), `gcp.network.custom_subnets` (6), and
`gcp.reviewed.compute.deletion_protection` (6). All 23 had the exact saved AI
review `{verdict: FAIL, reason: ""}`, matched their expected typed failing
field value, and retained status, severity, base severity, evidence, and
evidence summary in the final report. The scan with ID starting `1504c3e6`
had no eligible candidate observation or Hardening AI review. The other eight
source reviewed scalar IDs remain `retain_ai` because they were unobserved.

This proves saved review parity for the four observed checks on these scans.
It does not prove a current hosted model quality or cost gate, or establish
parity for other GCP workloads. The receipt remains `saved_parity_only`; GCP
native-final runtime admission is unchanged and inactive. GCP Hardening AI
continues to run.

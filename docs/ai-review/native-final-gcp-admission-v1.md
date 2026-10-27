# GCP native-final admission candidate v1

The separate GCP gate in `peaso/ai/gcp_native_final.py` selects four checks
with exact source and saved review proof. Its versioned manifest is
`peaso/ai/gcp_native_final_allowlist.json`. Admission requires the GCP enable
switch, the exact manifest SHA-256 pin, source hashes, and a qualified hosted
receipt. The committed manifest has `pending_hosted`, so it admits zero checks
even if the enable switch and manifest pin are supplied. AWS admission is
unchanged.
The gate's hosted receipt pin is also unset in code; root must verify and pin
the hosted receipt, qualify the manifest, and explicitly enable it in a later
reviewed change.

The gate selects only GCP Hardening native FAIL observations whose recorded
field path, type, and failing value match the reviewed source. Other statuses,
incomplete dependencies, and unbound evidence continue to AI. Pipeline
partitioning emits synthetic `{finding_id, verdict: FAIL, reason: ""}` rows
for selected findings and sends only the remainder to Hardening AI. Priorities
receives the complete original Hardening and Exposure finding set and combined
reviews.

The [offline replay](native-final-gcp-offline-replay-v1.json) uses four private,
same-snapshot pre-AI/final GCP report pairs. It substituted 23 selected
reviews, leaving 721 Hardening AI input IDs across the four scans. All
synthetic review rows matched the saved AI rows exactly. Priorities finding
and review ID sets were unchanged. The replay projected every original
finding through the existing review application code and matched the saved
final status, severity, base severity, evidence, evidence summary, and, for
remaining AI rows, review metadata. Final-only findings were retained. The
saved action lists and their references were preserved; no model generated
new actions in this replay. This is an offline parity gate, not a hosted cost
or quality replay.

For a later comparable production scan, the [baseline recipe](native-final-gcp-baseline-recipe-v1.json)
records completed GCP scan `0864235ed9db4305a594e55bf8bceb82`, connector
`9433af297c084a3b82bb4e7544904203`, canonical request SHA-256
`ae30080f709475b4b264384c59da5ab5cd5493ce4ca6afcd841a5080a097160f`,
the exact request selection, and queued, Collect, Analyze, and completion
timestamps from a strongly consistent DDB job read. A rerun would need root
dispatch after deployment; this audit started no scan.

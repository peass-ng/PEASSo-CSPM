Optional Lambda public pipeline review — 2026-10-19

Existing ID: `aws.review.lambda_function.package_content_secret_indicators`. Eight focused tests passed with botocore 1.43.38; no failures, runtime defects or proposed source changes.

The real public planner binds the named check and explicit opt-in, then calls collect_live and aws.collect. Native Stubber responses feed real Requests, in-memory ZIP/HTTP projection, successful shared request Futures and the existing registered evaluate_snapshot callback; no expected snapshot fields are injected.

Kingfisher SDK 1.4.0 and TruffleHog 3.92.5 run their installed offline detection adapters without mocks. Kingfisher uses scan_input only; TruffleHog uses stdin with verification, updates and verification caching disabled. No live cloud/content access, credential validation, scanner network, infrastructure changes, full suites, builds or deploys were performed.

Only AWS transport/session selection and the regional S3 HTTP opener are replaced with inert fixtures. The positive result merges the same synthetic value across both real detectors; the negative result requires complete source inspection and both detector runs.

| Native case | Registered outcome |
|---|---|
| positive | FAIL; complete bound ZIP; same synthetic secret merged across real Kingfisher and TruffleHog; credential validation not attempted |
| negative | PASS; complete bound ZIP and both offline detectors completed with no selected indicator |
| denied | UNKNOWN; native GetFunction denied with no HTTP fetch |
| hash_mismatch | UNKNOWN; exact SDK identity/version but downloaded hash differs |
| missing_version | UNKNOWN; native returned version absent, no HTTP fetch |
| truncated_zip | UNKNOWN; SDK hash/size match truncated ZIP but ZIP preflight rejects incomplete archive |
| default_off | UNKNOWN; named content check without opt-in produces no GetFunction or HTTP fetch |
| unselected | UNKNOWN when subsequently evaluating the content check; opt-in with a different named Lambda check produces no GetFunction or HTTP fetch |

Receipt: `/tmp/peasso-aws-review-20261019/optional-lambda-public/accepted.xml`; SHA256 `c5db3fa88fe55c35a4254efdb47918bd6de4a1fbdb84d7f5dad648c9c43839f8`. Test source SHA256 `68f1c2a05f8b0dc7140208ef6bbd141da84cb788fac212ce9605689c98426f6f`; JUnit contains 16 source-bound field emissions and eight consumer outcomes. Field emission does not certify exhaustive semantic consumption.

The synthetic matched value and temporary download URL are absent from public snapshots, successful request-cache values and final reports. The original workload follow-up and package tests were reconciled; the historical dual-final.xml receipt is retained without rerunning its scanner suite.

Remaining unproved:

- Live AWS/S3 behavior, provider-side truth and external credential validity are unproved.
- Published numeric versions, aliases, image-code functions, Lambda layers, other partitions/Regions and concurrency races were not exercised in this focused suite.
- Archive bombs, links, duplicate entries, limits, HTTP metadata/redirects, cancellation and partial-positive retention remain covered only to the scope of existing dedicated tests, not newly certified here.
- No exhaustive detector recall, upstream algorithm equivalence, exhaustive semantic coverage or full branch certification is claimed.

The enabled public collector proof now complements the prior default-off and helper-level content proofs; root owns integration and any broader acceptance accounting. Native support configuration, declared role permissions and optional content inspection remain separate evidence scopes.

AWS defines GetFunction as returning function/version information and a temporary package location, with Qualifier selecting a version or alias: [GetFunction](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html). ZIP integrity and subject binding use the native CodeSize, CodeSha256, FunctionArn and Version members: [FunctionConfiguration](https://docs.aws.amazon.com/lambda/latest/api/API_FunctionConfiguration.html).

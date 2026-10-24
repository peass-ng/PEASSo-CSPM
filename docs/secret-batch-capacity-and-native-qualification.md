# Bounded secret batches and current native witnesses

A full 64 MiB preparation batch could not fit a default 64 MiB `/dev/shm` while retaining the required 1 MiB safety margin. Preparation then returned to per-source TruffleHog processes. The batch adapter now stages smaller groups only on the same verified volatile tmpfs. All groups share the original deadline and output ceiling. An unsupported host, oversized individual payload, failed group or exhausted bound retains the serial path. Source attribution, detector versions, offline flags and private-evidence handling remain unchanged.

A network-disabled Linux amd64 Docker comparison used 64 distinct 1 MiB clean inputs and pinned TruffleHog 3.92.5. The serial detector stage took 162.33 seconds; capacity-aware preparation took 11.57 seconds with two filesystem detector invocations instead of 64 stdin invocations. Both retained all 64 clean results. This local emulated benchmark establishes the preparation improvement for these inputs, not production or whole-scan latency.

IAM's separate sparse-policy improvement and its limits are documented in [Policy-free native inventory](iam-policy-free-inventory-performance.md).

The ACR consumer now requires both a filename receipt and consecutive content chunk receipts for every fully inspected regular file, including empty files and complete index children. A filename alone cannot establish that file content was inspected. Partial positive evidence keeps its existing separate path. Directed negative tests remove either receipt and require UNKNOWN; complete clean and positive native cases remain PASS and FAIL respectively.

Current generic Azure storage and ACR witnesses are generated through the normal collector using synthetic native ARM/OAuth/registry responses. Their compressed fixture pins its producers/evaluators and preserves historical fixture files. Generic detector stubs establish fixture behavior only; separate native wire tests and live registry qualifications establish tool behavior. ACR index layout tests explicitly inject a FakeReader adapter; they do not replace transport acceptance.

Catalog validation resolves only the registered exact-duplicate aliases and still rejects missing native evaluators. Source framework conservation uses the same alias identity. Date-bound Azure unused-IAM collector tests now bind their producer clock to their fixed snapshot instead of depending on the current day; the one-day evidence freshness boundary is preserved.

Unused-resource predicates also reject malformed or foreign Identity Center consumer declarations, malformed Kubernetes Ingress paths and NetworkPolicy expressions even with an empty Pod inventory. Azure network attachment checks enforce declared scan-local capture identities. Valid known permission-set consumers survive unrelated incomplete reads; complete absence still requires the complete account inventory. These changes harden snapshot evaluation; they do not establish that normal cloud collectors emitted the malformed inputs.

The finite source review extends existing current transitions. Historical predecessor hashes and the retained private-source archive remain unchanged; dependent current receipts and the build-time SDK inventory are explicitly refreshed. No new admission layer, cloud grant or remote credential verification is introduced.

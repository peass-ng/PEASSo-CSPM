# Inactive schema-v2 code-manifest candidate

The [candidate JSON](native-final-code-manifest-v2-candidate.json) contains the 20 source-proven high-representative IDs from v3. It has `replay_qualification.status=pending` and a null replay receipt, so the code gate admits no IDs from this file. It is not the production allowlist.

Every source field names the collector API operation, native snapshot field path, typed source semantics, and a reference pinned to the exact 992 snapshot SHA256. A reference to an enclosing response or collection status is used where the API field is absent in the recorded FAIL branch. The `operation` member is the code gate's predicate-class descriptor; the [per-check proof ledger](native-final-proofs-v3.json) gives the exact boundary, missing-field branch, joins, and boolean terms. In particular, the gate's boolean-combination descriptor does not encode the 365-day CloudWatch retention constants; those are pinned to evaluator source lines in the proof ledger.

The [validation receipt](../../outputs/native-final-code-manifest-v2-validation.json) records 62 resolved snapshot references, zero admissions while pending, 20 admissions from a temporary qualified test copy, and zero after an exact-SHA tamper. The temporary replay receipt and qualified copy were created only under a temporary test directory. No replay or model call was made.

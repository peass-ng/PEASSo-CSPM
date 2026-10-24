# Policy-free native inventory

IAM analysis previously constructed a node identifier and memoized an empty policy-document tuple for every native resource, including records with none of the fields that the policy parser reads. The parser now returns an empty tuple directly for exact ordinary or sealed JSON dictionaries with no policy surface. Records with any supported policy field retain the original decoder, review, provenance and cache path. Replaced policy parsers or decoders also retain their original behavior.

An offline profiled comparison over 349,765 captured native resources retained exactly the same 415 IAM review findings, including their serialized output digest. Local stage wall time changed from 13.13 to 6.26 seconds, CPU time from 12.95 to 6.20 seconds, and derived-cache entries from 1,049,298 to 701,847. Peak process RSS was approximately 2.08 GB before and 1.84 GB with the installed change. These are single local profiled stage measurements including a previously loaded inventory; they do not establish production or whole-scan latency.

Regression coverage retains each supported policy wrapper/list shape, principal extraction, all four providers' policy-free inventories, custom parser/decoder hooks and existing scan-local IAM reuse tests. Hash-bound API presentation and SDK source inventories are updated explicitly for the reviewed code.

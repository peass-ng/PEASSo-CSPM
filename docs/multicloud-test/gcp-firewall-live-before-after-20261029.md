GCP regional firewall collection: live qualification
===================================================

The previously unintegrated `b2d09d88` change is rebased onto main `1f45df8d`.
It runs independent region/network reads through the existing bounded,
order-preserving streaming helper. Explicit resource caps keep serial reads.
The exact current-source inverse and API source inventory are rebound; historical
predecessor bytes, source roster, guards and request permissions are unchanged.

| Local native collection | Before | After |
|---|---:|---:|
| Full wall | 263.454s | 219.801s |
| Process CPU | 14.484s | 14.402s |
| Process peak RSS | 751,648,768 bytes | 757,563,392 bytes |
| Regional firewall wall | 54.572s | 6.468s |
| Regional firewall successful HTTP reads | 42 | 42 |
| Logical transport calls | 1,837 | 1,837 |
| Observed requests-library wire calls | 1,548 | 1,571 |

The firewall stage is **8.44× faster**; full local native collection improves
**16.57% (1.20×)** in this pair. Both runs contain exactly **443 collections and
14,708 item identities**, with zero missing/new collection identities, changed
statuses, per-collection count changes or item-identity changes. The histogram
is 40 collected, 107 empty, three denied, 292 unknown and one partial.

All 42 regional reads returned 200 in one attempt on both sides. The ordered
native firewall item data and each item's bound request references match.
Comparison removes only provenance collection timestamps and maps scan-local
request IDs to exact method/URL/query/scope/operation signatures. The aggregate
collection bibliography has the same 42 references in a different order because
wire request IDs are assigned concurrently; sorting that bibliography completes
normalized envelope equality. No native item field or item order is discarded.

This is one before/after **live local** pair, not production timing, whole-payload
equality for all inventories, or a 2× full-collection result. Network failures
increase from 43 to 67, and whole-run wire calls increase by 23 despite identical
logical call counts. No same-wire-cost claim is made for the full run. Numeric
receipts retain those differences. Peak RSS increases 0.79%; no memory win is
claimed. Monitoring covers requests-library traffic; direct GKE HTTPS is outside
its wire counters. Concurrent span totals cannot be added as critical-path wall.

The profile preserves product function bindings through Python 3.12
[per-code monitoring](https://docs.python.org/3.12/library/sys.monitoring.html).
The initial wrapper-based attempt failed source admission and is excluded.
Private mode0600 snapshots, events, profiler and comparison script are hash-bound
in the numeric companion. No provider resources, connector, scan or model were
mutated or invoked beyond the local read-only collector. AWS Access Analyzer,
push and deployment operations remain zero.

Validation: **27 focused tests**, **seven combined release checks**, **nine
strict source checks**, and **one whole historical-epoch reconstruction** pass.
A scoped-resume test's stale exact error message also failed unchanged main;
its expected message now names the earlier finite-source guard, retaining the
same tamper payload and required AdmissionError. No production guard was changed.

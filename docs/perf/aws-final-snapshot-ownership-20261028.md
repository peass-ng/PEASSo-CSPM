# AWS final snapshot ownership bench

The AWS collector's `append()` sanitizes and copies every native item into
collector-owned envelopes. At return, the collector has no further use for
those item lists. Passing `owned=True` to the existing snapshot builder lets
the validated final snapshot adopt them, avoiding another traversal and copy
of the 391,103-item inventory.

The private bf67 saved snapshot was replayed locally through
`make_snapshot()` with the same provider, scopes, 1,292 collection envelopes,
creation time, and metadata. Both modes produced the exact original
`snapshot_id` and 391,103 items. No AWS calls occurred in this replay.

| Measure | Copy mode | Owned mode |
| --- | ---: | ---: |
| Wall, ordinary run | 5.633 s | 3.419 s |
| CPU, ordinary run | 3.523 s | 2.232 s |
| Peak process RSS, ordinary run | 1,937,342,464 B | 2,230,009,856 B |
| Wall, allocation-traced run | 25.141 s | 24.577 s |
| CPU, allocation-traced run | 20.185 s | 16.442 s |
| Peak process RSS, allocation-traced run | 2,030,485,504 B | 1,866,907,648 B |
| Peak traced allocations during build | 660,891,680 B | 183,622,224 B |
| API calls | 0 | 0 |

Peak process RSS varies between separate runs, as the ordinary runs show.
The allocation trace isolates the builder and shows 477 MB fewer peak
allocations; it also imposes substantial instrumentation overhead. This is
a measured final-builder improvement, not proof that the roughly 300-second
production post-job tail is explained by this copy.

Focused tests (`--noconftest`) for the snapshot builder and both AWS
concurrency changes passed: 28 tests. The live production Collect target and
full before/after coverage diff remain open.

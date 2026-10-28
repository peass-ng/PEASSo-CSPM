# AWS Collect content tail and ECS native read reuse

The saved bf67 CloudWatch event stream starts at 0s and ends at 1656.8s.
Automatic content progress begins at 4s. ECS `DescribeTaskDefinition` reaches
4,960 calls by 420s and 9,751 by 780s, then stays at 9,752. The saved
snapshot contains 4,755 task-definition resources. There were 239 throttled
attempts, but the ECS read wave finishes about 510s before the content job.

ECR `GetDownloadUrlForLayer` finishes its 179 calls by about 1290s, with 0
throttles and 5.951s cumulative SDK wall time. Content scanner batch metrics
continue to 1280s. From 900–1290s, one collection job remains active;
37 scanner batches consume 51,759 windows and 511.3 MB input. Preparation
sums to 144.3s and consumption to 125.0s. Process plus completed child CPU
advances about 406s in this 390s interval, near one fully occupied core.
The tail is scanner/archive work, not ECR API throttling. Content was already
started close to t=0; moving its scheduler earlier has at most a few seconds
of headroom before native inventory supplies targets.

The automatic ECS content pass uses a separate safe projection and copies the
request context, so its SDK reads could not reuse the ordinary native raw-read
cache. The cache now admits only the exact immutable
`DescribeTaskDefinition` request from the separately authorized content
client. Its key binds the canonical session, endpoint, operation and ARN.
Raw responses remain in the bounded scan-local cache; the public projected
Future still holds only safe output. The cache retains its 96 MiB ceiling and evicts ordinary metadata first.
ECS revisions beyond that ceiling may require a second physical read. The native
ECS detail also carries only already redacted environment names to its later
name view, avoiding another logical call.
The selected content request uses its existing endpoint admission slot when
populating the raw cache; a second nested limiter slot had reduced effective
concurrency in the focused limiter test and was removed.

A read-only `wiki` ten-definition sample measured the same task/container
result digest before and after. Physical SDK calls were 20→10, raw-cache hits
0→10, wall 4.545→2.413s, CPU 0.049→0.025s, peak RSS 229.8→231.3 MB.
The sample came from the original 256 MiB candidate; its ten revisions fit
within the retained 96 MiB ceiling. Full-scan hit rate with this ceiling has
not yet been measured.
The predecessor's second name-view call was itself a projected-cache hit:
10 physical SDK calls and 10 projected-cache hits on a separate wiki check.
Thus the bf67 near-double SDK wave belongs to the automatic content profile,
not the name-view call.

For bf67, removing the second ECS wave could save up to 4,791 physical calls
and the 377.2s of their cumulative SDK service time from 420–780s. Its wall
window is 360s. Because the ECR scanner job continues to about 1290s, the
critical-path projection for **this ECS change alone is 0s of total Collect
wall saving** if the two jobs remain independent. A 4-way scan of the serial
900–1290s scanner work has an optimistic ceiling of about 202s saving
(`269s × 3/4`), implying no better than about 1464s total Collect before
other stages change. This is a bound from bf67 timing, not a measured
production result. Root's guarded scan must measure actual overlap and
coverage.

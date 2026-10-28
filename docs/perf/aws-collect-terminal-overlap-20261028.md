# AWS Collect terminal publication, bf67 projection

The saved bf67 collector stream places the last `collection.job` at about
t1290 and the final `worker.collect` edge at t1607. The successful AWS content
tail forced a cumulative checkpoint report after the jobs ended. At t1290 the
stream had 36 completed public checkpoints (584.6 cumulative wall seconds) and
five Markdown publications (360.2 cumulative wall seconds). Its next evaluation
ran from roughly t1310 to t1390. A public checkpoint then occupied the worker
from roughly t1391 to t1529; the sixth Markdown publication occupied t1430 to
t1490. By t1530, public checkpoint cumulative wall was 722.7 seconds and
Markdown cumulative wall was 420.0 seconds. The collector's provider completion
edge appeared at t1531, and final validation/replay ended at t1607.

The successful content-tail edge now stops routine cumulative publication.
Settled envelopes still enter bounded durable raw batches during collection;
`finish_collection` flushes the last batch and watermark. The analyzer performs
the full final evaluation. Interrupted collection still forces its latest
partial report during `close`. The private state digest used for final envelope
replay is cached only for an exact unchanged per-scan set of sealed records and
credentials; a changed record or nonempty mutable redaction map takes the
uncached path. These changes do not alter the final native envelopes, public
snapshot, analysis report, or Markdown rendering inputs.

**Projection from bf67, not a new production measurement:** removing roughly
80–90 seconds of post-job evaluation and 138 seconds of public checkpoint
removes about 218–228 seconds from the serial tail. With unchanged remaining
work, `worker.collect` would end around t1379–t1389. The final replay/cache
may shorten some of the remaining ~77 seconds,
but bf67 does not isolate digest cost, so no additional seconds are credited.
The ~30-second post-job target remains a follow-up production check; a full
scan is needed to prove it. The 1,292 collection identities and 391,103 item
identities in the saved snapshot are the coverage baseline for that check.

This slice made no cloud scan, push, or deployment.
